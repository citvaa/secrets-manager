# 04 — Izvršavanje i izolacija (Firecracker Orchestrator)

## 1. Arhitektura

### Tok poziva
```
cURL  GET /invoke/{token}
  → server (FastAPI)  —  pronalazi funkciju po tokenu
  → Orchestrator.execute(artifact_path)
      └── jailer → FC proces → MicroVM → guest agent → vsock rezultat
  → InvokeResponse  (stdout, stderr, return_value, return_code, duration_ms, execution_mode)
```

### Komponente

| Komponenta | Lokacija | Uloga |
|---|---|---|
| `Orchestrator` | `orchestrator/orchestrator.py` | Koordinira Firecracker MicroVM izvršavanje |
| `VmConfig` | `orchestrator/vm_config.py` | Parametri VM-a (vCPU, RAM, timeout, mreža) |
| `jailer.py` | `orchestrator/jailer.py` | Gradi argv listu za jailer CLI |
| `OrchestratorConfig` | `orchestrator/config.py` | Konfiguracija iz env promenljivih |
| Guest agent | `microvm/agent.py` | Init proces unutar MicroVM-a |
| Runner | `microvm/runner.py` | Izvršava korisnički `handler()`, hvata I/O |
| Build skript | `microvm/build_rootfs.sh` | Pravi Alpine+Python rootfs sliku |

### Korisnički ugovor
Korisnik postavlja `main.py` sa funkcijom potpisa:
```python
def handler(event: dict | None = None) -> dict: ...
```
Runner uvozi `main`, poziva `handler({})`, hvata `stdout`/`stderr` i povratnu vrednost,
i vraća JSON rezultat orkestratoru.

---

## 2. Izvršavanje u Firecracker MicroVM

**Tok:**
1. Kreira ext4 disk image sa sadržajem artefakta pomoću `genext2fs` (bez root privilegija)
2. Priprema jailer chroot direktorijum (`/srv/jailer/firecracker/{id}/root/`)
3. Otvara vsock Unix socket listener pre pokretanja VM-a (sprečava race condition)
4. Pokreće Firecracker pod jailerom (`--seccomp-level 2`, chroot, UID drop na 65533)
5. Konfiguriše VM putem Firecracker REST API (Unix socket):
   - `PUT /boot-source` — kernel image
   - `PUT /drives/rootfs` — read-only rootfs
   - `PUT /drives/code` — read-only disk sa korisničkim kodom
   - `PUT /machine-config` — vCPU/RAM
   - `PUT /vsock` — virtio socket za komunikaciju (uds_path je relativan na chroot)
   - `PUT /actions` — `InstanceStart`
6. Guest agent se konektuje na vsock port 52, prima event JSON, izvršava `handler()`, šalje rezultat
7. Orkestrator čita JSON rezultat, ubija FC proces, čisti chroot direktorijum

---

## 3. Bezbednosna analiza

### 3.1 Izolovanost procesa (Process Isolation)

**Pretnja:** Korisnički kod pristupa procesima hosta, modifikuje globalnu memoriju ili
komunicira između poziva.

**Ublažavanja:**
- KVM virtualizacija — potpuna izolacija od host procesa i memorije.
  Svaki poziv dobija svežu instancu VM-a (ne postoji stanje između poziva).

### 3.2 Sandbox Escape

**Pretnja:** Korisnički kod pokušava da pobegne iz sandbox-a i utiče na host sistem.

**Ublažavanja:**
- jailer: chroot u privremeni direktorijum, drop na neprivilegovani UID/GID (65533),
  cgroup v2 ograničenja.
- seccomp: Firecracker `--seccomp-level 2` — dozvoljeni su samo neophodni syscallovi
  (SECCOMP_MODE_FILTER sa striktnom allowlistom).
- Rootfs: read-only virtio-blk — korisnički kod ne može menjati guest OS.
- Code drive: read-only — korisnički kod ne može menjati sopstveni source.


### 3.3 Iscrpljivanje resursa / DoS

**Pretnja:** Korisnički kod troši neograničene CPU, RAM ili procesne resurse i usporava
ili ruši host.

**Ublažavanja:**
- `mem_size_mib: 128`, `vcpu_count: 1` — hypervisor hard limit.
- Wall-clock timeout (`OBLAK_VM_TIMEOUT_SECONDS`, default 30 s) + SIGKILL na FC proces.
- Jailer cgroup v2 ograničenja sprečavaju prekomerno grananje procesa unutar VM-a.

### 3.4 Eksfiltracija podataka

**Pretnja:** Korisnički kod čita osetljive fajlove sa hosta ili šalje podatke na
eksterni server.

**Ublažavanja:**
- Nema mrežnog interfejsa po defaultu (`OBLAK_VM_NETWORK_ENABLED=false`).
  Nema montiranog host fajl-sistema — jedini dostupan disk je read-only code drive.
  Vsock komunikacija je jednosmerna (samo ka orkestratoru).
- Pre izvršavanja: verifikacioni pipeline (Bandit + AST scan) statički odbija
  `import socket`, `subprocess`, `open`, itd. — sandbox je drugi sloj odbrane.

Ako je mreža potrebna za Firecracker VM (npr. za API pozive), preporučuje se:
```
iptables -A FORWARD -i tap+ -o eth0 -j DROP       # blokira egress na internet
iptables -A FORWARD -i tap+ -d 169.254.0.0/16 -j ACCEPT  # dozvoli IMDSv2 ako treba
```

---

## 4. Testni primeri

### Benigni testovi (`tests/benigni/`)

| Fajl | Opis | Očekivani ishod |
|---|---|---|
| `hello/main.py` | Vraća pozdravnu poruku | `return_code=0`, `{"message": "Zdravo, ..."}` |
| `math_ops/main.py` | Sabira i množi dva broja | `return_code=0`, `{"sum":7, "product":12}` |

### Maliciozni testovi (`tests/maliciozni/`)

| Payload | Napad | MicroVM containment |
|---|---|---|
| `fork_bomb` | `os.fork()` beskonačna petlja | 1 vCPU + jailer cgroup → `rc!=0` |
| `network_exfil` | `socket.connect("8.8.8.8", 53)` | Nema NIC-a → `OSError`, `rc!=0` |
| `path_traversal` | `open("/etc/passwd")` | Nema host FS-a → `IOError`, `rc!=0` |
| `resource_exhaustion` | 512 MB alokacija | `mem_size_mib=128` hypervisor limit → `rc!=0` |
| `cpu_exhaustion` | `while True: pass` | Wall-clock timeout SIGKILL → `rc!=0` |

---

## 5. Rezultati statičke analize

Alat: `bandit -r orchestrator/ microvm/ tests/ -f txt`

| Nivo | Broj nalaza |
|---|---|
| HIGH | **0** |
| MEDIUM | **0** |
| LOW | 33 (pretežno B404/B603/B101 — upotreba `subprocess` i `assert` u testovima; prihvaćen rizik) |

Pun izveštaj: `bandit_report.txt` u korenu projekta.

---

## 6. Otvorene stavke (zahteva sistemsko podešavanje)

Za aktiviranje Firecracker putanje potrebno je:

1. **Kernel image:** preuzeti `vmlinux` sa Firecracker GitHub Releases stranice i
   smestiti na `OBLAK_KERNEL_PATH` (default: `/var/lib/oblak/vmlinux`)

2. **Rootfs image:** pokrenuti `microvm/build_rootfs.sh` koji kreira Alpine Linux +
   Python 3 root filesystem sa guest agentom kao `/sbin/init`.
   Smestiti na `OBLAK_ROOTFS_PATH` (default: `/var/lib/oblak/rootfs.ext4`)

3. **Binarni fajlovi:** instalirati Firecracker i jailer:
   ```bash
   ARCH=$(uname -m)
   VERSION=v1.7.0
   curl -Lo firecracker "https://github.com/firecracker-microvm/firecracker/releases/download/${VERSION}/firecracker-${VERSION}-${ARCH}.tgz"
   # raspakovati i staviti na OBLAK_FIRECRACKER_BIN i OBLAK_JAILER_BIN
   ```

4. **KVM pristup:** server proces mora imati pristup `/dev/kvm`:
   ```bash
   sudo usermod -aG kvm $SERVICE_USER
   ```

5. **Dedicated UID za jailer:**
   ```bash
   sudo useradd -r -u 65533 -g 65533 -s /sbin/nologin oblak-vm
   ```

6. **cgroup v2 hijerarhija:** jailer koristi `--cgroup-version 2`; sistem mora imati
   cgroup v2 mountovan na `/sys/fs/cgroup`

7. **Mrežna izolacija (opcionalno):** ako se `OBLAK_VM_NETWORK_ENABLED=true`, dodati
   iptables egress pravila po VM network namespace-u

---

## 7. Konfiguracija (env promenljive)

| Promenljiva | Default | Opis |
|---|---|---|
| `OBLAK_FIRECRACKER_BIN` | `/usr/local/bin/firecracker` | Putanja do FC binarnog fajla |
| `OBLAK_JAILER_BIN` | `/usr/local/bin/jailer` | Putanja do jailer binarnog fajla |
| `OBLAK_KERNEL_PATH` | `/var/lib/oblak/vmlinux` | Linux kernel za VM |
| `OBLAK_ROOTFS_PATH` | `/var/lib/oblak/rootfs.ext4` | Base rootfs image |
| `OBLAK_VM_VCPUS` | `1` | Broj vCPU-ova |
| `OBLAK_VM_MEM_MIB` | `128` | RAM u MiB |
| `OBLAK_VM_TIMEOUT_SECONDS` | `30` | Wall-clock timeout |
| `OBLAK_VM_NETWORK_ENABLED` | `false` | Dozvoli VM mrežni interfejs |
| `OBLAK_JAILER_UID` | `65533` | UID za jailer drop |
| `OBLAK_JAILER_GID` | `65533` | GID za jailer drop |
