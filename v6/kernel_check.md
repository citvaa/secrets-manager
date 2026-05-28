# Kernel Review Module

Modul po uzoru na LinPEAS, sa ogranicenim obimom. Pokriva celinu provere kernel verzije i konteksta vezanog za kernel.

Skripta koristi postojece sistemske komande (LOTL pristup): uname, cat, ls, lsmod, sysctl, lsb_release, uptime i slicne. Skripta samo prikuplja i izvestava o potencijalno nesigurnim konfiguracijama. Ne sadrzi eksploatacione tehnike.

## Pokretanje

```bash
bash kernel_check.sh
sudo bash kernel_check.sh
```

Druga komanda se preporucuje jer su neke sysctl provere potpunije pod root nalogom.

Za cuvanje izvestaja u audit folder:

```bash
mkdir -p /tmp/audit
sudo bash kernel_check.sh &> /tmp/audit/kernel_check_$(date +%Y%m%d_%H%M).txt
```

## Implementirane funkcionalnosti

Svaka stavka odgovara jednoj funkciji u skripti. Pored opisa onoga sto se proverava, navedeno je i koje bezbednosne probleme provera pomaze da se uoce.

### 1. check_kernel_version

Prikuplja: ime kernela, release, version string, arhitekturu, hostname i pun ispis uname -a. Sadrzi heuristiku koja oznacava staru major liniju kernela (2.x i 3.x kao alert, 4.x kao warn).

Komande: uname -s, uname -r, uname -v, uname -m, uname -n, uname -a.

Bezbednosni problemi koje provera pomaze da se uoce:

1. Zastarela ili poznato ranjiva verzija kernela (CVE-ovi vezani za konkretan release).
2. Kernel za koji distribucija vise ne objavljuje patch-eve.
3. Brza vizuelna procena starosti kernel linije pre detaljnog CVE pretrazivanja.

Distribucije obicno back-portuju kernel patch-eve bez menjanja major.minor verzije, pa CVE proveru treba raditi protiv security advisory liste konkretne distribucije, a ne protiv generickog kernel changelog-a.

### 2. check_os_distribution

Cita /etc/os-release, /etc/debian_version, /etc/redhat-release, /etc/fedora-release, i pokrece lsb_release -a ako je dostupan.

Komande: cat, grep, sed, lsb_release -a.

Bezbednosni problemi koje provera pomaze da se uoce:

1. End-of-life (EOL) distribucija na kojoj se kernel vise ne patch-uje. Primer: Debian Lenny nije podrzan od februara 2012.
2. Bez konteksta distribucije, gola kernel verzija nije dovoljna za odluku da li je sistem ranjiv, zbog back-port problema opisanog iznad.

### 3. check_uptime

Prikazuje uptime i izracunava broj dana iz /proc/uptime. Klasifikuje uptime kao info (manje od 30 dana), warn (od 30 do 60 dana) i alert (60 dana i vise).

Komande: uptime, cat /proc/uptime, awk.

Bezbednosni problemi koje provera pomaze da se uoce:

1. Veliki uptime znaci da kernel verovatno nije patch-ovan duze vreme, jer patch kernela u pravilu zahteva reboot (izuzev livepatch sistema).
2. Tipican primer: sistem sa 70 dana uptime-a skoro sigurno nije imao primenjen kernel security patch u tom periodu.

### 4. check_pending_reboot

Proverava /var/run/reboot-required i /var/run/reboot-required.pkgs (Debian/Ubuntu indikator), zatim poredi pokrenuti kernel (uname -r) sa najnovijim /boot/vmlinuz fajlom.

Komande: ls -1t /boot/vmlinuz-*, cat, uname -r, sed.

Bezbednosni problem koji provera pomaze da se uoci:

1. Sistem ima instaliran patch-ovani kernel ali se i dalje pokrece starija, ranjiva verzija dok se ne uradi reboot. Cest propust nakon apt upgrade ili dnf update komandi.

### 5. check_kernel_hardening

Cita kljucne kernel sysctl vrednosti i komentarise svaku.

| Parametar | Sta oznacava |
|---|---|
| kernel.randomize_va_space | ASLR (preporuceno: 2) |
| kernel.kptr_restrict | skrivanje kernel pokazivaca (preporuceno: 1 ili 2) |
| kernel.dmesg_restrict | ogranicavanje pristupa kernel logu (preporuceno: 1) |
| kernel.yama.ptrace_scope | ogranicavanje ptrace-a (preporuceno: 1 ili vise) |
| net.ipv6.conf.all.disable_ipv6 | da li je IPv6 disable-ovan na nivou kernela |
| fs.suid_dumpable | da li setuid procesi mogu da dumpaju core (preporuceno: 0) |

Komande: sysctl -n, cat /proc/sys.

Bezbednosni problemi koje provera pomaze da se uoce:

1. Iskljucen ili delimican ASLR olaksava eksploataciju i kernel i userspace ranjivosti.
2. Curenje kernel adresa preko kptr_restrict=0 ili dmesg_restrict=0.
3. Mogucnost da bilo koji proces ptrace-uje druge procese istog korisnika.
4. Aktivan IPv6 bez ip6tables pravila predstavlja paralelni napadni vektor: IPv4 firewall pravila se ne primenjuju na IPv6 saobracaj. Ako IPv6 nije potreban, treba ga disable-ovati preko /etc/sysctl.d/disableipv6.conf.
5. Setuid procesi koji mogu da dumpaju core, sto otvara rizik od curenja senzitivnih podataka iz memorije.

### 6. check_loaded_modules

Broji i lista ucitane module preko lsmod ili /proc/modules.

Komande: lsmod, cat /proc/modules, wc -l, head.

Bezbednosni problemi koje provera pomaze da se uoce:

1. Neocekivan ili sumnjiv kernel modul moze biti znak rootkita ili zaboravljenog debug ili test modula.
2. Veliki broj ucitanih modula znaci vecu napadnu povrsinu kernela.
3. Polazna tacka za manuelnu proveru komandom modinfo. Skripta je ne pokrece da bi ostala striktno read-only.

## LOTL pristup

Sve provere koriste samo komande koje su vec prisutne na sistemu: uname, cat, ls, grep, awk, sed, head, wc, id, date, sysctl, lsmod, lsb_release, uptime.

Nema kompilacije, nema preuzimanja sa interneta, nema modifikacije fajlova. Skripta je striktno read-only.

## Read-only ponasanje

Skripta cita sistemske fajlove (kroz cat, sysctl -n i direktan pristup /proc/sys) i ne menja nijednu sistemsku konfiguraciju. Izlaz se moze preusmeriti u audit folder radi cuvanja zapisa o pregledu.
