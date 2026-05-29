# Users Review Module

Modul za pregled korisnickih naloga Linux sistema. Koristi LOTL pristup (living off the land, samo citanje postojecih sistemskih fajlova), bez modifikacija.

## Pokretanje

```bash
bash users_check.sh
sudo bash users_check.sh
```

Root pristup je preporucen jer neke provere zahtevaju citanje `/etc/shadow` i `/etc/sudoers`.

Za cuvanje izvestaja:

```bash
mkdir -p /tmp/audit
sudo bash users_check.sh &> /tmp/audit/users_check_$(date +%Y%m%d_%H%M).txt
```

---

## 1. Pregled /etc/passwd

### 1.1 Korisnici sa uid=0

**Sta se proverava:** Lista svih unosa u `/etc/passwd` gde je trece polje (uid) jednako 0.

**Zasto je to bezbednosni problem:**
Na Linux sistemima, uid=0 je identifikator koji kernelu signalizira da je proces pokrenut sa punim root privilegijama — bez obzira na ime naloga. Ako napadac uspe da kreira ili modifikuje nalog tako da mu postavi uid=0, taj nalog ima iste privilegije kao root, ali moze lako proci nezapazeno jer monitorisanje cesto prati ime `root`, a ne uid vrednost.

Backdoor putem uid=0 korisnika je jedna od klasicnih tehnika odrzavanja pristupa (persistence) nakon kompromitacije sistema.

**Kako popraviti:**
Proveriti sve unose rucno. Jedini nalog sa uid=0 treba da bude `root`. Ako se pronadje drugi:

```bash
# Promeniti uid nalog-u koji ne treba da ima 0
sudo usermod -u <novi_uid> <korisnik>
```

Ako je nalog nepoznat ili neocekivan, tretirati kao kompromitaciju i pokrenuti incident response proceduru.

---

### 1.2 Korisnici sa interaktivnim shellom

**Sta se proverava:** Lista korisnika ciji shell field u `/etc/passwd` pokazuje na interaktivan shell (`bash`, `sh`, `zsh`, `fish`, `dash`).

**Zasto je to bezbednosni problem:**
Servisni nalozi (npr. `www-data`, `mysql`, `nobody`, `daemon`) postoje iskljucivo da bi procesi mogli da se pokrecu sa smanjenim privilegijama. Ti nalozi ne treba da budu u stanju da se prijave na sistem interaktivno.

Ako napadac kompromituje servis koji radi pod takvim nalogom (npr. RCE ranjivost u web aplikaciji), a taj nalog ima interaktivan shell, napadac odmah dobija funkcionalan shell na sistemu. Ako nalog ima `/usr/sbin/nologin`, taj vektor je zatvoren.

**Kako popraviti:**
Za svaki servisni nalog koji nema potrebu za interaktivnim pristupom:

```bash
sudo usermod -s /usr/sbin/nologin <korisnik>
```

Legitimni administratorski nalozi koji zahtevaju shell mogu ga zadrzati. Kljucno je da svaki nalog sa shellom ima jasno opravdanje.

---

### 1.3 Prazan password field u /etc/passwd

**Sta se proverava:** Unosi u `/etc/passwd` gde je drugo polje (password) prazno.

**Zasto je to bezbednosni problem:**
Na starim Unix sistemima, hes lozinke se cuvao direktno u `/etc/passwd`, koji je citljiv svim korisnicima. Moderni sistemi koriste `/etc/shadow` za cuvanje heseva (cistljiv samo root-u), a u password polju `/etc/passwd` se nalazi `x` kao placeholder.

Ako je password field prazan (ne `x`, vec doslovno prazan string), na nekim konfiguracijama to znaci da se korisnik moze prijaviti bez lozinke. Cak i ako PAM to blokira, prazan field je jasan znak pogresne ili zastarele konfiguracije.

**Kako popraviti:**
Svaki unos treba da ima `x` u password polju, sto znaci da se lozinka proverava kroz `/etc/shadow`:

```bash
# Ako nalog nema lozinku a treba da je ima
sudo passwd <korisnik>

# Ako nalog nikad ne treba da se prijavljuje, zakljucati ga
sudo passwd -l <korisnik>
```

---

## 2. Pregled /etc/shadow

### 2.1 Hash algoritam po korisniku

**Sta se proverava:** Za svakog korisnika u `/etc/shadow`, skripta cita prefiks hash polja i identifikuje algoritam koji je koriscen.

| Prefiks | Algoritam | Ocena |
|---|---|---|
| bez `$` | DES | Kriticno |
| `$1$` | MD5 | Kriticno |
| `$2$`, `$2a$`, `$2b$` | Blowfish | Upozorenje |
| `$5$` | SHA-256 | Upozorenje |
| `$6$` | SHA-512 | Dobro |
| `!` | Zakljucan nalog | Info |
| `*` | Sistem/servis (bez prijave) | Info |
| prazno | Bez lozinke | Kriticno |

**Zasto je to bezbednosni problem:**
DES ogranicava lozinku na 8 karaktera i izuzetno je brz za brute-force. MD5 nema ogranicenje duzine, ali je dizajniran da bude brz — modernim GPU-ovima se mogu isprobati milijarde MD5 heseva u sekundi. SHA-512 je spor po dizajnu (podesiv broj iteracija) i otporniji na brute-force napade.

Vazno je razumeti da napadac koji dodje do `/etc/shadow` fajla (npr. kroz lokalnu ranjivost ili backup koji je procurio) moze offline da brute-force-uje sve korisnicke lozinke. Slabiji algoritam direktno smanjuje vreme potrebno za otkrivanje lozinke.

**Kako popraviti:**
Promeniti podrazumevani algoritam u PAM konfiguraciji na SHA-512, a zatim prisiliti sve korisnike da promene lozinku kako bi se hesevi regenerisali novim algoritmom:

```bash
# Debian/Ubuntu — u /etc/pam.d/common-password, pam_unix.so linija treba da sadrzi:
# password sufficient pam_unix.so sha512 shadow

# Prisiliti sve korisnike na promenu lozinke pri sledecem loginu
sudo chage -d 0 <korisnik>
```

---

### 2.2 Istek lozinke po korisniku

**Sta se proverava:** Polje `maxdays` u `/etc/shadow` (peto polje) za svaki aktivni korisnicki nalog. Vrednost 99999 ili -1 znaci da lozinka nikad ne istice.

**Zasto je to bezbednosni problem:**
Lozinka koja nikad ne istice ostaje validna neograniceno — cak i ako je kompromitovana. Redovna rotacija lozinki smanjuje prozor tokom kojeg napadac moze koristiti ukradene kredencijale. Industrijska preporuka (CIS Benchmark) je maksimalno 90 dana.

**Kako popraviti:**

```bash
# Podesiti istek na 90 dana za konkretnog korisnika
sudo chage -M 90 <korisnik>

# Proveriti trenutne postavke za korisnika
sudo chage -l <korisnik>
```

---

### 2.3 Globalna politika lozinki (/etc/login.defs)

**Sta se proverava:** Tri parametra u `/etc/login.defs` koji definisu globalnu politiku za sve novokreirane naloge:

| Parametar | Preporucena vrednost | Znacenje |
|---|---|---|
| `PASS_MAX_DAYS` | <= 90 | Maksimalni broj dana pre isteka |
| `PASS_MIN_DAYS` | >= 1 | Minimalni broj dana pre promene |
| `PASS_WARN_AGE` | >= 7 | Broj dana upozorenja pre isteka |

**Zasto je to bezbednosni problem:**
`login.defs` postavlja podrazumevane vrednosti koje se primenjuju na sve novokreirane naloge. Ako `PASS_MAX_DAYS` nije podeseno, novi nalozi ce podrazumevano imati lozinke koje nikad ne isticu. `PASS_MIN_DAYS >= 1` sprecava korisnike da odmah ponovo postave staru lozinku nakon prinudne promene, zaobilazeci politiku rotacije.

**Kako popraviti:**

```
# /etc/login.defs
PASS_MAX_DAYS   90
PASS_MIN_DAYS   1
PASS_WARN_AGE   7
```

Napomena: ove vrednosti se primenjuju samo na novokreirane naloge. Za postojece naloge koristiti `chage`.

---

### 2.4 Podrazumevani PAM algoritam hesiranja

**Sta se proverava:** `pam_unix.so` linija u `/etc/pam.d/common-password` (Debian/Ubuntu) ili `/etc/pam.d/system-auth` (RedHat/CentOS) — eksplicitan naziv algoritma.

**Zasto je to bezbednosni problem:**
Cak i ako su trenutni hesevi SHA-512, ako PAM nije eksplicitno konfigurisan, buduci hesevi mogu koristiti slabiji podrazumevani algoritam, zavisno od verzije sistema. Eksplicitna konfiguracija elimise tu nesigurnost.

**Kako popraviti:**

```
# /etc/pam.d/common-password (Debian/Ubuntu)
password sufficient pam_unix.so sha512 shadow nullok try_first_pass use_authtok
```

---

### 2.5 Politika zakljucavanja naloga

**Sta se proverava:** Prisustvo `pam_faillock` (moderniji) ili `pam_tally2` (stariji) u PAM auth konfiguraciji, i vrednost parametra `deny`.

**Zasto je to bezbednosni problem:**
Bez politike zakljucavanja, napadac moze neograniceno pokusavati lozinke (online brute-force). `pam_faillock` zakljucava nalog na definisani period nakon N neuspelih pokusaja, sto cini online brute-force napade neprakticnim.

**Kako popraviti:**

```
# /etc/pam.d/common-auth (Debian/Ubuntu)
auth required pam_faillock.so preauth silent deny=5 unlock_time=900 fail_interval=900
auth [default=die] pam_faillock.so authfail deny=5 unlock_time=900 fail_interval=900
account required pam_faillock.so
```

Parametri:
- `deny=5` — zakljucaj nakon 5 neuspelih pokusaja
- `unlock_time=900` — zakljucaj na 15 minuta
- `fail_interval=900` — broji neuspele pokusaje u prozoru od 15 minuta

---

## 3. sudo konfiguracija i root pristup

### 3.1 NOPASSWD pravila

**Sta se proverava:** Sve linije u `/etc/sudoers` i fajlovima u `/etc/sudoers.d/` koje sadrze kljucnu rec `NOPASSWD`.

**Zasto je to bezbednosni problem:**
`NOPASSWD` oznacava da korisnik moze izvrsiti navedenu komandu sa root privilegijama bez unosa lozinke. Ovo elimise jedan od kljucnih zastitnih slojeva — cak i ako napadac preuzme sesiju korisnika (npr. XSS, session hijacking, ili fizicki pristup otvorenom terminalu), odmah dobija root pristup bez ikakve autentifikacije.

**Kako popraviti:**
Ukloniti `NOPASSWD` iz svih pravila osim ako ne postoji jasan operativni razlog (npr. automatizovani skripti koji se pokrecu bez interakcije). U tom slucaju, ograniciti pravilo na tacno odredjenu komandu i put, a ne na `ALL`.

```
# Lose:
deploy ALL=(ALL) NOPASSWD: ALL

# Bolje:
deploy ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart myapp.service
```

---

### 3.2 Neogranicena sudo pravila (ALL=(ALL) ALL)

**Sta se proverava:** Linije oblika `korisnik ALL=(ALL) ALL` ili `%grupa ALL=(ALL) ALL` koje daju potpun sudo pristup.

**Zasto je to bezbednosni problem:**
Ovakvo pravilo korisniku daje mogucnost da izvrsi bukvalno bilo koju komandu kao bilo koji korisnik, ukljucujuci root. Princip najmanjih privilegija (least privilege) nalaže da korisnik treba da ima pristup samo komandama koje su mu neophodne za posao.

**Kako popraviti:**
Definisati konkretne dozvoljene komande umesto `ALL`:

```
# Lose:
alice ALL=(ALL) ALL

# Bolje:
alice ALL=(ALL) /usr/bin/systemctl, /usr/bin/journalctl
```

---

### 3.3 Opasne komande u sudoers

**Sta se proverava:** Prisustvo komandi koje, iako izgledaju bezopasno, trivijalno omogucavaju eskalaciju privilegija do root-a.

**Zasto je to bezbednosni problem:**
Ovo je jedna od najcescih gresaka u sudo konfiguraciji. Korisnik sa pristupom npr. `/usr/bin/vim` putem sudoa moze iz vim-a pokrenuti shell komandu (`:!bash`) i dobiti root shell. Slicno vazi za:

| Komanda | Metod eskalacije |
|---|---|
| `vim`, `vi`, `nano` | `:!bash` ili shell escape |
| `less`, `more` | `!bash` iz pagera |
| `find` | `-exec /bin/bash \;` |
| `python`, `perl`, `ruby` | `os.system('/bin/bash')` |
| `awk`, `sed` | shell poziv iz skripte |
| `chown`, `chmod` | promena vlasnistva/dozvola nad `/etc/shadow` ili sudoers |
| `cp`, `mv` | zamena `/etc/sudoers` malicioznom kopijom |
| `bash`, `sh`, `zsh` | direktan shell |

**Kako popraviti:**
Ukloniti sve navedene komande iz sudoers. Ako je potreban pristup editoru za odredjene konfiguracione fajlove, koristiti `sudoedit` koji ne dozvoljava shell escape:

```
alice ALL=(ALL) sudoedit /etc/nginx/nginx.conf
```

---

### 3.4 Drop-in fajlovi (/etc/sudoers.d/)

**Sta se proverava:** Lista svih fajlova u `/etc/sudoers.d/` i njihov sadrzaj.

**Zasto je to bezbednosni problem:**
Sudo automatski ucitava sve fajlove iz `/etc/sudoers.d/`. Paketi pri instalaciji cesto dodaju svoje sudoers pravila ovde, bez eksplicitne potvrde administratora. Napadac sa pristupom ovom direktorijumu moze dodati sopstveno pravilo.

**Kako popraviti:**
Redovno pregledati sadrzaj direktorijuma i ukloniti nepotrebne fajlove. Proveriti dozvole na direktorijumu — treba da bude citljiv samo root-u:

```bash
ls -la /etc/sudoers.d/
# Ocekivano: drwx--x--- root root
```

---

### 3.5 Direktan root login (/etc/securetty)

**Sta se proverava:** Da li `/etc/securetty` sadrzi terminale na kojima root sme da se direktno prijavi.

**Zasto je to bezbednosni problem:**
Direktan root login zaobilazi sudoers log — nema zapisa ko je pokrenuo koja komanda. Takodje, ako je root lozinka kompromitovana, napadac odmah dobija neogranicen pristup bez traga. Preporucena praksa je da root lozinka bude poznata samo u nuzdi (pohranjena u sefu), a svakodnevni administrativni rad ide kroz `sudo` sa licnim nalozima.

**Kako popraviti:**
Isprazniti `/etc/securetty` da bi se onemogucio direktan root login na svim terminalima:

```bash
sudo sh -c '> /etc/securetty'
```

Osigurati da SSH takodje ima `PermitRootLogin no` u `/etc/ssh/sshd_config`.
