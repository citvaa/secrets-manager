# Services Review Module

Modul po uzoru na LinPEAS, sa ogranicenim obimom. Pokriva celinu pregleda pokrenutih servisa i njihovih konfiguracija (System Review Example, sekcija 8: Services Review).

Skripta koristi postojece sistemske komande (LOTL pristup): ps, grep, cat, find, timedatectl, ntpq, chronyc. Skripta samo prikuplja i izvestava o potencijalno nesigurnim konfiguracijama. Ne sadrzi eksploatacione tehnike.

## Pokretanje

```bash
bash services_check.sh
sudo bash services_check.sh
```

Druga komanda se preporucuje jer su neke provere potpunije pod root nalogom.

Za cuvanje izvestaja u audit folder:

```bash
mkdir -p /tmp/audit
sudo bash services_check.sh &> /tmp/audit/services_check_$(date +%Y%m%d_%H%M).txt
```

## Implementirane funkcionalnosti

Svaka stavka odgovara jednoj funkciji u skripti.

### 1. check_running_services

Prikuplja listu svih pokrenutih procesa (ps -edf) i posebno izdvaja procese koji rade pod root nalogom, filtriranjem kernel threadova (oznacenih uglastim zagradama). Proverava da li su aktivni syslog i fail2ban.

Komande: ps -edf, grep.

Bezbednosni problemi koje provera pomaze da se uoce:

1. Neprepoznat proces koji radi kao root moze biti znak rootkita ili kompromitovanog sistema; svaki nepoznat unos zahteva dodatnu provjeru.
2. Servisi koji rade kao root a ne moraju (npr. web server koji moze raditi kao www-data) povecavaju stetu u slucaju eksploatacije tog servisa.
3. Bez syslog servisa sistem ne biljezi bezbednosne dogadjaje i napad prolazi bez traga.
4. Bez fail2ban ili slicnog alata, bruteforce napadi na SSH i druge servise mogu ici neograniceno bez automatske blokade.

### 2. check_ssh_config

Cita /etc/ssh/sshd_config i proverava cetiri kljucne opcije: PermitRootLogin, PasswordAuthentication, Port i AllowTcpForwarding.

Komande: grep, cat /etc/ssh/sshd_config.

Bezbednosni problemi koje provera pomaze da se uoce:

1. PermitRootLogin = yes omogucava direktan bruteforce napad na root nalog; uspesni napad odmah daje puni pristup sistemu. Preporuka je koristiti obicnog korisnika i sudo.
2. PasswordAuthentication = yes dozvoljava napad pogadjanjem lozinke; SSH kljucevi su kriptografski znatno jaci i ne mogu se pogoditi.
3. Podrazumevani port 22 automatski skeniraju roboti po celom internetu odmah cim server dobije javnu IP adresu; promena porta smanjuje automatizovane napade.
4. AllowTcpForwarding = yes moze se koristiti za zaobilazenje mreznih restrikcija tunelovanjen saobracaja kroz SSH konekciju do internih sistema.

### 3. check_ntp

Proverava da li je aktivan neki od NTP servisa (systemd-timesyncd, ntpd, chronyd) i da li je vreme sinhronizovano. Prikazuje izlaz relevantnog alata (timedatectl, ntpq, chronyc). Proverava vremensku zonu i upozorava ako nije UTC.

Komande: timedatectl, ps -edf, ntpq -p -n, chronyc tracking, cat /etc/timezone.

Bezbednosni problemi koje provera pomaze da se uoce:

1. Netacno sistemsko vreme kvari log korelaciju: ne moze se tacno utvrditi redosled dogadjaja iz vise razlicitih izvora (web server log, syslog, aplikacijski log).
2. SSL/TLS sertifikati se odbijaju ako je sistemsko vreme daleko od stvarnog, jer sertifikati imaju datum pocetka i kraja vaznosti.
3. Vremenska zona sa prelaskom na letnje/zimsko racunanje vremena pravi skokove u logovima koji otezavaju forenziku i korelaciju dogadjaja.

### 4. check_logging

Cita /etc/rsyslog.conf i proverava tri stvari: da li se logovi salju na udaljeni server (remote logging), da li log fajlovi u /var/log imaju loose permisije, i da li rsyslog prima logove sa mreze.

Komande: grep, find /var/log, cat /etc/rsyslog.conf.

Bezbednosni problemi koje provera pomaze da se uoce:

1. Logovi koji ostaju samo na lokalnom disku mogu biti obrisani ako napadac dobije root pristup; remote logging cuva trag van dosega napadaca.
2. Log fajlovi citljivi od strane svih korisnika mogu otkriti osetljive informacije o sistemu (IP adrese, korisnicka imena, greske aplikacija).
3. Ako rsyslog prima logove sa mreze a nije namenjen za to, moze biti meta remote log injection napada ili sluziti kao nenamerni log agregator.

