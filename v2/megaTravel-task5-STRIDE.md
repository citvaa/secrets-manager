# ZADATAK 5 - Analiza pretnji i mitigacije (STRIDE) - MegaTravel

## Metodologija

STRIDE je metodologija za identifikaciju pretnji koja pretnje svrstava u 6 kategorija:
- **Spoofing** - lažno predstavljanje
- **Tampering** - neovlašćena izmena podataka
- **Repudiation** - poricanje izvršenih akcija
- **Information Disclosure** - neovlašćeno otkrivanje podataka
- **Denial of Service** - uskraćivanje usluge
- **Elevation of Privilege** - eskalacija privilegija

Analiza je urađena na osnovu DFD-a iz zadatka 4, po komponentama sistema.

---

## Web aplikacija i API

### Lažno predstavljanje korisnika
- **STRIDE:** Spoofing
- **Napad:** Credential stuffing ili phishing - napadač koristi procurele lozinke da preuzme korisnički nalog
- **Ranjivost:** Nema MFA, slabe lozinke, nema rate limitinga na login endpointu
- **Mitigacije:** MFA (TOTP), bcrypt/Argon2id za hešovanje lozinki, rate limiting i account lockout, HSTS + TLS

### Manipulacija rezervacijom (IDOR)
- **STRIDE:** Tampering
- **Napad:** Napadač menja ID rezervacije u zahtevu i pristupa ili menja tuđu rezervaciju
- **Ranjivost:** Nedovoljna autorizacija na API endpointima, predvidivi sekvencijalni ID-evi
- **Mitigacije:** Serverska provera vlasništva resursa pri svakom zahtevu, UUID umesto sekvencijalnih ID-eva, RBAC autorizacija na svakom endpointu

### SQL injekcija
- **STRIDE:** Tampering
- **Napad:** Napadač ubacuje SQL komande kroz forme i čita ili menja sadržaj baze
- **Ranjivost:** Direktna konkatenacija korisničkog unosa u SQL upit
- **Mitigacije:** Parametrizovani upiti i ORM, validacija i sanitizacija unosa, princip minimalnih privilegija za DB nalog aplikacije

### Cross-Site Scripting (XSS)
- **STRIDE:** Tampering
- **Napad:** Napadač ubacuje skripte kroz korisnički unos koje se izvršavaju u browseru žrtve i kradu session tokene
- **Ranjivost:** Nedovoljno escapovanje izlaza, nema Content Security Policy
- **Mitigacije:** Output encoding, CSP header, HttpOnly i Secure flagovi na kolačićima

### Poricanje izvršenih akcija
- **STRIDE:** Repudiation
- **Napad:** Korisnik ili agent tvrdi da nije napravio ili izmenio rezervaciju, a ne postoji zapis koji to opovrgava
- **Ranjivost:** Nedovoljni audit logovi
- **Mitigacije:** Audit log svakog kritičnog događaja sa `actor.id`, `action`, `object.id`, `source.ip`, `@timestamp` - centralizovano u ELK (`audit-*` indeks)

### Otkrivanje ličnih podataka
- **STRIDE:** Information Disclosure
- **Napad:** Napadač dobija pristup podacima korisnika kroz grešku u autorizaciji ili verbose error poruke
- **Ranjivost:** IDOR, preopširne greške, nema maskiranja osetljivih polja u API odgovorima
- **Mitigacije:** RBAC sa proverom vlasništva, maskiranje osetljivih polja (npr. broj kartice: `**** **** **** 1234`), generičke greške ka klijentu, TLS

### DoS napad
- **STRIDE:** Denial of Service
- **Napad:** Napadač šalje masovne zahteve i onemogućava korisnicima pristup platformi
- **Ranjivost:** Nema rate limitinga, nema WAF-a
- **Mitigacije:** Rate limiting po IP-u i korisniku, WAF ispred aplikacije, CDN sa DDoS zaštitom

### Eskalacija privilegija
- **STRIDE:** Elevation of Privilege
- **Napad:** Autentifikovani korisnik pristupa admin endpointima kojima ne bi trebalo da ima pristup
- **Ranjivost:** Autorizacione provjere samo u frontendu, nema serverskih provera
- **Mitigacije:** Autorizacione provere na svakom endpointu na serveru, RBAC sa principom minimalnih privilegija

---

## Baza podataka

### Krađa baze podataka
- **STRIDE:** Information Disclosure
- **Napad:** Napadač koji je kompromitovao backend server dobija direktan pristup bazi i eksfiltruje sve podatke
- **Ranjivost:** Nema mrežne segmentacije, podaci nisu enkriptovani u mirovanju
- **Mitigacije:** Mrežna segmentacija (DB dostupna samo backend servisima), enkripcija u mirovanju (TDE), minimalne DB privilegije za aplikacione korisnike

### Direktna izmena podataka
- **STRIDE:** Tampering
- **Napad:** Kompromitovani privilegovani nalog direktno menja rezervacije ili finansijske zapise zaobilazeći aplikacionu logiku
- **Ranjivost:** Prevelike privilegije DB korisnika, nema audit loga na nivou baze
- **Mitigacije:** Princip minimalnih privilegija, DB audit log (pgaudit za PostgreSQL), redovni backup i provera integriteta

### Ransomware
- **STRIDE:** Denial of Service
- **Napad:** Napadač briše ili enkriptuje podatke u bazi i traži otkupninu
- **Ranjivost:** Backup dostupan sa istog naloga koji ima pristup produkciji, nema offline kopija
- **Mitigacije:** Offline backupi (3-2-1 pravilo), backup nalozi odvojeni od produkcijskih, redovno testiranje restore procedure

---

## Config storovi

### Krađa API ključeva i tajni
- **STRIDE:** Information Disclosure
- **Napad:** Napadač dobija pristup config storeu i krade API ključeve i connection stringove za pristup eksternim servisima
- **Ranjivost:** Tajne u plaintext-u, previše naloga ima čitački pristup
- **Mitigacije:** Centralizovano upravljanje tajnama (HashiCorp Vault ili AWS Secrets Manager), enkripcija tajni (AES-256-GCM), rotacija ključeva, audit log pristupa

### Izmena konfiguracije aplikacije
- **STRIDE:** Tampering
- **Napad:** Napadač menja connection stringove ili parametre ponašanja aplikacije (npr. payment endpoint na maliciozni server)
- **Ranjivost:** Nema verzionisanja config promena, nema alertinga na izmene
- **Mitigacije:** Verzionisanje konfiguracije, audit log izmena sa `actor.id` i timestampom, RBAC za config store

---

## GDS integracija i eksterni sistemi

### Lažni odgovori od GDS-a
- **STRIDE:** Spoofing
- **Napad:** Napadač presreće API komunikaciju i ubacuje lažne podatke o cenama ili dostupnosti (MITM)
- **Ranjivost:** Nedovoljna validacija podataka primljenih od eksternih sistema
- **Mitigacije:** Mutual TLS (mTLS) za GDS komunikaciju, validacija svih dolaznih podataka, alerting na anomalije u podacima

### Curenje podataka ka trećim stranama
- **STRIDE:** Information Disclosure
- **Napad:** Lični podaci korisnika se prosleđuju analitičkim ili notifikacionim servisima bez adekvatne zaštite
- **Ranjivost:** Nema data minimization, PII se šalje u sirovom obliku
- **Mitigacije:** Data minimization, pseudonimizacija PII pre slanja eksternim servisima, DPA ugovori sa svim trećim stranama (GDPR obaveza), TLS za sve integracije

---

## Platni gateway

### Presretanje podataka o plaćanju
- **STRIDE:** Information Disclosure
- **Napad:** Napadač presreće komunikaciju i krade podatke kartice (MITM)
- **Ranjivost:** Loša TLS konfiguracija, kartični podaci prolaze kroz MegaTravel servere bez tokenizacije
- **Mitigacije:** TLS 1.2+, tokenizacija kartica (MegaTravel ne čuva PAN), PCI DSS usklađenost, koristiti provajdera koji preuzima obradu kartičnih podataka (Stripe, Adyen)

### Payment fraud
- **STRIDE:** Tampering
- **Napad:** Napadač manipuliše webhook događajima platnog procesora da potvrdi plaćanje koje nije izvršeno
- **Ranjivost:** Nema verifikacije potpisa webhook notifikacija
- **Mitigacije:** Verifikacija HMAC potpisa svakog webhook događaja, idempotentna obrada plaćanja, serverska provera statusa transakcije direktno od procesora, audit log svih platnih događaja

---

## Interna mreža zaposlenih - VPN i CRM

### Kompromitacija VPN pristupa
- **STRIDE:** Spoofing
- **Napad:** Napadač krade VPN kredencijale zaposlenog putem phishinga i dobija pristup internoj mreži i CRM-u
- **Ranjivost:** Samo lozinka za VPN, nema MFA, nema detekcije anomalnog logina
- **Mitigacije:** MFA obavezan za VPN (TOTP ili hardware token), monitoring neobičnih login pokušaja, zero-trust princip u internoj mreži

### Insajderska zloupotreba CRM-a
- **STRIDE:** Elevation of Privilege / Repudiation
- **Napad:** Agent korisničke podrške pristupa podacima klijenata kojima nije zadužen ili menja rezervacije u lične svrhe
- **Ranjivost:** Preopširne uloge u CRM-u, nema granularnog RBAC-a
- **Mitigacije:** Granularni RBAC (agent vidi samo svoje klijente), audit log svih pristupa i izmena, alerting na bulk export podataka, redovna revizija prava pristupa

---

## Administratorska mreža i ELK Stack

### Kompromitacija admin naloga
- **STRIDE:** Spoofing / Elevation of Privilege
- **Napad:** Napadač krade admin kredencijale i dobija pun pristup infrastrukturi i bazama podataka
- **Ranjivost:** Nema MFA za privilegovane naloge, SSH direktno izložen internetu
- **Mitigacije:** MFA za sve admin naloge (YubiKey/FIDO2), SSH i RDP dostupni samo iz management mreže, bastion host kao jedina ulazna tačka za admin pristup

### Izmena ili brisanje audit logova
- **STRIDE:** Tampering / Repudiation
- **Napad:** Napadač koji je kompromitovao sistem briše audit logove kako bi prikrio tragove napada
- **Ranjivost:** Admin ima write pristup log storageu, logovi se čuvaju samo lokalno
- **Mitigacije:** Centralizovani ELK odvojen od sistema koji loguju, strogi RBAC na `audit-*` indeksima (ingest nalog samo write, niko nema delete), TLS između izvora i Elasticsearcha, alerting na izostanak protoka logova

---

## Rezime prioritetnih mitigacija

| Kontrola | Pretnje | Komponente |
|---|---|---|
| MFA za privilegovane naloge | Spoofing, Elevation of Privilege | Admin pristup, VPN, Kibana |
| Enkripcija tajni (AES-256-GCM + Argon2id) | Information Disclosure, Tampering | Config storovi |
| PCI DSS + tokenizacija kartica | Information Disclosure, Tampering | Platni gateway |
| Centralizovani audit log (ELK audit-*) | Repudiation, Tampering | Sve komponente |
| Parametrizovani upiti + validacija unosa | SQL injection, XSS | Web aplikacija, Baza podataka |
| RBAC sa principom minimalnih privilegija | Elevation of Privilege, IDOR | Web App, CRM, DB, Config store |
| Mrežna segmentacija + firewall | Information Disclosure | Baza podataka, Admin mreža |
| Rate limiting + WAF | Denial of Service, brute-force | Web aplikacija, API |
| TLS 1.2+ za sve komunikacione kanale | Information Disclosure (MITM) | Sve integracije |
