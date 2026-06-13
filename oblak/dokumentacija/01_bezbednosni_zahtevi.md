# Oblak - Analiza sistema i bezbednosni zahtevi

Deo dokumentacije člana 1. Pokriva analizu celog sistema i posebno izvršavanje
korisničkog koda u virtuelnoj mašini (izolovanost procesa). Terminologija prati
materijal sa vežbi (analiza imovine, CIA ciljevi, površina napada, granice
poverenja) i predavanja (inženjerstvo bezbednosnih zahteva, osnovni principi).

## 1. Opis i namena sistema

Oblak je platforma koja korisnicima (programerima) omogućava da prenesu Python kod
na server i da ga pokreću na zahtev preko generisanog URL-a (model Function as a
Service, FaaS). Pošto je korisnički kod po definiciji nepoverljiv, sistem mora da
ga analizira pre izvršavanja i da ga izvršava u izolovanom okruženju (preporučeno
Firecracker MicroVM).

Glavne komponente:

| Komponenta | Uloga |
|---|---|
| CDK CLI | Konzolni klijent: autentikacija, pakovanje i prenos koda |
| Server | Centralni API: auth, prijem koda, koordinacija ostalih komponenti |
| Code Storage | Skladište prenetog koda |
| Code Verifier | Antivirus, statička i LLM analiza prenetog koda |
| Priprema i URL | Povlačenje zavisnosti, kreiranje artefakta, generisanje URL-a |
| Firecracker Orchestrator i MicroVM | Izolovano izvršavanje koda na zahtev |
| Baza podataka | Korisnici, funkcije, metapodaci, audit zapisi |

## 2. Klase napadača (threat actors)

Prema pristupu sa vežbi, ne zahtevaju svi delovi sistema isti nivo zaštite. Klase
napadača za Oblak:

1. Maliciozni korisnik platforme (autentikovan). Ima legitiman nalog i namerno
   prenosi maliciozni kod sa ciljem bekstva iz sandboxa, eksfiltracije podataka
   drugih korisnika, ili zloupotrebe resursa (kripto-rudarenje, botnet). Visok
   prioritet, jer je ovo primarni, inherentni napadač FaaS platforme.
2. Anonimni napadač sa Interneta. Nema nalog, cilja autentikaciju (brute-force,
   credential stuffing), izložene endpointe i javne URL-ove funkcija.
3. Napadač koji je kompromitovao kod korisnika (supply chain). Kroz zlonamernu
   zavisnost u `requirements.txt` ili kompromitovan nalog ubacuje maliciozni kod.
4. Insajder ili privilegovani operater. Pristup serveru, bazi ili logovima,
   pretnja poverljivosti i neporecivosti.
5. Mrežni napadač (MITM). Prisluškuje ili menja saobraćaj CLI ka serveru ako nije
   zaštićen TLS-om.

Procena: sistem nije meta država-sponzorisanih napada, ali jeste visoko vredna meta
za zloupotrebu računarskih resursa i napade na izolaciju, pa je nivo zaštite
izvršnog okruženja kritičan.

## 3. Imovina (assets) i bezbednosni ciljevi (CIA)

| Imovina | Poverljivost | Integritet | Dostupnost | Uticaj kompromitacije |
|---|:--:|:--:|:--:|---|
| Korisnički nalozi i kredencijali | Visok | Visok | Srednji | Preuzimanje naloga, lažno predstavljanje |
| Korisnički kod (izvor) | Visok | Visok | Srednji | Krađa intelektualne svojine, ubacivanje backdoor-a |
| Tajne platforme (JWT ključ, DB lozinka) | Kritičan | Kritičan | Srednji | Potpuna kompromitacija sistema |
| Artefakti za izvršavanje | Srednji | Visok | Srednji | Izvršavanje izmenjenog koda |
| Host server ili hipervizor | Kritičan | Kritičan | Kritičan | Sandbox escape i kontrola nad svim funkcijama |
| Audit logovi | Srednji | Kritičan | Visok | Poricanje odgovornosti, brisanje tragova |
| Računarski resursi (CPU/RAM/mreža) | n/a | n/a | Visok | DoS, zloupotreba (rudarenje) |

## 4. Površina napada (attack surface)

Ulazne tačke kroz koje napadač može da deluje:

- AS-1 CLI ka Server REST API-ju (registracija, prijava, upload, list).
- AS-2 Javni URL funkcije (poziv izvršavanja, npr. preko `cURL`), dostupan
  anonimno sa Interneta.
- AS-3 Sadržaj prenete arhive: sam Python kod i `requirements.txt` (ulaz u
  Code Verifier i u izvršno okruženje).
- AS-4 Zavisnosti koje se povlače tokom pripreme (PyPI ili eksterni izvori).
- AS-5 Izvršavanje korisničkog koda unutar MicroVM (granica VM prema host-u).
- AS-6 Administrativni ili operativni pristup (SSH, baza, logovi).

## 5. Granice poverenja (trust boundaries)

- TB-1 Internet prema serveru (CLI i javni URL prelaze ovu granicu).
- TB-2 Server prema Code Verifier-u (nepoverljiv kod ulazi u analizu).
- TB-3 Server ili Orchestrator prema MicroVM (najvažnija granica: izvršava se
  nepoverljiv kod, pa se sve preko ove granice tretira kao neprijateljsko).
- TB-4 Aplikacija prema skladištu tajni ili bazi.

## 6. Bezbednosni zahtevi za ceo sistem

Zahtevi su grupisani po sigurnosnim ciljevima. Oznaka `[M1/M2/M3]` označava člana
odgovornog za primarnu implementaciju.

### 6.1 Autentikacija i upravljanje identitetom

- ZR-A1 Svi privilegovani endpointi servera moraju zahtevati autentikaciju. [M1]
- ZR-A2 Lozinke se čuvaju isključivo kao heš sa salt-om, savremenim algoritmom
  (Argon2id, alternativno bcrypt, scrypt ili PBKDF2). Nikada plaintext, nikada
  MD5 ili SHA-1 bez salt-a (pouka sa vežbi: izbeći `md5` bez salt-a). [M1]
- ZR-A3 Prijava izdaje kratkoročni token (JWT, HMAC-SHA256) potpisan tajnim
  ključem, token nosi rok važenja (`exp`) i identitet korisnika. [M1]
- ZR-A4 Token se verifikuje korišćenjem HMAC (ne obične heš funkcije) i mora se
  odbiti ako potpis nedostaje ili ne odgovara (sprečavanje signature bypass-a iz
  primera sa vežbi). [M1]
- ZR-A5 Zaštita od brute-force napada: ograničenje broja pokušaja prijave
  (rate limiting ili lockout). [M1]
- ZR-A6 (Otvorena stavka, pattern sa vežbi) Podrška za višefaktorsku
  autentikaciju (lozinka i TOTP) za administrativne naloge.

### 6.2 Autorizacija

- ZR-Z1 Korisnik sme da pristupa, menja i pokreće isključivo svoje funkcije
  (provera vlasništva nad resursom na svakom pozivu), čime se sprečava
  authorization bypass iz primera sa vežbi. [M1/M2]
- ZR-Z2 Javni URL funkcije mora biti teško pogodljiv (kriptografski nasumičan
  identifikator), a ne sekvencijalni ID. [M2]
- ZR-Z3 Princip najmanje privilegije za sve servisne naloge (server, verifier,
  orchestrator, DB). [svi]

### 6.3 Validacija ulaza i prenos koda

- ZR-V1 Sav ulaz se validira (Pydantic šeme): tipovi, dužine, dozvoljeni znakovi
  za imena funkcija. [M1]
- ZR-V2 Prenos koda mora imati ograničenje veličine i tipa, a arhiva se raspakuje
  uz zaštitu od path traversal i zip-slip napada (odbiti putanje sa `..` i
  apsolutne putanje). [M1]
- ZR-V3 Nazivi i putanje fajlova se sanitizuju, korisnik ne sme da utiče na
  putanju skladištenja izvan svog prostora (pouka: ranjivost izlistavanja
  direktorijuma preko korisničkog imena `..`). [M1/M2]
- ZR-V4 Preneti kod se mora verifikovati (antivirus, statička i LLM analiza) pre
  pripreme i izvršavanja, a kod koji ne prođe se odbija. [M2]

### 6.4 Poverljivost i kriptografija

- ZR-K1 Sva komunikacija CLI ka serveru i poziv URL-a mora ići preko TLS-a (HTTPS).
  [M1/infra]
- ZR-K2 Tajne (JWT ključ, DB kredencijali) se ne smeju nalaziti u izvornom kodu,
  već se injektuju kroz promenljive okruženja ili konfiguracione fajlove (pouka sa
  vežbi: hardcoded secrets). [M1]
- ZR-K3 Lokalni kredencijali CLI klijenta čuvaju se u fajlu sa restriktivnim
  dozvolama (`0600`). [M1]
- ZR-K4 (Pattern sa vežbi) Ako se tajne čuvaju radi kasnijeg čitanja, koristi se
  enkripcija sa ključem izvedenim iz master lozinke (PBKDF2 ili Argon2, pa AES-GCM).

### 6.5 Revizija i neporecivost (auditing, non-repudiation)

- ZR-L1 Svaki bezbednosno relevantan događaj (registracija, prijava sa uspehom i
  neuspehom, upload, brisanje, izvršavanje) se loguje. [M1]
- ZR-L2 Audit zapis sadrži tačno vreme (UTC), aktera, akciju, resurs, ishod i
  identifikator zahteva, tako da akter ne može da porekne radnju. [M1]
- ZR-L3 Audit zapisi ne smeju sadržati osetljive podatke (lozinke, tokene,
  sadržaj koda). [M1]
- ZR-L4 Logovi moraju imati zaštićen integritet i dostupnost (append-only,
  ograničene dozvole, rotacija, opciono otpremanje na udaljeni sistem ili ELK). [M1]

### 6.6 Dostupnost i otpornost

- ZR-D1 Ograničenja resursa po izvršavanju (CPU, RAM, vreme, veličina izlaza) radi
  sprečavanja DoS-a i zloupotrebe. [M3]
- ZR-D2 Rate limiting na javnim endpointima. [M1/M2]
- ZR-D3 Bezbedni podrazumevani izbori: sistem podrazumevano odbija (default-deny)
  na granicama poverenja. [svi]

## 7. Bezbednosni zahtevi za izvršavanje koda u MicroVM (izolacija)

Ovo je najkritičniji deo (granica TB-3). Implementira ih primarno član 3, ali se
zahtevi definišu ovde radi celovitosti.

- ZI-1 Izolacija procesa i jezgra. Svaka funkcija se izvršava u zasebnoj MicroVM sa
  sopstvenim jezgrom, korisnički kod nema pristup host kernelu niti drugim
  funkcijama.
- ZI-2 Minimalna površina hipervizora. Korišćenje Firecracker `jailer`-a i seccomp
  filtera za ograničavanje sistemskih poziva dostupnih VMM procesu.
- ZI-3 Bez pristupa host fajl-sistemu. VM dobija samo svoj rootfs ili artefakt, bez
  deljenih mountova sa hostom van neophodnog (read-only gde je moguće).
- ZI-4 Kontrola mreže. Podrazumevano bez izlaznog mrežnog pristupa, eksplicitno
  dozvoliti samo ako je neophodno (sprečavanje eksfiltracije i C2 saobraćaja).
- ZI-5 Ograničenje resursa. Tvrde granice CPU, RAM i vremena izvršavanja, prekid
  (timeout) i gašenje VM po isteku (zaštita od fork bomb-a i DoS-a).
- ZI-6 Efemernost. VM se uništava nakon izvršavanja, bez perzistencije stanja
  između poziva (sprečava ostavljanje backdoor-a i curenje podataka).
- ZI-7 Neprivilegovano izvršavanje. VMM i orchestrator ne smeju raditi kao `root`,
  princip najmanje privilegije (pouka secure deployment vežbe).
- ZI-8 Logovanje izvršavanja. Svako pokretanje (ko, koja funkcija, trajanje,
  ishod) ide u audit log (povezuje se sa ZR-L1).

## 8. Mapiranje zahteva na pretnje

Svaki zahtev iz ovog dokumenta adresira jednu ili više STRIDE pretnji opisanih u
`02_threat_model_STRIDE.md`. Tabela praćenja (zahtev, pretnja, ublažavanje) nalazi
se u tom dokumentu.

## 9. Otvorene stavke (open items)

Stavke koje su prepoznate kao potrebne, ali su prevelike za pun obim projekta. Uz
svaku je opisano šta bi trebalo uraditi (kako postavka dozvoljava):

- OS-1 MFA (TOTP) za administratore (ZR-A6).
- OS-2 Udaljeno centralizovano logovanje (ELK) sa MFA pristupom Kibani (ZR-L4).
- OS-3 Potpisivanje i provera integriteta artefakata za izvršavanje (npr. preko
  potpisa u stilu sigstore alata).
- OS-4 Pun mrežni egress firewall po funkciji (ZI-4) na nivou hosta.
