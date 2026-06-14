# Oblak - Model pretnji i STRIDE analiza

Deo dokumentacije člana 1. Metodologija: dijagram toka podataka (DFD) sa granicama
poverenja, zatim identifikacija pretnji po STRIDE, pa ublažavanja (mitigations).
Nadovezuje se na `01_bezbednosni_zahtevi.md`.

## 1. Dijagram toka podataka (DFD)

Spoljni entiteti: Programer (CLI) i Pozivalac funkcije (cURL ili Internet).
Procesi su u zagradama `( )`, skladišta podataka kao `[ ]`, a granice poverenja
označene su isprekidanim linijama.

```
                      INTERNET (nepoverljivo)
  +----------------+                         +------------------------+
  | Programer      |                         | Pozivalac funkcije     |
  | (CDK CLI)      |                         | (cURL)                 |
  +----------------+                         +------------------------+
        | (1) register/login/upload (HTTPS)        | (8) GET /invoke/{token}
        v                                          v
====================== TB-1: Internet <-> Server ==========================
        |                                          |
        v                                          v
   (  Server / API  ) <----------------------------+
        |   |   |
        |   |   +--(2) auth (verify JWT, hash lozinke)---> [ Baza: korisnici ]
        |   |
        |   +------(3) audit zapis ------------------------> [ Audit log ]
        |
        v (4) prosledi kod
== TB-2: Server <-> Verifier ==
        v
   ( Code Verifier ) --(5) odbij/odobri--> [ Code Storage ]
        |
        v (6) priprema (povlačenje zavisnosti) <--- AS-4: PyPI / eksterni izvori
   ( Priprema + URL ) --------------------> [ Artefakti ]
        |
        v (7) zahtev za izvršavanje
== TB-3: Host/Orchestrator <-> MicroVM (KRITIČNA GRANICA) ==
        v
   ( Firecracker Orchestrator )
        v
   [ MicroVM: izvršava nepoverljiv korisnički kod ]
```

Tok koji gradi član 1 obuhvata korake (1), (2), (3) i predaju u koraku (4).
Koraci (5) do (7) su član 2, a izvršavanje u koracima (7) i (8) preko granice TB-3
je član 3.

## 2. STRIDE analiza po elementima

STRIDE: Spoofing, Tampering, Repudiation, Information disclosure, Denial of service,
Elevation of privilege. Za svaku pretnju navedeno je ublažavanje i veza sa zahtevom
iz dokumenta zahteva.

### 2.1 Granica TB-1 i Server API (fokus člana 1)

| # | STRIDE | Pretnja | Ublažavanje | Zahtev |
|---|---|---|---|---|
| T1 | S | Napadač se lažno predstavlja kao drugi korisnik (krađa ili pogađanje kredencijala) | Argon2 heširanje lozinki, JWT sa rokom važenja, rate-limit na prijavi | ZR-A2, A3, A5 |
| T2 | S | Falsifikovanje JWT tokena ili izostavljanje potpisa (signature bypass) | Obavezna HMAC verifikacija potpisa, odbiti token bez ili sa neispravnim potpisom | ZR-A4 |
| T3 | T | Izmena zahteva ili koda u prenosu (MITM) | TLS (HTTPS) za sav saobraćaj | ZR-K1 |
| T4 | T | Zip-slip ili path traversal pri raspakivanju arhive (pisanje van ciljnog direktorijuma) | Validacija putanja, odbijanje `..` i apsolutnih putanja, sanitizacija imena | ZR-V2, V3 |
| T5 | R | Korisnik poriče da je preneo maliciozni kod | Audit log sa akterom, vremenom, akcijom i hešom koda | ZR-L1, L2 |
| T6 | I | Curenje tajni iz koda ili odgovora, odnosno poruka o grešci | Tajne van koda (env), generičke poruke o grešci, bez stack-trace-a klijentu | ZR-K2 |
| T7 | I | Curenje kredencijala kroz logove | Zabrana logovanja lozinki, tokena i sadržaja | ZR-L3 |
| T8 | D | Brute-force ili preplavljivanje endpointa | Rate limiting, ograničenje veličine uploada | ZR-A5, D2, V2 |
| T9 | E | Pristup tuđim funkcijama (horizontalna eskalacija) | Provera vlasništva nad resursom na svakom zahtevu | ZR-Z1 |

### 2.2 Code Storage, Verifier i Priprema (član 2)

| # | STRIDE | Pretnja | Ublažavanje | Zahtev |
|---|---|---|---|---|
| T10 | T | Izmena sačuvanog koda ili artefakta | Heš integriteta, kontrola pristupa skladištu | ZR-Z3, V4 |
| T11 | I | Čitanje tuđeg koda iz skladišta | Izolacija po korisniku, najmanja privilegija | ZR-Z1, Z3 |
| T12 | T/E | Maliciozna zavisnost u `requirements.txt` (supply chain) | Zakucane verzije i provera heša, izolovan build, skeniranje | ZR-V4, AS-4 |
| T13 | S | Verifier zaobiđen (kod se izvršava bez provere) | Obavezan korak verifikacije pre pripreme, fail-closed | ZR-V4, D3 |
| T14 | E | Pogađanje URL-a funkcije i neovlašćeno pokretanje | Kriptografski nasumičan, teško pogodljiv URL | ZR-Z2 |

### 2.3 Granica TB-3 i MicroVM izvršavanje (član 3), najkritičnije

| # | STRIDE | Pretnja | Ublažavanje | Zahtev |
|---|---|---|---|---|
| T15 | E | Sandbox ili VM escape do pristupa hostu | Firecracker, jailer i seccomp, neprivilegovan VMM | ZI-1, ZI-2, ZI-7 |
| T16 | I | Eksfiltracija podataka drugih funkcija ili hosta | Efemerne VM, bez deljenog FS, bez izlazne mreže | ZI-3, ZI-4, ZI-6 |
| T17 | D | Fork bomb, beskonačna petlja, memorijska bomba | Tvrde granice CPU, RAM i vremena, timeout i gašenje | ZI-5, ZR-D1 |
| T18 | T | Trajna izmena okruženja (perzistentni backdoor) | Efemernost VM, svež rootfs po pozivu | ZI-6 |
| T19 | R | Poricanje izvršavanja | Audit log pokretanja (ko, šta, kad, ishod) | ZI-8, ZR-L1 |

## 3. Sumarno mapiranje (traceability)

```
Pretnja   -> Zahtev(i)        -> Implementira (član)
T1, T2    -> ZR-A2 do A5      -> M1 (security.py, auth_routes.py)
T3,T6,T7  -> ZR-K1, K2, L3    -> M1 (config, audit)
T4,T5,T8  -> ZR-V2, L1, A5/D2 -> M1 (function_routes.py, audit.py)
T9        -> ZR-Z1            -> M1/M2
T10 do T14-> ZR-V4, Z2, Z3    -> M2
T15 do T19-> ZI-1 do ZI-8     -> M3
```

## 4. Zaključak za fazu člana 1

Komponente koje član 1 isporučuje (auth, upload, audit) adresiraju pretnje T1 do T9
direktno u kodu. Pretnje vezane za skladištenje i verifikaciju (T10 do T14) i
izvršavanje (T15 do T19) dokumentovane su i dodeljene članovima 2 i 3, uz definisane
zahteve i granice poverenja, kako bi naredne faze imale jasan bezbednosni okvir.
