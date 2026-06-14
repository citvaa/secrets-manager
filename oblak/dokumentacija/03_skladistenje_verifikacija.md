# Oblak - Skladištenje, verifikacija i priprema koda

Deo dokumentacije člana 2. Pokriva drugu fazu životnog ciklusa: šta se dešava sa
funkcijom nakon što je član 1 primi i sačuva sa statusom `UPLOADED`, do trenutka
kada postane spremna za izvršavanje (`READY`) i dobije invoke URL. Nadovezuje se na
`01_bezbednosni_zahtevi.md` i `02_threat_model_STRIDE.md`.

## 1. Opseg faze

Ulaz: preneti paket sa statusom `UPLOADED` (rezultat faze 1).
Izlaz: pripremljen artefakt i jedinstven invoke URL, status `READY` (ulaz za fazu 3).

Komponente koje član 2 isporučuje:

- `server/app/storage.py` (proširenje): provera integriteta, ekstrakcija izvornog
  koda, direktorijum artefakta.
- `server/app/code_verifier.py`: verifikacija prenetog koda u četiri koraka.
- `server/app/preparation.py`: bezbedna priprema izvršnog artefakta sa zavisnostima.
- `server/app/routers/verification.py`: orkestracija pipeline-a i generisanje URL-a.

## 2. Tok obrade (pipeline)

Statusi funkcije (`FunctionStatus`) prelaze redom:

```
UPLOADED  ->  VERIFYING  ->  PREPARING  ->  READY
                  |              |
                  v              v
              REJECTED        FAILED
```

- `VERIFYING` se postavlja na početku verifikacije.
- `REJECTED` znači da kod nije prošao bezbednosnu proveru (HTTP 422).
- `PREPARING` se postavlja pre instalacije zavisnosti.
- `FAILED` označava tehnički neuspeh (integritet ili priprema), HTTP 500.
- `READY` je uspeh: artefakt spreman, invoke URL generisan.

Verifikacija se pokreće automatski: CDK CLI komanda `deploy` odmah posle uploada
poziva pipeline (endpoint `POST /functions/{name}/verify`), tako da korisnik ne mora
ručno da je okida. Isti endpoint ostaje dostupan za ručnu re-verifikaciju (komanda
`verify` ili direktan poziv).

Re-verifikacija je dozvoljena samo iz `UPLOADED`, `REJECTED` ili `FAILED`. Pokušaj
re-verifikacije funkcije koja je već `READY` vraća HTTP 409 (idempotentnost i zaštita
od nepotrebnog ponavljanja).

## 3. Skladištenje (storage)

Proširenja sloja za skladištenje iz faze 1:

- Provera integriteta (`verify_integrity`): ponovo se računa SHA-256 sačuvanog
  paketa i poredi sa očekivanom vrednošću zabeleženom pri uploadu. Neslaganje znači
  da je paket menjan u skladištu i obrađuje se kao greška (adresira pretnju T5/T10,
  zahtev ZR-V3).
- Ekstrakcija izvornog koda (`extract_source`): paket se raspakuje u izolovan
  direktorijum funkcije, uz ponovljenu zaštitu od path traversal i zip-slip napada
  (zahtev ZR-V2/V3, pretnja T4).
- Direktorijum artefakta (`artifact_dir`): poseban prostor po korisniku i funkciji za
  pripremljeni izvršni artefakt.
- Izolacija i dozvole: skladište je organizovano po korisniku i funkciji, sa
  restriktivnim dozvolama nad direktorijumima i fajlovima (zahtev ZR-Z1/Z3,
  pretnja T11).

## 4. Verifikacija koda (Code Verifier)

Verifikacija se izvršava u četiri koraka. Prva tri rade po principu fail-closed:
prvi korak koji ne prođe odbija funkciju. Nijedan korak ne propušta sirov korisnički
kod u poruke o grešci ili logove.

### Korak 1: Antivirus (ClamAV)

Paket se skenira preko `clamdscan`. Pronađen maliciozni sadržaj odbija funkciju. Ako
ClamAV daemon nije dostupan, korak se preskače uz upozorenje u logu (otvorena stavka
OS-AV-1; u produkciji treba da bude obavezan). Zahtev ZR-V4.

### Korak 2: Statička analiza (Bandit)

Bandit se pokreće nad svim `.py` fajlovima izvornog koda. Nalazi visoke ozbiljnosti
(HIGH) odbijaju funkciju; nalazi niže ozbiljnosti se beleže. Zahtev ZR-V5.

### Korak 3: Zabranjeni obrasci (AST)

Svaki `.py` fajl se parsira u AST (apstraktno sintaksno stablo) da bi se izbegli
lažni pozitivi iz komentara i stringova. Odbija se kod koji koristi:

- zabranjene import-e: `subprocess`, `socket`, `pty`, `ctypes`, `cffi`,
  `importlib`, `pickle`, `shelve`, `marshal`;
- zabranjene pozive: `eval`, `exec`, `compile`, `os.system`, `os.popen`,
  `os.execve`/`os.execvp`, `subprocess.*`, `__import__`, `open`, `socket.socket`.

Ovo direktno smanjuje sposobnost korisničkog koda da pokreće procese, otvara mrežne
konekcije ili pristupa fajl-sistemu i pre nego što dođe do izvršnog okruženja.
Zahtev ZR-V5. (Napomena: zabrana `open` je namerno stroga; ako legitimni slučajevi
zahtevaju rad sa fajlovima, ovu listu treba revidirati, videti otvorene stavke.)

### Korak 4: LLM analiza

Izvorni kod (do ograničene dužine) se šalje jezičkom modelu koji vraća kratak opis
ponašanja i ocenu sumnjivosti (`LOW`, `MEDIUM`, `HIGH`). Ocena `HIGH` odbija
funkciju. Ako API ključ nije podešen ili poziv ne uspe, korak daje bezbedan rezultat
i ne blokira pipeline (graceful fallback). Zahtev ZR-V6.

## 5. Priprema artefakta (preparation)

Nakon uspešne verifikacije priprema se izvršni artefakt:

- Validacija `requirements.txt`: odbijaju se specifikatori koji otvaraju put za
  supply-chain napade ili izlazak iz kontrolisanog izvora paketa: editable instalacije
  (`-e`), VCS URL-ovi (`git+`, `hg+`, `svn+`, `bzr+`), lokalne putanje (`./`, `../`,
  `file://`) i override-i indeksa (`--index-url`, `--extra-index-url`, `--find-links`).
  Verzije bez zakucavanja (`==`) se beleže kao upozorenje. Zahtev ZR-SC1, pretnja T12.
- Izolovan virtuelni okruženje (venv) se pravi unutar direktorijuma artefakta, a
  zavisnosti se instaliraju sa:
  - `--no-cache-dir` (sprečava trovanje keša između funkcija),
  - eksplicitnim `--index-url https://pypi.org/simple` (blokira slučajno korišćenje
    kompromitovanog mirror-a),
  - vremenskim ograničenjem instalacije (zaštita od DoS-a preko zaglavljene
    instalacije).

## 6. Generisanje invoke URL-a

Po uspešnoj pripremi generiše se jedinstven, kriptografski nasumičan token
(`secrets.token_urlsafe(32)`), koji se mapira na funkciju, a URL ima oblik
`/invoke/{token}`. Token je teško pogodljiv (nije sekvencijalni ID) i ostaje isti pri
ponovnoj verifikaciji (idempotentno). Zahtev ZR-Z2/ZR-U1, pretnja T14.

Endpoint `GET /invoke/{token}` je za sada placeholder: pronalazi funkciju po tokenu,
proverava da je `READY`, i vraća HTTP 503 dok član 3 ne poveže Firecracker
orkestrator. Tako je ugovor (URL i provera tokena) definisan, a izvršavanje je jasno
razgraničena obaveza faze 3.

## 7. API endpointi

| Metoda i putanja | Opis | Auth |
|---|---|---|
| `POST /functions/{name}/verify` | Pokreće ceo pipeline i generiše invoke URL | Da |
| `GET /functions/{name}` | Detalji funkcije, uključujući invoke token kada je READY | Da |
| `GET /invoke/{token}` | Pokretanje funkcije (placeholder, 503 do faze 3) | Ne |

Na svim koracima pipeline-a upisuje se audit zapis (integrity_check, verify_av,
verify_bandit, verify_patterns, verify_llm, prepare, ready) sa ishodom SUCCESS ili
FAILURE, povezujući fazu 2 sa mehanizmom revizije iz faze 1 (zahtevi ZR-L1/L2).

## 8. Dodatni zahtevi faze 2

Faza 2 precizira zahteve verifikacije iz dokumenta zahteva (ZR-V4) u konkretne
podzahteve:

- ZR-V4 Antivirus skeniranje prenetog paketa.
- ZR-V5 Statička analiza i provera zabranjenih obrazaca (Bandit + AST).
- ZR-V6 LLM analiza ponašanja koda.
- ZR-SC1 Zaštita lanca snabdevanja pri povlačenju zavisnosti.
- ZR-U1 Jedinstven, teško pogodljiv invoke URL po funkciji (precizira ZR-Z2).

## 9. Mapiranje na pretnje (traceability)

```
Pretnja            -> Korak / mehanizam                       -> Zahtev
T4  (zip-slip)     -> extract_source sa proverom putanja      -> ZR-V2/V3
T5/T10 (integritet)-> verify_integrity (SHA-256)              -> ZR-V3
T11 (tuđi kod)     -> izolacija skladišta po korisniku        -> ZR-Z1/Z3
T12 (supply chain) -> validacija requirements + izolovan pip  -> ZR-SC1
T13 (zaobilaženje
     verifikacije) -> fail-closed pipeline, status REJECTED   -> ZR-V4..V6
T14 (pogađanje URL)-> token_urlsafe(32) invoke URL            -> ZR-U1/Z2
```

## 10. Testovi

`server/tests/test_verification.py` pokriva: benigni kod koji prolazi do statusa
`READY`, više malicioznih primera koje pipeline odbija (`eval`, `exec`, `os.system`,
`subprocess`, `socket`, `from socket import ...`), detekciju narušenog integriteta,
ponašanje placeholder invoke endpointa (503), i edge slučajeve (nepoznata funkcija
404, re-verifikacija READY funkcije 409). Maliciozni primer za ručnu demonstraciju
nalazi se u `examples/evil_function`.

## 11. Otvorene stavke (open items)

- OS-AV-1 ClamAV u produkciji treba da bude obavezan (ne samo graceful fallback).
- OS-SC-1 Zakucavanje heša zavisnosti (`--require-hashes`) u `requirements.txt`.
- Zabrana poziva `open` je stroga; razmotriti kontrolisan pristup fajl-sistemu za
  legitimne funkcije ako se pokaže potreba.
- Izvršavanje preko `GET /invoke/{token}` (Firecracker) je obaveza faze 3.
