# OSINT Writeup - Task 3: COMMITMENT, Task 4: Nigerian Prince

**Autor:** Vuk Vicentic, SV45/2022

## Task 3 - COMMITMENT

**Flag format:** `csictf{...}`

### Zadatak

> hoshimaseok is up to no good. Track him down.

### Resenje

Posto je jedina informacija korisnicko ime, prvo sam pretrazio GitHub i nasao profil korisnika **hoshimaseok** sa dva repozitorijuma: `SomethingFishy` i `weatherAPI`. Ime prvog je dovoljno sumnjivo da pocnem od njega.

Klonirao sam oba:

```bash
git clone https://github.com/hoshimaseok/SomethingFishy
git clone https://github.com/hoshimaseok/weatherAPI
```

Sledeci korak je pregled commit istorije. Cak i ako je nesto obrisano iz poslednje verzije koda, git cuva sve promene. Iskoristio sam `git log -p --all` da vidim svaki commit sa kompletnim diffom:

```bash
cd SomethingFishy
git log -p --all > /tmp/history.txt
grep -i "csictf{" /tmp/history.txt
```

Grep je odmah vratio pogodak. U commitu nazvanom `"fix: Did you see my python?"` je u prethodnoj verziji postojala linija:

```
-FLAG = csictf{sc4r3d_0f_c0mm1tm3nt}
```

Linija je dodata u jednom commitu i uklonjena u sledecem, sto je klasican scenario gde neko slucajno commituje tajnu i onda pokusa da je sakrije, ali git historija ostaje.

Sto se tice `weatherAPI`, tu je bio commit "Added API key" koji je dodao `.env` u `.gitignore`, ali sam API kljuc u diffu bio je samo placeholder `"randomapi"` pa tu nema nista interesantno.

**Flag:** `csictf{sc4r3d_0f_c0mm1tm3nt}`

---

## Task 4 - Nigerian Prince

**Flag format:** `UNS{...}`

### Zadatak

Dat je fajl `email.txt` sa sadrzajem spam emaila. Treba naci skrivenu poruku.

### Analiza emaila

Email na prvi pogled izgleda kao obican spam koji svi dobijamo. Ali posto je ovo CTF zadatak, ocito nesto nije kako izgleda. Tekst je podeljen u dva pasusa koji imaju identicnu strukturu:

- pocinju sa "Dear Friend ;" i "Dear Internet user ;"
- sadrze lazne reference na zakone ("Senate bill 1622, Title 8 ; Section 308")
- standardne spam elemente (MLM, popusti, testimonijali)

Ono sto odmah upada u oci je da tekst zvuci previse mehanicki. Svaka recenica prati isti sablon, nema prirodnog toka pisanja. To obicno znaci da je tekst generisan algoritmom, a ne napisan rucno.

### Identifikacija tehnike

Kratka pretraga po prepoznatljivim frazama kao sto je "Dear Friend ; Senate bill" brzo dovodi do alata koji se zove **Spammimic** (spammimic.com).

Spammimic je alat koji implementira tzv. *mimic funkcije* koje je opisao Peter Wayner u knjizi "Disappearing Cryptography" (1996). Nacin rada je sledeci: tajna poruka se konvertuje u niz bitova, a onda se koristi kontekstno-slobodna gramatika (CFG) da se ti bitovi enkoduju kao spam tekst. Svaka "alternativa" u gramatici (npr. koji pozdrav da se koristi, koji zakon da se citira, koji testimonijal da se doda) nosi odredjenu bit-vrednost. Dekodiranje radi obrnuto - prolazi kroz tekst prema istoj gramatici i rekonstruise originalne bitove.

Rezultat je tekst koji izgleda kao pravi spam ali u sebi nosi skrivenu poruku. Ovo je primer tekstualne steganografije.

Isti obrazac emaila se pojavljuje u vise CTF zadataka (RingZer0 #231, HacktivityCon "Unsubscribe") i svi su reseni na isti nacin.

### Resenje

Dekodiranje je jednostavno:

1. Otvoriti https://www.spammimic.com/decode.shtml
2. Kopirati ceo sadrzaj `email.txt` u polje "Spam text"
3. Kliknuti "Decode"

Server prolazi kroz gramaticko stablo i vraca originalnu poruku.

**Flag:** `UNS{EM4IL_5P4M_AG4N?}`

---

## Zakljucak

Oba zadatka se svode na isti princip: informacije koje izgledaju benigno mogu da sadrze tajne podatke. U zadatku 3 to je git historija gde commit koji "brise" tajni podatak zapravo ne brise nista. U zadatku 4 to je steganografija u tekstu gde spam email krije enkodovanu poruku.
