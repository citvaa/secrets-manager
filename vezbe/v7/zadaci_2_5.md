# OSINT Writeup - Task 2: PIRATES OF MEMORIAL, Task 5: Educational Purposes Only

**Autor:** Miloš Milosavljević, SV80/2022

---

## Task 2 - PIRATES OF MEMORIAL

**Flag format:** `csictf{...}`

### Zadatak

> The original photographer of this picture commented the flag on his post. Find the flag.

Data je fotografija Victoria Memoriala u Kolkati, Indija, snimljena pod oblačnim nebom uoči nevremena.

### Rešenje

Slika je prepoznata kao snimak poznate građevine (Victoria Memorial, Kolkata), ali ime fotografa nije bilo direktno čitljivo iz fajla. Reverse image search (pretraga slike, ne teksta) odveo je do tvita korisnika **@rishibagree** objavljenog 11. jula 2018. godine sa istom fotografijom.

U komentarima ispod tvita razvila se diskusija oko toga ko je *stvarni* autor fotografije — jedan od komentara (Partha Sarat..., 10. feb 2019) ispravlja pogrešno pripisivanje i navodi pravo ime fotografa: **Arunopal Banerjee**.

Sledeći korak bio je pronaći Instagram profil fotografa Arunopala Banerjeea i potražiti originalnu objavu te fotografije. Flag se nalazio direktno u komentarima ispod originalnog Instagram posta.

**Flag:** `csictf{pl4g14r1sm_1s_b4d}`

Flag tematski odgovara nazivu zadatka — "PIRATES OF MEMORIAL" referiše na krađu/pogrešno pripisivanje autorstva fotografije (plagijat), što je tačno ono što je istraživanje otkrilo.

---

## Task 5 - Educational Purposes Only

**Flag format:** `UNS{...}`

### Zadatak

> Together with your friends, you browsed the web archive of the Faculty of Technical Sciences and came across some very old archive. You downloaded it to see what was inside, but it was locked. Along with it, you also found a file that you think can help you unlock the archive.

Uz arhivu (`old.rar`) dat je fajl `forgotten_password.txt` sa četiri pitanja o istoriji Fakulteta tehničkih nauka. Svaki odgovor je praćen MD5 hešom za verifikaciju, a tačni odgovori spojeni zajedno (bez separatora, istim redosledom kao u pitanjima) čine lozinku arhive.

### Rešenje

Svako pitanje je zahtevalo drugačiji OSINT izvor — generička pretraga nije bila dovoljna za sva četiri.

**Pitanje 1 — Datum osnivanja FTN**

Standardna pretraga (Wikipedia, zvanični FTN sajt) odmah daje podatak: Fakultet tehničkih nauka osnovan je **18. maja 1960. godine**, odlukom Narodne skupštine NR Srbije, kao Mašinski fakultet u Novom Sadu.

```
Odgovor: 18/05/1960
MD5(18/05/1960) = 02c3890bb0b03a24b99c3e4a39f18c44  ✓
```

**Pitanje 2 — Dekan FTN (01.10.1975–30.09.1977)**

Ovaj podatak nije dostupan kroz generičku pretragu niti na Wikipediji (koja navodi samo nekoliko ključnih imena kroz istoriju). Pravi izvor je zvanična jubilarna monografija fakulteta — **"Педесет пет година развоја Факултета техничких наука"** (Radoš Radivojević, 2015) — koja sadrži posebno poglavlje "Декани и продекани" sa kompletnim spiskom kroz istoriju. Za traženi period dekan je bio **dr Dragutin Zelenović**, vanredni profesor.

```
Odgovor: Dragutin
MD5(Dragutin) = 06904f68128802c069e782b772e85eda  ✓
```

**Pitanje 3 — Datum lansiranja FTN sajta**

Najteže pitanje u zadatku. Pravci koji NISU dali odgovor:
- Wayback Machine najraniji zabeleženi snimak sajta — 3. april 2009. (to je samo prvi put da je Wayback *zabeležio* sajt, ne kad je *lansiran*)
- WHOIS na `uns.ac.rs` — vraća samo datum registracije `.ac.rs` zone u celini (10.03.2008), nevezano za konkretan sajt
- Datum osnivanja Računarskog centra FTN-a (1994) — osnivanje *službe*, ne lansiranje *sajta*

Trag: na arhiviranoj verziji sajta iz 2009. (Wayback Machine), footer je sadržao `© 2005. by MMC` — pokazatelj da je sajt postojao već od 2005. Pošto je FTN tradicionalno vezan za datum **18. maj** (Dan fakulteta, isti dan kao osnivanje 1960.), pretpostavljeno je da je sajt lansiran baš tog datuma. Brute-force pretragom MD5 heša kroz sve datume u opsegu 1995–2015 (Python skripta, ~7300 kandidata) potvrđen je odgovor:

```
Odgovor: 18/05/2005
MD5(18/05/2005) = f4d7caf81e33bc156cc3e98cf8095d2e  ✓
```

**Pitanje 4 — Godina uvođenja studija "Poštanski saobraćaj i telekomunikacije"**

Web pretraga (zvanični sajt Departmana za saobraćaj, forumski post studenata FTN-a) potvrđuje da je smer **PTT saobraćaj** (kasnije preimenovan u Poštanski saobraćaj i telekomunikacije) osnovan u školskoj **1999/2000.** godini.

```
Odgovor: 1999
MD5(1999) = 5ec829debe54b19a5f78d9a65b900a39  ✓
```

### Formiranje lozinke

Odgovori spojeni direktno, istim redosledom kao u pitanjima, bez separatora:

```
Lozinka: 18/05/1960Dragutin18/05/20051999
```

Ovom lozinkom otvorena je `old.rar` arhiva.

**Flag:** `UNS{V3RY_OLD_4RCH1V3}`

---

## Zaključak

Oba zadatka pokazuju da OSINT istraživanje zahteva biranje **specijalizovanog izvora** prema tipu traženog podatka:
- Krađa/pripisivanje autorstva slike → reverse image search + praćenje diskusije u komentarima do originalnog izvora
- Istorija institucije → zvanična jubilarna monografija, ne Wikipedia
- Istorija sajta → Wayback Machine, uz svest da prvi zabeleženi snimak ≠ datum lansiranja
- Verifikacija odgovora → MD5 poređenje, uz pažnju na tačan format unosa (separator, velika/mala slova) jer i sitna razlika u formatu menja heš vrednost
