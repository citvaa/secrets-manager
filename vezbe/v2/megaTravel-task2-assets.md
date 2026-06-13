# ZADATAK 2 — Osetljiva imovina MegaTravel-a

U nastavku je lista najvažnijih osetljivih sredstava (assets) za imaginarni sistem MegaTravel, uz procenu njihove inherentne izloženosti, bezbednosnih ciljeva i uticaja u slučaju kompromitacije.

## 1. Lični podaci klijenata (PII)

**Primeri:** ime i prezime, adresa, e-mail, broj telefona, datum rođenja, pasoški podaci, putne preferencije.

### Inherentna izloženost
- Pristup imaju korisnici, korisnička podrška, administratori, sistemi za obradu rezervacija i integracije sa spoljnim partnerima.
- Podaci se često prenose između više sistema i filijala širom sveta.

### Bezbednosni ciljevi
- **Poverljivost:** veoma visoka
- **Integritet:** visoka
- **Dostupnost:** srednja do visoka

### Uticaj kompromitacije
- Krađa identiteta i prevare
- Kršenje privatnosti korisnika
- Gubitak poverenja i reputacije
- Regulativne kazne prema zakonima o zaštiti podataka
- Moguće tužbe i obavezno prijavljivanje incidenta

## 2. Podaci o plaćanju

**Primeri:** brojevi kartica, tokeni plaćanja, fakture, refundacije, transakcioni zapisi.

### Inherentna izloženost
- Pristup imaju platni procesori, autorizacioni servisi, finansijski tim, ograničeni sistemski administratori i eksterni payment provider-i.
- Veoma atraktivno sredstvo za napadače i kriminalce.

### Bezbednosni ciljevi
- **Poverljivost:** ekstremno visoka
- **Integritet:** ekstremno visoka
- **Dostupnost:** visoka

### Uticaj kompromitacije
- Finansijski gubici
- Prevara sa karticama i refundacijama
- Sankcije zbog neusklađenosti sa PCI DSS standardom
- Masovni incidenti i reputaciona šteta
- Moguće blokiranje obrade plaćanja

## 3. Nalozi korisnika i autentikacioni podaci

**Primeri:** korisnička imena, hash-ovane lozinke, MFA tajne, reset tokeni, session tokeni.

### Inherentna izloženost
- Pristup imaju korisnici, sistem za autentikaciju, helpdesk, bezbednosni tim i aplikacioni serveri.
- Osetljivo jer omogućava direktan pristup uslugama.

### Bezbednosni ciljevi
- **Poverljivost:** veoma visoka
- **Integritet:** veoma visoka
- **Dostupnost:** visoka

### Uticaj kompromitacije
- Preuzimanje naloga
- Neovlašćene rezervacije i izmene
- Krađa loyalty bodova ili korisničkih kredita
- Credential stuffing i lančani napadi na druge servise
- Povećan broj korisničke podrške i trošak oporavka

## 4. Rezervacije, itinereri i istorija putovanja

**Primeri:** podaci o letovima, hotelima, rent-a-car rezervacijama, destinacijama, datumima putovanja.

### Inherentna izloženost
- Pristup imaju korisnici, agenti podrške, partneri (hoteli, aviokompanije, rent-a-car), kao i interni operateri.
- Podaci se često dele između više organizacija.

### Bezbednosni ciljevi
- **Poverljivost:** visoka
- **Integritet:** veoma visoka
- **Dostupnost:** veoma visoka

### Uticaj kompromitacije
- Pogrešne ili lažne rezervacije
- Finansijski gubici i reklamacije
- Poremećaji putovanja korisnika
- Pravna odgovornost prema potrošačima i partnerima
- Oštećenje poslovnih odnosa sa dobavljačima

## 5. Korporativne poslovne strategije i ugovori

**Primeri:** pregovori sa partnerima, marže, cene, popusti, planovi ekspanzije, ugovori sa dobavljačima.

### Inherentna izloženost
- Pristup imaju rukovodstvo, pravni tim, nabavka, finansije i ograničen broj menadžera.
- Često distribuirano među sedištima u Londonu, Bostonu i Hong Kongu.

### Bezbednosni ciljevi
- **Poverljivost:** ekstremno visoka
- **Integritet:** visoka
- **Dostupnost:** srednja

### Uticaj kompromitacije
- Gubitak konkurentske prednosti
- Industrijska špijunaža
- Neuspešni pregovori sa partnerima
- Finansijski i strateški gubici
- Mogući pravni sporovi i povreda ugovorne tajnosti

## 6. Zaposleni podaci i HR evidencija

**Primeri:** lični podaci zaposlenih, plate, evaluacije, ugovori, disciplinske mere, pristupni podaci.

### Inherentna izloženost
- Pristup imaju HR, menadžment, finansije, payroll sistemi i administratori.
- Osetljivo zbog velikog broja zaposlenih i globalne organizacije.

### Bezbednosni ciljevi
- **Poverljivost:** veoma visoka
- **Integritet:** visoka
- **Dostupnost:** srednja

### Uticaj kompromitacije
- Povreda privatnosti zaposlenih
- Unutrašnji konflikti i nezadovoljstvo
- Pravne posledice po zakonima o radu i privatnosti
- Zloupotreba za socijalni inženjering

## 7. Sistemi za rezervacije i aplikaciona logika

**Primeri:** web aplikacija, API, backend servisi, poslovna pravila, cenovni modeli, workflow za rezervacije.

### Inherentna izloženost
- Pristup imaju korisnici preko interneta, developeri, DevOps, administratori i automatizovani servisi.
- Ovo je glavni javni napadni prostor.

### Bezbednosni ciljevi
- **Poverljivost:** visoka
- **Integritet:** ekstremno visoka
- **Dostupnost:** ekstremno visoka

### Uticaj kompromitacije
- Manipulacija rezervacijama i cenama
- Prekid poslovanja
- Neispravne transakcije
- Eksploatacija ranjivosti i eskalacija privilegija
- Veliki reputacioni i finansijski gubici

## 8. Konfiguracioni skladišta (config stores)

**Primeri:** API ključevi, tajne, konekcioni stringovi, parametri infrastrukture, feature flags.

### Inherentna izloženost
- Pristup imaju aplikacioni servisi, DevOps, administratori i ponekad razvojni tim.
- Posebno rizično ako ih koriste i web server i background worker process.

### Bezbednosni ciljevi
- **Poverljivost:** ekstremno visoka
- **Integritet:** ekstremno visoka
- **Dostupnost:** visoka

### Uticaj kompromitacije
- Otkrivanje tajni i preuzimanje sistema
- Kompromitacija baza podataka i eksternih servisa
- Promena ponašanja aplikacije
- Omogućavanje daljih napada kroz lateral movement

## 9. Baza podataka

**Primeri:** korisnici, rezervacije, transakcije, poslovni podaci, logovi.

### Inherentna izloženost
- Pristup imaju backend servisi, DBA tim, administratori i backup sistemi.
- U nekim slučajevima i partneri kroz integracije.

### Bezbednosni ciljevi
- **Poverljivost:** ekstremno visoka
- **Integritet:** ekstremno visoka
- **Dostupnost:** ekstremno visoka

### Uticaj kompromitacije
- Masovna krađa podataka
- Izmena ili brisanje rezervacija i finansijskih podataka
- Potpuni prekid rada platforme
- Regulatorne i ugovorne posledice
- Visok trošak oporavka i vraćanja podataka

## 10. Logovi i audit zapisi

**Primeri:** pristupni logovi, sigurnosni incidenti, audit trail, transakcioni logovi.

### Inherentna izloženost
- Pristup imaju bezbednosni tim, administratori, SIEM sistemi i ponekad developeri.
- Često sadrže osetljive tragove i metapodatke.

### Bezbednosni ciljevi
- **Poverljivost:** srednja do visoka
- **Integritet:** ekstremno visoka
- **Dostupnost:** visoka

### Uticaj kompromitacije
- Brisanje tragova napada
- Otežana forenzika i detekcija
- Slabija sposobnost odgovora na incident
- Moguća pravna i regulatorna odgovornost

## 11. Infrastruktura za zaposlene filijale i sedišta

**Primeri:** interne mreže, VPN, endpoint uređaji, email sistemi, kolaboracione platforme.

### Inherentna izloženost
- Pristup imaju zaposleni, IT administratori, helpdesk i eksterni servisi.
- Široko distribuirana po više geografskih lokacija.

### Bezbednosni ciljevi
- **Poverljivost:** visoka
- **Integritet:** visoka
- **Dostupnost:** visoka

### Uticaj kompromitacije
- Širenje malware-a ili ransomware-a
- Kompromitacija više filijala
- Prekid rada zaposlenih
- Krađa poverljivih komunikacija
- Lateralno kretanje ka kritičnim sistemima

## 12. Brend, reputacija i poverenje korisnika

**Primeri:** javni ugled, ocene korisnika, društvene mreže, PR kanali.

### Inherentna izloženost
- Pristup je javni — kroz internet, medije i društvene mreže.
- Iako nije tehnički asset u užem smislu, poslovno je izuzetno vredan.

### Bezbednosni ciljevi
- **Poverljivost:** niska do srednja
- **Integritet:** veoma visoka
- **Dostupnost:** visoka

### Uticaj kompromitacije
- Gubitak poverenja tržišta
- Otkazivanje rezervacija
- Pad prihoda
- Dugoročna reputaciona šteta
- Povećani troškovi marketinga i kriznog PR-a

## Zakonodavni i regulatorni okviri koji utiču na ovu imovinu

Pošto je MegaTravel multinacionalna kompanija, na nju bi mogli uticati različiti propisi, uključujući:

- **GDPR** — zaštita ličnih podataka korisnika iz EU
- **UK GDPR / Data Protection Act** — za sedište u Londonu
- **CCPA/CPRA** — za korisnike iz Kalifornije
- **PCI DSS** — za obradu podataka o plaćanju
- **Lokalni zakoni o privatnosti i radu** — za zaposlene i korisnike u različitim državama
- **Ugovorne obaveze** prema partnerima, hotelima, aviokompanijama i payment providerima
- **Pravila o čuvanju podataka** i reviziji, u zavisnosti od jurisdikcije

Ovi propisi dodatno povećavaju značaj podataka kao što su PII, payment information, HR podaci i audit logovi.

## Prioritetno najosetljivija imovina

Najkritičnija sredstva za MegaTravel su:

1. **Podaci o plaćanju**
2. **Lični podaci klijenata**
3. **Nalozi korisnika i autentikacioni podaci**
4. **Baza podataka**
5. **Konfiguraciona skladišta**
6. **Rezervacije i itinereri**
7. **Aplikaciona logika i API**
8. **Korporativni ugovori i poslovne strategije**