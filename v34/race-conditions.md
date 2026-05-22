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

Hajde da analiziramo kako izgleda kupovina nekog proizvoda i primena promo koda; Kada se proizvod dodaje u korpu, šalje se `POST` zahtev na `/cart` endpoint sa šifrom proizvoda. Kada se primenjuje promo kod, šalje se `POST` zahtev na `/cart/coupon`. Ako ponovo pokušamo da primenimo isti kupon, dobijamo poruku `Coupon already applied`. Uz svaki zahtev se šalje token sesije. Ako pokušamo da dobavimo proizvode iz korpe gađanjem `/cart` endpointa sa `GET` bez tokena sesije, dobijamo praznu korpu. Ovo naznačuje da se podaci o sesiji čuvaju na serverskoj strani.

Potencijalna kolizija postoji pri obradi zahteva, kada server dobavlja podatke o sesiji i proverava validnost sesije. Pokušaćemo da iskoristimo slabost pri obradi zahteva za primenu promo koda. Možda, server prvo primeni promo kod, pa tek onda proverava validnost sesije, tj. da li je promo kod već primenjen.

Da bi ovo proverili, prvo dodajemo proizvod koji želimo da kupimo u korpu. Kada je proizvod u korpi, šaljemo zahtev za primenu promo koda u Burp Repeater. Pravi se duplikat tog zahteva, 20 duplikata bi trebalo da je dovoljno. Zahtevi se grupišu, i grupa zahteva se šalje u paraleli. Nakon što se svi zahtevi izvrše, vidimo da je svaki uspešno izvršen. Refreshom stranice sa korpom vidimo da je promo kod više puta primenjen, nakon čega možemo kupiti proizvod. Zadatak je rešen.

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

Nakon što pokrenemo skriptu na dugme `Attack`, slanje zahteva se izvršava i dobijamo tabelu sa rezultatima izvršavanja HTTP zahteva. Tabelu sortiramo po statusnom kodu odgovora, i tražimo status 302. Analizom zahteva sa statusom 302 pronalazimo lozinku, nakon čega se preko web interfejsa prijavljujemo na administratorski nalog i brišemo administratorskog korisnika. Zadatak je rešen.

## Zadatak 3 - Plavi

### *Multi-endpoint race conditions*


Cilj ovog zadatka je iskoristiti trku uslova u toku kupovine kako bi se kupio proizvod po nenamerenoj ceni. Napadaču su dati kredencijali za nalog na web shopu čiji saldo nije dovoljan za kupovinu željenog proizvoda.

Prijavljujemo se na nalog i kupujemo poklon karticu kako bi analizirali tok kupovine. Iz analize HTTP saobraćaja identifikujemo sve endpointe za interakciju sa korpom: `POST /cart` dodaje proizvod u korpu, a `POST /cart/checkout` predaje porudžbinu.

Dodajemo još jednu poklon karticu u korpu i šaljemo `GET /cart` zahtev u Burp Repeater. Slanjem tog zahteva sa i bez kolačića sesije potvrđujemo da bez kolačića sesije dobijamo praznu korpu - stanje korpe se čuva na serverskoj strani i vezano je za sesiju korisnika. Ovo ukazuje na potencijalnu koliziju.

Primetimo i da se predaja i potvrda uspešne porudžbine odvijaju u jednom ciklusu zahtev/odgovor. Postoji potencijalni prozor trke između trenutka kada server proverava da li korisnik ima dovoljno sredstava i trenutka kada se porudžbina potvrđuje - moguće je dodati proizvod u korpu nakon što je provera već izvršena.

Da bi procenili uticaj mrežne arhitekture na napad, šaljemo `POST /cart` i `POST /cart/checkout` u Repeater i dodajemo ih u istu grupu. Slanjem oba zahteva sekvencijalno kroz jednu konekciju, primećujemo da prvi zahtev konzistentno traje znatno duže od drugog. Dodavanjem `GET` zahteva za početnu stranicu na čelo grupe i ponovnim slanjem sva tri zahteva sekvencijalno, primećujemo da "zagrevanje" konekcije na ovaj način drastično smanjuje vremensku razliku između drugog i trećeg zahteva. Zaključujemo da kašnjenje potiče od mrežne arhitekture bekenda, a ne od vremena obrade samih endpointa, i da neće ometati napad. `GET` zahtev za početnu stranicu zatim uklanjamo iz grupe.

Za dokazivanje koncepta, u korpu stavljamo jednu poklon karticu. U Repeateru menjamo `POST /cart` zahtev tako da parametar `productId` odgovara šifri skupog proizvoda koji želimo da kupimo. Slanjem zahteva sekvencijalno dobijamo odgovor da nemamo dovoljno sredstava, što je očekivano.

Uklanjamo skup proizvod iz korpe i dodajemo novu poklon karticu. Sada šaljemo oba zahteva (`POST /cart` sa skupim proizvodom i `POST /cart/checkout`) paralelno. Ako dobijemo odgovor o nedovoljnim sredstvima, uklanjamo proizvod i ponavljamo napad. Napad može zahtevati više pokušaja. Nakon uspešnog pokušaja, `POST /cart/checkout` vraća status `200` i proizvod je uspešno kupljen. Zadatak je rešen.

## Zadatak 4 - Plavi

### *Single-endpoint race conditions*

Cilj ovog zadatka je iskoristiti trku uslova u funkciji promene email adrese kako bi se preuzela email adresa drugog korisnika i nasledila administratorska prava.

Prijavljujemo se na nalog i pokušavamo da promenimo email adresu na neku adresu kojoj imamo pristup. Primećujemo da se na novu adresu šalje email sa potvrdom koji sadrži jedinstveni token, a da je promena validna tek nakon klika na link u emailu. Ako pošaljemo dva zahteva za promenu email adrese na različite adrese, i potom pokušamo da iskoristimo link iz prvog emaila, primećujemo da taj link više nije validan. Iz ovoga zaključujemo da sistem čuva samo jednu adresu na čekanju i da svaki novi zahtev prepisuje prethodnu, umesto da ih nadovezuje. Ovo ukazuje na potencijalnu koliziju.

Da bi potvrdili sumnju, šaljemo `POST /my-account/change-email` zahtev u Repeater i pravimo 19 duplikata, svaki sa jedinstvenom email adresom. Grupe zahteva šaljemo sekvencijalno kroz odvojene konekcije i primećujemo da smo dobili po jedan email potvrde za svaki zahtev, što je očekivano ponašanje.

Ponavljamo slanje iste grupe zahteva, ali ovaj put paralelno. Analizom primljenih emailova primećujemo da se adresa primaoca ne poklapa uvek sa adresom koja je bila navedena u odgovarajućem zahtevu. Zaključujemo da postoji prozor trke između trenutka kada sistem pokreće zadatak slanja emaila i trenutka kada dohvata adresu na čekanju iz baze radi formiranja email poruke. Ako paralelni zahtev u tom prozoru promeni adresu u bazi, email se šalje na pogrešnu adresu.

Za dokazivanje koncepta, pravimo novu grupu od dva `POST /my-account/change-email` zahteva. U jednom postavljamo adresu kojoj imamo pristup, a u drugom adresu administratora koji ima privedeni poziv (`carlos@ginandjuice.shop`). Zahteve šaljemo paralelno i proveravamo inbox. Ako u telu primljenog emaila vidimo adresu administratora, klikćemo na link za potvrdu čime preuzimamo tu adresu. Ako je adresa u telu emaila naša sopstvena, ponavljamo napad. Napad može zahtevati više pokušaja. Nakon uspešne promene, na stranici naloga pojavljuje se link za administratorski panel. Pristupamo panelu i brišemo korisnika `carlos`. Zadatak je rešen.

## Zadatak 5 - Plavi

### *Exploiting time-sensitive vulnerabilities*

Cilj ovog zadatka je iskoristiti ranjivost u mehanizmu resetovanja lozinke koja ne potiče od klasične trke uslova, već od slabog kriptografskog dizajna - konkretno, od upotrebe vremenskog žiga kao ulaza u generisanje tokena.

Analizom procesa resetovanja lozinke uočavamo da svaki zahtev za reset rezultuje emailom sa linkom koji u query stringu sadrži korisničko ime i token. Slanjem više uzastopnih zahteva za reset primećujemo da svaki put dobijamo drugačiji token. Token je uvek iste dužine, što sugeriše da je reč o heš vrednosti nekog internog stanja - verovatno vremenskog žiga, brojača ili sličnog podatka.

Dupliramo zahtev u Repeateru, dodajemo oba u grupu i šaljemo ih paralelno više puta. Primećujemo da i dalje postoji značajno kašnjenje između odgovora i da su tokeni u emailovima i dalje različiti. Zaključujemo da server obrađuje zahteve sekvencijalno, a ne istovremeno. Uzrok tome je kolačić sesije - server koristi PHP bekend koji podrazumevano obrađuje samo jedan zahtev po sesiji istovremeno.

Da bi zaobišli ovo ograničenje, šaljemo `GET /forgot-password` bez kolačića sesije kako bi dobili novu sesiju. Iz odgovora kopiramo novi kolačić sesije i CSRF token i njima zamenjujemo odgovarajuće vrednosti u jednom od dva `POST /forgot-password` zahteva. Na taj način imamo par zahteva za reset koji potiču iz dve različite sesije.

Ponovo šaljemo oba zahteva paralelno više puta i primećujemo da su vremena obrade sada znatno bliža, a ponekad i identična. Kada su vremena obrade identična, proveravamo inbox i uočavamo da oba emaila sadrže isti token. Ovo potvrđuje da je vremenski žig ulaz u heš funkciju koja generiše token.

Pored toga, primetimo da zahtev sadrži i poseban parametar `username`. Ovo sugeriše da korisničko ime možda nije deo ulaza u heš, što bi značilo da dva korisnika mogu dobiti isti token ako im se zahtevi obrade u istom trenutku.

U Repeateru, u jednom od zahteva menjamo `username` parametar na `carlos`, a drugi ostavljamo sa sopstvenim korisničkim imenom. Šaljemo oba zahteva paralelno i proveravamo inbox. Ovaj put smo primili samo jedan email - zaključujemo da je drugi email sa istim tokenom otišao korisniku `carlos`. Kopiramo link iz primljenog emaila, menjamo vrednost `username` parametra u query stringu na `carlos` i otvaramo ga u pretraživaču. Stranica za postavljanje nove lozinke prikazuje se normalno. Postavljamo novu lozinku i prijavljujemo se kao `carlos`. Ako prijava ne uspe, ponavljamo napad. Nakon uspešne prijave, pristupamo administratorskom panelu i brišemo korisnika `carlos`. Zadatak je rešen.
