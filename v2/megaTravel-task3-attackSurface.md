# Zadatak 3 - analiza površine napada MegaTravela

Ispitajte koji korisnici (ljudski, eksterni sistemi) komuniciraju sa MegaTravel sistemom i odatle mapirajte površinu
napada kao skup ulaznih tačaka sa kojih napadači mogu da sprovedu svoje napade.

## Površina napada

Površinom napada možemo smartati:

1. Skup svih putanja preko kojih podaci/naredbe ulaze/izlaze iz programa.
2. Programski kod koji obezbeđuje ove putanje(povezivanje na resurse, autentikacija, autorizacija, logovanje aktivnosti, validacija podataka, enkodiranje)
3. Svi podaci od značaja koje aplikacija koristi(tajne i ključevi, intelektualna svojina, poslovni podaci od kritične važnosti, lični podaci, PII...)
4. Programski kod koji obezbeđuje ove podatke(enkripcija, chekcsum, nadzor pristupa, provera integriteta podataka...)

## Identifikacija korisnika

Korisnikom sistema smatra se sve što komunicira sa sistemom, i pored ljudskih korisnika obuhvata i eksterne sisteme koji su neophodni za rad.

Ljudske korisnike delimo u različite grupe na osnovu njihovih uloga u sistemu, što određuje njihova prava pristupa i način na koji pristupaju sistemu. To mogu biti:
- **Klijenti** - Rezervišu smeštaj, prevoz, izlete. Verovatno koriste web/mobilnu aplikaciju.
- **Zaposleni** - Turistički agenti, menadžeri, korisnička podrška, računovodstvo... Koriste interne aplikacije, CRM.
- **Administratori** - IT osoblje, sistemski admini. Imaju veću moć pristupa od ostalih korisnika.

Neki od eksternih sistema sa kojima sistem može komunicirati su:
- **GDS** - *Global Distribution System*, centralizovana baza podataka i mreža koja povezuje ponuđače usluga poput smeštaja, avio i drumski prevoz, *rent-a-car*, krstarenja, aktivnosti i izleta .
- **Platni procesori** - Posrednik između korisnika, MegaTravel-a i banaka. Čini plaćanja brzim, sigurnim i pouzdanim.
- **3rd party analitički sistemi** - Platforme koje skupljaju metapodatke o upotrebi sistema kako bi se poboljšalo korisničko iskustvo.
- **Notifikacioni servisi** - Servisi zaduženi za slanje mejlova, SMS poruka i ostalih obaveštenja korisnicima.

## Kanali komunikacije

Korisnici sa sistemom komuniciraju kroz interfejse/kanale gde svaki od tih kanala predstavlja potencijalnu ulaznu tačku.

**Klijenti** koriste **web aplikaciju** i **mobilnu aplikaciju**. Komunikacija sa web i mobilnom aplikacijom se vrši preko HTTPS protokola, što značajno otežava krađu informacija *"u letu"*, ali klijenta je i dalje moguće kompromitovati preko fishing/spoofing prevara.

Ulazne tačke u ove kanale su login forme, forme za rezervaciju, stranica za pretragu, upload dokumenata(pogotovo identifikacionih dokumenata), upravljanje sesijom...

**Zaposleni** koriste ekosistem aplikacija posebno namenjenih za upotrebu unutar kompanije. Kako bi se ograničio i osigurao pristup internoj mreži, ulazne tačke zaposlenih u sistem su **VPN**, **SSO**, **hardverski ključevi**.

**Administratori** koriste panele i aplikacije koji sadrže poverljive informacije i prava na privilegovane operacije. Ulazne tačke u ovakav komunikacioni kanal su **hardverski ključevi**, **SSH** i **RD protokol**.

**GDS** komunicira sa sistemom pomoću svog **REST/SOAP API-ja**. Potencijalne ulazne tačke u ovakav kanal komunikacije su **API ključevi**, **webhook endpointi**

**Platni procesori** i sistem komuniciraju preko **platnog gateway-a**. Potencijalne ulazne tačke koje mogu biti kompromitovane su forma za unos kartičnih podataka, phishing stranica za plaćanje, API klju;evi, Webhook endpointi, Callback URL-ovi.

## Mapiranje površine napada

Ulazne tačke se mogu grupisati na osnovu kategorije napadne površine. Podelićemo ih u 3 grupe, **digitalna napadna površina**, **fizička napadna površina** i **napadna površina društvenog inženjeringa**.

### Digitalna napadna površina

U ovu kategoriju napadne površine spadaju sve potencijalne ulazne tačke kojima napadač može pristupiti pomoću internet veze. U ovu kategoriju se mogu svrstati:

- (*klijent, zaposleni, administratori*) **Autentifikacioni mehanizmi** - Login forme, VPN portal, SSH ključevi. Ranjivost ove ulazne tačke može biti slaba lozinka/ključ koji se mogu probiti brute force napadom.
- (*administratori*) **Imovina izložena internetu** - Greške u implementaciji, konfiguraciji, nezaštićeni API endpointi, injekcija, loše podešen firewall, loše podešeni servisi 3. lica.
- (*administratori*) **Zastareli softver** - Starije verzije softvera mogu sadržati javno poznate ranjivosti.
- (*zaposleni*) **Shadow IT** - Digitalni uređaji/softver koji zaposleni koriste za obavljanje posla bez prethodnog odobrenja od strane IT osoblja.

### Fizička napadna površina

U ovu kategoriju napadne površine spadaju sve potencijalne ulazne tačke kojima napadač može pristupiti uz autorizovani pristup fizičkoj imovini sistema.

- (*zaposleni, administratori*) **Maliciozna interni korisnik** - Nezadovoljan ili podmićen zaposleni može iskorisiti svoja prava prisutpa da našteti sistemu.
- (*zaposleni, administratori*) **Krađa uređaja** - Ukoliko napadač ukrade, bilo koji "krajni" uređaj, ili pristupi prostorijama u kojima se nalazi infrastruktura sistema, moguć mu je pristup poverljivim podacima sistema. Napadač može ukrasti identitet uređaja kako bi pristupio ostalim resursima sistema. U krajnje uređaje spadaju računari zaposlenih koji rade na daljinu, lični uređaji zaposlenih, hardverski ključevi, nepropisno odloženi uređaji i sl.
- (*zaposleni, administratori*) **Mamljenje** - Napadač podmeće fleš memorije ili slične uređaje sa malicioznim softverom u nadi da će korisnik sa privilegovanim pristupom povezati uređaj sa krajnjim uređajem.

### Napadna površina društvenog inženjeringa

U ovu kategoriju napadne površine spadaju sve potencijalne ulazne tačke prouzrokovane ljudskim nemarom. U ovu kategoriju se mogu svrstati:

- (*zaposleni, administrator*) **Deljenje informacija koje ne bi trebalo da dele**
- (*zaposleni, administrator*) **Preuzimanje softvera koji ne bi trebalo da preuzimaju**
- (*zaposleni, administrator*) **Posećivanje veb sajtova koje ne bi trebalo da posećuju**
