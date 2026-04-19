# Sigurno cuvanje kljuceva

## Bezbedno generisanje kljuceva za enrkipciju/dekripciju

Glavna ideja je osmisliti sistem za koji se ne mogu predvideti buduci ili zakljuciti prethodni kljucevi na osnovu trenutnog stanja. Ovo je izazovno zato sto racunar nikada ne moze da generise nasumicne vrednosti, vec samo pseudonasumicne. Racunar ne poznaje koncept nasumicnosti, i svaki put kada generise "nasumicnu" vrednost to radi na osnovu nekog algoritma ili pravila.

Nacin na koji se generisanje pseudoslucajnih vrednosti moze "ojacati" jeste postavljanje inicijalnog kljuca koji ce biti jedan od parametara za generisanje svakog narednog kljuca.
Pri odabiru pocetnog kljuca, vazno je da on bude visoke entropije, tj. da bude sastavljen bez ikakvih pravila, sablona, konteksta ili bilo cega na osnovu cega je kljuc moguce pretpostaviti. Inicijalni kljuc se drugacije naziva "passphrase" ili "password", i pozeljno je da se sadrzi od barem 40 bitova.

Pri odabiru algoritma za generisanje kljuceva je bitno odabrati algoritam koji je otporan na "brute-force" napade. Jedan od ovakvih algoritama jeste Argon2, koji je namerno dizajniran kao veoma skup i spor. Kada korisnik generise kljuc, morace da saceka izvrsavanje algoritma, ali nakon toga je siguran da ima bezbedan kljuc. Pokusaji brute-forceovanja protiv ovakvog algoritma traju neisplativo dugo i traze ozbiljne racunarske resurse.

## Algoritmi simetricne enkripcije

Simetricka enkripcija podrazuvema enkodiranje i dekodiranje podataka upotrebom istog kljuca. 
Ovakav pristup je dobar za cuvanje tajni, zato sto kljuc nije neophodno deliti, ali nije pogodan za enkripciju poruka, za to je bolje koristiti algoritme asimetricne enkripcije.

Neki od poznatih sigurnih algoritama simetricne enkripcije su AES, ChaCha20, CAST, Twofish, dok postoje i nesigurni algoritmi poput DES i RC4.

Algoritmi se smatraju nesigurnim uglavnom ako koriste sifru niske entropije(<64 bita), ili ako postoje nesigurnosti u algoritmu koje dopustaju da se na osnovu sifrovanih vrednosti zakljuci sifra enkripcije. 

Najpoznatiji algoritam simetricne enkripije je AES ili Rijndael. Ovaj algoritam provlaci ulazne podatke kroz iteracije, tj. "runde", gde u svakoj rundi generise vrednost na osnovu vrednosti prethodne runde i sifre za tu rundu. Ista sifra se ne koristi u vise rundi, vec svaka runda ima svoju sifru koja se naziva "round key". Broj rundi zavisi od entropije ulaznog kljuca, koji je uglavnom 128, 196 ili 256 bita. Kljucevi svake runde se generisu unapred, pre samih rundi, na osnovu AES Key Schedule, i generise se jedan round key za svaku rundu + 1.
Dodatni kljuc se koristi u "nultoj" rundi sluzi da se pomesa sa ulaznim podacima, kako ne bi dosli do toga da sifrujemo "gole" podatke.

Nakon toga, vrsi se 3, 9, 11 ili 13 rundi transformacija koje obuhvataju SubBytes, ShiftRows, MixColumns ulaza, i na kraju ga pomesaju sa round keyem.

Poslednja runda vrsi samo SubBytes, ShiftRows i AddRoundKey.

## Parametri Argon2

m - memory cost, preporuceni minimum 19mb
t - iterations, sto je veci treba vise procesorskog vremena, preporuceno minimum 2 iteracije za 19mb, 1 iteracija za 64mb
p - paralelizam, broj threadova. ne utice na sigurnost, ubrzava proces
output length, duzina izlaznog kljuca
salt length, random generisana vrednost, minimum 16 bita

## Paramteri AES

AES ima 2 parametra, koji su kljuc i broj rundi, medjutim, broj rundi se moze zakljuciti na osnovu entropije kljuca. Za 128-bitni kljuc se izvrsava 10 rundi, za 192-bitni kljuc se izvrsava 12, a za 256-bitni 14 rundi.

## Provideri

JavaScript - Web Crypto API
Python - cryptography
Java - Bouncy Castle
Go - crypto/aes
Rust - aes
.NET - System.Security.Cryptography

## CVE

Nijedna implementacija trenutno nema otkrivenih slabosti.

## Implementacija

1. Korisnik generise sifru visoke entropije(master sifra)
3. Kada korisnik zeli da sacuva secret, kljuc enkripcije se generise pomocu master kljuca, nakon cega se secret enkriptuje novonastalim kljucem.
