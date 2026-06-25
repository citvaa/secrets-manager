# OSINT zadaci sa mapama

## Ilija Jordanovski SV 73/2022

### Zadatak 9

Na slici se vidi znak na kojem pise Spomen kuca Save Sumanovica cirilicom, znaci da je verovatno u Srbiji. Flag je formata XX.XXXXXXX,XX.XXXXXXX sto znaci da se traze koordinate. 

Kada se na Gugl mapama trazi Spomen kuca Save Sumanovica, jedini rezultat se nalazi u Sidu. Na datoj slici, znak nam govori da je spomen kuca sa leve strane trazenog mesta. Trazimo raskrsnice desno od spomen kuce. 

Raskrsnica Save Sumanovica i Svetog Save se savrseno poklapa sa fotografijom.

Flag UNS{45.1263864,19.229221}

### Zadatak 10

Na slici se vidi jezero, o kojem nemamo dodatnog konteksta. Upotrebom AI alata `https://picarta.ai/`, dobijamo informaciju da je fotografija potencijalno uslikana na jednoj od sledecih lokacija:

- Djurici, Srbija
- Nova Varos, Srbija
- Hanbin, Kina
- Rumboci, BiH

Djurici nemaju jezero, ali postoji Zaovinsko jezero u blizini. Bedemi na fotografiji se podudaraju sa bedemima na jezeru, "krivine" na fotografiji se podudaraju sa pravim jezerom. Tacno mesto sa kog je fotografija napravljena nisam uspeo da odredim

UNS{43.8759639,19.3974293}

### Sakura izazovi

#### T2 - tipoff

Dobijamo samo jednu sliku sa fotografijom, treba da nadjemo ime napadaca.

U pozadini slike se nalaze osmobitni binarni brojevi, tj. bajtovi, a znamo da je jedan karakter jedan bajt. Prekucavanjem binarnog koda u tekst, dobijamo "Sakura loves OSINT", sto nije ime napadaca. 

Nakon sto pokrenemo `exiftool` nad fotografijom, imamo uvid u metapodatke fotografije, ovo je rezultat:

```
ExifTool Version Number         : 13.57
File Name                       : sakurapwnedletter.svg
Directory                       : .
File Size                       : 850 kB
File Modification Date/Time     : 2026:06:25 21:23:35+02:00
File Access Date/Time           : 2026:06:25 21:23:35+02:00
File Inode Change Date/Time     : 2026:06:25 21:23:35+02:00
File Permissions                : -rw-r--r--
File Type                       : SVG
File Type Extension             : svg
MIME Type                       : image/svg+xml
Xmlns                           : http://www.w3.org/2000/svg
Image Width                     : 116.29175mm
Image Height                    : 174.61578mm
View Box                        : 0 0 116.29175 174.61578
SVG Version                     : 1.1
ID                              : svg8
Version                         : 0.92.5 (2060ec1f9f, 2020-04-08)
Docname                         : pwnedletter.svg
Export-filename                 : /home/SakuraSnowAngelAiko/Desktop/pwnedletter.png
Export-xdpi                     : 96
Export-ydpi                     : 96
Metadata ID                     : metadata5
Work Format                     : image/svg+xml
Work Type                       : http://purl.org/dc/dcmitype/StillImage
Work Title                      :
```

U polju `Export-filename` vidimo putanju sa koje je slika objavljena, i korisnicko ime napadaca, `SakuraSnowAngelAiko`.

#### T3 - reconnaisance

Ovde treba da nadjemo email adresu i ime i prezime napadaca iz zadatka 2. Nagovesteno nam je da je napadac koristio isto korisnicko ime na vise sajtova.  

Nakon sto guglamo korisnicko ime `SakuraSnowAngelAiko`, jedan od prvih linkova vodi na GitHub korisnika sa istim korisnickim imenom. Korisnik ima par repozitorijuma, ali onaj koji je nama zanimljiv je `PGP` repozitorijum, zbog sumnje da sadrzi PGP kljuceve korisnika. 

Repozitorijum sadrzi fajl `publickey` koji u sebi sadrzi javan PGP kljuc

```
-----BEGIN PGP PUBLIC KEY BLOCK-----

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
23pRnPKc+41cwL3oq8yb/Fhj+biohgIp
=grbk
-----END PGP PUBLIC KEY BLOCK-----
```

PGP kljucevi sadrze sifrovane informacije i mogu se analizirati pomocu `gpg` alata. 

Nakon sto pokrenemo `gpg --show-keys` nad javnim kljucem, dobijamo sledecu informaciju:

```
pub   rsa3072 2021-01-23 [SC] [expired: 2023-01-22]
      A6519F273BF88E9126B0F4C5ECDD0FD294110450
uid                      SakuraSnowAngel83@protonmail.com
sub   rsa3072 2021-01-23 [E] [expired: 2023-01-22]

gpg: WARNING: No valid encryption subkey left over.
```

Sto nam daje mejl, `SakuraSnowAngel83@protonmail.com`. Preostaje nam ime i prezime.

Ako guglamo mejl, dobijamo samo writeupe o ovom zadatku.

Ako guglamo korisnicko ime ponovo, dolazimo do sajta `https://leadcontact.ai/en/contact/sakurasnowangelaiko`, na kojem saznajemo da su ime i prezime napadaca `Aiko Abe`
