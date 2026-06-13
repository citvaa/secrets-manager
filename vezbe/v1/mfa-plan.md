# VIŠEFAKTORSKA AUTENTIKACIJA (MFA) - Miloš Milosavljević SV80/2022

---

## 1) Tipovi višefaktorske autentikacije

MFA se zasniva na kombinaciji dva ili više faktora iz različitih kategorija:

- **Nešto što znaš** (*knowledge factor*): lozinka, PIN, sigurnosno pitanje
- **Nešto što imaš** (*possession factor*): fizički token, TOTP aplikacija (Google Authenticator, Authy), SMS, hardware key (YubiKey)
- **Nešto što jesi** (*inherence factor*): biometrija – otisak prsta, prepoznavanje lica, glas

### Komentar po tipu:

| Faktor | Primjer | Prednosti | Slabosti |
|--------|---------|-----------|----------|
| Lozinka | Korisnička lozinka | Jednostavno, svuda podržano | Phishing, credential stuffing |
| TOTP | Google Authenticator | Bez mreže, vremenski ograničen | Gubitak uređaja, sinhronizacija |
| SMS OTP | Kod putem SMS-a | Lako za korisnika | SIM swapping, SS7 napadi |
| Push notifikacija | Duo Security | Korisničko iskustvo | MFA fatigue napadi |
| Hardware token | YubiKey (FIDO2/WebAuthn) | Phishing-resistant | Cijena, gubitak uređaja |
| Biometrija | Otisak prsta | Nije prenosivo | Privatnost, lažni pozitivi |

**Odabrana kombinacija: Lozinka + TOTP**

Razlog: TOTP je dobro podržan, ne zahtijeva mrežnu vezu pri generisanju koda, i znatno smanjuje rizik od kompromitacije samo lozinkom.

---

## 2) Implementacija odabranih faktora

### 2a) Faktor 1 – Lozinka

- Hashovanje: **bcrypt** (cost factor ≥ 12) ili **Argon2id**
- Nikad ne čuvati lozinku u plaintext-u
- Politika: minimalno 12 karaktera, provjera protiv liste poznatih lozinki (HaveIBeenPwned API ili lokalna lista)
- Account lockout / rate limiting na endpoint-u za prijavu

**Koraci:**
- `POST /auth/login` → prima `username` + `password`
- Provjeri hash u bazi; ako ne odgovara → `401` (bez informacije koja polja su pogrešna)
- Ako odgovara → prelazi se na drugi faktor (ne izdaje se token još uvijek)

---

### 2b) Faktor 2 – TOTP (Time-Based One-Time Password)

TOTP funkcioniše po **RFC 6238** standardu:

1. **Registracija:**
   - Server generiše tajni ključ (npr. 20 bajtova, base32-enkodovan) po korisniku
   - Ključ se čuva enkriptovan u bazi (AES-256-GCM)
   - Korisniku se prikazuje QR kod koji sadrži `otpauth://totp/<app>:<user>?secret=<base32>&issuer=<app>`
   - Korisnik skenira QR kod u TOTP aplikaciji (Google Authenticator, Authy, itd.)
   - **Verifikacija registracije:** korisnik odmah unosi generisani kod kako bi potvrdio da je skeniranje prošlo uspješno

2. **Generisanje koda (na strani klijenta/aplikacije):**
   - `T = floor(unix_timestamp / 30)` — vremenski korak od 30 sekundi
   - `TOTP = HOTP(secret, T)` → 6-cifreni kod
   - Kod se mijenja svakih 30 sekundi

3. **Verifikacija (na strani servera):**
   - Server računa TOTP za trenutni vremenski korak i ±1 korak (tolerance window)
   - Ako kod odgovara → autentikacija uspješna, izdaje se JWT/session token
   - **Replay zaštita:** jednom iskorišten kod se čuva u kratkoročnom cache-u (Redis, TTL 90s) – ne smije se prihvatiti dva puta
   - Bilježi se `last_used_counter` u bazi

4. **Obnavljanje (backup kodovi):**
   - Pri registraciji TOTP-a generiše se 8–10 jednokratnih backup kodova (svaki 10–16 alfanumeričkih karaktera)
   - Čuvaju se kao hash u bazi (bcrypt), **ne** u plaintext-u
   - Korisnik ih čuva na sigurnom (štampa ili password manager)
   - Svaki backup kod može se iskoristiti samo jednom; biljezi se u bazi

**Koraci implementacije:**
- Biblioteka (Node.js): `speakeasy` ili `otplib`; (Python): `pyotp`
- Tok:
  1. `POST /auth/mfa/setup` → generisanje tajnog ključa + QR kod
  2. `POST /auth/mfa/verify-setup` → verifikacija prvog TOTP koda
  3. `POST /auth/mfa/validate` → svaki login (prima `totp_code`)
  4. `POST /auth/mfa/backup` → prihvata backup kod umjesto TOTP-a

---

## 3) Najčešće greške i bezbednosni propusti u implementaciji MFA

| Propust | Opis | Mitigacija |
|---------|------|------------|
| **Sinhronizacija vremena** | Server i klijent imaju različito sistemsko vrijeme → kod uvijek odbijen | NTP/chrony na serveru; tolerance window ±1 korak |
| **Replay napad** | Presretnuti TOTP kod se koristi ponovo u roku od 30s | Cache iskorišćenih kodova (Redis TTL 90s) |
| **Brute-force TOTP** | 6-cifreni kod ima 10^6 kombinacija; bez rate-limitinga moguće pogoditi | Rate limiting (max 5 pokušaja), pa lockout |
| **Phishing / MITM** | Napadač presrétne TOTP u realnom vremenu (real-time phishing) | FIDO2/WebAuthn je jedina puna zaštita; za TOTP: HSTS, certifikat |
| **SIM swapping (SMS OTP)** | Napadač preuzme telefonski broj žrtve | Ne koristiti SMS OTP za privilegovane naloge |
| **Izlaganje backup kodova** | Backup kodovi u plaintext-u u bazi ili logu | Hash backup kodova (bcrypt), nikad logovanje |
| **MFA fatigue (push)** | Korisnik odobri push notifikaciju slučajno ili iz navike | Nije primjenjivo za TOTP; relevantno za push MFA |
| **Insecure secret storage** | TOTP tajni ključ u bazi u plaintext-u | Enkriptovati ključ (AES-256-GCM) + key management (HSM ili KMS) |
| **Bypass pri oporavku naloga** | Account recovery tok zaobilazi MFA | Recovery mora biti jednako siguran (identity verification) |
| **Preskakanje MFA na API-ju** | MFA samo na web UI-u, API endpoint bez provjere | MFA token obavezan i za API (OAuth scope, header) |

---

## 4) Integracija MFA u ELK okruženju (Kibana admin login)

### Kontekst

Kibana podržava autentikaciju putem **Elastic Stack security featura**. Za MFA admina u Kibani postoje dva pristupa:

### Pristup A – Native Elastic Security + vanjski IdP sa MFA

Elastic Stack (8.x) podržava **SAML** i **OIDC** SSO. Preporučena arhitektura:

```
Admin → Kibana → SAML/OIDC redirect → IdP (npr. Keycloak / Okta) → MFA (TOTP) → token → Kibana
```

**Koraci:**
1. Podesiti Keycloak (ili drugi IdP) sa TOTP obaveznim za `admin` rolu
2. U `kibana.yml` konfiguracija:
   ```yaml
   xpack.security.authc.providers:
     saml.saml1:
       order: 0
       realm: saml1
       description: "Login with SSO"
   ```
3. U Elasticsearch `elasticsearch.yml`:
   ```yaml
   xpack.security.authc.realms.saml.saml1:
     order: 1
     idp.metadata.path: /etc/elasticsearch/saml/idp-metadata.xml
     idp.entity_id: "https://idp.example.com"
     sp.entity_id: "https://kibana.example.com"
     sp.acs: "https://kibana.example.com/api/security/saml/callback"
     attributes.principal: "nameid"
     attributes.groups: "groups"
   ```
4. Admin login → redirect na IdP → unos lozinke + TOTP koda → SAML assertion → Kibana sesija

### Pristup B – Reverse proxy sa MFA (npr. Nginx + OAuth2 Proxy)

```
Admin → Nginx (OAuth2 Proxy) → OIDC/MFA → Kibana (bez direktnog pristupa)
```

**Koraci:**
- Kibana sluša samo na `localhost:5601`
- Nginx proxy sa `oauth2-proxy` ispred Kibane
- `oauth2-proxy` konfigurisan sa OIDC provajderom koji zahtijeva TOTP

### Audit logovanje MFA događaja u ELK-u

- Svaki pokušaj MFA logina u Kibanu bilježi se kao audit događaj:
  - `event_category: "audit"`
  - `event_type: "mfa_attempt"` / `"mfa_success"` / `"mfa_failure"`
  - `actor.username`, `source.ip`, `@timestamp`
- Elastic sam generiše audit logove za authentication evente (ako je uključen `xpack.security.audit.enabled: true` u `elasticsearch.yml`)
- Ti logovi se indeksiraju u `audit-*` indeks i vidljivi su u Kibani kao i ostali audit eventi

**Preporučeni Kibana dashboard za MFA:**
- Failed MFA attempts po korisniku i IP-u
- MFA bypass pokušaji (direktan pristup bez autentikacije)
- Admin login trend (uspješni vs neuspješni)

---

## 5) Sažetak zahtjeva za bezbjednu implementaciju MFA

- Koristiti **lozinka + TOTP** kao minimum za sve privilegovane naloge
- TOTP tajni ključ čuvati enkriptovan (AES-256-GCM) u bazi
- Implementirati replay zaštitu (cache iskorišćenih kodova, Redis TTL 90s)
- Rate limiting na MFA endpointu (max 5 grešaka → lockout)
- Backup kodovi hashirani (bcrypt), jednokratni, nikad logovani
- NTP sinhronizacija na serveru (tolerance window ±1 vremenski korak)
- MFA obavezan i za API pristup, ne samo za UI
- U ELK-u: `xpack.security.audit.enabled: true` + integracija sa IdP-om koji nameće TOTP za admin role
- Sve MFA greške logirati kao `event_category: "audit"`, `event_outcome: "failure"` – bez osetljivih podataka
