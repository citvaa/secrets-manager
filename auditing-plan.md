# MEHANIZAM REVIZIJE (AUDITING)

## 1) Logovi moraju biti korisni
- Strukturisani logovi: **JSON**
- Standardna polja u svakom logu:
  - `timestamp` (UTC, ISO-8601), `level`, `service`, `env`, `host`
  - `event_type`
  - `request_id` / `trace_id`
  - `status_code`, `latency_ms`
  - `message` (kratko), `error.*` samo kad treba
- Razdvajanje kanala:
  - **app logovi** (operativni)
  - **audit logovi** (bezbednosni / odgovornost)

**Koraci:**
- Logger sa JSON formatterom
- Middleware koji generiše `request_id` i ubacuje u kontekst

---

## 2) Non-repudiation (akteri bitni) + lako izdvajanje takvih događaja
- Audit događaje obeležavam:
  - `event_category: "audit"`
  - `event_outcome: "success" | "failure"`
- Obavezna audit polja:
  - `actor.id`, `actor.username`, `actor.roles`
  - `source.ip`, `user_agent`, `session_id`
  - `action`
  - `object.type`, `object.id`
- Šta obavezno auditujem:
  - login/logout + neuspele prijave
  - reset/promena lozinke
  - promene rola/privilegija
  - brisanja/izmene bitnih podataka
  - promene konfiguracije / admin akcije
  - pristup osetljivim funkcijama (npr. export)

**Koraci:**
- U aplikaciji pravim centralni modul `auditLog(event)`
- U ELK-u odvajam audit događaje:
  - indeks `audit-*` (ili bar filter po `event_category:audit`)

---

## 3) Log stavke ne smeju sadržati osetljive podatke
- Nikad ne logujem:
  - lozinke, OTP, API keys, JWT tokene, Authorization header
  - privatne ključeve, “secrets”
  - nepotrebne PII podatke
- Minimalni podaci:
  - `user_id` umesto email-a (ili maskiran email ako baš treba)
  - delimične vrednosti (npr. “last4” gde ima smisla)
- Sanitizacija:
  - redaction/maskiranje polja (`password`, `token`, `secret`, `authorization`)
  - escapovanje kontrolnih karaktera (pomaže i protiv log injection)

**Koraci:**
- Redaction filter u logger-u (pre upisa)
- Dodatni redaction u Logstash filterima (ako nešto “procuri”)

---

## 4) Pouzdanost + dostupnost + integritet logova
- Centralizacija u ELK (da logovi ne ostanu samo lokalno)
- Integritet i zaštita prenosa:
  - TLS između ingest-a (agent/Logstash) i Elasticsearch-a
- Kontrola pristupa:
  - RBAC u Elasticsearch-u (posebno strogo za `audit-*`)
  - ingest korisnik: samo write; analitika: read
- Dostupnost:
  - replicas u Elasticsearch-u
  - snapshot/backup politika za indekse

**Koraci:**
- Podesiti TLS sertifikate i korisnike/role
- Uključiti snapshot-e i pratiti ingest (alert ako stane dotok)

---

## 5) Precizno vreme nastanka događaja
- `timestamp` u UTC + ISO-8601 (npr. `2026-03-30T12:34:56.789Z`)
- Sinhronizacija vremena: NTP/chrony na hostovima
- Čuvam i:
  - `@timestamp` (vreme događaja)
  - `ingest_timestamp` (vreme prijema)

**Koraci:**
- NTP na svim serverima
- Pipeline dodaje `ingest_timestamp`

---

## 6) Uredni logovi (minimalna “pretrpanost”)
- Pravila za nivoe:
  - DEBUG isključen u produkciji (osim privremeno)
  - INFO samo “state change” + ključni događaji
  - WARN/ERROR sa kontekstom, bez osetljivih podataka
- Anti-spam:
  - sampling/rate limiting za ponavljajuće poruke
  - standardizovan `event_type` (da nema “haosa” u pretrazi)

**Koraci:**
- Logging policy + code review pravilo
- Rate-limit mehanizam za iste WARN/ERROR događaje

---

# LOGROTATE

## Kako koristim logrotate
- Konfig u `/etc/logrotate.d/<moja-aplikacija>`
- Tipična pravila:
  - `daily/weekly` ili `size`
  - `rotate N`
  - `compress`
  - `create` (vlasnik/permisije)
  - `su user group` (bezbednije izvršavanje)

## Problemi
- **Log injection** (ubacivanje lažnih linija preko unosa):
  - mitigacija: JSON logovi + escapovanje + sanitizacija inputa
- **Race condition / symlink problemi** (rotacija prepiše/kreira pogrešan fajl):
  - mitigacija: stroge permisije na log direktorijum, ispravan ownership, `create` + `su`, izbegavanje world-writable lokacija

---

# ELK stack

## 1) Pipeline za prijem logova (app/sistem/WAF)
- Tok:
  - izvori logova (aplikacija, sistem, WAF) → Filebeat/agent → Logstash → Elasticsearch → Kibana
- Plan:
  - svi audit događaji nose `event_category:audit`
  - WAF događaji nose npr. `event_category:waf`

**Koraci:**
- Filebeat: input putanje logova + output ka Logstash
- Logstash: input(beats) + filter(parse JSON, normalize, redact) + output(Elasticsearch)

---

## 2) Indeksiranje i čuvanje u Elasticsearch-u
- Indeksi:
  - `app-*` (operativno)
  - `audit-*` (non-repudiation / bezbednost)
- Neophodno:
  - index template/mapping (npr. `source.ip` kao `ip`, `@timestamp` kao `date`, ID kao `keyword`)
  - ILM (retencija: audit duže nego app)
  - replicas/shards
  - RBAC (strože za `audit-*`)

**Koraci:**
- Kreirati template za `audit-*` i `app-*`
- Uključiti ILM politiku (hot→warm→delete)
- Podesiti role i dozvole

---

## 3) Kibana: vizualizacija i filtriranje
- Data View:
  - `audit-*`
- Filteri:
  - `event_category:audit`
  - `event_outcome:failure`
  - `source.ip`, `actor.username`, `action`, vreme
- Dashboard primeri:
  - failed login trend
  - top IP adrese / WAF blokiranja
  - admin audit trail (promene rola/konfiguracije)

**Koraci:**
- Napraviti Data View + Saved searches
- Napraviti “Security Overview” dashboard