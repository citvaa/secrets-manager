# Modul za pregled pokrenutih servisa i njihovih konfiguracija

if [ -t 1 ]; then
    C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'
    C_RED=$'\033[31m';  C_GREEN=$'\033[32m'
    C_YELLOW=$'\033[33m'; C_BLUE=$'\033[34m'; C_CYAN=$'\033[36m'
else
    C_RESET=""; C_BOLD=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_CYAN=""
fi

print_section()    { echo; echo "${C_BOLD}${C_BLUE}========================================================${C_RESET}"; echo "${C_BOLD}${C_BLUE}  $1${C_RESET}"; echo "${C_BOLD}${C_BLUE}========================================================${C_RESET}"; }
print_subsection() { echo; echo "${C_BOLD}${C_CYAN}-- $1 --${C_RESET}"; }
print_info()       { echo "${C_GREEN}[INFO]${C_RESET}  $*"; }
print_warn()       { echo "${C_YELLOW}[WARN]${C_RESET}  $*"; }
print_alert()      { echo "${C_RED}[ALERT]${C_RESET} $*"; }
print_kv()         { printf "  %-28s : %s\n" "$1" "$2"; }
have()             { command -v "$1" >/dev/null 2>&1; }

# --------------------------------------------------------------------
# 1) Pokrenuti servisi
# Bezbednosni problemi koje provera pomaze da se uoce:
#   - Neprepoznat root proces moze biti znak rootkita ili kompromitovanog sistema
#   - Bez syslog-a sistem ne biljezi bezbednosne dogadjaje
#   - Bez fail2ban bruteforce napadi na SSH idu nesmetano
# --------------------------------------------------------------------
check_running_services() {
    print_section "1. POKRENUTI SERVISI"

    print_subsection "Svi pokrenuti procesi"
    ps -edf 2>/dev/null | sed 's/^/  /'

    print_subsection "Procesi koji rade kao root"
    ps -edf 2>/dev/null | awk '$1 == "root"' | grep -v '\[' | sed 's/^/  /'

    print_subsection "Syslog"
    if ps -edf 2>/dev/null | grep -qE '[r]syslogd|[s]yslogd|[s]ystemd-journald'; then
        print_info "Syslog servis je aktivan."
    else
        print_alert "Syslog servis nije pronadjen - sistem ne loguje dogadjaje."
    fi

    print_subsection "Fail2ban"
    if have fail2ban-client || ps -edf 2>/dev/null | grep -q '[f]ail2ban'; then
        print_info "fail2ban je aktivan."
    else
        print_warn "fail2ban nije pronadjen. Preporuka: apt install fail2ban"
    fi
}

# --------------------------------------------------------------------
# 2) SSH konfiguracija
# Bezbednosni problemi koje provera pomaze da se uoce:
#   - PermitRootLogin yes: napadac moze direktno napadati root nalog
#   - PasswordAuthentication yes: moguc bruteforce napad na lozinku
#   - Port 22: automatski skeneri ga odmah pronalaze i napadaju
#   - AllowTcpForwarding yes: server se moze koristiti za zaobilazenje firewalla
# --------------------------------------------------------------------
check_ssh_config() {
    print_section "2. SSH KONFIGURACIJA"

    local sshd_cfg="/etc/ssh/sshd_config"

    if [ ! -f "$sshd_cfg" ]; then
        print_info "SSH server nije instaliran - preskacemo."
        return
    fi

    local permit_root
    permit_root=$(grep -i "^PermitRootLogin" "$sshd_cfg" 2>/dev/null | awk '{print $2}')
    print_kv "PermitRootLogin" "${permit_root:-nije postavljen}"
    case "${permit_root,,}" in
        yes)                                    print_alert "PermitRootLogin = yes - root moze direktno da se prijavi!" ;;
        no|prohibit-password|forced-commands-only) print_info "PermitRootLogin = $permit_root (dobro)." ;;
        *)                                      print_warn  "PermitRootLogin nije postavljen - na starijim sistemima default je yes." ;;
    esac

    local pass_auth
    pass_auth=$(grep -i "^PasswordAuthentication" "$sshd_cfg" 2>/dev/null | awk '{print $2}')
    print_kv "PasswordAuthentication" "${pass_auth:-nije postavljen}"
    if [ -z "$pass_auth" ] || echo "$pass_auth" | grep -iq "^yes$"; then
        print_warn "PasswordAuthentication = yes - moguc bruteforce napad na lozinku."
    else
        print_info "PasswordAuthentication = $pass_auth (dobro)."
    fi

    local ssh_port
    ssh_port=$(grep -i "^Port" "$sshd_cfg" 2>/dev/null | awk '{print $2}')
    print_kv "Port" "${ssh_port:-22 (podrazumevani)}"
    if [ -z "$ssh_port" ] || [ "$ssh_port" = "22" ]; then
        print_warn "SSH koristi podrazumevani port 22 - automatski skeneri ga lako pronalaze."
    else
        print_info "SSH koristi nestandardni port $ssh_port (dobro)."
    fi

    local tcp_fwd
    tcp_fwd=$(grep -i "^AllowTcpForwarding" "$sshd_cfg" 2>/dev/null | awk '{print $2}')
    print_kv "AllowTcpForwarding" "${tcp_fwd:-nije postavljen}"
    if [ -z "$tcp_fwd" ] || echo "$tcp_fwd" | grep -iq "^yes$"; then
        print_warn "AllowTcpForwarding nije iskljucen - server se moze koristiti za zaobilazenje firewalla."
    else
        print_info "AllowTcpForwarding = $tcp_fwd (dobro)."
    fi
}

# --------------------------------------------------------------------
# 3) NTP sinhronizacija vremena
# Bezbednosni problemi koje provera pomaze da se uoce:
#   - Netacno vreme kvari korelaciju logova iz razlicitih izvora
#   - SSL sertifikati se odbijaju ako je vreme netacno
#   - Vremenska zona sa DST pravi skokove u logovima
# --------------------------------------------------------------------
check_ntp() {
    print_section "3. NTP SINHRONIZACIJA VREMENA"

    print_kv "Trenutno vreme" "$(date 2>/dev/null)"

    local ntp_found=0

    if have timedatectl; then
        print_subsection "timedatectl status"
        timedatectl 2>/dev/null | sed 's/^/  /'
        if timedatectl 2>/dev/null | grep -qE "synchronized: yes|NTP synchronized: yes|NTP service: active"; then
            print_info "Vreme je sinhronizovano."
            ntp_found=1
        fi
    fi

    if ps -edf 2>/dev/null | grep -q '[n]tpd'; then
        print_info "ntpd je pokrenut."
        ntp_found=1
        have ntpq && ntpq -p -n 2>/dev/null | sed 's/^/  /'
    fi

    if ps -edf 2>/dev/null | grep -q '[c]hronyd'; then
        print_info "chronyd je pokrenut."
        ntp_found=1
        if have chronyc; then
            print_subsection "chronyc tracking"
            chronyc tracking 2>/dev/null | sed 's/^/  /'
        fi
    fi

    [ "$ntp_found" -eq 0 ] && print_alert "Nije pronadjen nijedan NTP servis!"

    print_subsection "Vremenska zona"
    local tz=""
    [ -f /etc/timezone ] && tz=$(cat /etc/timezone 2>/dev/null)
    [ -z "$tz" ] && have timedatectl && tz=$(timedatectl 2>/dev/null | grep "Time zone" | awk '{print $3}')
    print_kv "Vremenska zona" "${tz:-nije pronadjena}"
    if echo "$tz" | grep -q "UTC"; then
        print_info "Koristi se UTC (dobro)."
    elif [ -n "$tz" ]; then
        print_warn "Nije UTC ($tz) - na produkcijskim serverima se preporucuje UTC."
    fi
}

# --------------------------------------------------------------------
# 4) Konfiguracija logovanja
# Bezbednosni problemi koje provera pomaze da se uoce:
#   - Bez remote logovanja napadac moze obrisati lokalne logove
#   - Log fajlovi citljivi svim korisnicima mogu otkriti osetljive podatke
#   - rsyslog koji prima logove sa mreze moze biti meta injection napada
# --------------------------------------------------------------------
check_logging() {
    print_section "4. KONFIGURACIJA LOGOVANJA"

    local rsyslog_cfg="/etc/rsyslog.conf"

    if [ ! -f "$rsyslog_cfg" ]; then
        print_warn "rsyslog nije pronadjen - proveriti da li se koristi drugi syslog daemon."
        return
    fi

    print_kv "Konfiguracioni fajl" "$rsyslog_cfg"

    print_subsection "Remote logging"
    if grep -qE "^[^#]*@@?[a-zA-Z0-9]" "$rsyslog_cfg" 2>/dev/null || \
       find /etc/rsyslog.d/ -name "*.conf" -exec grep -lE "^[^#]*@@?[a-zA-Z0-9]" {} \; 2>/dev/null | grep -q .; then
        print_info "Logovi se salju na udaljeni server (dobro)."
    else
        print_warn "Logovi se NE salju na udaljeni server - napadac ih moze obrisati."
    fi

    print_subsection "Permisije log fajlova"
    local world_readable
    world_readable=$(find /var/log -maxdepth 1 -type f -perm /004 2>/dev/null | head -10)
    if [ -n "$world_readable" ]; then
        print_warn "Log fajlovi citljivi od strane svih korisnika:"
        echo "$world_readable" | sed 's/^/  /'
    else
        print_info "Log fajlovi nisu citljivi od strane svih korisnika (dobro)."
    fi

    print_subsection "Prijem logova sa mreze"
    if grep -qE "^\\\$ModLoad imudp|^\\\$UDPServerRun|^\\\$ModLoad imtcp|^\\\$InputTCPServerRun" "$rsyslog_cfg" 2>/dev/null; then
        print_warn "rsyslog prima logove sa mreze - proveriti da li je namerno."
    else
        print_info "rsyslog ne prima logove sa mreze (dobro)."
    fi
}

# --------------------------------------------------------------------
# Main
# --------------------------------------------------------------------
main() {
    echo "${C_BOLD}Secure Deployment Environment - Services Review Module${C_RESET}"
    echo "Datum: $(date 2>/dev/null)"
    echo "Korisnik: $(id -un 2>/dev/null) (UID=$(id -u 2>/dev/null))"

    [ "$(id -u 2>/dev/null)" -ne 0 ] && print_warn "Nije root - neke provere mogu biti nepotpune. Preporuka: sudo."

    check_running_services
    check_ssh_config
    check_ntp
    check_logging
}

main "$@"