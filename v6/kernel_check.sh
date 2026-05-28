#!/usr/bin/env bash
#
# kernel_check.sh
# ---------------
# Modul za pregled (review) Linux sistema, deo: KERNEL.
#
# Cilj: edukativan i defanzivan. Skripta SAMO prikuplja i izvestava
# informacije koristeci postojece sistemske komande (LOTL pristup).
# Ne sadrzi eksploatacione tehnike.
#
# Pokrenuti kao:
#   bash kernel_check.sh            # osnovne provere
#   sudo bash kernel_check.sh       # neke provere zahtevaju root
#

# --------------------------------------------------------------------
# Pomocne funkcije za formatiranje izlaza
# --------------------------------------------------------------------

# Boje (ako je terminal interaktivan)
if [ -t 1 ]; then
    C_RESET=$'\033[0m'
    C_BOLD=$'\033[1m'
    C_RED=$'\033[31m'
    C_GREEN=$'\033[32m'
    C_YELLOW=$'\033[33m'
    C_BLUE=$'\033[34m'
    C_CYAN=$'\033[36m'
else
    C_RESET=""; C_BOLD=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_CYAN=""
fi

print_section() {
    local title="$1"
    echo
    echo "${C_BOLD}${C_BLUE}========================================================${C_RESET}"
    echo "${C_BOLD}${C_BLUE}  $title${C_RESET}"
    echo "${C_BOLD}${C_BLUE}========================================================${C_RESET}"
}

print_subsection() {
    echo
    echo "${C_BOLD}${C_CYAN}-- $1 --${C_RESET}"
}

print_info()  { echo "${C_GREEN}[INFO]${C_RESET}  $*"; }
print_warn()  { echo "${C_YELLOW}[WARN]${C_RESET}  $*"; }
print_alert() { echo "${C_RED}[ALERT]${C_RESET} $*"; }
print_kv()    { printf "  %-28s : %s\n" "$1" "$2"; }

have() { command -v "$1" >/dev/null 2>&1; }

# --------------------------------------------------------------------
# 1) Verzija kernela, arhitektura, hostname
# --------------------------------------------------------------------
# Bezbednosni problem koji ova provera pomaze da se uoci:
#   - Zastarela / ranjiva verzija kernela (CVE-ovi vezani za konkretnu
#     verziju kernela; potrebno je proveriti listu ranjivosti distribucije
#     jer distribucije back-portuju patch-eve bez menjanja major/minor
#     verzije).
#   - Identifikacija arhitekture i imena hosta je osnova svakog
#     review-a (System Review Example, sekcija "Kernel").
check_kernel_version() {
    print_section "1. KERNEL VERZIJA I OSNOVNE INFORMACIJE"

    if ! have uname; then
        print_alert "Komanda 'uname' nije dostupna na sistemu - ne moze se nastaviti."
        return 1
    fi

    local kernel_name release version machine hostname_val
    kernel_name=$(uname -s 2>/dev/null)
    release=$(uname -r 2>/dev/null)
    version=$(uname -v 2>/dev/null)
    machine=$(uname -m 2>/dev/null)
    hostname_val=$(uname -n 2>/dev/null)

    print_kv "Kernel"        "$kernel_name"
    print_kv "Release"       "$release"
    print_kv "Version"       "$version"
    print_kv "Arhitektura"   "$machine"
    print_kv "Hostname"      "$hostname_val"

    # Pun ispis radi audit logova
    print_subsection "uname -a"
    uname -a 2>/dev/null

    # Brza heuristika: kernel 2.x ili 3.x na produkciji = veoma stara verzija.
    case "$release" in
        2.*|3.*)
            print_alert "Detektovana stara major linija kernela ($release)."
            print_alert "Velika je verovatnoca da postoje poznate ranjivosti."
            print_alert "Proveriti listu ranjivosti distribucije za ovaj kernel."
            ;;
        4.*)
            print_warn "Kernel 4.x je stariji - preporucljiv je upgrade i provera CVE liste."
            ;;
        5.*|6.*)
            print_info "Kernel major verzija ($release) je relativno aktuelna."
            print_info "Ipak, OBAVEZNO proveriti CVE listu distribucije za tacan release."
            ;;
        *)
            print_warn "Nepoznat oblik kernel verzije: '$release'. Proveriti rucno."
            ;;
    esac
}

# --------------------------------------------------------------------
# 2) Operativni sistem (distribucija) - direktno potrebno za interpretaciju
#    kernel verzije jer distribucije back-portuju patch-eve.
# --------------------------------------------------------------------
# Bezbednosni problem koji ova provera pomaze da se uoci:
#   - End-of-life (EOL) distribucije => kernel se vise NE PATCH-uje.
#     (Primer: Debian Lenny nije podrzan od 02/2012.)
#   - Bez ovog konteksta, gola kernel verzija nije dovoljna za odluku
#     da li je sistem ranjiv.
check_os_distribution() {
    print_section "2. DISTRIBUCIJA OPERATIVNOG SISTEMA"

    # Najpouzdaniji izvor (systemd-based distros)
    if [ -r /etc/os-release ]; then
        print_subsection "/etc/os-release"
        # Prikazujemo samo kljucna polja umesto kompletnog fajla
        grep -E '^(NAME|PRETTY_NAME|VERSION|VERSION_ID|ID|ID_LIKE)=' /etc/os-release 2>/dev/null \
            | sed 's/^/  /'
    else
        print_warn "/etc/os-release nije citljiv ili ne postoji."
    fi

    # Debian-specific
    if [ -r /etc/debian_version ]; then
        print_kv "Debian version" "$(cat /etc/debian_version 2>/dev/null)"
    fi

    # RedHat-family
    if [ -r /etc/redhat-release ]; then
        print_kv "RedHat-release" "$(cat /etc/redhat-release 2>/dev/null)"
    fi
    if [ -r /etc/fedora-release ]; then
        print_kv "Fedora-release" "$(cat /etc/fedora-release 2>/dev/null)"
    fi

    # Ubuntu / generic LSB
    if have lsb_release; then
        print_subsection "lsb_release -a"
        lsb_release -a 2>/dev/null | sed 's/^/  /'
    fi

    print_info "NAPOMENA: proveriti da li je distribucija jos uvek podrzana (NIJE EOL)."
    print_info "Distribucije obicno back-portuju kernel patch-eve, pa CVE proveru raditi"
    print_info "iskljucivo protiv security advisory liste konkretne distribucije."
}

# --------------------------------------------------------------------
# 3) Uptime - indikator kada je kernel poslednji put restartovan/patch-ovan
# --------------------------------------------------------------------
# Bezbednosni problem koji ova provera pomaze da se uoci:
#   - Veliki uptime znaci da kernel verovatno NIJE patch-ovan jako dugo
#     (kernel patch zahteva reboot, osim ako se koristi livepatch).
#   - Tipican primer: 70 dana uptime znaci da kernel skoro sigurno nije patch-ovan.
check_uptime() {
    print_section "3. UPTIME (indikator nadogradnje kernela)"

    if ! have uptime; then
        print_warn "Komanda 'uptime' nije dostupna."
        return
    fi

    print_subsection "uptime"
    uptime | sed 's/^/  /'

    # Pokusaj da izvuce broj dana iz /proc/uptime (pouzdaniji parsing)
    if [ -r /proc/uptime ]; then
        local up_seconds up_days
        up_seconds=$(awk '{print int($1)}' /proc/uptime 2>/dev/null)
        if [ -n "$up_seconds" ]; then
            up_days=$(( up_seconds / 86400 ))
            print_kv "Uptime (dana)" "$up_days"

            if [ "$up_days" -ge 60 ]; then
                print_alert "Uptime ($up_days dana) je veoma velik."
                print_alert "Kernel verovatno nije patch-ovan tokom ovog perioda."
                print_alert "Razmotriti reboot nakon primene kernel security update-a."
            elif [ "$up_days" -ge 30 ]; then
                print_warn "Uptime ($up_days dana) je srednji - proveriti da li ima neprimenjenih kernel update-a."
            else
                print_info "Uptime ($up_days dana) je u prihvatljivom opsegu."
            fi
        fi
    fi
}

# --------------------------------------------------------------------
# 4) Pending reboot - postoji li noviji kernel instaliran cijim
#    aktiviranjem treba rebootovati sistem
# --------------------------------------------------------------------
# Bezbednosni problem koji ova provera pomaze da se uoci:
#   - Sistem moze imati instaliran patch-ovani kernel, ali se i dalje
#     pokrece SA STARIJIM, RANJIVIM kernelom dok se ne uradi reboot.
#   - To je tipican propust nakon `apt upgrade` ili `dnf update`.
check_pending_reboot() {
    print_section "4. PROVERA POTREBE ZA REBOOT-OM (pending kernel)"

    # Debian/Ubuntu standardni indikator
    if [ -e /var/run/reboot-required ]; then
        print_alert "Postoji /var/run/reboot-required => sistem zahteva reboot."
        if [ -r /var/run/reboot-required.pkgs ]; then
            print_subsection "Paketi koji su trigerovali potrebu za reboot-om"
            sed 's/^/  /' /var/run/reboot-required.pkgs
        fi
    else
        print_info "Nema /var/run/reboot-required (na Debian/Ubuntu sistemima ovo je dobar znak)."
    fi

    # Uporedjivanje pokrenutog i instaliranog kernela
    local running_kernel newest_installed
    running_kernel=$(uname -r 2>/dev/null)

    if [ -d /boot ] && have ls; then
        # Najnoviji vmlinuz u /boot
        newest_installed=$(ls -1t /boot/vmlinuz-* 2>/dev/null | head -n1 | sed 's|^/boot/vmlinuz-||')
        if [ -n "$newest_installed" ]; then
            print_kv "Pokrenut kernel"        "$running_kernel"
            print_kv "Najnoviji u /boot"      "$newest_installed"
            if [ "$running_kernel" != "$newest_installed" ]; then
                print_alert "Pokrenut kernel se RAZLIKUJE od najnovijeg instaliranog."
                print_alert "Verovatno postoji neaktivan novi kernel - potreban reboot."
            else
                print_info "Pokrenut kernel je isti kao najnoviji instalirani."
            fi
        fi
    fi
}

# --------------------------------------------------------------------
# 5) Kernel hardening - sysctl runtime parametri vezani za kernel
# --------------------------------------------------------------------
# Bezbednosni problem koji ova provera pomaze da se uoci:
#   - Pogresno postavljeni sysctl parametri olaksavaju eksploataciju
#     kernel ranjivosti i procurivanje informacija iz kernel prostora.
#   - Ukljucuje proveru ASLR-a, ogranicavanje pristupa kernel adresama,
#     i `net.ipv6.conf.all.disable_ipv6` (relevantno ako IPv6 nije potreban).
check_kernel_hardening() {
    print_section "5. KERNEL HARDENING (sysctl runtime parametri)"

    if ! have sysctl && [ ! -d /proc/sys ]; then
        print_warn "Ni 'sysctl' ni /proc/sys nisu dostupni - preskacem."
        return
    fi

    # Citac koji prvo proba sysctl, pa onda direktno /proc/sys
    get_sysctl() {
        local key="$1" val
        if have sysctl; then
            val=$(sysctl -n "$key" 2>/dev/null)
        fi
        if [ -z "$val" ]; then
            local path="/proc/sys/${key//.//}"
            [ -r "$path" ] && val=$(cat "$path" 2>/dev/null)
        fi
        echo "$val"
    }

    # ASLR
    local aslr
    aslr=$(get_sysctl kernel.randomize_va_space)
    print_kv "kernel.randomize_va_space" "${aslr:-N/A}"
    case "$aslr" in
        2) print_info "ASLR je u potpunosti ukljucen (preporuceno)." ;;
        1) print_warn "ASLR je delimicno ukljucen - preporuceno je postaviti na 2." ;;
        0) print_alert "ASLR je ISKLJUCEN - kernel je mnogo lakse eksploatisati." ;;
        *) print_warn "ASLR vrednost nije procitana ili je nepoznata." ;;
    esac

    # Skrivanje kernel adresa od non-root korisnika
    local kptr
    kptr=$(get_sysctl kernel.kptr_restrict)
    print_kv "kernel.kptr_restrict" "${kptr:-N/A}"
    case "$kptr" in
        1|2) print_info "kptr_restrict skriva kernel pokazivace (dobro)." ;;
        0)   print_warn "kptr_restrict = 0 => kernel pokazivaci vidljivi svima (info-leak)." ;;
        *)   print_warn "kptr_restrict vrednost nije procitana." ;;
    esac

    # Ogranicavanje dmesg pristupa
    local dmesg_r
    dmesg_r=$(get_sysctl kernel.dmesg_restrict)
    print_kv "kernel.dmesg_restrict" "${dmesg_r:-N/A}"
    case "$dmesg_r" in
        1) print_info "dmesg je restriktovan na root (dobro)." ;;
        0) print_warn "dmesg moze cita bilo koji korisnik - moze procuriti senzitivne informacije." ;;
        *) print_warn "dmesg_restrict vrednost nije procitana." ;;
    esac

    # YAMA ptrace_scope - ogranicava ptrace izmedju procesa istog korisnika
    local yama
    yama=$(get_sysctl kernel.yama.ptrace_scope)
    print_kv "kernel.yama.ptrace_scope" "${yama:-N/A}"
    case "$yama" in
        1|2|3) print_info "ptrace_scope je restriktovan (dobro)." ;;
        0)     print_warn "ptrace_scope = 0 => proces moze ptrace-ovati bilo koji drugi proces istog korisnika." ;;
        *)     print_warn "ptrace_scope vrednost nije procitana." ;;
    esac

    # IPv6 - ako nije potreban, treba ga disable-ovati na nivou kernela
    # (sekcija NETWORK REVIEW / IPv6: bez ip6tables pravila aktivan IPv6 je dodatna napadna povrsina)
    local ipv6_dis
    ipv6_dis=$(get_sysctl net.ipv6.conf.all.disable_ipv6)
    print_kv "net.ipv6.conf.all.disable_ipv6" "${ipv6_dis:-N/A}"
    if [ "$ipv6_dis" = "1" ]; then
        print_info "IPv6 je disable-ovan na nivou kernela."
    else
        print_warn "IPv6 je aktivan - ako nije potreban i nema ip6tables pravila, predstavlja dodatnu povrsinu napada."
        print_warn "Preporuka: kreirati /etc/sysctl.d/disableipv6.conf sa net.ipv6.conf.all.disable_ipv6=1."
    fi

    # SUID dumpable - utice na to da li setuid procesi mogu da dumpaju core
    local suid_d
    suid_d=$(get_sysctl fs.suid_dumpable)
    print_kv "fs.suid_dumpable" "${suid_d:-N/A}"
    case "$suid_d" in
        0) print_info "fs.suid_dumpable = 0 (dobro - setuid procesi ne mogu da dumpaju core)." ;;
        1) print_alert "fs.suid_dumpable = 1 - setuid procesi mogu da dumpaju core (rizik od info-leak-a)." ;;
        2) print_info "fs.suid_dumpable = 2 (core moze, ali samo root cita)." ;;
        *) print_warn "fs.suid_dumpable vrednost nije procitana." ;;
    esac
}

# --------------------------------------------------------------------
# 6) Lista ucitanih kernel modula
# --------------------------------------------------------------------
# Bezbednosni problem koji ova provera pomaze da se uoci:
#   - Neocekivan/sumnjiv kernel modul moze biti znak rootkita ili
#     zaboravljenog debug/testing modula.
#   - Veliki broj modula = veca napadna povrsina kernela.
check_loaded_modules() {
    print_section "6. UCITANI KERNEL MODULI"

    if [ ! -r /proc/modules ] && ! have lsmod; then
        print_warn "Ni lsmod ni /proc/modules nisu dostupni - preskacem."
        return
    fi

    local module_count
    if have lsmod; then
        module_count=$(lsmod | tail -n +2 | wc -l)
    else
        module_count=$(wc -l < /proc/modules)
    fi
    print_kv "Broj ucitanih modula" "$module_count"

    print_subsection "Prvih 20 modula (lsmod)"
    if have lsmod; then
        lsmod | head -n 21 | sed 's/^/  /'
    else
        head -n 20 /proc/modules | sed 's/^/  /'
    fi

    print_info "Pregledati listu i identifikovati module koji NISU potrebni za ulogu sistema."
    print_info "Sumnjive module manualno proveriti komandom 'modinfo <ime>'."
}

# --------------------------------------------------------------------
# Glavna procedura
# --------------------------------------------------------------------
main() {
    echo "${C_BOLD}Secure Deployment Environment - Kernel Review Module${C_RESET}"
    echo "Datum: $(date 2>/dev/null)"
    echo "Korisnik: $(id -un 2>/dev/null) (UID=$(id -u 2>/dev/null))"

    if [ "$(id -u 2>/dev/null)" -ne 0 ]; then
        print_warn "Skripta nije pokrenuta kao root - neke provere mogu biti nepotpune."
        print_warn "Preporuka: ponovo pokrenuti sa 'sudo'."
    fi

    check_kernel_version
    check_os_distribution
    check_uptime
    check_pending_reboot
    check_kernel_hardening
    check_loaded_modules

    echo
    print_section "PREGLED ZAVRSEN"
    echo "Sve provere zavrsene. Sacuvati izlaz u audit folder, npr.:"
    echo "  mkdir -p /tmp/audit && bash $0 &> /tmp/audit/kernel_check_\$(date +%Y%m%d_%H%M).txt"
    echo
}

main "$@"
