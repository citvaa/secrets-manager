#!/usr/bin/env bash
#
# users_check.sh
# Modul za pregled korisnickih naloga Linux sistema.
# LOTL pristup - samo citanje, bez modifikacija.
#
# Pokretanje:
#   bash users_check.sh
#   sudo bash users_check.sh      # preporuceno (shadow, sudoers)

# ── boje ────────────────────────────────────────────────────────────
if [ -t 1 ]; then
    R=$'\033[0m' BOLD=$'\033[1m'
    cRED=$'\033[31m' cYEL=$'\033[33m' cGRN=$'\033[32m' cCYN=$'\033[36m'
else
    R="" BOLD="" cRED="" cYEL="" cGRN="" cCYN=""
fi

hdr()  { echo; echo "${BOLD}${cCYN}=== $* ===${R}"; }
ok()   { echo "  ${cGRN}[*]${R} $*"; }
warn() { echo "  ${cYEL}[!]${R} $*"; }
crit() { echo "  ${cRED}[!!]${R} $*"; }
row()  { printf "      %-20s %s\n" "$1" "$2"; }

# ────────────────────────────────────────────────────────────────────
# 1. /etc/passwd
# ────────────────────────────────────────────────────────────────────
check_passwd() {
    hdr "1. /etc/passwd"

    [ -r /etc/passwd ] || { crit "/etc/passwd nije citljiv."; return 1; }

    # uid=0
    echo
    echo "  ${BOLD}uid=0 korisnici:${R}"
    local found_uid0=0
    while IFS=: read -r name _ uid _; do
        [ "$uid" = "0" ] || continue
        found_uid0=1
        if [ "$name" = "root" ]; then
            ok "root (uid=0) — ocekivano"
        else
            crit "'$name' ima uid=0 — potencijalni backdoor!"
        fi
    done < /etc/passwd
    [ "$found_uid0" -eq 0 ] && crit "Nije pronadjen root uid=0 unos — nestandardno."

    # interaktivni shell
    echo
    echo "  ${BOLD}Korisnici sa interaktivnim shellom:${R}"
    local shells="bash sh zsh fish dash"
    local n=0
    while IFS=: read -r name _ uid _ _ _ shell; do
        local base
        base=$(basename "$shell" 2>/dev/null)
        echo "$shells" | grep -qw "$base" || continue
        row "$name" "uid=$uid  shell=$shell"
        n=$(( n + 1 ))
    done < /etc/passwd
    [ "$n" -eq 0 ] && ok "Nema neocekivanih interaktivnih shella."
    [ "$n" -gt 0 ] && warn "$n korisnika ima interaktivan shell — proveriti da li su svi legitimni."

    # prazan password field
    echo
    echo "  ${BOLD}Prazan password field (/etc/passwd):${R}"
    local empty
    empty=$(awk -F: '$2 == "" { print $1 }' /etc/passwd)
    if [ -n "$empty" ]; then
        for u in $empty; do crit "'$u' ima prazan password field!"; done
    else
        ok "Nema korisnika sa praznim password fieldom."
    fi
}

# ────────────────────────────────────────────────────────────────────
# 2. /etc/shadow
# ────────────────────────────────────────────────────────────────────
check_shadow() {
    hdr "2. /etc/shadow — lozinke i politika isteka"

    if [ "$(id -u)" -ne 0 ]; then
        warn "/etc/shadow zahteva root — preskacem pregled hes algoritma i isteka."
    else
        [ -r /etc/shadow ] || { crit "/etc/shadow nije citljiv."; return 1; }

        # --- hash algoritam po korisniku ---
        echo
        echo "  ${BOLD}Hash algoritam po korisniku:${R}"
        while IFS=: read -r name hash _; do
            [ -z "$name" ] && continue
            case "$hash" in
                '!')           ok  "$name — zakljucan nalog (bez prijave)" ;;
                '*')           ok  "$name — nalog bez lozinke (sistem/servis)" ;;
                '')            crit "$name — PRAZAN hash, prijava bez lozinke moguca!" ;;
                '$6$'*)        ok  "$name — SHA-512 (dobro)" ;;
                '$5$'*)        warn "$name — SHA-256 (preporuciti prelaz na SHA-512)" ;;
                '$2b$'*|'$2a$'*|'$2$'*) warn "$name — Blowfish (prihvatljivo, ali neobicno za Linux)" ;;
                '$1$'*)        crit "$name — MD5! Slab algoritam, lako se brute-force-uje." ;;
                *)             crit "$name — DES ili nepoznat format! Veoma slab ili nestandardan." ;;
            esac
        done < /etc/shadow

        # --- istek lozinke po korisniku ---
        echo
        echo "  ${BOLD}Istek lozinke po korisniku (shadow polje maxdays):${R}"
        while IFS=: read -r name _ _ _ maxdays _ _ expdate _; do
            # preskoci sistemske naloge (prazni hash ili zakljucani)
            local hash
            hash=$(awk -F: -v u="$name" '$1==u{print $2}' /etc/shadow)
            case "$hash" in '!'*|'*'|'') continue ;; esac

            if [ -z "$maxdays" ] || [ "$maxdays" = "99999" ] || [ "$maxdays" = "-1" ]; then
                warn "$name — lozinka NIKAD ne istice (maxdays=$maxdays)"
            elif [ "$maxdays" -le 90 ] 2>/dev/null; then
                ok  "$name — maxdays=$maxdays"
            else
                warn "$name — maxdays=$maxdays (preporuceno <= 90)"
            fi
        done < /etc/shadow
    fi

    # --- globalna politika (/etc/login.defs) ---
    echo
    echo "  ${BOLD}Globalna politika lozinki (/etc/login.defs):${R}"
    if [ -r /etc/login.defs ]; then
        for key in PASS_MAX_DAYS PASS_MIN_DAYS PASS_WARN_AGE; do
            local val
            val=$(grep -E "^${key}\s" /etc/login.defs 2>/dev/null | awk '{print $2}')
            if [ -z "$val" ]; then
                warn "$key — nije podeseno"
                continue
            fi
            case "$key" in
                PASS_MAX_DAYS)
                    [ "$val" -le 90 ] 2>/dev/null && ok "$key = $val" \
                        || warn "$key = $val (preporuceno <= 90)"
                    ;;
                PASS_MIN_DAYS)
                    [ "$val" -ge 1 ] 2>/dev/null && ok "$key = $val" \
                        || warn "$key = $val (preporuceno >= 1, sprecava brzu zamenu lozinke)"
                    ;;
                PASS_WARN_AGE)
                    [ "$val" -ge 7 ] 2>/dev/null && ok "$key = $val" \
                        || warn "$key = $val (preporuceno >= 7 dana upozorenja)"
                    ;;
            esac
        done
    else
        warn "/etc/login.defs nije citljiv."
    fi

    # --- podrazumevani PAM algoritam ---
    echo
    echo "  ${BOLD}Podrazumevani algoritam hesiranja (PAM):${R}"
    local pam_file=""
    for f in /etc/pam.d/common-password /etc/pam.d/system-auth /etc/pam.d/password-auth; do
        [ -r "$f" ] && { pam_file="$f"; break; }
    done

    if [ -z "$pam_file" ]; then
        warn "Nije pronadjen PAM password fajl — proveriti rucno."
    else
        local pam_algo
        pam_algo=$(grep -E 'pam_unix\.so' "$pam_file" 2>/dev/null | grep -oE 'sha512|sha256|md5|blowfish' | head -1)
        case "$pam_algo" in
            sha512)   ok  "$pam_file — SHA-512 (dobro)" ;;
            sha256)   warn "$pam_file — SHA-256 (preporuciti sha512)" ;;
            md5)      crit "$pam_file — MD5! Promeniti na sha512 u pam_unix.so liniji." ;;
            blowfish) warn "$pam_file — Blowfish (neobicno za Linux, proveriti)" ;;
            '')       warn "$pam_file — algoritam nije eksplicitno naveden (proveriti rucno)" ;;
        esac
    fi

    # --- politika zakljucavanja nakon neuspelih pokusaja ---
    echo
    echo "  ${BOLD}Politika zakljucavanja naloga (pam_faillock / pam_tally2):${R}"
    local auth_file=""
    for f in /etc/pam.d/common-auth /etc/pam.d/system-auth /etc/pam.d/password-auth; do
        [ -r "$f" ] && { auth_file="$f"; break; }
    done

    if [ -z "$auth_file" ]; then
        warn "Nije pronadjen PAM auth fajl — proveriti rucno."
    else
        if grep -qE 'pam_faillock\.so|pam_tally2\.so' "$auth_file" 2>/dev/null; then
            local deny
            deny=$(grep -E 'pam_faillock\.so|pam_tally2\.so' "$auth_file" | grep -oE 'deny=[0-9]+' | head -1 | cut -d= -f2)
            ok "Zakljucavanje je konfigurisano${deny:+ (deny=$deny)}."
            [ -n "$deny" ] && [ "$deny" -gt 5 ] && warn "deny=$deny — preporuceno <= 5 pokusaja."
        else
            crit "pam_faillock/pam_tally2 NIJE konfigurisano — nalog se ne zakljucava nakon pogresnih lozinki."
        fi
    fi
}

# ────────────────────────────────────────────────────────────────────
# 3. sudo konfiguracija i root pristup
# ────────────────────────────────────────────────────────────────────
check_sudo() {
    hdr "3. sudo konfiguracija i root pristup"

    # --- /etc/sudoers ---
    echo
    echo "  ${BOLD}Analiza /etc/sudoers:${R}"

    if [ ! -r /etc/sudoers ]; then
        warn "/etc/sudoers nije citljiv — pokrenuti kao root."
    else
        # Ignorisati komentare i prazne linije
        local rules
        rules=$(grep -Ev '^\s*(#|$)' /etc/sudoers 2>/dev/null)

        # NOPASSWD
        local nopasswd
        nopasswd=$(echo "$rules" | grep -i 'NOPASSWD')
        if [ -n "$nopasswd" ]; then
            crit "NOPASSWD pravila pronadjena — korisnik moze sudo bez lozinke:"
            echo "$nopasswd" | while read -r line; do
                echo "      $line"
            done
        else
            ok "Nema NOPASSWD pravila."
        fi

        # ALL=(ALL) ALL — neogranicen pristup
        echo
        local allall
        allall=$(echo "$rules" | grep -E 'ALL\s*=\s*\(ALL\).*ALL' | grep -v NOPASSWD)
        if [ -n "$allall" ]; then
            warn "Neogranicena sudo pravila (ALL=(ALL) ALL):"
            echo "$allall" | while read -r line; do
                echo "      $line"
            done
            warn "Proveriti da li svaki navedeni korisnik/grupa zaista treba pun pristup."
        else
            ok "Nema otvorenih ALL=(ALL) ALL pravila (osim NOPASSWD vec navedenih)."
        fi

        # Opasne komande
        echo
        local dangerous="vim vi nano less more awk sed python python3 perl ruby lua bash sh zsh fish dash find nmap wget curl nc netcat chmod chown cp mv tar dd"
        local found_dangerous=0
        for cmd in $dangerous; do
            local matches
            matches=$(echo "$rules" | grep -E "/(bin|usr/bin|sbin|usr/sbin)/${cmd}([[:space:]]|$)")
            if [ -n "$matches" ]; then
                [ "$found_dangerous" -eq 0 ] && crit "Sudo pristup opasnim komandama (moguca eskalacija privilegija):"
                found_dangerous=1
                echo "$matches" | while read -r line; do
                    echo "      [$cmd] $line"
                done
            fi
        done
        [ "$found_dangerous" -eq 0 ] && ok "Nisu pronadjene ocigledne opasne komande u sudoers."
    fi

    # --- /etc/sudoers.d/ ---
    echo
    echo "  ${BOLD}Drop-in fajlovi (/etc/sudoers.d/):${R}"
    if [ -d /etc/sudoers.d ] && [ -r /etc/sudoers.d ]; then
        local dropins
        dropins=$(ls /etc/sudoers.d/ 2>/dev/null | grep -Ev '^\.')
        if [ -z "$dropins" ]; then
            ok "Nema drop-in fajlova."
        else
            warn "Pronadjeni drop-in fajlovi — proveriti svaki:"
            for f in $dropins; do
                local fpath="/etc/sudoers.d/$f"
                echo "      $fpath"
                if [ -r "$fpath" ]; then
                    grep -Ev '^\s*(#|$)' "$fpath" | while read -r line; do
                        echo "        $line"
                        echo "$line" | grep -qi 'NOPASSWD' && crit "  ^^^ NOPASSWD u drop-in fajlu!"
                    done
                else
                    warn "      $fpath nije citljiv."
                fi
            done
        fi
    else
        warn "/etc/sudoers.d nije dostupan ili nije citljiv."
    fi

    # --- /etc/securetty (direktan root login na konzoli) ---
    echo
    echo "  ${BOLD}Direktan root login (/etc/securetty):${R}"
    if [ ! -e /etc/securetty ]; then
        warn "/etc/securetty ne postoji — sistem mozda ne kontrolise root konzolni pristup."
    elif [ ! -r /etc/securetty ]; then
        warn "/etc/securetty nije citljiv — pokrenuti kao root."
    else
        local tty_count
        tty_count=$(grep -Ecv '^\s*(#|$)' /etc/securetty 2>/dev/null)
        if [ "$tty_count" -eq 0 ]; then
            ok "/etc/securetty je prazan — direktan root login na konzoli je onemogucen."
        else
            warn "/etc/securetty sadrzi $tty_count terminal(a) — root moze da se prijavi direktno:"
            grep -Ev '^\s*(#|$)' /etc/securetty | while read -r line; do
                echo "      $line"
            done
            warn "Razmotriti praznjenje fajla i koristiti sudo umesto direktnog root logina."
        fi
    fi
}

# ────────────────────────────────────────────────────────────────────
main() {
    echo "${BOLD}Users Review — $(hostname 2>/dev/null)${R}"
    echo "Datum   : $(date)"
    echo "Korisnik: $(id -un) (uid=$(id -u))"
    [ "$(id -u)" -ne 0 ] && warn "Nije root — neke provere ce biti nepotpune (shadow, sudoers)."

    check_passwd
    check_shadow
    check_sudo

    echo
    hdr "Kraj pregleda"
    echo "  Sacuvati izlaz: sudo bash $0 &> /tmp/audit/users_\$(date +%Y%m%d_%H%M).txt"
    echo
}

main "$@"
