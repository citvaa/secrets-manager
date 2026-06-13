#!/usr/bin/env bash
#
# demo_weaken.sh
# Namerno slabi bezbednost Ubuntu servera radi demonstracije users_check.sh.
# Sve promene su reverzibilne — restore mod vraca sistem u prethodno stanje.
#
# Pokretanje:
#   sudo bash demo_weaken.sh --weaken
#   sudo bash demo_weaken.sh --restore

set -euo pipefail

BACKUP_DIR="/root/demo_restore"
DEMO_USER="audit_demo"
DEMO_SUDOERS="/etc/sudoers.d/audit_demo"

# ── boje ────────────────────────────────────────────────────────────
if [ -t 1 ]; then
    R=$'\033[0m' BOLD=$'\033[1m'
    cRED=$'\033[31m' cYEL=$'\033[33m' cGRN=$'\033[32m' cCYN=$'\033[36m'
else
    R="" BOLD="" cRED="" cYEL="" cGRN="" cCYN=""
fi

step()    { echo; echo "${BOLD}${cCYN}>> $*${R}"; }
done_()   { echo "   ${cGRN}[ok]${R} $*"; }
note()    { echo "   ${cYEL}[~]${R}  $*"; }
fail()    { echo "   ${cRED}[!!]${R} $*"; }

require_root() {
    [ "$(id -u)" -eq 0 ] || { fail "Pokrenuti kao root (sudo bash $0 $1)"; exit 1; }
}

backup() {
    local src="$1"
    local dst="${BACKUP_DIR}/$(basename "$src").bak"
    [ -f "$src" ] && cp -p "$src" "$dst" && note "Backup: $src → $dst"
}

# ════════════════════════════════════════════════════════════════════
weaken() {
    require_root --weaken
    mkdir -p "$BACKUP_DIR"
    echo "${BOLD}demo_weaken.sh — rezim slabljenja${R}"
    echo "Backup direktorijum: $BACKUP_DIR"

    # ── 1. Backdoor korisnik sa uid=0 ───────────────────────────────
    step "1. Kreiranje korisnika '$DEMO_USER' sa uid=0 (backdoor)"
    if id "$DEMO_USER" &>/dev/null; then
        note "Korisnik '$DEMO_USER' vec postoji — preskacem kreiranje."
    else
        useradd -m -s /bin/bash "$DEMO_USER"
        echo "${DEMO_USER}:demo1234" | chpasswd
        done_ "Korisnik '$DEMO_USER' kreiran sa lozinkom 'demo1234'."
    fi
    # Sacuvati originalni passwd pre izmene
    backup /etc/passwd
    # Postaviti uid=0 direktnom izmenom (usermod ne dozvoljava uid=0)
    sed -i "s/^${DEMO_USER}:x:[0-9]*:[0-9]*:/${DEMO_USER}:x:0:0:/" /etc/passwd
    done_ "'$DEMO_USER' sada ima uid=0."

    # ── 2. Servisni nalog sa interaktivnim shellom ───────────────────
    step "2. Dodela bash shella korisniku 'www-data'"
    backup /etc/passwd   # vec backupovan gore, ali ostavljamo radi jasnoce
    usermod -s /bin/bash www-data 2>/dev/null || {
        note "'www-data' ne postoji — koristim 'nobody' umesto toga."
        usermod -s /bin/bash nobody
    }
    done_ "'www-data' (ili 'nobody') sada ima /bin/bash shell."

    # ── 3. Slaba politika lozinki (login.defs) ──────────────────────
    step "3. Slabljenje /etc/login.defs (PASS_MAX_DAYS, PASS_MIN_DAYS)"
    backup /etc/login.defs
    sed -i 's/^\(PASS_MAX_DAYS\s*\).*/\199999/' /etc/login.defs
    sed -i 's/^\(PASS_MIN_DAYS\s*\).*/\10/'     /etc/login.defs
    sed -i 's/^\(PASS_WARN_AGE\s*\).*/\10/'     /etc/login.defs
    done_ "PASS_MAX_DAYS=99999, PASS_MIN_DAYS=0, PASS_WARN_AGE=0."

    # ── 4. Onemogucavanje pam_faillock ──────────────────────────────
    step "4. Onemogucavanje zakljucavanja naloga (pam_faillock)"
    local pam_auth="/etc/pam.d/common-auth"
    if [ -f "$pam_auth" ]; then
        backup "$pam_auth"
        # Zakomentarisati sve pam_faillock i pam_tally2 linije
        sed -i 's/^\([^#].*pam_faillock\)/# \1/' "$pam_auth"
        sed -i 's/^\([^#].*pam_tally2\)/# \1/'   "$pam_auth"
        done_ "pam_faillock/pam_tally2 linije zakomentarisane u $pam_auth."
    else
        note "$pam_auth nije pronadjen — pam_faillock verovatno vec nije konfigurisan."
    fi

    # ── 5. NOPASSWD sudo pravilo ─────────────────────────────────────
    step "5. Dodavanje NOPASSWD sudo pravila za '$DEMO_USER'"
    cat > "$DEMO_SUDOERS" <<EOF
# DEMO: namerno slaba sudo konfiguracija
${DEMO_USER} ALL=(ALL) NOPASSWD: ALL
${DEMO_USER} ALL=(ALL) /usr/bin/vim, /usr/bin/find, /usr/bin/python3
EOF
    chmod 0440 "$DEMO_SUDOERS"
    done_ "Kreiran $DEMO_SUDOERS sa NOPASSWD i opasnim komandama."

    # ── 6. /etc/securetty — dozvola direktnog root logina ───────────
    step "6. Dodavanje terminala u /etc/securetty"
    backup /etc/securetty 2>/dev/null || true
    # Na modernom Ubuntuu fajl mozda ne postoji — kreirati ga
    printf 'tty1\ntty2\ntty3\n' >> /etc/securetty
    done_ "tty1, tty2, tty3 dodati u /etc/securetty."

    # ── Rezime ───────────────────────────────────────────────────────
    echo
    echo "${BOLD}${cRED}════ Slabljenje zavrseno ════${R}"
    echo "Pokrenuti users_check.sh da se vide pronadjene slabosti:"
    echo "  sudo bash users_check.sh"
    echo
    echo "Za restore: sudo bash $0 --restore"
    echo
}

# ════════════════════════════════════════════════════════════════════
restore() {
    require_root --restore
    echo "${BOLD}demo_weaken.sh — rezim obnavljanja${R}"

    if [ ! -d "$BACKUP_DIR" ]; then
        fail "Backup direktorijum '$BACKUP_DIR' ne postoji. Da li je --weaken pokrenut?"
        exit 1
    fi

    # ── 1. Ukloniti backdoor korisnika ──────────────────────────────
    step "1. Brisanje korisnika '$DEMO_USER'"
    if id "$DEMO_USER" &>/dev/null; then
        userdel -r "$DEMO_USER" 2>/dev/null || userdel "$DEMO_USER"
        done_ "Korisnik '$DEMO_USER' obrisan."
    else
        note "Korisnik '$DEMO_USER' ne postoji — preskacem."
    fi

    # ── 2. Restore /etc/passwd ───────────────────────────────────────
    step "2. Obnavljanje /etc/passwd"
    if [ -f "${BACKUP_DIR}/passwd.bak" ]; then
        cp -p "${BACKUP_DIR}/passwd.bak" /etc/passwd
        done_ "/etc/passwd obnovljen iz backupa."
    else
        note "Backup /etc/passwd nije pronadjen — rucno vratiti shell za www-data/nobody."
        usermod -s /usr/sbin/nologin www-data 2>/dev/null || true
        usermod -s /usr/sbin/nologin nobody   2>/dev/null || true
    fi

    # ── 3. Restore /etc/login.defs ───────────────────────────────────
    step "3. Obnavljanje /etc/login.defs"
    if [ -f "${BACKUP_DIR}/login.defs.bak" ]; then
        cp -p "${BACKUP_DIR}/login.defs.bak" /etc/login.defs
        done_ "/etc/login.defs obnovljen iz backupa."
    else
        note "Backup login.defs nije pronadjen."
    fi

    # ── 4. Restore PAM common-auth ───────────────────────────────────
    step "4. Obnavljanje /etc/pam.d/common-auth"
    if [ -f "${BACKUP_DIR}/common-auth.bak" ]; then
        cp -p "${BACKUP_DIR}/common-auth.bak" /etc/pam.d/common-auth
        done_ "/etc/pam.d/common-auth obnovljen iz backupa."
    else
        note "Backup common-auth nije pronadjen — preskacem."
    fi

    # ── 5. Ukloniti demo sudoers fajl ────────────────────────────────
    step "5. Brisanje $DEMO_SUDOERS"
    if [ -f "$DEMO_SUDOERS" ]; then
        rm -f "$DEMO_SUDOERS"
        done_ "$DEMO_SUDOERS obrisan."
    else
        note "$DEMO_SUDOERS ne postoji — preskacem."
    fi

    # ── 6. Restore /etc/securetty ────────────────────────────────────
    step "6. Obnavljanje /etc/securetty"
    if [ -f "${BACKUP_DIR}/securetty.bak" ]; then
        cp -p "${BACKUP_DIR}/securetty.bak" /etc/securetty
        done_ "/etc/securetty obnovljen iz backupa."
    else
        # Fajl nije postojao pre — ukloniti dodane linije
        sed -i '/^tty[0-9]/d' /etc/securetty 2>/dev/null || true
        done_ "Dodane tty linije uklonjene iz /etc/securetty."
    fi

    # ── Ciscenje backupa ─────────────────────────────────────────────
    step "Brisanje backup direktorijuma"
    rm -rf "$BACKUP_DIR"
    done_ "$BACKUP_DIR obrisan."

    echo
    echo "${BOLD}${cGRN}════ Obnavljanje zavrseno ════${R}"
    echo
}

# ════════════════════════════════════════════════════════════════════
case "${1:-}" in
    --weaken)  weaken ;;
    --restore) restore ;;
    *)
        echo "Upotreba: sudo bash $0 [--weaken | --restore]"
        echo
        echo "  --weaken   Namerno slabi bezbednost sistema radi demonstracije."
        echo "  --restore  Vraca sve promene u prethodno stanje."
        exit 1
        ;;
esac
