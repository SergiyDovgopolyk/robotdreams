#!/usr/bin/env bash
# set -euo pipefail - ТИМЧАСОВО ВИМКНЕНО для діагностики
set -uo pipefail

# ============================================================
#  cis_check.sh – Спрощений CIS Checklist (Linux)
#  Версія: 2.1 (виправлена ShellCheck)
# ============================================================

# --- кольорові коди ---
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[0;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly MAGENTA='\033[0;35m'
readonly BOLD='\033[1m'
readonly NC='\033[0m'

# --- глобальні лічильники ---
PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0

# --- допоміжні функції ---
print_header() {
    echo -e "\n${BOLD}${CYAN}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${CYAN}║  $* ${NC}"
    echo -e "${BOLD}${CYAN}╚═══════════════════════════════════════════════════════════╝${NC}"
}

print_pass() {
    echo -e "  ${GREEN}✅ PASS${NC}    $*"
    ((PASS_COUNT++)) || true
}

print_fail() {
    echo -e "  ${RED}❌ FAIL${NC}    $*"
    ((FAIL_COUNT++)) || true
}

print_warn() {
    echo -e "  ${YELLOW}⚠ WARN${NC}    $*"
    ((WARN_COUNT++)) || true
}

print_info() {
    echo -e "  ${BLUE}ℹ INFO${NC}    $*"
}

print_detail() {
    echo -e "  ${MAGENTA}└─${NC} $*"
}

# --- безпечне отримання значень ---
safe_grep() {
    grep "$@" 2>/dev/null || true
}

safe_awk() {
    awk "$@" 2>/dev/null || true
}

# --- перевірка команд ---
check_cmd() {
    command -v "$1" &>/dev/null
}

# ============================================================
#  ПОЧАТОК ПЕРЕВІРКИ
# ============================================================
echo -e "${BOLD}${CYAN}"
echo "╔════════════════════════════════════════════════════════════╗"
echo "║         СПРОЩЕНИЙ CIS CHECKLIST v2.1                      ║"
echo "║         Перевірка базової безпеки Linux                   ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

print_info "Час запуску: $(date '+%Y-%m-%d %H:%M:%S')"
print_info "Користувач: $(whoami)"
echo ""

# Перевірка прав
if [[ $EUID -eq 0 ]]; then
    print_info "Запущено від root ✓"
else
    print_warn "Запущено від звичайного користувача (деякі перевірки можуть бути неповними)"
fi

# ============================================================
#  1. ПАРОЛЬНА ПОЛІТИКА
# ============================================================
print_header "1. ПАРОЛЬНА ПОЛІТИКА"

print_info "Перевірка налаштувань паролів у /etc/login.defs:"

if [[ -f /etc/login.defs ]]; then
    # Мінімальна довжина
    MIN_LEN=$(safe_grep -E "^PASS_MIN_LEN" /etc/login.defs | safe_awk '{print $2}')
    if [[ -z "$MIN_LEN" ]]; then
        MIN_LEN="0"
    fi

    if [[ "$MIN_LEN" -ge 8 ]]; then
        print_pass "Мінімальна довжина пароля: $MIN_LEN (>=8)"
    else
        print_fail "Мінімальна довжина пароля: $MIN_LEN (<8)"
        print_detail "Виправте: sudo nano /etc/login.defs → PASS_MIN_LEN 8"
    fi

    # Максимальний вік
    MAX_DAYS=$(safe_grep -E "^PASS_MAX_DAYS" /etc/login.defs | safe_awk '{print $2}')
    if [[ -z "$MAX_DAYS" ]]; then
        MAX_DAYS="99999"
    fi

    if [[ "$MAX_DAYS" -le 90 ]]; then
        print_pass "Максимальний вік пароля: $MAX_DAYS днів (<=90)"
    else
        print_fail "Максимальний вік пароля: $MAX_DAYS днів (>90)"
        print_detail "Виправте: sudo nano /etc/login.defs → PASS_MAX_DAYS 90"
    fi

    # Мінімальний вік
    MIN_DAYS=$(safe_grep -E "^PASS_MIN_DAYS" /etc/login.defs | safe_awk '{print $2}')
    if [[ -z "$MIN_DAYS" ]]; then
        MIN_DAYS="0"
    fi

    if [[ "$MIN_DAYS" -ge 7 ]]; then
        print_pass "Мінімальний вік пароля: $MIN_DAYS днів (>=7)"
    else
        print_warn "Мінімальний вік пароля: $MIN_DAYS днів (<7)"
        print_detail "Рекомендується: PASS_MIN_DAYS 7"
    fi

    # Попередження
    WARN_AGE=$(safe_grep -E "^PASS_WARN_AGE" /etc/login.defs | safe_awk '{print $2}')
    if [[ -z "$WARN_AGE" ]]; then
        WARN_AGE="0"
    fi

    if [[ "$WARN_AGE" -ge 7 ]]; then
        print_pass "Попередження за $WARN_AGE днів до закінчення терміну"
    else
        print_warn "Попередження за $WARN_AGE днів (<7)"
        print_detail "Рекомендується: PASS_WARN_AGE 7"
    fi
else
    print_fail "/etc/login.defs не знайдено"
fi

# Перевірка PAM
print_info "Перевірка модулів PAM (pam_pwquality.so):"

PAM_FOUND=false
for pam_file in /etc/pam.d/common-password /etc/pam.d/system-auth /etc/pam.d/passwd; do
    if [[ -f "$pam_file" ]] && safe_grep -q "pam_pwquality.so" "$pam_file"; then
        print_pass "Модуль pam_pwquality.so налаштовано ($pam_file)"
        PAM_FOUND=true
        break
    fi
done

if [[ "$PAM_FOUND" == false ]]; then
    print_warn "Модуль pam_pwquality.so не налаштовано"
    print_detail "Встановіть: sudo apt install libpam-pwquality"
fi

# Користувачі без пароля
print_info "Перевірка користувачів без пароля:"
if [[ -f /etc/shadow ]]; then
    USERS_NO_PASS=$(safe_grep -E '^[^:]+::' /etc/shadow | cut -d: -f1 | head -5)
    if [[ -n "$USERS_NO_PASS" ]]; then
        print_fail "Знайдено користувачів без пароля:"
        echo "$USERS_NO_PASS" | while read -r user; do
            print_detail "$user"
        done
    else
        print_pass "Користувачів без пароля не знайдено"
    fi
fi

# ============================================================
#  2. ФАЄРВОЛ
# ============================================================
print_header "2. ФАЄРВОЛ (UFW)"

if check_cmd ufw; then
    UFW_STATUS=$(ufw status 2>/dev/null | safe_grep -i "Status:" | safe_awk '{print $2}')
    if [[ "$UFW_STATUS" == "active" ]]; then
        print_pass "UFW активний"
        UFW_RULES=$(ufw status numbered 2>/dev/null | safe_grep -E "^\[[0-9]+\]" | wc -l)
        print_detail "Кількість правил: $UFW_RULES"
    else
        print_fail "UFW не активний"
        print_detail "Увімкнути: sudo ufw enable"
    fi
else
    print_warn "UFW не встановлено"

    # Альтернативи
    if check_cmd iptables; then
        IPTABLES_RULES=$(iptables -L 2>/dev/null | safe_grep -c "Chain" || echo "0")
        if [[ "$IPTABLES_RULES" -gt 0 ]]; then
            print_info "Використовується iptables ($IPTABLES_RULES правил)"
        fi
    fi

    if check_cmd firewalld; then
        if systemctl is-active --quiet firewalld 2>/dev/null; then
            print_info "Використовується firewalld (активний)"
        fi
    fi
fi

# ============================================================
#  3. SSH НАЛАШТУВАННЯ
# ============================================================
print_header "3. SSH НАЛАШТУВАННЯ"

SSH_CONFIG="/etc/ssh/sshd_config"
if [[ -f "$SSH_CONFIG" ]]; then
    # 3.1. Заборона рутового входу
    print_info "Перевірка рутового входу через SSH:"
    PERMIT_ROOT=$(safe_grep -E "^PermitRootLogin" "$SSH_CONFIG" | safe_awk '{print $2}')

    if [[ "$PERMIT_ROOT" == "no" ]]; then
        print_pass "Рутовий вхід через SSH заборонено"
    elif [[ "$PERMIT_ROOT" == "prohibit-password" ]] || [[ "$PERMIT_ROOT" == "without-password" ]]; then
        print_pass "Рутовий вхід через SSH лише з ключами"
    elif [[ "$PERMIT_ROOT" == "yes" ]]; then
        print_fail "Рутовий вхід через SSH дозволено!"
        print_detail "Виправте: PermitRootLogin no"
    else
        print_warn "PermitRootLogin не налаштовано (за замовчуванням: yes)"
        print_detail "Додайте: PermitRootLogin no"
    fi

    # 3.2. Автентифікація за ключами
    PUBKEY_AUTH=$(safe_grep -E "^PubkeyAuthentication" "$SSH_CONFIG" | safe_awk '{print $2}')
    if [[ "$PUBKEY_AUTH" == "yes" ]]; then
        print_pass "Автентифікація за SSH-ключами увімкнена"
    else
        print_warn "PubkeyAuthentication не налаштовано або вимкнено"
    fi

    # 3.3. Парольна автентифікація
    PASSWORD_AUTH=$(safe_grep -E "^PasswordAuthentication" "$SSH_CONFIG" | safe_awk '{print $2}')
    if [[ "$PASSWORD_AUTH" == "no" ]]; then
        print_pass "Парольна автентифікація вимкнена"
    elif [[ "$PASSWORD_AUTH" == "yes" ]]; then
        print_warn "Парольна автентифікація увімкнена (рекомендується вимкнути)"
    else
        print_warn "PasswordAuthentication не налаштовано"
    fi

    # 3.4. Порт SSH
    SSH_PORT=$(safe_grep -E "^Port" "$SSH_CONFIG" | safe_awk '{print $2}')
    if [[ -n "$SSH_PORT" && "$SSH_PORT" != "22" ]]; then
        print_pass "SSH використовує нестандартний порт: $SSH_PORT"
    else
        print_warn "SSH використовує стандартний порт 22"
        print_detail "Рекомендується змінити на нестандартний"
    fi
else
    print_warn "Файл $SSH_CONFIG не знайдено (SSH не встановлено?)"
fi

# ============================================================
#  4. АВТОМАТИЧНІ ОНОВЛЕННЯ
# ============================================================
print_header "4. АВТОМАТИЧНІ ОНОВЛЕННЯ"

# 4.1. unattended-upgrades (Debian/Ubuntu)
if check_cmd unattended-upgrades; then
    if systemctl is-active --quiet unattended-upgrades 2>/dev/null; then
        print_pass "unattended-upgrades активний"

        if [[ -f /etc/apt/apt.conf.d/20auto-upgrades ]]; then
            UPDATE_LIST=$(safe_grep "APT::Periodic::Update-Package-Lists" /etc/apt/apt.conf.d/20auto-upgrades | safe_awk '{print $3}' | tr -d ';')
            UPGRADE=$(safe_grep "APT::Periodic::Unattended-Upgrade" /etc/apt/apt.conf.d/20auto-upgrades | safe_awk '{print $3}' | tr -d ';')
            print_detail "Оновлення списку пакетів: $UPDATE_LIST"
            print_detail "Автоматичне оновлення: $UPGRADE"
        fi
    else
        print_warn "unattended-upgrades встановлено, але не активний"
        print_detail "Активувати: sudo systemctl enable --now unattended-upgrades"
    fi
else
    print_warn "unattended-upgrades не встановлено"
    print_detail "Встановити: sudo apt install unattended-upgrades"

    # Перевірка dnf-automatic (Fedora/RHEL)
    if check_cmd dnf-automatic; then
        if systemctl is-active --quiet dnf-automatic.timer 2>/dev/null; then
            print_pass "dnf-automatic активний"
        fi
    fi
fi

# 4.2. Останні оновлення
if [[ -f /var/log/apt/history.log ]]; then
    LAST_UPGRADE=$(safe_grep "Start-Date:" /var/log/apt/history.log | tail -1 | cut -d' ' -f2-)
    if [[ -n "$LAST_UPGRADE" ]]; then
        print_info "Останнє оновлення: $LAST_UPGRADE"
    fi
fi

# ============================================================
#  5. БЛОКУВАННЯ ОБЛІКОВОГО ЗАПИСУ
# ============================================================
print_header "5. ПОЛІТИКА БЛОКУВАННЯ ОБЛІКОВОГО ЗАПИСУ"

# 5.1. fail2ban
if check_cmd fail2ban-client; then
    if systemctl is-active --quiet fail2ban 2>/dev/null; then
        print_pass "fail2ban активний"
        JAILS=$(fail2ban-client status 2>/dev/null | safe_grep "Number of jail" | safe_awk '{print $5}' || echo "0")
        print_detail "Активних джейлів: $JAILS"
    else
        print_warn "fail2ban встановлено, але не активний"
        print_detail "Активувати: sudo systemctl enable --now fail2ban"
    fi
else
    print_warn "fail2ban не встановлено"
    print_detail "Встановити: sudo apt install fail2ban"
fi

# 5.2. pam_tally2
print_info "Перевірка pam_tally2:"
PAM_TALLY_FOUND=false
for pam_file in /etc/pam.d/common-auth /etc/pam.d/system-auth; do
    if [[ -f "$pam_file" ]] && safe_grep -q "pam_tally2.so" "$pam_file"; then
        print_pass "pam_tally2 налаштовано ($pam_file)"
        DENY=$(safe_grep "pam_tally2.so" "$pam_file" | safe_grep -o "deny=[0-9]*" | head -1 | cut -d= -f2)
        [[ -n "$DENY" ]] && print_detail "Блокування після $DENY спроб"
        PAM_TALLY_FOUND=true
        break
    fi
done

if [[ "$PAM_TALLY_FOUND" == false ]]; then
    print_warn "pam_tally2 не налаштовано"
fi

# ============================================================
#  6. ДОДАТКОВІ ПЕРЕВІРКИ
# ============================================================
print_header "6. ДОДАТКОВІ ПЕРЕВІРКИ"

# 6.1. Оновлення системи
print_info "Перевірка оновлень системи:"
if [[ -f /etc/os-release ]]; then
    OS_NAME=$(safe_grep "^PRETTY_NAME" /etc/os-release | cut -d'"' -f2)
    print_detail "ОС: $OS_NAME"
fi

if check_cmd apt; then
    UPDATES=$(apt list --upgradable 2>/dev/null | safe_grep -c "upgradable" || echo "0")
    if [[ "$UPDATES" -gt 0 ]]; then
        print_warn "Доступно оновлень: $UPDATES"
        print_detail "Оновіть: sudo apt update && sudo apt upgrade"
    else
        print_pass "Система оновлена"
    fi
fi

# 6.2. Активні сесії
print_info "Активні сесії користувачів:"
WHO_OUT=$(who 2>/dev/null | head -5)
if [[ -n "$WHO_OUT" ]]; then
    echo "$WHO_OUT" | while read -r line; do
        print_detail "$line"
    done
else
    print_detail "Немає активних сесій"
fi

# ============================================================
#  ПІДСУМОК
# ============================================================
print_header "ПІДСУМОК ПЕРЕВІРКИ CIS"

echo -e "  ${GREEN}✅ PASS${NC}    : $PASS_COUNT"
echo -e "  ${YELLOW}⚠ WARN${NC}    : $WARN_COUNT"
echo -e "  ${RED}❌ FAIL${NC}    : $FAIL_COUNT"

echo ""
if [[ $FAIL_COUNT -eq 0 && $WARN_COUNT -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}✅ ВСІ ПЕРЕВІРКИ ПРОЙДЕНО УСПІШНО!${NC}"
elif [[ $FAIL_COUNT -eq 0 ]]; then
    echo -e "${YELLOW}${BOLD}⚠ Є ЗАСТЕРЕЖЕННЯ, АЛЕ КРИТИЧНИХ ПРОБЛЕМ НЕМАЄ${NC}"
else
    echo -e "${RED}${BOLD}❌ ВИЯВЛЕНО $FAIL_COUNT КРИТИЧНИХ ПРОБЛЕМ!${NC}"
    echo -e "${RED}Рекомендується негайно виправити:${NC}"
    echo "   1. Налаштувати парольну політику (/etc/login.defs)"
    echo "   2. Увімкнути фаєрвол (sudo ufw enable)"
    echo "   3. Заборонити рутовий вхід через SSH"
    echo "   4. Встановити автоматичні оновлення"
    echo "   5. Налаштувати fail2ban"
fi

echo ""
print_info "Рекомендовані команди для виправлення:"
echo "   sudo nano /etc/login.defs  # PASS_MIN_LEN 8, PASS_MAX_DAYS 90"
echo "   sudo ufw enable"
echo "   sudo nano /etc/ssh/sshd_config  # PermitRootLogin no"
echo "   sudo apt install unattended-upgrades fail2ban"
echo "   sudo systemctl enable --now unattended-upgrades fail2ban"

exit 0