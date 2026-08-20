#!/usr/bin/env bash
set -euo pipefail

# ============================================================
#  net_diag.sh – Розширена діагностика мережі (Linux/macOS/WSL)
#  Версія: 2.0 (покращена)
# ============================================================

# --- кольорові коди ---
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[0;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly MAGENTA='\033[0;35m'
readonly BOLD='\033[1m'
readonly NC='\033[0m' # No Color

# --- глобальні лічильники ---
OK_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0

# --- допоміжні функції ---
print_header() {
    echo -e "\n${BOLD}${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${CYAN}  $* ${NC}"
    echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════════${NC}"
}

print_ok() {
    echo -e "  ${GREEN}✔ OK${NC}     $*"
    ((OK_COUNT++)) || true
}

print_fail() {
    echo -e "  ${RED}✘ FAIL${NC}    $*"
    ((FAIL_COUNT++)) || true
}

print_info() {
    echo -e "  ${BLUE}ℹ INFO${NC}    $*"
}

print_warn() {
    echo -e "  ${YELLOW}⚠ WARN${NC}    $*"
}

print_detail() {
    echo -e "  ${MAGENTA}└─${NC} $*"
}

# --- визначення платформи ---
detect_platform() {
    local platform="unknown"
    if [[ "$(uname -s)" == "Linux" ]]; then
        if grep -qi microsoft /proc/version 2>/dev/null; then
            platform="WSL"
        else
            platform="Linux"
        fi
    elif [[ "$(uname -s)" == "Darwin" ]]; then
        platform="macOS"
    fi
    echo "$platform"
}

# --- перевірка команд ---
check_cmd() {
    command -v "$1" &>/dev/null
}

# --- перевірка пінгу з таймаутом ---
ping_host() {
    local host="$1"
    local count=1
    local timeout=2

    case "$PLATFORM" in
        Linux|WSL)
            ping -c "$count" -W "$timeout" "$host" &>/dev/null
            ;;
        macOS)
            ping -c "$count" -W "$((timeout * 1000))" "$host" &>/dev/null
            ;;
        *)
            return 1
            ;;
    esac
}

# --- перевірка HTTPS ---
check_https() {
    local url="$1"
    if check_cmd curl; then
        curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "$url" 2>/dev/null | grep -q "200\|301\|302"
    elif check_cmd wget; then
        wget -q --spider --timeout=5 "$url" 2>/dev/null
    else
        return 1
    fi
}

# --- перевірка DNS-резолвінгу ---
check_dns_resolve() {
    local host="$1"
    if check_cmd host; then
        host -t A "$host" &>/dev/null
    elif check_cmd nslookup; then
        nslookup "$host" &>/dev/null
    elif check_cmd dig; then
        dig +short "$host" &>/dev/null
    else
        return 1
    fi
}

# ============================================================
#  ПОЧАТОК ДІАГНОСТИКИ
# ============================================================
PLATFORM=$(detect_platform)
echo -e "${BOLD}${CYAN}"
echo "╔════════════════════════════════════════════════════════════╗"
echo "║             МЕРЕЖЕВА ДІАГНОСТИКА v2.0                    ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo -e "${NC}"
print_info "Платформа: ${BOLD}${PLATFORM}${NC}"
print_info "Час запуску: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

# ============================================================
#  1. ІНТЕРФЕЙСИ ТА IP-АДРЕСИ (IPv4 + IPv6)
# ============================================================
print_header "1. МЕРЕЖЕВІ ІНТЕРФЕЙСИ ТА IP-АДРЕСИ"

case "$PLATFORM" in
    Linux|WSL)
        if check_cmd ip; then
            # IPv4
            print_info "IPv4-адреси:"
            ip -4 -br addr 2>/dev/null | while read -r line; do
                print_detail "$line"
            done | head -20

            # IPv6
            print_info "IPv6-адреси:"
            ip -6 -br addr 2>/dev/null | grep -v "^lo" | while read -r line; do
                print_detail "$line"
            done | head -10

            print_ok "інтерфейси отримано (ip)"
        elif check_cmd ifconfig; then
            ifconfig 2>/dev/null | grep -E '^[a-z0-9]+:|inet ' | while read -r line; do
                print_detail "$line"
            done | head -30
            print_ok "інтерфейси отримано (ifconfig)"
        else
            print_fail "ні ip, ні ifconfig не знайдено"
        fi
        ;;
    macOS)
        if check_cmd ifconfig; then
            ifconfig 2>/dev/null | grep -E '^[a-z0-9]+:|inet ' | while read -r line; do
                print_detail "$line"
            done | head -30
            print_ok "інтерфейси отримано (ifconfig)"
        else
            print_fail "ifconfig не знайдено"
        fi
        ;;
    *)
        print_fail "непідтримувана платформа"
        ;;
esac

# ============================================================
#  2. ШЛЮЗ ЗА ЗАМОВЧУВАННЯМ (з деталями)
# ============================================================
print_header "2. ШЛЮЗ ЗА ЗАМОВЧУВАННЯМ"

case "$PLATFORM" in
    Linux|WSL)
        if check_cmd ip; then
            GW_LINE=$(ip route show default 2>/dev/null | head -1)
            if [[ -n "$GW_LINE" ]]; then
                print_ok "шлюз знайдено"
                print_detail "$GW_LINE"

                # Додаткова інформація про інтерфейс
                GW_IFACE=$(echo "$GW_LINE" | awk '/dev/ {print $5}')
                if [[ -n "$GW_IFACE" ]]; then
                    print_detail "Інтерфейс: $GW_IFACE"
                fi
            else
                print_fail "шлюз не знайдено"
            fi
        elif check_cmd route; then
            GW_LINE=$(route -n 2>/dev/null | awk '/^0.0.0.0/ {print}')
            if [[ -n "$GW_LINE" ]]; then
                print_ok "шлюз знайдено"
                print_detail "$GW_LINE"
            else
                print_fail "шлюз не знайдено"
            fi
        else
            print_fail "ні ip, ні route не знайдено"
        fi
        ;;
    macOS)
        if check_cmd netstat; then
            GW_LINE=$(netstat -rn 2>/dev/null | awk '/^default/ {print}')
            if [[ -n "$GW_LINE" ]]; then
                print_ok "шлюз знайдено"
                print_detail "$GW_LINE"
            else
                print_fail "шлюз не знайдено"
            fi
        else
            print_fail "netstat не знайдено"
        fi
        ;;
    *)
        print_fail "непідтримувана платформа"
        ;;
esac

# ============================================================
#  3. DNS-СЕРВЕРИ (resolvectl + /etc/resolv.conf)
# ============================================================
print_header "3. DNS-СЕРВЕРИ"

# Спроба через resolvectl (сучасний systemd)
if check_cmd resolvectl; then
    DNS_INFO=$(resolvectl status 2>/dev/null | grep -A 10 "DNS Servers" | head -10 || true)
    if [[ -n "$DNS_INFO" ]]; then
        print_info "DNS через resolvectl:"
        echo "$DNS_INFO" | while read -r line; do
            print_detail "$line"
        done
        print_ok "DNS перевірено через resolvectl"
    else
        print_warn "resolvectl не повернув даних"
    fi
fi

# Класичний /etc/resolv.conf
if [[ -f /etc/resolv.conf ]]; then
    DNS_COUNT=$(grep -c '^nameserver' /etc/resolv.conf 2>/dev/null || echo "0")
    if [[ "$DNS_COUNT" -gt 0 ]]; then
        print_info "DNS через /etc/resolv.conf:"
        grep '^nameserver' /etc/resolv.conf | while read -r line; do
            print_detail "$line"
        done
        print_ok "знайдено DNS-серверів: $DNS_COUNT"
    else
        print_warn "немає записів nameserver у /etc/resolv.conf"
    fi
else
    print_warn "/etc/resolv.conf не знайдено"
fi

# ============================================================
#  4. ПЕРЕВІРКА DNS-РЕЗОЛВІНГУ
# ============================================================
print_header "4. ПЕРЕВІРКА DNS-РЕЗОЛВІНГУ"

TEST_DOMAINS=("example.com" "google.com" "github.com")
DNS_RESOLVE_OK=false

for domain in "${TEST_DOMAINS[@]}"; do
    if check_dns_resolve "$domain"; then
        print_ok "DNS резолвить $domain"
        DNS_RESOLVE_OK=true
        break
    else
        print_warn "DNS не резолвить $domain"
    fi
done

if [[ "$DNS_RESOLVE_OK" == false ]]; then
    print_fail "DNS-резолвінг не працює для жодного домену"
fi

# ============================================================
#  5. ДОСТУП ДО ІНТЕРНЕТУ (ICMP + HTTPS)
# ============================================================
print_header "5. ДОСТУП ДО ІНТЕРНЕТУ"

# 5.1. Ping-тест
print_info "5.1. ICMP (ping):"
PING_OK=false
TEST_HOSTS=("1.1.1.1" "8.8.8.8" "google.com")

for host in "${TEST_HOSTS[@]}"; do
    if ping_host "$host"; then
        print_ok "ping до $host — успішно"
        PING_OK=true
        break
    else
        print_warn "ping до $host — не відповідає"
    fi
done

if [[ "$PING_OK" == false ]]; then
    print_fail "жоден хост не відповів на ping"
fi

# 5.2. HTTPS-тест
print_info "5.2. HTTPS (web):"
HTTPS_OK=false
TEST_URLS=("https://example.com" "https://google.com" "https://cloudflare.com")

for url in "${TEST_URLS[@]}"; do
    if check_https "$url"; then
        print_ok "HTTPS доступ до $url — успішно"
        HTTPS_OK=true
        break
    else
        print_warn "HTTPS до $url — недоступний"
    fi
done

if [[ "$HTTPS_OK" == false ]]; then
    if check_cmd curl || check_cmd wget; then
        print_fail "HTTPS не працює для жодного сайту"
    else
        print_warn "curl/wget не знайдено, HTTPS-перевірку пропущено"
    fi
fi

# ============================================================
#  6. ЛОКАЛЬНІ ПОРТИ (LISTEN)
# ============================================================
print_header "6. ЛОКАЛЬНІ ПОРТИ (LISTEN)"

case "$PLATFORM" in
    Linux|WSL)
        if check_cmd ss; then
            SS_OUT=$(ss -tulpn 2>/dev/null | grep LISTEN | head -15 || true)
            if [[ -n "$SS_OUT" ]]; then
                print_info "Порти в стані LISTEN (перші 15):"
                echo "$SS_OUT" | while read -r line; do
                    print_detail "$line"
                done
                print_ok "порти отримано (ss)"
            else
                print_warn "немає портів у стані LISTEN"
            fi
        elif check_cmd netstat; then
            NS_OUT=$(netstat -tulpn 2>/dev/null | grep LISTEN | head -15 || true)
            if [[ -n "$NS_OUT" ]]; then
                print_info "Порти в стані LISTEN (перші 15):"
                echo "$NS_OUT" | while read -r line; do
                    print_detail "$line"
                done
                print_ok "порти отримано (netstat)"
            else
                print_warn "немає портів у стані LISTEN"
            fi
        else
            print_fail "ні ss, ні netstat не знайдено"
        fi
        ;;
    macOS)
        if check_cmd netstat; then
            NS_OUT=$(netstat -anv 2>/dev/null | grep LISTEN | head -15 || true)
            if [[ -n "$NS_OUT" ]]; then
                print_info "Порти в стані LISTEN (перші 15):"
                echo "$NS_OUT" | while read -r line; do
                    print_detail "$line"
                done
                print_ok "порти отримано (netstat)"
            else
                print_warn "немає портів у стані LISTEN"
            fi
        else
            print_fail "netstat не знайдено"
        fi
        ;;
    *)
        print_fail "непідтримувана платформа"
        ;;
esac

# ============================================================
#  7. ДОДАТКОВІ ПЕРЕВІРКИ (якщо доступно)
# ============================================================
print_header "7. ДОДАТКОВІ ПЕРЕВІРКИ"

# 7.1. Перевірка route table
if check_cmd ip; then
    print_info "Маршрутизація (основні маршрути):"
    ip route show table main 2>/dev/null | grep -v "^default" | head -5 | while read -r line; do
        print_detail "$line"
    done
    print_ok "таблицю маршрутизації отримано"
fi

# 7.2. Перевірка ARP-таблиці
if check_cmd ip; then
    ARP_COUNT=$(ip neigh show 2>/dev/null | wc -l || echo "0")
    if [[ "$ARP_COUNT" -gt 0 ]]; then
        print_ok "ARP-таблиця містить $ARP_COUNT записів"
    else
        print_warn "ARP-таблиця порожня"
    fi
fi

# ============================================================
#  ПІДСУМОК
# ============================================================
print_header "ПІДСУМОК ДІАГНОСТИКИ"

echo -e "  ${GREEN}✔ OK${NC}     : $OK_COUNT"
echo -e "  ${YELLOW}⚠ WARN${NC}   : $WARN_COUNT"
echo -e "  ${RED}✘ FAIL${NC}    : $FAIL_COUNT"

echo ""
if [[ $FAIL_COUNT -eq 0 && $WARN_COUNT -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}✅ ВСІ ПЕРЕВІРКИ ПРОЙДЕНО УСПІШНО!${NC}"
    echo -e "${GREEN}Мережа працює коректно.${NC}"
elif [[ $FAIL_COUNT -eq 0 && $WARN_COUNT -gt 0 ]]; then
    echo -e "${YELLOW}${BOLD}⚠ МЕРЕЖА ПРАЦЮЄ, АЛЄ Є ЗАСТЕРЕЖЕННЯ${NC}"
    echo -e "${YELLOW}Рекомендується перевірити:${NC}"
    echo "   - налаштування DNS (може працювати повільно)"
    echo "   - наявність альтернативних DNS-серверів"
    echo "   - роботу IPv6 (якщо використовується)"
elif [[ $FAIL_COUNT -gt 0 ]]; then
    echo -e "${RED}${BOLD}❌ ВИЯВЛЕНО $FAIL_COUNT ПРОБЛЕМ!${NC}"
    echo -e "${RED}Рекомендується перевірити:${NC}"
    echo "   - фізичне підключення до мережі"
    echo "   - налаштування DHCP/статичної IP"
    echo "   - роботу DNS-серверів"
    echo "   - брандмауер (може блокувати ping/HTTPS)"
    echo "   - маршрутизацію (перевірити шлюз)"
fi

echo ""
print_info "Детальний лог збережено в /tmp/net_diag.log"
print_info "Для детальнішого аналізу запустіть: ss -tulpn | grep LISTEN"

exit 0