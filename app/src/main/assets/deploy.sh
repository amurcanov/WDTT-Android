#!/bin/bash
# ==============================================================================
#  WDTT VPN Server — Универсальный установщик для VPS
#  Поддержка: Debian 11+, Ubuntu 20.04+, CentOS/RHEL/Fedora/AlmaLinux/Rocky
#  Версия: 3.0  |  Дата: 2026-04-01
#  NAT:  MASQUERADE (стандартный iptables, без Full Cone NAT)
#  WG:   порт 56001 (не конфликтует с существующим WG на 51820)
#  DTLS: порт 56000
# ==============================================================================
set -uo pipefail

readonly SCRIPT_VERSION="3.0"
readonly LOG_FILE="/var/log/wdtt-install.log"
readonly WG_PORT=56001
readonly DTLS_PORT=56000

# ─── Цвета ───────────────────────────────────────────────────────────────────
C_GREEN=''; C_YELLOW=''; C_RED=''
C_CYAN='';  C_BOLD='';      C_NC=''

log_info()  { echo -e "${C_GREEN}[✓]${C_NC} $*" | tee -a "$LOG_FILE"; }
log_warn()  { echo -e "${C_YELLOW}[!]${C_NC} $*" | tee -a "$LOG_FILE"; }
log_error() { echo -e "${C_RED}[✗]${C_NC} $*" | tee -a "$LOG_FILE"; }
log_step()  { echo -e "${C_CYAN}[►]${C_NC} ${C_BOLD}$*${C_NC}" | tee -a "$LOG_FILE"; }

die() { log_error "$*"; exit 1; }

prog() { echo "WDTT_PROGRESS|$1|$2"; }

# ─── Проверка root ────────────────────────────────────────────────────────────
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        die "Скрипт должен быть запущен от root! Используйте: sudo bash $0 $*"
    fi
}

# ─── Определение ОС ──────────────────────────────────────────────────────────
OS_ID="" ; PKG_MGR=""

detect_os() {
    log_step "Определение операционной системы..."
    if [ ! -f /etc/os-release ]; then
        die "Файл /etc/os-release не найден."
    fi
    . /etc/os-release
    OS_ID="${ID:-unknown}"
    case "$OS_ID" in
        ubuntu|debian|linuxmint|pop)     PKG_MGR="apt" ;;
        centos|rhel|rocky|almalinux|oracle) PKG_MGR="yum"
            command -v dnf &>/dev/null && PKG_MGR="dnf" ;;
        fedora)                          PKG_MGR="dnf" ;;
        arch|manjaro|endeavouros)        PKG_MGR="pacman" ;;
        *) die "Неподдерживаемый дистрибутив: $OS_ID" ;;
    esac
    log_info "ОС: ${PRETTY_NAME:-$OS_ID} | PM: $PKG_MGR"
}

# ─── Автоопределение WAN-интерфейса ──────────────────────────────────────────
detect_wan_interface() {
    local iface=""
    iface=$(ip route show default 2>/dev/null | head -1 | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}')
    [ -z "$iface" ] && iface=$(ip -4 addr show scope global 2>/dev/null | grep -oP '(?<=dev )\S+' | head -1)
    [ -z "$iface" ] && iface=$(ls /sys/class/net/ | grep -v lo | head -1)
    echo "$iface"
}

# ─── Определение доступного firewall-бэкенда ─────────────────────────────────
FW_BACKEND=""

detect_firewall() {
    if command -v iptables &>/dev/null; then
        FW_BACKEND="iptables"
    elif command -v nft &>/dev/null; then
        FW_BACKEND="nft"
    else
        log_warn "Ни iptables, ни nft не найдены. Пытаемся установить iptables..."
        case "$PKG_MGR" in
            apt)    apt-get install -y -qq iptables 2>>"$LOG_FILE" ;;
            dnf)    dnf install -y iptables 2>>"$LOG_FILE" ;;
            yum)    yum install -y iptables 2>>"$LOG_FILE" ;;
            pacman) pacman -Sy --noconfirm iptables 2>>"$LOG_FILE" ;;
        esac
        if command -v iptables &>/dev/null; then
            FW_BACKEND="iptables"
        else
            die "Не удалось установить iptables. Настройте firewall вручную."
        fi
    fi
    log_info "Firewall бэкенд: $FW_BACKEND"
}

# ─── Firewall-абстракция ─────────────────────────────────────────────────────
fw_add_input_udp() {
    local port="$1"
    case "$FW_BACKEND" in
        iptables)
            iptables -C INPUT -p udp --dport "$port" -j ACCEPT 2>/dev/null || \
                iptables -I INPUT -p udp --dport "$port" -j ACCEPT 2>/dev/null || true
            ;;
        nft)
            nft add rule inet filter input udp dport "$port" accept 2>/dev/null || true
            ;;
    esac
}

fw_add_input_tcp() {
    local port="$1"
    case "$FW_BACKEND" in
        iptables)
            iptables -C INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null || \
                iptables -I INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null || true
            ;;
        nft)
            nft add rule inet filter input tcp dport "$port" accept 2>/dev/null || true
            ;;
    esac
}

fw_add_input_udp_range() {
    local from="$1" to="$2"
    case "$FW_BACKEND" in
        iptables)
            iptables -C INPUT -p udp --dport "$from:$to" -j ACCEPT 2>/dev/null || \
                iptables -I INPUT -p udp --dport "$from:$to" -j ACCEPT 2>/dev/null || true
            ;;
        nft)
            nft add rule inet filter input udp dport "$from"-"$to" accept 2>/dev/null || true
            ;;
    esac
}

fw_add_forward() {
    case "$FW_BACKEND" in
        iptables)
            iptables -C FORWARD -j ACCEPT 2>/dev/null || \
                iptables -I FORWARD -j ACCEPT 2>/dev/null || true
            ;;
        nft)
            nft add rule inet filter forward accept 2>/dev/null || true
            ;;
    esac
}

fw_add_masquerade() {
    local iface="$1" subnet="$2"
    case "$FW_BACKEND" in
        iptables)
            iptables -t nat -C POSTROUTING -s "$subnet" -o "$iface" -j MASQUERADE 2>/dev/null || \
                iptables -t nat -A POSTROUTING -s "$subnet" -o "$iface" -j MASQUERADE 2>/dev/null || true
            ;;
        nft)
            nft add table nat 2>/dev/null || true
            nft add chain nat postrouting '{ type nat hook postrouting priority 100; }' 2>/dev/null || true
            nft add rule nat postrouting ip saddr "$subnet" oifname "$iface" masquerade 2>/dev/null || true
            ;;
    esac
}

fw_add_mss_clamping() {
    local subnet="$1"
    case "$FW_BACKEND" in
        iptables)
            # Применяем правило ТОЛЬКО к нашей подсети WDTT
            iptables -t mangle -C FORWARD -s "$subnet" -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || \
                iptables -t mangle -I FORWARD -s "$subnet" -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
            iptables -t mangle -C FORWARD -d "$subnet" -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || \
                iptables -t mangle -I FORWARD -d "$subnet" -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
            ;;
        nft)
            nft add table inet mangle 2>/dev/null || true
            nft add chain inet mangle forward '{ type filter hook forward priority -150; }' 2>/dev/null || true
            nft add rule inet mangle forward ip saddr "$subnet" tcp flags syn tcp option maxseg size set rt mtu 2>/dev/null || true
            nft add rule inet mangle forward ip daddr "$subnet" tcp flags syn tcp option maxseg size set rt mtu 2>/dev/null || true
            ;;
    esac
}

fw_add_established() {
    case "$FW_BACKEND" in
        iptables)
            iptables -C INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
                iptables -I INPUT 2 -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
            ;;
        nft)
            nft add rule inet filter input ct state established,related accept 2>/dev/null || true
            ;;
    esac
}

# ══════════════════════════════════════════════════════════════════════════════
#  WDTT VPN SERVER DEPLOYMENT
# ══════════════════════════════════════════════════════════════════════════════

# ─── Очистка старого WDTT ─────────────────────────────────────────────────────
wdtt_cleanup() {
    prog 0.05 "Очистка..."
    echo "🧹 Очистка старой установки WDTT..."

    # Защита SSH
    fw_add_input_tcp 22

    systemctl unmask wdtt 2>/dev/null || true
    systemctl stop wdtt 2>/dev/null || true
    systemctl disable wdtt 2>/dev/null || true
    rm -f /etc/systemd/system/wdtt.service 2>/dev/null || true
    systemctl daemon-reload 2>/dev/null || true
    pkill -9 -f wdtt-server 2>/dev/null || killall -9 wdtt-server 2>/dev/null || true

    # Удаляем только WDTT WireGuard интерфейс (wg0), НЕ трогаем другие
    ip link del wg0 2>/dev/null || true

    # Удаляем старые правила NAT для WDTT подсети
    for i in {1..5}; do
        iptables -t nat -D POSTROUTING -s 10.66.66.0/24 -j FULLCONENAT 2>/dev/null || true
        iptables -t nat -D PREROUTING -j FULLCONENAT 2>/dev/null || true
        iptables -t nat -D POSTROUTING -s 10.66.66.0/24 -j MASQUERADE 2>/dev/null || true
        iptables -t nat -D POSTROUTING -s 10.66.66.0/24 -o "$(detect_wan_interface)" -j MASQUERADE 2>/dev/null || true
    done

    rm -f /usr/local/bin/wdtt-server 2>/dev/null || true
    rm -rf /etc/wireguard/wg-keys.dat /etc/wireguard/passwords.json /etc/wireguard/server.log 2>/dev/null || true

    # Освобождаем ТОЛЬКО порты WDTT (56001 и 56000), НЕ трогаем 51820!
    fuser -k -9 ${WG_PORT}/udp ${DTLS_PORT}/udp 2>/dev/null || true

    echo "✓ Очистка завершена"
}

# ─── Sysctl тюнинг ───────────────────────────────────────────────────────────
setup_sysctl() {
    prog 0.20 "Sysctl..."
    echo "⚙️  Настройка сетевых параметров..."

    echo 1 > /proc/sys/net/ipv4/ip_forward
    cat > /etc/sysctl.d/99-wdtt.conf << 'SYSEOF'
net.ipv4.ip_forward = 1
net.ipv6.conf.all.disable_ipv6 = 1
net.netfilter.nf_conntrack_udp_timeout = 300
net.netfilter.nf_conntrack_udp_timeout_stream = 300
SYSEOF

    echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null || true
    echo 300 > /proc/sys/net/netfilter/nf_conntrack_udp_timeout 2>/dev/null || true
    echo 300 > /proc/sys/net/netfilter/nf_conntrack_udp_timeout_stream 2>/dev/null || true
    sysctl -p /etc/sysctl.d/99-wdtt.conf >/dev/null 2>&1 || true

    echo "✓ Sysctl настроен"
}

# ─── Настройка NAT + Firewall ─────────────────────────────────────────────────
setup_nat_and_firewall() {
    prog 0.40 "NAT + Firewall..."
    echo "🛡  Настройка NAT и фаервола..."

    local iface
    iface=$(detect_wan_interface)

    if [ -z "$iface" ]; then
        log_warn "Не удалось определить WAN-интерфейс!"
        log_warn "Настройте NAT вручную: iptables -t nat -A POSTROUTING -s 10.66.66.0/24 -o <iface> -j MASQUERADE"
        return 0
    fi

    log_info "WAN-интерфейс: $iface"

    # === SSH (всегда первое правило!) ===
    fw_add_input_tcp 22
    fw_add_established

    # === WDTT порты ===
    fw_add_input_udp "$DTLS_PORT"   # 56000 — DTLS сервер
    fw_add_input_udp "$WG_PORT"     # 56001 — WireGuard
    fw_add_input_udp_range 1024 65535  # Весь диапазон UDP (TURN relay)

    # === Forward ===
    fw_add_forward

    # === NAT: MASQUERADE для подсети WireGuard ===
    fw_add_masquerade "$iface" "10.66.66.0/24"
    
    # === MSS Clamping для исправления MTU (DonationAlerts / Cloudflare) ===
    fw_add_mss_clamping "10.66.66.0/24"

    echo "✓ NAT: MASQUERADE на $iface для 10.66.66.0/24"
    echo "✓ Порты: 22/tcp(SSH), ${DTLS_PORT}/udp(DTLS), ${WG_PORT}/udp(WG), 1024-65535/udp"
    echo "✓ TCP MSS Clamping включен"
}

# ─── Установка бинарника wdtt-server ──────────────────────────────────────────
setup_wdtt_binary() {
    prog 0.60 "Бинарник..."
    echo "📦 Установка wdtt-server..."

    if [ -f /tmp/wdtt-server ]; then
        chmod +x /tmp/wdtt-server
        mv /tmp/wdtt-server /usr/local/bin/wdtt-server
        echo "✓ wdtt-server установлен"
    elif [ -f /usr/local/bin/wdtt-server ]; then
        echo "✓ wdtt-server уже установлен"
    else
        echo "⚠ wdtt-server не найден в /tmp/ — пропускаем"
        echo "  Загрузите бинарник вручную в /usr/local/bin/wdtt-server"
    fi

    mkdir -p /etc/wireguard
}

# ─── Systemd-сервис WDTT ─────────────────────────────────────────────────────
setup_wdtt_service() {
    prog 0.75 "Сервис..."
    echo "🔧 Создание systemd-сервиса WDTT..."

    cat > /etc/systemd/system/wdtt.service << WDTTSVC
[Unit]
Description=WDTT VPN Server
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStartPre=-/usr/bin/env bash -c "fuser -k -9 ${WG_PORT}/udp ${DTLS_PORT}/udp || true"
ExecStartPre=-/usr/bin/env bash -c "ip link del wg0 2>/dev/null || true"
ExecStart=/usr/local/bin/wdtt-server -listen 0.0.0.0:${DTLS_PORT} -wg-port ${WG_PORT} -config-dir /etc/wireguard ${WDTT_ARGS}
Restart=always
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
WDTTSVC

    systemctl daemon-reload
    systemctl unmask wdtt >/dev/null 2>&1 || true
    systemctl enable wdtt >/dev/null 2>&1 || true
    echo "✓ Сервис wdtt.service создан и включён"
}

# ─── Запуск WDTT ─────────────────────────────────────────────────────────────
start_wdtt() {
    prog 0.90 "Запуск..."
    echo "🚀 Запуск WDTT VPN Server..."

    if [ ! -f /usr/local/bin/wdtt-server ]; then
        echo "⚠ wdtt-server не установлен — запуск пропущен"
        return 0
    fi

    systemctl restart wdtt

    sleep 2
    local status
    status=$(systemctl is-active wdtt 2>/dev/null || echo "unknown")

    prog 1.0 "Готово!"

    echo ""
    echo "══════════════════════════════════════════════════════════════"

    if [ "$status" = "active" ]; then
        echo "✅ Деплой успешно завершён!"
        echo "   NAT:  MASQUERADE (стандартный)"
        echo "   DTLS: порт ${DTLS_PORT}"
        echo "   WG:   порт ${WG_PORT}"
    else
        echo "⚠️ Сервис wdtt не запустился. Статус: $status"
        echo "   Последние логи:"
        journalctl -u wdtt -n 7 --no-pager 2>/dev/null | sed 's/^/   >> /'
    fi

    echo "   Логи:   journalctl -u wdtt -f"
    echo "   Статус: systemctl status wdtt"
    echo "══════════════════════════════════════════════════════════════"
    echo ""
}

# ─── Команда: uninstall ──────────────────────────────────────────────────────
do_uninstall() {
    log_step "Удаление WDTT..."

    systemctl stop wdtt 2>/dev/null || true
    systemctl disable wdtt 2>/dev/null || true
    rm -f /etc/systemd/system/wdtt.service
    systemctl daemon-reload

    ip link del wg0 2>/dev/null || true
    pkill -9 -f wdtt-server 2>/dev/null || true

    local iface
    iface=$(detect_wan_interface)
    if [ -n "$iface" ]; then
        for i in {1..5}; do
            iptables -t nat -D POSTROUTING -s 10.66.66.0/24 -o "$iface" -j MASQUERADE 2>/dev/null || true
            iptables -t mangle -D FORWARD -s 10.66.66.0/24 -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
            iptables -t mangle -D FORWARD -d 10.66.66.0/24 -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
        done
        iptables -D INPUT -p udp --dport ${DTLS_PORT} -j ACCEPT 2>/dev/null || true
        iptables -D INPUT -p udp --dport ${WG_PORT} -j ACCEPT 2>/dev/null || true
        iptables -D INPUT -p udp --dport 1024:65535 -j ACCEPT 2>/dev/null || true
    fi

    rm -f /usr/local/bin/wdtt-server
    rm -f /etc/sysctl.d/99-wdtt.conf
    sysctl --system >/dev/null 2>&1 || true

    log_info "WDTT полностью удалён."
}

# ─── Команда: status ─────────────────────────────────────────────────────────
do_status() {
    echo "Статус WDTT:"
    echo ""
    if systemctl is-active wdtt &>/dev/null; then
        log_info "Сервис: АКТИВЕН"
    else
        log_warn "Сервис: НЕ АКТИВЕН"
    fi
    if [ -f /usr/local/bin/wdtt-server ]; then
        log_info "Бинарник: установлен"
    else
        log_warn "Бинарник: НЕ найден"
    fi
    if ip link show wg0 &>/dev/null; then
        log_info "WireGuard (wg0): активен"
    else
        log_warn "WireGuard (wg0): не активен"
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════
main() {
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║       WDTT VPN Server — Installer v${SCRIPT_VERSION}                    ║"
    echo "║       DTLS: ${DTLS_PORT}  |  WG: ${WG_PORT}  |  NAT: MASQUERADE       ║"
    echo "╚══════════════════════════════════════════════════════════════╝"

    local action="${1:-install}"
    check_root

    mkdir -p "$(dirname "$LOG_FILE")"
    echo "=== WDTT Installer v${SCRIPT_VERSION} — $(date) ===" >> "$LOG_FILE"

    detect_os
    detect_firewall

    case "$action" in
        status|--status|-s)       do_status ;;
        uninstall|--uninstall|-u) do_uninstall ;;
        install|--install|-i|*)
            wdtt_cleanup
            setup_sysctl
            setup_nat_and_firewall
            setup_wdtt_binary
            setup_wdtt_service
            start_wdtt
            ;;
    esac
}

main "$@"
