#!/bin/bash
# mod_tools.sh - MSY VPN
# Herramientas: Hysteria UDP, funciones del menú

# ====================
# INSTALAR HYSTERIA UDP
# ====================
echo "Instalando Hysteria UDP Manager..."
BASE_URL="https://raw.githubusercontent.com/juanitoprosniff/script_msyvpn/main/installer"
wget -q -O install_agnudp.sh "$BASE_URL/install_agnudp.sh" 2>/dev/null
wget -q -O agnudp_manager.sh "$BASE_URL/agnudp_manager.sh" 2>/dev/null

if [ -f install_agnudp.sh ] && [ -f agnudp_manager.sh ]; then
    chmod +x install_agnudp.sh agnudp_manager.sh
    bash install_agnudp.sh 2>/dev/null
    cp agnudp_manager.sh /usr/local/bin/hysteria-manager
    chmod +x /usr/local/bin/hysteria-manager
    echo "✓ Hysteria UDP instalado"
else
    echo "⚠ No se pudo descargar Hysteria UDP"
fi

# ====================
# FUNCIONES DEL MENÚ
# ====================
cat > /root/ssh-vpn-functions.sh <<'FUNCEOF'
#!/bin/bash

GREEN='\033[1;32m'
CYAN='\033[1;36m'
YELLOW='\033[1;33m'
RED='\033[1;31m'
BLUE='\033[0;34m'
NC='\033[0m'
BOLD='\033[1m'

# -----------------------------------------------------------
# Estado de un puerto (ON/OFF)
# -----------------------------------------------------------
port_status() {
    local port=$1
    local proto=${2:-tcp}
    if ss -${proto}lnp 2>/dev/null | grep -q ":${port} "; then
        echo -e "${GREEN}ON${NC}"
    else
        echo -e "${RED}OFF${NC}"
    fi
}

# -----------------------------------------------------------
# Listar usuarios conectados
# -----------------------------------------------------------
list_connected_users() {
    echo "═══════════════════════════════════════════════"
    echo "           USUARIOS SSH CONECTADOS"
    echo "═══════════════════════════════════════════════"
    echo ""

    local users
    users=$(who 2>/dev/null | grep -v "^$" | awk '{print $1}' | sort -u)

    if [ -z "$users" ]; then
        echo "  Sin usuarios conectados por SSH"
    else
        local n=1
        while IFS= read -r u; do
            [ -z "$u" ] && continue
            local info
            info=$(who 2>/dev/null | grep "^$u " | head -1 | awk '{print $5}' | tr -d '()')
            echo "  $n) $u  [${info:-conectado}]"
            n=$((n+1))
        done <<< "$users"
    fi
    echo ""
    echo "═══════════════════════════════════════════════"
}

# -----------------------------------------------------------
# Gestión de proxies
# -----------------------------------------------------------
start_proxy() {
    local port=$1 response=$2 banner=$3 ssh_port=${4:-143} save=${5:-1}

    if screen -list 2>/dev/null | grep -q "proxy-$port"; then
        echo "✗ Puerto $port ya en uso"
        return 1
    fi

    screen -dmS "proxy-$port" python3 /etc/proxy-python/proxy.py "$port" "$response" "$banner" "$ssh_port"
    sleep 1

    if screen -list 2>/dev/null | grep -q "proxy-$port"; then
        echo "✓ Proxy :$port → SSH:$ssh_port | $response $banner"
        if [ "$save" = "1" ]; then
            sed -i "/^${port}|/d" /etc/proxy-python/proxies.conf 2>/dev/null
            echo "${port}|${response}|${banner}|${ssh_port}" >> /etc/proxy-python/proxies.conf
        fi
    else
        echo "✗ Error al iniciar proxy en puerto $port"
    fi
}

stop_proxy() {
    local port=$1
    screen -X -S "proxy-$port" quit 2>/dev/null
    pkill -f "proxy.py $port " 2>/dev/null
    local pid
    pid=$(lsof -ti:$port 2>/dev/null)
    [ -n "$pid" ] && kill -9 $pid 2>/dev/null
    sleep 1
    fuser -k $port/tcp 2>/dev/null
    sed -i "/^${port}|/d" /etc/proxy-python/proxies.conf 2>/dev/null
    echo "✓ Proxy :$port detenido"
}

stop_all_proxies() {
    screen -ls 2>/dev/null | grep "proxy-" | awk '{print $1}' | xargs -I {} screen -X -S {} quit 2>/dev/null
    pkill -9 -f "proxy.py" 2>/dev/null
    echo "✓ Proxies detenidos"
}

restore_proxies() {
    local conf=/etc/proxy-python/proxies.conf
    if [ ! -f "$conf" ] || [ ! -s "$conf" ]; then
        echo '80|101|<span style="background-color: #000000;"><span style="color:#eeff01;">MSY VPN SCRIPT</span></span>|143'   > "$conf"
        echo '8080|101|<span style="background-color: #000000;"><span style="color:#eeff01;">MSY VPN SCRIPT</span></span>|143' >> "$conf"
        echo '8880|101|<span style="background-color: #000000;"><span style="color:#eeff01;">MSY VPN SCRIPT</span></span>|143' >> "$conf"
        echo '8888|101|<span style="background-color: #000000;"><span style="color:#eeff01;">MSY VPN SCRIPT</span></span>|143' >> "$conf"
    fi
    while IFS='|' read -r port response banner ssh_port; do
        [ -z "$port" ] && continue
        screen -list 2>/dev/null | grep -q "proxy-$port" && continue
        start_proxy "$port" "$response" "$banner" "$ssh_port" "0"
    done < "$conf"
}

restart_proxies() {
    echo "Reiniciando proxies..."
    stop_all_proxies
    sleep 1
    restore_proxies
    echo "✓ Proxies reiniciados"
}

restart_all_services() {
    echo "Reiniciando todos los servicios..."
    systemctl restart ssh       && echo "✓ OpenSSH"       || echo "✗ OpenSSH error"
    systemctl restart dropbear-legacy 2>/dev/null && echo "✓ Dropbear 2016" || echo "✗ Dropbear error"
    systemctl restart stunnel4  && echo "✓ Stunnel"       || echo "✗ Stunnel error"
    systemctl restart badvpn-udpgw && echo "✓ BadVPN"     || echo "✗ BadVPN error"
    restart_proxies
    echo "✓ Listo"
}

FUNCEOF

chmod +x /root/ssh-vpn-functions.sh
echo "✓ Funciones del menú instaladas"
