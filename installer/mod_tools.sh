#!/bin/bash
# mod_tools.sh - MSY VPN v104+
# Hysteria UDP + funciones del menú (incluyendo SSL robustecido y watchdog)

# ====================
# INSTALAR HYSTERIA UDP
# ====================
echo "Instalando Hysteria UDP Manager..."
BASE_URL="https://raw.githubusercontent.com/juanitoprosniff/script_msyvpn/main/installer"
wget -q -O /root/install_agnudp.sh  "$BASE_URL/install_agnudp.sh"  2>/dev/null
wget -q -O /root/agnudp_manager.sh  "$BASE_URL/agnudp_manager.sh"  2>/dev/null

if [ -f /root/install_agnudp.sh ] && [ -f /root/agnudp_manager.sh ]; then
    chmod +x /root/install_agnudp.sh /root/agnudp_manager.sh
    bash /root/install_agnudp.sh 2>/dev/null
    cp /root/agnudp_manager.sh /usr/local/bin/hysteria-manager
    chmod +x /usr/local/bin/hysteria-manager
    echo "✓ Hysteria UDP instalado"
else
    echo "⚠ No se pudo descargar Hysteria UDP"
fi

# ====================
# FUNCIONES DEL MENÚ
# (incluye mejoras SSL + proxy watchdog + desinstalación limpia)
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
    local port=$1 proto=${2:-tcp}
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
    local users; users=$(who 2>/dev/null | awk '{print $1}' | sort -u)
    if [ -z "$users" ]; then
        echo "  Sin usuarios conectados por SSH"
    else
        local n=1
        while IFS= read -r u; do
            [ -z "$u" ] && continue
            local info; info=$(who 2>/dev/null | grep "^$u " | head -1 | awk '{print $5}' | tr -d '()')
            echo "  $n) $u  [${info:-conectado}]"
            n=$((n+1))
        done <<< "$users"
    fi
    echo ""
    echo "═══════════════════════════════════════════════"
}

# -----------------------------------------------------------
# stunnel_restart: reinicio robusto (Ubuntu 20/22 compatible)
# Usa init.d como método principal porque systemctl restart
# frecuentemente devuelve "active (exited)" sin arrancar realmente
# -----------------------------------------------------------
stunnel_restart() {
    local quiet=${1:-0}

    pkill -9 -x stunnel4        2>/dev/null
    pkill -9 -f "stunnel4 /etc" 2>/dev/null
    sleep 1

    # Liberar todos los puertos del conf
    if [ -f /etc/stunnel/stunnel.conf ]; then
        while IFS= read -r line; do
            local p; p=$(echo "$line" | grep -oP ':\K[0-9]+$')
            [ -n "$p" ] && fuser -k "${p}/tcp" 2>/dev/null
        done < <(grep "^accept" /etc/stunnel/stunnel.conf)
    fi
    for p in 443 444 777; do fuser -k "${p}/tcp" 2>/dev/null; done
    sleep 1

    mkdir -p /var/run/stunnel4
    if getent group stunnel4 >/dev/null 2>&1; then
        chown stunnel4:stunnel4 /var/run/stunnel4 2>/dev/null
    else
        chown nobody:nogroup /var/run/stunnel4 2>/dev/null
    fi
    chmod 755 /var/run/stunnel4

    # Método 1: init.d (más confiable)
    if [ -f /etc/init.d/stunnel4 ]; then
        /etc/init.d/stunnel4 stop  2>/dev/null; sleep 1
        /etc/init.d/stunnel4 start 2>/dev/null; sleep 2
    fi

    # Método 2: systemctl
    if ! pgrep -x stunnel4 >/dev/null 2>&1; then
        systemctl daemon-reload 2>/dev/null
        systemctl restart stunnel4 2>/dev/null; sleep 2
    fi

    # Método 3: binario directo
    if ! pgrep -x stunnel4 >/dev/null 2>&1; then
        /usr/bin/stunnel4 /etc/stunnel/stunnel.conf 2>/dev/null &
        sleep 2
    fi

    if pgrep -x stunnel4 >/dev/null 2>&1; then
        [ "$quiet" = "0" ] && echo "✓ Stunnel activo"
        return 0
    else
        [ "$quiet" = "0" ] && echo "✗ Stunnel no pudo iniciar"
        return 1
    fi
}

# -----------------------------------------------------------
# ssl_remove_port: elimina un túnel SSL por número de puerto
# -----------------------------------------------------------
ssl_remove_port() {
    local target_port=$1
    local conf=/etc/stunnel/stunnel.conf

    if [ -z "$target_port" ]; then
        echo "✗ Indica el puerto a eliminar"
        return 1
    fi

    local section
    section=$(awk -v port=":${target_port}" '
        /^\[/ { sec=substr($0,2,length($0)-2) }
        /^accept/ && index($0, port) { print sec; exit }
    ' "$conf")

    if [ -z "$section" ]; then
        echo "✗ No se encontró túnel en puerto $target_port"
        return 1
    fi

    python3 - "$conf" "$section" "$target_port" <<'PYREMOVE'
import sys, re
conf_path, section, port = sys.argv[1], sys.argv[2], sys.argv[3]
with open(conf_path, 'r') as f:
    content = f.read()
pattern = r'\n\[' + re.escape(section) + r'\].*?(?=\n\[|\Z)'
new_content = re.sub(pattern, '', content, flags=re.DOTALL)
with open(conf_path, 'w') as f:
    f.write(new_content)
print(f"✓ Túnel [{section}] (puerto {port}) eliminado del conf")
PYREMOVE

    stunnel_restart
}

# -----------------------------------------------------------
# ssl_add_port: agrega nuevo túnel SSL
# -----------------------------------------------------------
ssl_add_port() {
    local nombre=$1 entrada=$2 destino=$3
    local conf=/etc/stunnel/stunnel.conf

    if grep -q ":${entrada}$" "$conf" 2>/dev/null; then
        echo "✗ Puerto $entrada ya está en uso en stunnel"
        return 1
    fi

    cat >> "$conf" <<TUNNEL

[${nombre}]
client      = no
accept      = 0.0.0.0:${entrada}
connect     = 127.0.0.1:${destino}
cert        = /etc/stunnel/stunnel.pem
verify      = 0
TIMEOUTidle = 86400
TUNNEL

    echo "✓ Túnel [${nombre}] puerto $entrada → $destino agregado"
    stunnel_restart
}

# -----------------------------------------------------------
# Gestión de proxies Python
# -----------------------------------------------------------
start_proxy() {
    local port=$1 response=$2 banner=$3 ssh_port=${4:-143} save=${5:-1}

    # Limpiar si quedó un screen muerto
    if screen -list 2>/dev/null | grep -q "proxy-$port"; then
        # Verificar si el puerto realmente está escuchando
        if ss -tlnp 2>/dev/null | grep -q ":${port} "; then
            echo "✗ Puerto $port ya en uso"
            return 1
        else
            # Screen zombie — limpiarlo
            screen -X -S "proxy-$port" quit 2>/dev/null
            fuser -k "${port}/tcp" 2>/dev/null
            sleep 1
        fi
    fi

    # Liberar puerto por si quedó ocupado por proceso anterior
    fuser -k "${port}/tcp" 2>/dev/null
    sleep 0.5

    screen -dmS "proxy-$port" python3 /etc/proxy-python/proxy.py \
        "$port" "$response" "$banner" "$ssh_port"
    sleep 1

    if screen -list 2>/dev/null | grep -q "proxy-$port"; then
        echo "✓ Proxy :$port → SSH:$ssh_port | Código: $response"
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
    pkill -f "proxy.py $port "    2>/dev/null
    # Liberar el puerto con fuerza
    fuser -k "${port}/tcp"        2>/dev/null
    sleep 1
    # Segunda pasada por si quedó algo
    local pid; pid=$(lsof -ti:"$port" 2>/dev/null)
    [ -n "$pid" ] && kill -9 $pid 2>/dev/null
    sed -i "/^${port}|/d" /etc/proxy-python/proxies.conf 2>/dev/null
    echo "✓ Proxy :$port detenido y puerto liberado"
}

stop_all_proxies() {
    # Detener screens
    screen -ls 2>/dev/null | grep "proxy-" | awk '{print $1}' | \
        xargs -I {} screen -X -S {} quit 2>/dev/null
    pkill -9 -f "proxy.py" 2>/dev/null
    sleep 1
    # Liberar todos los puertos configurados
    if [ -f /etc/proxy-python/proxies.conf ]; then
        while IFS='|' read -r port _rest; do
            [ -z "$port" ] && continue
            fuser -k "${port}/tcp" 2>/dev/null
        done < /etc/proxy-python/proxies.conf
    fi
    echo "✓ Proxies detenidos y puertos liberados"
}

restore_proxies() {
    local conf=/etc/proxy-python/proxies.conf
    if [ ! -f "$conf" ] || [ ! -s "$conf" ]; then
        {
            echo '80|101|<span style="background-color: #000000;"><span style="color:#eeff01;">MSY VPN SCRIPT</span></span>|143'
            echo '8080|101|<span style="background-color: #000000;"><span style="color:#eeff01;">MSY VPN SCRIPT</span></span>|143'
            echo '8880|101|<span style="background-color: #000000;"><span style="color:#eeff01;">MSY VPN SCRIPT</span></span>|143'
            echo '8888|101|<span style="background-color: #000000;"><span style="color:#eeff01;">MSY VPN SCRIPT</span></span>|143'
        } > "$conf"
    fi
    while IFS='|' read -r port response banner ssh_port; do
        [ -z "$port" ] && continue
        screen -list 2>/dev/null | grep -q "proxy-$port" && continue
        start_proxy "$port" "$response" "$banner" "$ssh_port" "0"
    done < "$conf"
    # Arrancar watchdog si no está corriendo
    systemctl is-active --quiet proxy-watchdog || systemctl start proxy-watchdog 2>/dev/null
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
    systemctl restart ssh              && echo "✓ OpenSSH"       || echo "✗ OpenSSH error"
    systemctl restart dropbear-legacy 2>/dev/null \
                                       && echo "✓ Dropbear 2016" || echo "✗ Dropbear error"
    stunnel_restart
    systemctl restart badvpn-udpgw    && echo "✓ BadVPN"        || echo "✗ BadVPN error"
    restart_proxies
    echo "✓ Listo"
}

# -----------------------------------------------------------
# kill_all_ports: libera TODOS los puertos del script
# Usado por desinstalación para no dejar puertos colgados
# -----------------------------------------------------------
kill_all_ports() {
    echo "Liberando puertos..."
    # Puertos SSL
    for p in 443 444 777; do
        fuser -k "${p}/tcp" 2>/dev/null
    done
    # Puertos del conf de stunnel (túneles personalizados)
    if [ -f /etc/stunnel/stunnel.conf ]; then
        while IFS= read -r line; do
            local p; p=$(echo "$line" | grep -oP ':\K[0-9]+$')
            [ -n "$p" ] && fuser -k "${p}/tcp" 2>/dev/null
        done < <(grep "^accept" /etc/stunnel/stunnel.conf)
    fi
    # Puertos de proxies
    if [ -f /etc/proxy-python/proxies.conf ]; then
        while IFS='|' read -r port _rest; do
            [ -z "$port" ] && continue
            fuser -k "${port}/tcp" 2>/dev/null
        done < /etc/proxy-python/proxies.conf
    fi
    # Puertos SSH fijos
    for p in 22 143 7300; do
        fuser -k "${p}/tcp" 2>/dev/null
        fuser -k "${p}/udp" 2>/dev/null
    done
    echo "✓ Puertos liberados"
}

FUNCEOF

chmod +x /root/ssh-vpn-functions.sh
echo "✓ Funciones del menú instaladas (con stunnel_restart y watchdog)"
