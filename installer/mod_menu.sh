#!/bin/bash
# mod_menu.sh - MSY VPN v105
# Panel principal: muestra Dropbear 2016.74 (:143) y 2019.78 (:142)
# Opción 7: Gestión Dropbear — cambiar versión por puerto, recompilar

cat > /root/vpn-installer.sh << 'MAINSCRIPT'
#!/bin/bash

if [ ! -f /root/ssh-vpn-functions.sh ]; then
    echo "Error: Archivo de funciones no encontrado"
    exit 1
fi

source /root/ssh-vpn-functions.sh

DB_DIR="/opt/dropbear-bins"
DB_KEYS="/etc/dropbear-legacy"

# ============================================================
# HELPERS: leer estado guardado por mod_ssh.sh
# ============================================================
_db_active_ver()  { cat "$DB_KEYS/active_version.txt" 2>/dev/null || echo "?"; }
_db_active_bin()  { cat "$DB_KEYS/active_bin.txt"     2>/dev/null || echo ""; }
_db_has_2016()    { cat "$DB_KEYS/has_2016.txt"       2>/dev/null || echo "0"; }
_db_has_2019()    { cat "$DB_KEYS/has_2019.txt"       2>/dev/null || echo "0"; }

_db_port_status() {
    # $1 = versión ("2016.74" o "2019.78"), $2 = puerto público
    local SVC="dropbear-${1//./-}"
    local WR="msy-wrap-${2}"
    if systemctl is-active --quiet "$SVC" 2>/dev/null \
       || systemctl is-active --quiet "$WR" 2>/dev/null \
       || ss -tlnp 2>/dev/null | grep -q ":${2} "; then
        echo -e "\033[1;32mON\033[0m"
    else
        echo -e "\033[1;31mOFF\033[0m"
    fi
}

# ============================================================
# FUNCIÓN: cambiar la versión de Dropbear en un puerto dado
#
# $1 = versión destino ("2016.74" / "2019.78" / "ssh_fallback")
# $2 = puerto público (143 o 142)
# $3 = puerto interno (1143 o 1142)
# ============================================================
_cambiar_dropbear_puerto() {
    local VER="$1"
    local PPUB="$2"
    local PINT="$3"
    local BIN="$DB_DIR/dropbear-${VER}"
    local SVC="dropbear-${VER//./-}"
    local WR_SVC="msy-wrap-${PPUB}"

    # Detener cualquier cosa corriendo en ese puerto
    # Buscar qué servicio ocupa el puerto ahora y detenerlo
    for old_svc in dropbear-2016-74 dropbear-2019-78 msy-wrap-${PPUB}; do
        systemctl stop "$old_svc" 2>/dev/null
    done
    pkill -9 -f "dropbear.*${PINT}" 2>/dev/null
    pkill -9 -f "socat.*${PPUB}"    2>/dev/null
    fuser -k "${PPUB}/tcp" 2>/dev/null
    fuser -k "${PINT}/tcp" 2>/dev/null
    sleep 1

    if [ "$VER" = "ssh_fallback" ]; then
        # Quitar Dropbear del puerto y poner OpenSSH
        fuser -k "${PPUB}/tcp" 2>/dev/null
        if ! grep -q "^Port ${PPUB}" /etc/ssh/sshd_config; then
            sed -i "/^Port 22/a Port ${PPUB}" /etc/ssh/sshd_config
        fi
        systemctl restart ssh
        sleep 1
        ss -tlnp | grep -q ":${PPUB} " \
            && echo "✓ OpenSSH fallback activo en :${PPUB}" \
            || echo "✗ No se pudo activar OpenSSH en :${PPUB}"
        [ "$PPUB" = "143" ] && echo "ssh_fallback" > "$DB_KEYS/active_version.txt"
        return
    fi

    if [ ! -x "$BIN" ]; then
        echo "✗ Binario $BIN no encontrado"
        echo "  Usa la opción de Recompilar en el menú Dropbear"
        return 1
    fi

    # Si el puerto tenía OpenSSH, quitarlo de sshd_config
    if grep -q "^Port ${PPUB}" /etc/ssh/sshd_config 2>/dev/null; then
        sed -i "/^Port ${PPUB}/d" /etc/ssh/sshd_config
        systemctl restart ssh 2>/dev/null
    fi

    local KF=""
    [ -f "$DB_KEYS/dropbear_rsa_host_key" ]   && KF="$KF -r $DB_KEYS/dropbear_rsa_host_key"
    [ -f "$DB_KEYS/dropbear_ecdsa_host_key" ] && KF="$KF -r $DB_KEYS/dropbear_ecdsa_host_key"

    # Crear/actualizar wrapper
    local WS="/usr/local/bin/msy-wrap-${PPUB}.sh"
    cat > "$WS" <<WRAP
#!/bin/bash
read -t 10 -r L
if   [[ "\$L" == SSH-* ]];      then { printf '%s\r\n' "\$L"; cat; } | socat - TCP:127.0.0.1:${PINT}
elif [[ "\$L" == CONNECT\ * ]]; then printf 'HTTP/1.0 200 Connection established\r\n\r\n'; socat - TCP:127.0.0.1:${PINT}
elif [[ -z "\$L" ]];            then socat - TCP:127.0.0.1:${PINT}
else                                 printf 'HTTP/1.0 400 Bad Request\r\nContent-Length: 0\r\n\r\n'
fi
WRAP
    chmod +x "$WS"

    cat > "/etc/systemd/system/${SVC}.service" <<DBSVC
[Unit]
Description=Dropbear $VER :${PINT} interno MSY VPN
After=network.target

[Service]
Type=simple
ExecStart=${BIN} -F -E -p 127.0.0.1:${PINT} ${KF} -b ${DB_KEYS}/banner.txt -K 120 -I 600
Restart=always
RestartSec=3
KillMode=process
StandardOutput=null
StandardError=null
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
DBSVC

    cat > "/etc/systemd/system/${WR_SVC}.service" <<WRSVC
[Unit]
Description=MSY Wrapper :${PPUB}→:${PINT} (Dropbear)
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/socat TCP-LISTEN:${PPUB},reuseaddr,fork,backlog=256 EXEC:${WS}
Restart=always
RestartSec=3
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
WRSVC

    systemctl daemon-reload
    systemctl enable "$SVC" "$WR_SVC" >/dev/null 2>&1
    systemctl restart "$SVC"
    sleep 1

    if systemctl is-active --quiet "$SVC"; then
        systemctl restart "$WR_SVC"
        sleep 1
        if systemctl is-active --quiet "$WR_SVC"; then
            echo "✓ Dropbear $VER activo en :${PPUB} (con wrapper)"
        else
            # Directo sin wrapper
            systemctl stop "$SVC" 2>/dev/null
            fuser -k "${PPUB}/tcp" 2>/dev/null
            sed -i "s|127.0.0.1:${PINT}|0.0.0.0:${PPUB}|g" "/etc/systemd/system/${SVC}.service"
            systemctl daemon-reload
            systemctl restart "$SVC"
            sleep 1
            systemctl is-active --quiet "$SVC" \
                && echo "✓ Dropbear $VER activo en :${PPUB} (directo)" \
                || { echo "✗ Dropbear $VER no pudo iniciar"; journalctl -u "$SVC" --no-pager -n 8; return 1; }
        fi
        [ "$PPUB" = "143" ] && echo "$VER" > "$DB_KEYS/active_version.txt" && echo "$BIN" > "$DB_KEYS/active_bin.txt"
        echo "✓ Listo"
    else
        echo "✗ Dropbear $VER no inició"
        journalctl -u "$SVC" --no-pager -n 8 2>/dev/null
        return 1
    fi
}

# ============================================================
# FUNCIÓN: RECOMPILAR DROPBEAR DESDE FUENTE
# Idéntica a mod_ssh.sh para coherencia
# ============================================================
_recompilar_dropbear() {
    local VER="$1"   # "2016.74" o "2019.78"
    local URL="$2"
    local PREFIX="$3"
    local CF="$4"
    local DEST_BIN="$DB_DIR/dropbear-${VER}"
    local DEST_KEY="$DB_DIR/dropbearkey-${VER}"
    local TB="dropbear-${VER}.tar.bz2"

    echo "Descargando dropbear-${VER}..."
    cd /usr/src
    wget -q --timeout=90 -O "$TB" "$URL" 2>/dev/null \
    || wget -q --timeout=90 -O "$TB" "https://dropbear.nl/mirror/releases/$TB" 2>/dev/null

    if [ ! -s "$TB" ]; then
        echo "✗ No se pudo descargar el tarball"
        cd /root; return 1
    fi

    rm -rf "/usr/src/dropbear-${VER}"
    tar xjf "$TB" -C /usr/src 2>/dev/null
    cd "/usr/src/dropbear-${VER}" || { echo "✗ Error extrayendo"; cd /root; return 1; }

    for f in sysoptions.h default_options.h options.h; do
        [ -f "$f" ] && grep -q "LOCAL_IDENT" "$f" && \
            sed -i 's|#define LOCAL_IDENT.*|#define LOCAL_IDENT "SSH-2.0-ByJuanitoProSniff"|' "$f"
    done

    export CFLAGS="$CF"
    ./configure --prefix="$PREFIX" --disable-zlib --disable-wtmp --disable-lastlog >/dev/null 2>&1

    echo "Compilando... (puede tardar 2-5 minutos)"
    if echo "$VER" | grep -q "^2016"; then
        echo "  → Sublibs en -j1 primero (necesario para 2016)..."
        [ -d libtommath  ] && make -C libtommath  -j1 CFLAGS="$CF" >/dev/null 2>&1
        [ -d libtomcrypt ] && make -C libtomcrypt -j1 CFLAGS="$CF" >/dev/null 2>&1
    fi
    make -j$(nproc) PROGRAMS="dropbear dropbearkey" CFLAGS="$CF" >/tmp/recomp_${VER}.log 2>&1

    if make install PROGRAMS="dropbear dropbearkey" >/dev/null 2>&1 \
            && [ -x "${PREFIX}/sbin/dropbear" ]; then
        cp "${PREFIX}/sbin/dropbear"   "$DEST_BIN"
        cp "${PREFIX}/bin/dropbearkey" "$DEST_KEY" 2>/dev/null
        chmod +x "$DEST_BIN" "$DEST_KEY" 2>/dev/null
        unset CFLAGS
        VER_CORTA=$(echo "$VER" | cut -d. -f1)
        echo "1" > "$DB_KEYS/has_${VER_CORTA}.txt"
        echo "✓ Dropbear $VER compilado correctamente"
        cd /root; return 0
    else
        unset CFLAGS
        echo "✗ Compilación fallida — últimas líneas:"
        tail -8 "/tmp/recomp_${VER}.log" 2>/dev/null
        cd /root; return 1
    fi
}

# ============================================================
# MENÚ PRINCIPAL
# ============================================================
menu_principal() {
    while true; do
        clear

        IP=$(curl -4 -s --max-time 5 ifconfig.me 2>/dev/null \
          || curl -4 -s --max-time 5 api4.ipify.org 2>/dev/null \
          || hostname -I | tr ' ' '\n' | grep -v ':' | head -1)

        # Estado de puertos
        S_SSH=$(port_status 22 t)
        S_DB143=$(port_status 143 t)
        S_DB142=$(port_status 142 t)
        S_SSL443=$(port_status 443 t)
        S_SSL444=$(port_status 444 t)
        S_SSL777=$(port_status 777 t)
        S_P80=$(port_status 80 t)
        S_P8080=$(port_status 8080 t)
        S_P8880=$(port_status 8880 t)
        S_P8888=$(port_status 8888 t)
        S_BADVPN=$(port_status 7300 u)
        S_HYSTERIA=$(systemctl is-active --quiet hysteria 2>/dev/null \
            && echo -e "\033[1;32mON\033[0m" || echo -e "\033[1;31mOFF\033[0m")

        # Versiones activas
        DB_VER143=$(cat "$DB_KEYS/active_version.txt" 2>/dev/null || echo "?")
        # Para puerto 142, detectar cuál está corriendo
        if systemctl is-active --quiet dropbear-2019-78 2>/dev/null \
           || systemctl is-active --quiet msy-wrap-142 2>/dev/null; then
            DB_VER142="2019.78"
        else
            DB_VER142="---"
        fi

        echo -e "${CYAN}╔══════════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║${NC}      ${BOLD}MSY VPN PANEL - v105${NC}              ${CYAN}║${NC}"
        echo -e "${CYAN}║${NC}      t.me/FREEINTERNETVPNMSY              ${CYAN}║${NC}"
        echo -e "${CYAN}╚══════════════════════════════════════════════╝${NC}"
        echo -e " ${GREEN}IP:${NC} ${YELLOW}$IP${NC}"
        echo ""
        echo -e " ${CYAN}━━━ PUERTOS ACTIVOS ━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "  SSH       :22   $S_SSH"
        echo -e "  DB v${DB_VER143}  :143  $S_DB143  ← Principal"
        echo -e "  DB v${DB_VER142}  :142  $S_DB142  ← Secundario"
        echo -e "  SSL       :443  $S_SSL443  │  SSL  :444  $S_SSL444"
        echo -e "  SSL       :777  $S_SSL777"
        echo -e "  Proxy     :80   $S_P80    │  Proxy :8080  $S_P8080"
        echo -e "  Proxy     :8880 $S_P8880  │  Proxy :8888  $S_P8888"
        echo -e " ${CYAN}━━━ UDP ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "  BadVPN UDPGW :7300  $S_BADVPN"
        echo -e "  Hysteria UDP        $S_HYSTERIA"
        echo -e " ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        echo -e " ${BLUE}1)${NC} Crear usuario       ${BLUE}2)${NC} Eliminar usuario"
        echo -e " ${BLUE}3)${NC} Ver conectados      ${BLUE}4)${NC} Proxies Python"
        echo -e " ${BLUE}5)${NC} Túneles SSL/TLS     ${BLUE}6)${NC} Banner HTTP proxy"
        echo -e " ${BLUE}7)${NC} Dropbear :143/:142  ${BLUE}8)${NC} Hysteria UDP"
        echo -e " ${BLUE}9)${NC} Estado servicios   ${BLUE}10)${NC} Reiniciar servicios"
        echo -e "${RED} D)${NC} Desinstalar script  ${RED} 0)${NC} Salir"
        echo -e " ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        read -p " Opción: " option

        case $option in
            1)
                clear
                echo "CREAR USUARIO VPN"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                read -p "Nombre de usuario: " username
                read -p "Contraseña: " password
                read -p "Días de validez (0 = ilimitado): " days

                if id "$username" &>/dev/null; then
                    echo "El usuario ya existe"
                    read -p "ENTER para continuar..."; continue
                fi

                useradd -m -s /bin/bash "$username"
                echo "$username:$password" | chpasswd

                if [ "$days" -gt 0 ] 2>/dev/null; then
                    expiry=$(date -d "+$days days" +%Y-%m-%d)
                    chage -E "$expiry" "$username"
                else
                    expiry="Ilimitado"
                fi

                mkdir -p /etc/ssh-vpn/users
                cat > "/etc/ssh-vpn/users/$username.txt" <<USEREOF
Usuario: $username
Contraseña: $password
Fecha creación: $(date +%Y-%m-%d)
Fecha expiración: $expiry
Estado: Activo
USEREOF
                echo ""
                echo "✓ Usuario $username creado — expira: $expiry"
                read -p "ENTER para continuar..."
                ;;

            2)
                clear
                echo "ELIMINAR USUARIO"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                read -p "Usuario a eliminar: " username
                if ! id "$username" &>/dev/null; then
                    echo "El usuario no existe"
                    read -p "ENTER para continuar..."; continue
                fi
                pkill -9 -u "$username" 2>/dev/null
                userdel -r "$username" 2>/dev/null
                rm -f "/etc/ssh-vpn/users/$username.txt"
                echo "✓ Usuario $username eliminado"
                read -p "ENTER para continuar..."
                ;;

            3)
                clear
                list_connected_users
                read -p "ENTER para continuar..."
                ;;

            4)
                clear
                echo "PROXIES PYTHON"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                echo "1) Iniciar nuevo proxy"
                echo "2) Detener todos los proxies"
                echo "3) Ver proxies activos"
                echo "4) Detener proxy específico"
                echo "0) Volver"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                read -p "Opción: " proxy_opt
                case $proxy_opt in
                    1)
                        read -p "Puerto: " port
                        read -p "Código respuesta [101]: " response
                        response=${response:-101}
                        read -p "Banner [ENTER = default]: " banner
                        banner=${banner:-'<span style="background-color: #000000;"><span style="color:#eeff01;">MSY VPN SCRIPT</span></span>'}
                        echo "Backend SSH:"
                        echo "  1) Dropbear :143 (principal — 2016.74)"
                        echo "  2) Dropbear :142 (secundario — 2019.78)"
                        echo "  3) OpenSSH  :22"
                        echo "  4) Otro puerto"
                        read -p "Opción [1]: " backend
                        case $backend in
                            2) ssh_port=142 ;;
                            3) ssh_port=22 ;;
                            4) read -p "Puerto: " ssh_port ;;
                            *) ssh_port=143 ;;
                        esac
                        start_proxy "$port" "$response" "$banner" "$ssh_port"
                        read -p "ENTER..."
                        ;;
                    2) stop_all_proxies; read -p "ENTER..." ;;
                    3)
                        echo "PROXIES ACTIVOS:"
                        screen -ls 2>/dev/null | grep "proxy-" | awk -F'.' '{print $2}' | while read n; do
                            port=$(echo "$n" | sed 's/proxy-//')
                            cfg=$(grep "^${port}|" /etc/proxy-python/proxies.conf 2>/dev/null)
                            echo "  :$port — ${cfg:-sin config}"
                        done
                        screen -ls 2>/dev/null | grep -q "proxy-" || echo "  Ninguno activo"
                        echo ""
                        cat /etc/proxy-python/proxies.conf 2>/dev/null || echo "  Sin config guardada"
                        read -p "ENTER..."
                        ;;
                    4)
                        echo "Proxies activos:"; screen -ls 2>/dev/null | grep "proxy-" | awk '{print $1}'
                        echo ""
                        read -p "Puerto a detener: " del_port
                        [ -n "$del_port" ] && stop_proxy "$del_port"
                        read -p "ENTER..."
                        ;;
                esac
                ;;

            5)
                clear
                echo "TÚNELES SSL/TLS (Stunnel)"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                echo "1) Ver túneles activos"
                echo "2) Agregar nuevo túnel"
                echo "3) Desactivar / eliminar un túnel"
                echo "4) Reiniciar Stunnel"
                echo "0) Volver"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                read -p "Opción: " tunnel_opt
                case $tunnel_opt in
                    1)
                        clear
                        echo "TÚNELES SSL ACTIVOS:"
                        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                        grep -E '^\[|^accept|^connect' /etc/stunnel/stunnel.conf 2>/dev/null
                        echo ""
                        echo "Puertos escuchando:"
                        ss -tlnp 2>/dev/null | grep stunnel || echo "  (ninguno)"
                        echo ""
                        pgrep -x stunnel4 >/dev/null 2>&1 \
                            && echo -e "${GREEN}✓ Stunnel activo (PID: $(pgrep -x stunnel4 | head -1))${NC}" \
                            || echo -e "${RED}✗ Stunnel NO activo${NC}"
                        read -p "ENTER..."
                        ;;
                    2)
                        clear
                        echo "AGREGAR NUEVO TÚNEL SSL"
                        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                        read -p "Nombre del túnel (ej: tunnel-8443): " tunnel_name
                        read -p "Puerto de escucha (ej: 8443): " tunnel_port
                        echo "Backend destino:"
                        echo "  143 - Dropbear 2016.74 (principal)"
                        echo "  142 - Dropbear 2019.78 (secundario)"
                        echo "   22 - OpenSSH"
                        read -p "Puerto destino [143]: " tunnel_dest
                        tunnel_dest=${tunnel_dest:-143}
                        ssl_add_port "$tunnel_name" "$tunnel_port" "$tunnel_dest"
                        read -p "ENTER..."
                        ;;
                    3)
                        clear
                        echo "DESACTIVAR TÚNEL SSL"
                        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                        echo "Túneles configurados:"
                        grep -E '^\[|^accept' /etc/stunnel/stunnel.conf 2>/dev/null | \
                            awk '/^\[/{n=$0} /^accept/{print n" → "$0}'
                        echo ""
                        read -p "Puerto a desactivar (ej: 443): " rm_port
                        [ -n "$rm_port" ] && ssl_remove_port "$rm_port" || echo "Cancelado."
                        read -p "ENTER..."
                        ;;
                    4)
                        stunnel_restart
                        read -p "ENTER..."
                        ;;
                esac
                ;;

            6)
                clear
                echo "BANNER HTTP PROXY"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                echo "Banner actual:"
                grep "BANNER_TEXT = " /etc/proxy-python/proxy.py 2>/dev/null
                echo ""
                read -p "Nuevo texto [HTML o texto simple]: " new_banner
                new_banner=${new_banner:-'<span style="background-color: #000000;"><span style="color:#eeff01;">MSY VPN SCRIPT</span></span>'}
                sed -i "s|BANNER_TEXT = .*|BANNER_TEXT = '$new_banner'|" /etc/proxy-python/proxy.py
                echo "✓ Banner actualizado — reinicia proxies desde Opción 10"
                read -p "ENTER para continuar..."
                ;;

            7)
                # ============================================================
                # SUB-MENÚ DROPBEAR
                # Permite cambiar la versión en :143 y en :142 independientemente
                # ============================================================
                while true; do
                    clear
                    DB2016=$(_db_has_2016)
                    DB2019=$(_db_has_2019)

                    # Detectar qué corre en cada puerto
                    if systemctl is-active --quiet dropbear-2016-74 2>/dev/null \
                       || systemctl is-active --quiet msy-wrap-143 2>/dev/null; then
                        VER143_ACTIVA="2016.74"
                    elif ss -tlnp 2>/dev/null | grep -q ":143 "; then
                        VER143_ACTIVA="(activo)"
                    else
                        VER143_ACTIVA="inactivo"
                    fi

                    if systemctl is-active --quiet dropbear-2019-78 2>/dev/null \
                       || systemctl is-active --quiet msy-wrap-142 2>/dev/null; then
                        VER142_ACTIVA="2019.78"
                    elif ss -tlnp 2>/dev/null | grep -q ":142 "; then
                        VER142_ACTIVA="(activo)"
                    else
                        VER142_ACTIVA="inactivo"
                    fi

                    ST143=$(_db_port_status "2016.74" 143)
                    ST142=$(_db_port_status "2019.78" 142)

                    echo -e "${CYAN}╔══════════════════════════════════════════════╗${NC}"
                    echo -e "${CYAN}║${NC}       ${BOLD}GESTIÓN DROPBEAR - MSY VPN${NC}        ${CYAN}║${NC}"
                    echo -e "${CYAN}╚══════════════════════════════════════════════╝${NC}"
                    echo ""
                    echo -e " ${CYAN}━━━ PUERTOS DROPBEAR ━━━━━━━━━━━━━━━━━━━━━━━${NC}"
                    echo -e "  Puerto ${YELLOW}:143${NC} → versión activa: ${YELLOW}${VER143_ACTIVA}${NC}  $ST143"
                    echo -e "  Puerto ${YELLOW}:142${NC} → versión activa: ${YELLOW}${VER142_ACTIVA}${NC}  $ST142"
                    echo ""
                    echo -e " ${CYAN}━━━ VERSIONES COMPILADAS ━━━━━━━━━━━━━━━━━━━${NC}"
                    if [ "$DB2016" = "1" ]; then
                        echo -e "  ${GREEN}✓${NC} 2016.74  → $DB_DIR/dropbear-2016.74"
                    else
                        echo -e "  ${RED}✗${NC} 2016.74  → no compilado"
                    fi
                    if [ "$DB2019" = "1" ]; then
                        echo -e "  ${GREEN}✓${NC} 2019.78  → $DB_DIR/dropbear-2019.78"
                    else
                        echo -e "  ${RED}✗${NC} 2019.78  → no compilado"
                    fi
                    echo -e "  ${GREEN}✓${NC} OpenSSH  → siempre disponible (fallback)"
                    echo ""
                    echo -e " ${CYAN}━━━ CAMBIAR VERSIÓN EN PUERTO 143 ━━━━━━━━━━━${NC}"
                    echo -e " ${BLUE}1)${NC} Poner Dropbear ${YELLOW}2016.74${NC} en :143 (recomendado)"
                    echo -e " ${BLUE}2)${NC} Poner Dropbear ${YELLOW}2019.78${NC} en :143"
                    echo -e " ${BLUE}3)${NC} Poner OpenSSH (fallback) en :143"
                    echo ""
                    echo -e " ${CYAN}━━━ CAMBIAR VERSIÓN EN PUERTO 142 ━━━━━━━━━━━${NC}"
                    echo -e " ${BLUE}4)${NC} Poner Dropbear ${YELLOW}2019.78${NC} en :142 (recomendado)"
                    echo -e " ${BLUE}5)${NC} Poner Dropbear ${YELLOW}2016.74${NC} en :142"
                    echo -e " ${BLUE}6)${NC} Desactivar puerto :142"
                    echo ""
                    echo -e " ${CYAN}━━━ OTRAS ACCIONES ━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
                    echo -e " ${BLUE}7)${NC} Reiniciar ambos puertos Dropbear"
                    echo -e " ${BLUE}8)${NC} Ver log Dropbear :143"
                    echo -e " ${BLUE}9)${NC} Ver log Dropbear :142"
                    echo -e " ${BLUE}10)${NC} Cambiar banner Dropbear"
                    echo -e " ${BLUE}11)${NC} Recompilar Dropbear 2016.74"
                    echo -e " ${BLUE}12)${NC} Recompilar Dropbear 2019.78"
                    echo -e " ${BLUE}0)${NC}  Volver al menú principal"
                    echo -e " ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
                    read -p " Opción: " db_opt

                    case $db_opt in
                        1)
                            if [ "$DB2016" != "1" ]; then
                                echo "✗ 2016.74 no compilado — usa opción 11"
                            else
                                _cambiar_dropbear_puerto "2016.74" 143 1143
                            fi
                            read -p "ENTER..."
                            ;;
                        2)
                            if [ "$DB2019" != "1" ]; then
                                echo "✗ 2019.78 no compilado — usa opción 12"
                            else
                                _cambiar_dropbear_puerto "2019.78" 143 1143
                            fi
                            read -p "ENTER..."
                            ;;
                        3)
                            _cambiar_dropbear_puerto "ssh_fallback" 143 1143
                            read -p "ENTER..."
                            ;;
                        4)
                            if [ "$DB2019" != "1" ]; then
                                echo "✗ 2019.78 no compilado — usa opción 12"
                            else
                                _cambiar_dropbear_puerto "2019.78" 142 1142
                            fi
                            read -p "ENTER..."
                            ;;
                        5)
                            if [ "$DB2016" != "1" ]; then
                                echo "✗ 2016.74 no compilado — usa opción 11"
                            else
                                _cambiar_dropbear_puerto "2016.74" 142 1142
                            fi
                            read -p "ENTER..."
                            ;;
                        6)
                            echo "Desactivando puerto 142..."
                            systemctl stop dropbear-2019-78 msy-wrap-142 2>/dev/null
                            fuser -k 142/tcp 2>/dev/null
                            echo "✓ Puerto 142 desactivado"
                            read -p "ENTER..."
                            ;;
                        7)
                            echo "Reiniciando Dropbear :143 y :142..."
                            systemctl restart dropbear-2016-74 msy-wrap-143 2>/dev/null
                            systemctl restart dropbear-2019-78 msy-wrap-142 2>/dev/null
                            sleep 2
                            echo -e ":143 $(port_status 143 t)"
                            echo -e ":142 $(port_status 142 t)"
                            read -p "ENTER..."
                            ;;
                        8)
                            clear
                            echo "LOG Dropbear :143 (últimas 25 líneas):"
                            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                            journalctl -u dropbear-2016-74 --no-pager -n 25 2>/dev/null \
                                || echo "  Sin logs disponibles"
                            read -p "ENTER..."
                            ;;
                        9)
                            clear
                            echo "LOG Dropbear :142 (últimas 25 líneas):"
                            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                            journalctl -u dropbear-2019-78 --no-pager -n 25 2>/dev/null \
                                || echo "  Sin logs disponibles"
                            read -p "ENTER..."
                            ;;
                        10)
                            clear
                            echo "BANNER DROPBEAR"
                            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                            echo "Banner actual:"
                            cat "$DB_KEYS/banner.txt" 2>/dev/null || echo "(vacío)"
                            echo ""
                            echo "Nuevo banner (escribe FIN en línea sola para terminar):"
                            > /tmp/new_banner.txt
                            while true; do
                                read -r line
                                [ "$line" = "FIN" ] && break
                                echo "$line" >> /tmp/new_banner.txt
                            done
                            if [ -s /tmp/new_banner.txt ]; then
                                cp /tmp/new_banner.txt "$DB_KEYS/banner.txt"
                                systemctl restart dropbear-2016-74 dropbear-2019-78 2>/dev/null
                                echo "✓ Banner actualizado y Dropbear reiniciado"
                            fi
                            rm -f /tmp/new_banner.txt
                            read -p "ENTER..."
                            ;;
                        11)
                            clear
                            echo "RECOMPILAR Dropbear 2016.74"
                            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                            # Determinar flags según GCC
                            GCC_NOW=$(gcc -dumpversion 2>/dev/null | cut -d. -f1); GCC_NOW=${GCC_NOW:-0}
                            if [ "$GCC_NOW" -ge 10 ] 2>/dev/null; then
                                CF_2016="-w -fcommon -Wno-error=implicit-function-declaration -Wno-error=implicit-int -Wno-error=int-conversion -Wno-error=incompatible-pointer-types -Wno-error=deprecated-declarations"
                            else
                                CF_2016="-w -fcommon"
                            fi
                            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq gcc make libc6-dev 2>/dev/null
                            _recompilar_dropbear \
                                "2016.74" \
                                "https://matt.ucc.asn.au/dropbear/releases/dropbear-2016.74.tar.bz2" \
                                "/opt/dropbear-2016" \
                                "$CF_2016"
                            if [ $? -eq 0 ]; then
                                read -p "¿Activar 2016.74 en :143 ahora? (s/n): " act
                                [[ $act == "s" || $act == "S" ]] && _cambiar_dropbear_puerto "2016.74" 143 1143
                            fi
                            read -p "ENTER..."
                            ;;
                        12)
                            clear
                            echo "RECOMPILAR Dropbear 2019.78"
                            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                            GCC_NOW=$(gcc -dumpversion 2>/dev/null | cut -d. -f1); GCC_NOW=${GCC_NOW:-0}
                            if [ "$GCC_NOW" -ge 12 ] 2>/dev/null; then
                                CF_2019="-w -fcommon -Wno-error=deprecated-declarations"
                            else
                                CF_2019="-w -fcommon"
                            fi
                            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq gcc make libc6-dev 2>/dev/null
                            _recompilar_dropbear \
                                "2019.78" \
                                "https://matt.ucc.asn.au/dropbear/releases/dropbear-2019.78.tar.bz2" \
                                "/opt/dropbear-2019" \
                                "$CF_2019"
                            if [ $? -eq 0 ]; then
                                read -p "¿Activar 2019.78 en :142 ahora? (s/n): " act
                                [[ $act == "s" || $act == "S" ]] && _cambiar_dropbear_puerto "2019.78" 142 1142
                            fi
                            read -p "ENTER..."
                            ;;
                        0) break ;;
                    esac
                done
                ;;

            8)
                clear
                if [ -f /usr/local/bin/hysteria-manager ]; then
                    bash /usr/local/bin/hysteria-manager
                else
                    echo "⚠ Hysteria UDP no está instalado"
                    read -p "¿Instalar ahora? (s/n): " install_hyst
                    if [[ $install_hyst == "s" || $install_hyst == "S" ]]; then
                        BASE_URL="https://raw.githubusercontent.com/juanitoprosniff/script_msyvpn/main/installer"
                        cd /root
                        wget -q -O install_agnudp.sh "$BASE_URL/install_agnudp.sh"
                        wget -q -O agnudp_manager.sh "$BASE_URL/agnudp_manager.sh"
                        if [ -f install_agnudp.sh ]; then
                            chmod +x install_agnudp.sh agnudp_manager.sh
                            bash install_agnudp.sh
                            cp agnudp_manager.sh /usr/local/bin/hysteria-manager
                            chmod +x /usr/local/bin/hysteria-manager
                            echo "✓ Hysteria instalado"
                        fi
                    fi
                    read -p "ENTER..."
                fi
                ;;

            9)
                clear
                echo -e "${CYAN}╔════════════════════════════════════════════╗${NC}"
                echo -e "${CYAN}║${NC}          ${BOLD}ESTADO DE SERVICIOS${NC}             ${CYAN}║${NC}"
                echo -e "${CYAN}╚════════════════════════════════════════════╝${NC}"
                echo ""

                systemctl is-active --quiet ssh \
                    && echo -e "${GREEN}✓ OpenSSH:          Activo${NC}  (puerto 22)" \
                    || echo -e "${RED}✗ OpenSSH:          Inactivo${NC}"

                # Dropbear :143
                if systemctl is-active --quiet dropbear-2016-74 2>/dev/null \
                   || systemctl is-active --quiet msy-wrap-143 2>/dev/null; then
                    echo -e "${GREEN}✓ Dropbear :143:    Activo${NC}  (v2016.74 — principal)"
                elif ss -tlnp 2>/dev/null | grep -q ":143 "; then
                    echo -e "${GREEN}✓ Puerto :143:      Activo${NC}  (servicio alternativo)"
                else
                    echo -e "${RED}✗ Dropbear :143:    Inactivo${NC}"
                fi

                # Dropbear :142
                if systemctl is-active --quiet dropbear-2019-78 2>/dev/null \
                   || systemctl is-active --quiet msy-wrap-142 2>/dev/null; then
                    echo -e "${GREEN}✓ Dropbear :142:    Activo${NC}  (v2019.78 — secundario)"
                elif ss -tlnp 2>/dev/null | grep -q ":142 "; then
                    echo -e "${GREEN}✓ Puerto :142:      Activo${NC}  (servicio alternativo)"
                else
                    echo -e "${YELLOW}⚠ Dropbear :142:    Inactivo${NC}"
                fi

                systemctl is-active --quiet stunnel4 \
                    && echo -e "${GREEN}✓ Stunnel SSL:      Activo${NC}  (443, 444, 777)" \
                    || echo -e "${RED}✗ Stunnel SSL:      Inactivo${NC}"
                systemctl is-active --quiet badvpn-udpgw \
                    && echo -e "${GREEN}✓ BadVPN UDPGW:     Activo${NC}  (UDP :7300)" \
                    || echo -e "${RED}✗ BadVPN UDPGW:     Inactivo${NC}"
                systemctl is-active --quiet hysteria 2>/dev/null \
                    && echo -e "${GREEN}✓ Hysteria UDP:     Activo${NC}" \
                    || echo -e "${YELLOW}⚠ Hysteria UDP:     No instalado / Inactivo${NC}"

                echo ""
                active_proxies=$(screen -ls 2>/dev/null | grep -c "proxy-")
                echo -e "${YELLOW}Python Proxies activos:${NC} $active_proxies"
                echo ""
                echo -e "${YELLOW}Disco:${NC} $(df -h / | awk 'NR==2{print $3"/"$2" ("$5" usado)"}')"
                echo -e "${YELLOW}RAM:${NC}   $(free -h | awk '/^Mem/{print $3"/"$2}')"
                echo -e "${YELLOW}Swap:${NC}  $(free -h | awk '/^Swap/{print $3"/"$2}')"
                echo ""
                echo -e "${CYAN}━━━ BINARIOS DROPBEAR ━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
                [ "$(_db_has_2016)" = "1" ] \
                    && echo -e "  ${GREEN}✓${NC} 2016.74  $DB_DIR/dropbear-2016.74" \
                    || echo -e "  ${RED}✗${NC} 2016.74  no compilado"
                [ "$(_db_has_2019)" = "1" ] \
                    && echo -e "  ${GREEN}✓${NC} 2019.78  $DB_DIR/dropbear-2019.78" \
                    || echo -e "  ${RED}✗${NC} 2019.78  no compilado"
                echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
                read -p "ENTER para continuar..."
                ;;

            10)
                clear
                echo "REINICIAR SERVICIOS"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                echo "1) Reiniciar proxies HTTP"
                echo "2) Reiniciar OpenSSH"
                echo "3) Reiniciar Dropbear :143 (2016.74)"
                echo "4) Reiniciar Dropbear :142 (2019.78)"
                echo "5) Reiniciar Stunnel"
                echo "6) Reiniciar BadVPN UDPGW"
                echo "7) Reiniciar Hysteria UDP"
                echo "8) Reiniciar TODO"
                echo "0) Volver"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                read -p "Opción: " restart_opt
                case $restart_opt in
                    1) restart_proxies; echo ""; read -p "ENTER..." ;;
                    2) systemctl restart ssh && echo "✓ OpenSSH reiniciado" || echo "✗ Error"; read -p "ENTER..." ;;
                    3) systemctl restart dropbear-2016-74 msy-wrap-143 2>/dev/null && echo "✓ Dropbear :143 reiniciado" || echo "✗ Error"; read -p "ENTER..." ;;
                    4) systemctl restart dropbear-2019-78 msy-wrap-142 2>/dev/null && echo "✓ Dropbear :142 reiniciado" || echo "✗ Error"; read -p "ENTER..." ;;
                    5) stunnel_restart; read -p "ENTER..." ;;
                    6) systemctl restart badvpn-udpgw && echo "✓ BadVPN reiniciado" || echo "✗ Error"; read -p "ENTER..." ;;
                    7) systemctl restart hysteria 2>/dev/null && echo "✓ Hysteria reiniciado" || echo "✗ Hysteria no instalado"; read -p "ENTER..." ;;
                    8) restart_all_services; echo ""; read -p "ENTER..." ;;
                esac
                ;;

            D|d)
                clear
                echo -e "${RED}╔══════════════════════════════════════════════╗${NC}"
                echo -e "${RED}║         DESINSTALAR MSY VPN SCRIPT           ║${NC}"
                echo -e "${RED}╚══════════════════════════════════════════════╝${NC}"
                echo ""
                echo -e "${YELLOW}Esto eliminará todos los servicios, archivos y${NC}"
                echo -e "${YELLOW}configuraciones instaladas por este script.${NC}"
                echo ""
                read -p "¿Confirmar desinstalación? (escribe SI para confirmar): " confirm
                if [ "$confirm" = "SI" ]; then
                    echo ""
                    echo "Desinstalando MSY VPN..."

                    kill_all_ports 2>/dev/null

                    echo "Deteniendo servicios..."
                    for svc in \
                        dropbear-2016-74 dropbear-2019-78 \
                        msy-wrap-143 msy-wrap-142 \
                        badvpn-udpgw stunnel4 restore-proxies proxy-watchdog hysteria; do
                        systemctl stop    "$svc" 2>/dev/null
                        systemctl disable "$svc" 2>/dev/null
                    done

                    echo "Eliminando procesos..."
                    pkill -9 -x stunnel4        2>/dev/null
                    pkill -9 -f "proxy.py"      2>/dev/null
                    pkill -9 -f "badvpn-udpgw"  2>/dev/null
                    pkill -9 -f "dropbear"       2>/dev/null
                    pkill -9 -f "msy-wrap"       2>/dev/null
                    screen -ls 2>/dev/null | grep "proxy-" | awk '{print $1}' | \
                        xargs -I {} screen -X -S {} quit 2>/dev/null

                    for p in 22 80 142 143 443 444 777 7300 8080 8880 8888; do
                        fuser -k "${p}/tcp" 2>/dev/null
                        fuser -k "${p}/udp" 2>/dev/null
                    done

                    echo "Eliminando archivos del sistema..."
                    for svcf in dropbear-2016-74 dropbear-2019-78 msy-wrap-143 msy-wrap-142 \
                                badvpn-udpgw restore-proxies proxy-watchdog; do
                        rm -f "/etc/systemd/system/${svcf}.service"
                    done
                    rm -f /usr/local/bin/msy-wrap-*.sh
                    systemctl daemon-reload

                    rm -rf /opt/dropbear-bins /opt/dropbear-2016 /opt/dropbear-2019
                    rm -f  /usr/bin/badvpn-udpgw
                    rm -rf /etc/dropbear-legacy /etc/proxy-python /etc/ssh-vpn /etc/hysteria 2>/dev/null

                    rm -f /etc/stunnel/stunnel.conf /etc/stunnel/stunnel.pem \
                          /etc/stunnel/stunnel.key  /etc/stunnel/stunnel.crt
                    echo "ENABLED=0" > /etc/default/stunnel4 2>/dev/null

                    rm -f /root/vpn-installer.sh /root/ssh-vpn-functions.sh \
                          /root/vpn-info.txt      /usr/local/bin/vpn-panel \
                          /usr/local/bin/vpn-manager /usr/local/bin/hysteria-manager 2>/dev/null

                    sed -i '/MSY VPN/,/fi/d' /root/.bashrc 2>/dev/null

                    rm -rf /usr/src/dropbear-2016.74 /usr/src/dropbear-2019.78 \
                           /usr/src/badvpn 2>/dev/null
                    rm -f  /usr/src/dropbear-2016.74.tar.bz2 \
                           /usr/src/dropbear-2019.78.tar.bz2 2>/dev/null

                    sed -i '/^Port 14[23]/d' /etc/ssh/sshd_config 2>/dev/null
                    systemctl restart ssh 2>/dev/null

                    echo ""
                    read -p "¿Eliminar también el Swap de 2GB? (s/n): " del_swap
                    if [[ $del_swap == "s" || $del_swap == "S" ]]; then
                        swapoff /swapfile 2>/dev/null
                        rm -f /swapfile
                        sed -i '/swapfile/d' /etc/fstab 2>/dev/null
                        echo "✓ Swap eliminado"
                    fi

                    echo ""
                    echo -e "${GREEN}✓ Desinstalación completada${NC}"
                    echo "  Eliminados: Dropbear 2016/2019, wrappers, BadVPN, Stunnel, Proxies"
                    echo "  OpenSSH se mantiene activo en puerto 22"
                    exit 0
                else
                    echo "Desinstalación cancelada."
                    read -p "ENTER para continuar..."
                fi
                ;;

            0)
                exit 0
                ;;
        esac
    done
}

menu_principal
MAINSCRIPT

chmod +x /root/vpn-installer.sh

# Acceso directo
cat > /usr/local/bin/vpn-panel <<'SHORTCUT'
#!/bin/bash
bash /root/vpn-installer.sh
SHORTCUT
chmod +x /usr/local/bin/vpn-panel
ln -sf /usr/local/bin/vpn-panel /usr/local/bin/vpn-manager

# Menú automático al login
sed -i '/MSY VPN/,/fi/d' /root/.bashrc 2>/dev/null
cat >> /root/.bashrc <<'AUTOEOF'

# MSY VPN - Menú automático
if [ -t 0 ] && [ -f /usr/local/bin/vpn-panel ]; then
    vpn-panel
fi
AUTOEOF

# Iniciar proxies
echo "Iniciando proxies por defecto..."
source /root/ssh-vpn-functions.sh
restore_proxies

# Resumen final
IP=$(curl -4 -s --max-time 5 ifconfig.me 2>/dev/null \
  || curl -4 -s --max-time 5 api4.ipify.org 2>/dev/null \
  || hostname -I | tr ' ' '\n' | grep -v ':' | head -1)

[ -z "$USER_VPN" ] && USER_VPN=$(ls /etc/ssh-vpn/users/*.txt 2>/dev/null | head -1 | xargs basename 2>/dev/null | sed 's/.txt//')
[ -z "$PASS_VPN" ] && PASS_VPN=$(grep "Contraseña:" /etc/ssh-vpn/users/${USER_VPN}.txt 2>/dev/null | awk '{print $2}')
[ -z "$ACTIVE_DB_VER" ] && ACTIVE_DB_VER=$(cat /etc/dropbear-legacy/active_version.txt 2>/dev/null || echo "?")

CYAN='\033[1;36m'; GREEN='\033[1;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

clear
echo -e "
${CYAN}╔══════════════════════════════════════════════╗${NC}
${CYAN}║${NC}  ${GREEN}✓ INSTALACIÓN COMPLETADA - v105${NC}          ${CYAN}║${NC}
${CYAN}╚══════════════════════════════════════════════╝${NC}

${YELLOW}IP (IPv4):${NC} ${CYAN}$IP${NC}

${GREEN}SERVICIOS:${NC}
  ✓ OpenSSH:              puerto :22
  ✓ Dropbear 2016.74:     puerto :143  ← PRINCIPAL
  ✓ Dropbear 2019.78:     puerto :142  ← SECUNDARIO
  ✓ Stunnel SSL/TLS:      :443, :444, :777
  ✓ Proxies Python:       :80, :8080, :8880, :8888 → DB:143
  ✓ BadVPN UDPGW:         UDP :7300
  ✓ Hysteria UDP:         ver opción 8 del panel

${YELLOW}CREDENCIALES:${NC}
  Usuario:   $USER_VPN
  Password:  $PASS_VPN

${YELLOW}PANEL:${NC} comando ${CYAN}vpn-panel${NC} (auto al conectar)

${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}
"

cat > /root/vpn-info.txt <<INFOEOF
MSY VPN SERVER v105
IP: $IP

SERVICIOS:
- OpenSSH:          :22
- Dropbear 2016.74: :143  (principal)
- Dropbear 2019.78: :142  (secundario)
- Stunnel:          :443→DB143 | :444→SSH22 | :777→DB143
- Proxies Python:   :80, :8080, :8880, :8888 → DB:143
- BadVPN UDPGW:     UDP :7300

USUARIO INICIAL:
$USER_VPN / $PASS_VPN

COMANDOS:
- Panel: vpn-panel
- Desinstalar: opción D del panel
INFOEOF

sleep 2
/usr/local/bin/vpn-panel
