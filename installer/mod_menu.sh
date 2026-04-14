#!/bin/bash
# mod_menu.sh - MSY VPN v106
# Panel principal con soporte completo:
#   - SSH Payload SNI (nuevo submenu en opción 5)
#   - SSL Remote Proxy (nuevo submenu en opción 5)
#   - Estado mejorado mostrando SNI proxies y SSL Remote
#   - restart_all_services incluye SNI proxies y SSL Remote
#   - Desinstalación limpia de todos los servicios nuevos

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
# FUNCIÓN: cambiar la versión de Dropbear en un puerto
# ============================================================
_cambiar_dropbear_puerto() {
    local VER="$1"
    local PPUB="$2"
    local PINT="$3"
    local BIN="$DB_DIR/dropbear-${VER}"
    local SVC="dropbear-${VER//./-}"
    local WR_SVC="msy-wrap-${PPUB}"

    for old_svc in dropbear-2016-74 dropbear-2019-78 msy-wrap-${PPUB}; do
        systemctl stop "$old_svc" 2>/dev/null
    done
    pkill -9 -f "dropbear.*${PINT}" 2>/dev/null
    pkill -9 -f "socat.*${PPUB}"    2>/dev/null
    fuser -k "${PPUB}/tcp" 2>/dev/null
    fuser -k "${PINT}/tcp" 2>/dev/null
    sleep 1

    if [ "$VER" = "ssh_fallback" ]; then
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

    if grep -q "^Port ${PPUB}" /etc/ssh/sshd_config 2>/dev/null; then
        sed -i "/^Port ${PPUB}/d" /etc/ssh/sshd_config
        systemctl restart ssh 2>/dev/null
    fi

    local KF=""
    [ -f "$DB_KEYS/dropbear_rsa_host_key" ]   && KF="$KF -r $DB_KEYS/dropbear_rsa_host_key"
    [ -f "$DB_KEYS/dropbear_ecdsa_host_key" ] && KF="$KF -r $DB_KEYS/dropbear_ecdsa_host_key"

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
# FUNCIÓN: RECOMPILAR DROPBEAR
# ============================================================
_recompilar_dropbear() {
    local VER="$1"
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

    if [ ! -s "$TB" ]; then echo "✗ No se pudo descargar el tarball"; cd /root; return 1; fi

    rm -rf "/usr/src/dropbear-${VER}"
    tar xjf "$TB" -C /usr/src 2>/dev/null
    cd "/usr/src/dropbear-${VER}" || { echo "✗ Error extrayendo"; cd /root; return 1; }

    for f in sysoptions.h default_options.h options.h; do
        [ -f "$f" ] && grep -q "LOCAL_IDENT" "$f" && \
            sed -i 's|#define LOCAL_IDENT.*|#define LOCAL_IDENT "SSH-2.0-ByJuanitoProSniff"|' "$f"
    done

    export CFLAGS="$CF"
    ./configure --prefix="$PREFIX" --disable-zlib --disable-wtmp --disable-lastlog >/dev/null 2>&1

    if echo "$VER" | grep -q "^2016"; then
        [ -d libtommath  ] && make -C libtommath  -j1 CFLAGS="$CF" >/dev/null 2>&1
        [ -d libtomcrypt ] && make -C libtomcrypt -j1 CFLAGS="$CF" >/dev/null 2>&1
    fi
    make -j$(nproc) PROGRAMS="dropbear dropbearkey" CFLAGS="$CF" >/tmp/db_compile_${VER}.log 2>&1

    if make install PROGRAMS="dropbear dropbearkey" >/dev/null 2>&1 \
            && [ -x "${PREFIX}/sbin/dropbear" ]; then
        cp "${PREFIX}/sbin/dropbear"   "$DEST_BIN"
        cp "${PREFIX}/bin/dropbearkey" "$DEST_KEY" 2>/dev/null
        chmod +x "$DEST_BIN" "$DEST_KEY" 2>/dev/null
        local VER_CORTA="${VER%%.*}"  # "2016" or "2019"
        echo "1" > "$DB_KEYS/has_${VER_CORTA}.txt"
        unset CFLAGS
        echo "✓ Dropbear $VER compilado correctamente"
        cd /root; return 0
    else
        unset CFLAGS
        echo "✗ Compilación fallida — últimas líneas del log:"
        tail -5 /tmp/db_compile_${VER}.log 2>/dev/null
        cd /root; return 1
    fi
}

# ============================================================
# MENÚ PRINCIPAL
# ============================================================
menu_principal() {
    while true; do
        clear

        DB_VER143=$(_db_active_ver)
        DB_VER142="2019.78"

        # Estado puertos
        port_status() {
            local port=$1 proto=${2:-tcp}
            if ss -${proto}lnp 2>/dev/null | grep -q ":${port} "; then
                echo -e "\033[1;32mON\033[0m"
            else
                echo -e "\033[1;31mOFF\033[0m"
            fi
        }

        S_SSH=$(port_status 22); S_DB143=$(port_status 143); S_DB142=$(port_status 142)
        S_SSL443=$(port_status 443); S_SSL444=$(port_status 444); S_SSL777=$(port_status 777)
        S_P80=$(port_status 80); S_P8080=$(port_status 8080)
        S_P8880=$(port_status 8880); S_P8888=$(port_status 8888)
        S_BADVPN=$(port_status 7300 udp)
        S_HYSTERIA=$(systemctl is-active --quiet hysteria 2>/dev/null && echo -e "\033[1;32mON\033[0m" || echo -e "\033[1;31mOFF\033[0m")
        S_SNIPROXY=$(screen -ls 2>/dev/null | grep -q "sni-" && echo -e "\033[1;32mON\033[0m" || echo -e "\033[1;31mOFF\033[0m")
        S_SSLREMOTE=$(pgrep -f "ssl-remote.conf" >/dev/null 2>&1 && echo -e "\033[1;32mON\033[0m" || echo -e "\033[1;31mOFF\033[0m")

        echo -e " \033[1;36m╔══════════════════════════════════════════════╗\033[0m"
        echo -e " \033[1;36m║\033[0m  \033[1m MSY VPN SCRIPT v106  t.me/FREEINTERNETVPNMSY\033[0m \033[1;36m║\033[0m"
        echo -e " \033[1;36m╚══════════════════════════════════════════════╝\033[0m"
        echo ""
        echo -e " \033[1;36m━━━ TCP ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
        echo -e "  SSH       :22   $S_SSH"
        echo -e "  DB v${DB_VER143}  :143  $S_DB143  ← Principal"
        echo -e "  DB v${DB_VER142}  :142  $S_DB142  ← Secundario"
        echo -e "  SSL       :443  $S_SSL443  │  SSL  :444  $S_SSL444"
        echo -e "  SSL       :777  $S_SSL777"
        echo -e "  Proxy     :80   $S_P80    │  Proxy :8080  $S_P8080"
        echo -e "  Proxy     :8880 $S_P8880  │  Proxy :8888  $S_P8888"
        echo -e "  SNI Proxy:      $S_SNIPROXY  │  SSL Remote: $S_SSLREMOTE"
        echo -e " \033[1;36m━━━ UDP ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
        echo -e "  BadVPN UDPGW :7300  $S_BADVPN"
        echo -e "  Hysteria UDP        $S_HYSTERIA"
        echo -e " \033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
        echo ""
        echo -e " \033[0;34m1)\033[0m Crear usuario       \033[0;34m2)\033[0m Eliminar usuario"
        echo -e " \033[0;34m3)\033[0m Ver conectados      \033[0;34m4)\033[0m Proxies HTTP"
        echo -e " \033[0;34m5)\033[0m Túneles SSL/SNI     \033[0;34m6)\033[0m Banner HTTP proxy"
        echo -e " \033[0;34m7)\033[0m Dropbear :143/:142  \033[0;34m8)\033[0m Hysteria UDP"
        echo -e " \033[0;34m9)\033[0m Estado servicios   \033[0;34m10)\033[0m Reiniciar servicios"
        echo -e "\033[1;31m D)\033[0m Desinstalar script  \033[1;31m 0)\033[0m Salir"
        echo -e " \033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
        read -p " Opción: " option

        case $option in
            1)
                clear
                echo "CREAR USUARIO VPN"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                read -p "Nombre de usuario: " username
                read -p "Contraseña: " password
                read -p "Días de validez (0 = ilimitado): \" days

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
                echo "PROXIES HTTP (Python)"
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
                # ============================================================
                # SUB-MENÚ SSL/TLS/SNI
                # ============================================================
                while true; do
                    clear
                    echo -e "\033[1;36m╔══════════════════════════════════════════════╗\033[0m"
                    echo -e "\033[1;36m║\033[0m       \033[1mTÚNELES SSL / SNI / REMOTE\033[0m         \033[1;36m║\033[0m"
                    echo -e "\033[1;36m╚══════════════════════════════════════════════╝\033[0m"
                    echo ""
                    echo -e " \033[1;33m── SSL/TLS SERVER (Stunnel) ────────────────\033[0m"
                    echo -e " \033[0;34m1)\033[0m Ver túneles SSL activos"
                    echo -e " \033[0;34m2)\033[0m Agregar nuevo túnel SSL"
                    echo -e " \033[0;34m3)\033[0m Desactivar / eliminar túnel SSL"
                    echo -e " \033[0;34m4)\033[0m Reiniciar Stunnel"
                    echo ""
                    echo -e " \033[1;33m── SSH PAYLOAD SNI PROXY ───────────────────\033[0m"
                    echo -e " \033[0;34m5)\033[0m Iniciar SSH Payload SNI Proxy"
                    echo -e " \033[0;34m6)\033[0m Ver SNI Proxies activos"
                    echo -e " \033[0;34m7)\033[0m Detener SNI Proxy"
                    echo ""
                    echo -e " \033[1;33m── SSL REMOTE PROXY (CLIENT MODE) ──────────\033[0m"
                    echo -e " \033[0;34m8)\033[0m Iniciar SSL Remote Proxy"
                    echo -e " \033[0;34m9)\033[0m Ver estado SSL Remote Proxy"
                    echo -e " \033[0;34mR)\033[0m Detener SSL Remote Proxy"
                    echo ""
                    echo -e " \033[1;31m0)\033[0m Volver"
                    echo -e " \033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
                    read -p " Opción: " tunnel_opt

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
                                && echo -e "\033[1;32m✓ Stunnel activo (PID: $(pgrep -x stunnel4 | head -1))\033[0m" \
                                || echo -e "\033[1;31m✗ Stunnel NO activo\033[0m"
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

                        # ── SSH PAYLOAD SNI ──────────────────────────────
                        5)
                            clear
                            echo "INICIAR SSH PAYLOAD SNI PROXY"
                            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                            echo "Conecta via SSL con SNI personalizado + payload HTTP"
                            echo "Útil cuando el operador requiere SNI específico"
                            echo ""
                            read -p "Puerto local (ej: 2443): " sni_local_port
                            read -p "Host remoto (IP o dominio): " sni_remote_host
                            read -p "Puerto remoto [443]: " sni_remote_port
                            sni_remote_port=${sni_remote_port:-443}
                            read -p "SNI host [ENTER = mismo que host remoto]: " sni_sni_host
                            sni_sni_host=${sni_sni_host:-$sni_remote_host}
                            echo ""
                            echo "Payload (usa [host],[port],[host_port],[crlf]):"
                            echo "  Ejemplo: CONNECT [host_port] HTTP/1.0[crlf]Host: [host][crlf][crlf]"
                            echo "  ENTER = payload CONNECT automático"
                            read -p "Payload: " sni_payload
                            echo "Backend SSH destino:"
                            echo "  1) Dropbear :143 (principal)"
                            echo "  2) Dropbear :142"
                            echo "  3) OpenSSH :22"
                            read -p "Opción [1]: " sni_backend
                            case $sni_backend in
                                2) sni_ssh_port=142 ;;
                                3) sni_ssh_port=22  ;;
                                *) sni_ssh_port=143 ;;
                            esac
                            echo ""
                            start_sni_proxy "$sni_local_port" "$sni_remote_host" \
                                            "$sni_remote_port" "$sni_sni_host" \
                                            "$sni_payload" "$sni_ssh_port"
                            echo ""
                            echo "Para conectar tu app VPN usa:"
                            echo "  Servidor: 127.0.0.1 (o IP del VPS)"
                            echo "  Puerto:   $sni_local_port"
                            echo "  SSL:      NO (el proxy maneja el SSL)"
                            read -p "ENTER..."
                            ;;
                        6)
                            clear
                            echo "SNI PROXIES ACTIVOS:"
                            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                            local found=0
                            screen -ls 2>/dev/null | grep "sni-" | while read -r line; do
                                port=$(echo "$line" | grep -oP 'sni-\K[0-9]+')
                                cfg=$(grep "^SNI_${port}|" /etc/proxy-python/sni-proxies.conf 2>/dev/null)
                                echo "  :$port — activo"
                                [ -n "$cfg" ] && echo "    Config: $cfg"
                                found=1
                            done
                            screen -ls 2>/dev/null | grep -q "sni-" || echo "  Ningún SNI Proxy activo"
                            echo ""
                            echo "Configuración guardada:"
                            cat /etc/proxy-python/sni-proxies.conf 2>/dev/null || echo "  (vacío)"
                            read -p "ENTER..."
                            ;;
                        7)
                            clear
                            echo "DETENER SNI PROXY"
                            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                            echo "SNI Proxies activos:"
                            screen -ls 2>/dev/null | grep "sni-" | awk '{print $1}' || echo "  Ninguno"
                            echo ""
                            read -p "Puerto a detener: " sni_stop_port
                            [ -n "$sni_stop_port" ] && stop_sni_proxy "$sni_stop_port" || echo "Cancelado."
                            read -p "ENTER..."
                            ;;

                        # ── SSL REMOTE PROXY ─────────────────────────────
                        8)
                            clear
                            echo "INICIAR SSL REMOTE PROXY"
                            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                            echo "Usa stunnel en modo CLIENT para conectar a un"
                            echo "servidor SSL remoto (CDN, CDNs, etc.)"
                            echo ""
                            read -p "Host remoto SSL (IP o dominio): " ssl_rem_host
                            read -p "Puerto remoto [443]: " ssl_rem_port
                            ssl_rem_port=${ssl_rem_port:-443}
                            read -p "SNI host [ENTER = mismo que host remoto]: " ssl_rem_sni
                            ssl_rem_sni=${ssl_rem_sni:-$ssl_rem_host}
                            read -p "Puerto local de salida [2443]: " ssl_rem_local
                            ssl_rem_local=${ssl_rem_local:-2443}
                            echo "Backend SSH destino tras el túnel:"
                            echo "  1) Dropbear :143 (principal)"
                            echo "  2) Dropbear :142"
                            echo "  3) OpenSSH :22"
                            read -p "Opción [1]: " ssl_rem_backend
                            case $ssl_rem_backend in
                                2) ssl_rem_ssh=142 ;;
                                3) ssl_rem_ssh=22  ;;
                                *) ssl_rem_ssh=143 ;;
                            esac
                            echo ""
                            ssl_remote_start "$ssl_rem_host" "$ssl_rem_port" \
                                             "$ssl_rem_sni"  "$ssl_rem_local" "$ssl_rem_ssh"
                            read -p "ENTER..."
                            ;;
                        9)
                            clear
                            echo "ESTADO SSL REMOTE PROXY"
                            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                            if pgrep -f "ssl-remote.conf" >/dev/null 2>&1; then
                                echo -e "\033[1;32m✓ SSL Remote Proxy activo\033[0m"
                                if [ -f /etc/ssh-vpn/ssl-remote.env ]; then
                                    source /etc/ssh-vpn/ssl-remote.env
                                    echo "  Remoto:  $REMOTE_HOST:$REMOTE_PORT"
                                    echo "  SNI:     $SNI_HOST"
                                    echo "  Local:   127.0.0.1:$LOCAL_OUT_PORT"
                                    echo "  SSH dst: $SSH_DEST_PORT"
                                fi
                            else
                                echo -e "\033[1;31m✗ SSL Remote Proxy NO activo\033[0m"
                                [ -f /etc/ssh-vpn/ssl-remote.env ] && echo "  (config guardada, se restaurará al reinicio)"
                            fi
                            echo ""
                            echo "Config SSL Remote:"
                            cat /etc/stunnel/ssl-remote.conf 2>/dev/null || echo "  (sin config activa)"
                            read -p "ENTER..."
                            ;;
                        R|r)
                            ssl_remote_stop
                            read -p "ENTER..."
                            ;;
                        0) break ;;
                    esac
                done
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
                # ── SUB-MENÚ DROPBEAR ────────────────────────────────
                while true; do
                    clear
                    DB2016=$(_db_has_2016)
                    DB2019=$(_db_has_2019)

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

                    echo -e "\033[1;36m╔══════════════════════════════════════════════╗\033[0m"
                    echo -e "\033[1;36m║\033[0m       \033[1mGESTIÓN DROPBEAR - MSY VPN\033[0m        \033[1;36m║\033[0m"
                    echo -e "\033[1;36m╚══════════════════════════════════════════════╝\033[0m"
                    echo ""
                    echo -e " \033[1;36m━━━ PUERTOS DROPBEAR ━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
                    echo -e "  Puerto \033[1;33m:143\033[0m → versión activa: \033[1;33m${VER143_ACTIVA}\033[0m  $ST143"
                    echo -e "  Puerto \033[1;33m:142\033[0m → versión activa: \033[1;33m${VER142_ACTIVA}\033[0m  $ST142"
                    echo ""
                    echo -e " \033[1;36m━━━ VERSIONES COMPILADAS ━━━━━━━━━━━━━━━━━━━\033[0m"
                    [ "$DB2016" = "1" ] \
                        && echo -e "  \033[1;32m✓\033[0m 2016.74  → $DB_DIR/dropbear-2016.74" \
                        || echo -e "  \033[1;31m✗\033[0m 2016.74  → no compilado"
                    [ "$DB2019" = "1" ] \
                        && echo -e "  \033[1;32m✓\033[0m 2019.78  → $DB_DIR/dropbear-2019.78" \
                        || echo -e "  \033[1;31m✗\033[0m 2019.78  → no compilado"
                    echo ""
                    echo -e " \033[1;36m━━━ ACCIONES PUERTO :143 ━━━━━━━━━━━━━━━━━━\033[0m"
                    echo -e " \033[0;34m1)\033[0m Poner Dropbear \033[1;33m2016.74\033[0m en :143 (recomendado)"
                    echo -e " \033[0;34m2)\033[0m Poner Dropbear \033[1;33m2019.78\033[0m en :143"
                    echo -e " \033[0;34m3)\033[0m Poner OpenSSH \033[1;33mfallback\033[0m en :143"
                    echo ""
                    echo -e " \033[1;36m━━━ ACCIONES PUERTO :142 ━━━━━━━━━━━━━━━━━━\033[0m"
                    echo -e " \033[0;34m4)\033[0m Poner Dropbear \033[1;33m2019.78\033[0m en :142 (recomendado)"
                    echo -e " \033[0;34m5)\033[0m Poner Dropbear \033[1;33m2016.74\033[0m en :142"
                    echo -e " \033[0;34m6)\033[0m Desactivar :142"
                    echo ""
                    echo -e " \033[1;36m━━━ COMPILACIÓN ━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
                    echo -e " \033[0;34m11)\033[0m Recompilar Dropbear 2016.74"
                    echo -e " \033[0;34m12)\033[0m Recompilar Dropbear 2019.78"
                    echo -e " \033[1;31m 0)\033[0m Volver"
                    echo -e " \033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
                    read -p " Opción: " db_opt

                    GCC_VER=$(gcc -dumpversion 2>/dev/null | cut -d. -f1); GCC_VER=${GCC_VER:-0}
                    if [ "$GCC_VER" -ge 10 ] 2>/dev/null; then
                        CF16="-w -fcommon -Wno-error=implicit-function-declaration -Wno-error=implicit-int -Wno-error=int-conversion -Wno-error=incompatible-pointer-types -Wno-error=deprecated-declarations"
                    else
                        CF16="-w -fcommon"
                    fi
                    if [ "$GCC_VER" -ge 12 ] 2>/dev/null; then
                        CF19="-w -fcommon -Wno-error=deprecated-declarations"
                    else
                        CF19="-w -fcommon"
                    fi

                    case $db_opt in
                        1)
                            [ "$DB2016" != "1" ] && { echo "✗ 2016.74 no compilado — usa opción 11"; read -p "ENTER..."; continue; }
                            _cambiar_dropbear_puerto "2016.74" 143 1143
                            read -p "ENTER..."
                            ;;
                        2)
                            [ "$DB2019" != "1" ] && { echo "✗ 2019.78 no compilado — usa opción 12"; read -p "ENTER..."; continue; }
                            _cambiar_dropbear_puerto "2019.78" 143 1143
                            read -p "ENTER..."
                            ;;
                        3)
                            _cambiar_dropbear_puerto "ssh_fallback" 143 1143
                            read -p "ENTER..."
                            ;;
                        4)
                            [ "$DB2019" != "1" ] && { echo "✗ 2019.78 no compilado — usa opción 12"; read -p "ENTER..."; continue; }
                            _cambiar_dropbear_puerto "2019.78" 142 1142
                            read -p "ENTER..."
                            ;;
                        5)
                            [ "$DB2016" != "1" ] && { echo "✗ 2016.74 no compilado — usa opción 11"; read -p "ENTER..."; continue; }
                            _cambiar_dropbear_puerto "2016.74" 142 1142
                            read -p "ENTER..."
                            ;;
                        6)
                            echo "Desactivando puerto 142..."
                            systemctl stop dropbear-2019-78 msy-wrap-142 2>/dev/null
                            fuser -k 142/tcp 2>/dev/null
                            echo "✓ Puerto :142 desactivado"
                            read -p "ENTER..."
                            ;;
                        11)
                            echo "RECOMPILAR Dropbear 2016.74"
                            _recompilar_dropbear "2016.74" \
                                "https://matt.ucc.asn.au/dropbear/releases/dropbear-2016.74.tar.bz2" \
                                "/opt/dropbear-2016" "$CF16"
                            read -p "ENTER..."
                            ;;
                        12)
                            echo "RECOMPILAR Dropbear 2019.78"
                            _recompilar_dropbear "2019.78" \
                                "https://matt.ucc.asn.au/dropbear/releases/dropbear-2019.78.tar.bz2" \
                                "/opt/dropbear-2019" "$CF19"
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
                echo -e "\033[1;36m╔════════════════════════════════════════════╗\033[0m"
                echo -e "\033[1;36m║\033[0m          \033[1mESTADO DE SERVICIOS\033[0m             \033[1;36m║\033[0m"
                echo -e "\033[1;36m╚════════════════════════════════════════════╝\033[0m"
                echo ""

                systemctl is-active --quiet ssh \
                    && echo -e "\033[1;32m✓ OpenSSH:          Activo\033[0m  (puerto 22)" \
                    || echo -e "\033[1;31m✗ OpenSSH:          Inactivo\033[0m"

                if systemctl is-active --quiet dropbear-2016-74 2>/dev/null \
                   || systemctl is-active --quiet msy-wrap-143 2>/dev/null; then
                    echo -e "\033[1;32m✓ Dropbear :143:    Activo\033[0m  (v2016.74 — principal)"
                elif ss -tlnp 2>/dev/null | grep -q ":143 "; then
                    echo -e "\033[1;32m✓ Puerto :143:      Activo\033[0m  (servicio alternativo)"
                else
                    echo -e "\033[1;31m✗ Dropbear :143:    Inactivo\033[0m"
                fi

                if systemctl is-active --quiet dropbear-2019-78 2>/dev/null \
                   || systemctl is-active --quiet msy-wrap-142 2>/dev/null; then
                    echo -e "\033[1;32m✓ Dropbear :142:    Activo\033[0m  (v2019.78 — secundario)"
                elif ss -tlnp 2>/dev/null | grep -q ":142 "; then
                    echo -e "\033[1;32m✓ Puerto :142:      Activo\033[0m  (servicio alternativo)"
                else
                    echo -e "\033[1;33m⚠ Dropbear :142:    Inactivo\033[0m"
                fi

                # Stunnel — verificar proceso real, no solo systemctl
                if pgrep -x stunnel4 >/dev/null 2>&1; then
                    echo -e "\033[1;32m✓ Stunnel SSL:      Activo\033[0m  (443, 444, 777)"
                else
                    echo -e "\033[1;31m✗ Stunnel SSL:      Inactivo\033[0m  ← usa Opción 10 → 5"
                fi

                systemctl is-active --quiet badvpn-udpgw \
                    && echo -e "\033[1;32m✓ BadVPN UDPGW:     Activo\033[0m  (UDP :7300)" \
                    || echo -e "\033[1;31m✗ BadVPN UDPGW:     Inactivo\033[0m"

                systemctl is-active --quiet hysteria 2>/dev/null \
                    && echo -e "\033[1;32m✓ Hysteria UDP:     Activo\033[0m" \
                    || echo -e "\033[1;33m⚠ Hysteria UDP:     No instalado / Inactivo\033[0m"

                # SSL Remote
                if pgrep -f "ssl-remote.conf" >/dev/null 2>&1; then
                    echo -e "\033[1;32m✓ SSL Remote Proxy: Activo\033[0m"
                else
                    echo -e "\033[1;33m⚠ SSL Remote Proxy: Inactivo\033[0m  (opcional)"
                fi

                echo ""
                active_proxies=$(screen -ls 2>/dev/null | grep -c "proxy-" || echo 0)
                active_sni=$(screen -ls 2>/dev/null | grep -c "sni-" || echo 0)
                echo -e "\033[1;33mProxy HTTP activos:\033[0m $active_proxies"
                echo -e "\033[1;33mSNI Proxies activos:\033[0m $active_sni"
                echo ""
                echo -e "\033[1;33mDisco:\033[0m $(df -h / | awk 'NR==2{print $3"/"$2" ("$5" usado)"}')"
                echo -e "\033[1;33mRAM:\033[0m   $(free -h | awk '/^Mem/{print $3"/"$2}')"
                echo -e "\033[1;33mSwap:\033[0m  $(free -h | awk '/^Swap/{print $3"/"$2}')"
                echo ""
                echo -e "\033[1;36m━━━ BINARIOS DROPBEAR ━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
                [ "$(_db_has_2016)" = "1" ] \
                    && echo -e "  \033[1;32m✓\033[0m 2016.74  $DB_DIR/dropbear-2016.74" \
                    || echo -e "  \033[1;31m✗\033[0m 2016.74  no compilado"
                [ "$(_db_has_2019)" = "1" ] \
                    && echo -e "  \033[1;32m✓\033[0m 2019.78  $DB_DIR/dropbear-2019.78" \
                    || echo -e "  \033[1;31m✗\033[0m 2019.78  no compilado"
                echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
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
                echo "8) Reiniciar SNI Proxies"
                echo "9) Reiniciar SSL Remote Proxy"
                echo "A) Reiniciar TODO"
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
                    8) 
                        echo "Reiniciando SNI Proxies..."
                        screen -ls 2>/dev/null | grep "sni-" | awk '{print $1}' | xargs -I {} screen -X -S {} quit 2>/dev/null
                        sleep 1
                        restore_sni_proxies
                        echo "✓ SNI Proxies reiniciados"
                        read -p "ENTER..."
                        ;;
                    9)
                        if [ -f /etc/ssh-vpn/ssl-remote.env ]; then
                            ssl_remote_stop
                            sleep 1
                            source /etc/ssh-vpn/ssl-remote.env
                            ssl_remote_start "$REMOTE_HOST" "$REMOTE_PORT" "$SNI_HOST" "$LOCAL_OUT_PORT" "$SSH_DEST_PORT"
                        else
                            echo "⚠ Sin config SSL Remote guardada"
                        fi
                        read -p "ENTER..."
                        ;;
                    A|a) restart_all_services; echo ""; read -p "ENTER..." ;;
                esac
                ;;

            D|d)
                clear
                echo -e "\033[1;31m╔══════════════════════════════════════════════╗\033[0m"
                echo -e "\033[1;31m║         DESINSTALAR MSY VPN SCRIPT           ║\033[0m"
                echo -e "\033[1;31m╚══════════════════════════════════════════════╝\033[0m"
                echo ""
                echo -e "\033[1;33mEsto eliminará todos los servicios, archivos y\033[0m"
                echo -e "\033[1;33mconfiguraciones instaladas por este script.\033[0m"
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
                        badvpn-udpgw stunnel4 restore-proxies proxy-watchdog \
                        ssl-remote-proxy hysteria; do
                        systemctl stop    "$svc" 2>/dev/null
                        systemctl disable "$svc" 2>/dev/null
                    done

                    echo "Eliminando procesos..."
                    pkill -9 -x stunnel4        2>/dev/null
                    pkill -9 -f "proxy.py"      2>/dev/null
                    pkill -9 -f "proxy_sni.py"  2>/dev/null
                    pkill -9 -f "ssl-remote"    2>/dev/null
                    pkill -9 -f "badvpn-udpgw"  2>/dev/null
                    pkill -9 -f "dropbear"       2>/dev/null
                    pkill -9 -f "msy-wrap"       2>/dev/null
                    screen -ls 2>/dev/null | grep -E "proxy-|sni-" | awk '{print $1}' | \
                        xargs -I {} screen -X -S {} quit 2>/dev/null

                    for p in 22 80 142 143 443 444 777 2443 7300 8080 8880 8888; do
                        fuser -k "${p}/tcp" 2>/dev/null
                        fuser -k "${p}/udp" 2>/dev/null
                    done

                    echo "Eliminando archivos del sistema..."
                    for svcf in dropbear-2016-74 dropbear-2019-78 msy-wrap-143 msy-wrap-142 \
                                badvpn-udpgw restore-proxies proxy-watchdog ssl-remote-proxy; do
                        rm -f "/etc/systemd/system/${svcf}.service"
                    done
                    rm -f /usr/local/bin/msy-wrap-*.sh
                    rm -f /usr/local/bin/ssl-remote-proxy-*.sh
                    systemctl daemon-reload

                    rm -rf /opt/dropbear-bins /opt/dropbear-2016 /opt/dropbear-2019
                    rm -f  /usr/bin/badvpn-udpgw
                    rm -rf /etc/dropbear-legacy /etc/proxy-python /etc/ssh-vpn /etc/hysteria 2>/dev/null

                    rm -f /etc/stunnel/stunnel.conf /etc/stunnel/ssl-remote.conf \
                          /etc/stunnel/stunnel.pem /etc/stunnel/stunnel.key /etc/stunnel/stunnel.crt
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
                    echo -e "\033[1;32m✓ Desinstalación completada\033[0m"
                    echo "  Eliminados: Dropbear 2016/2019, wrappers, BadVPN, Stunnel, Proxies, SNI, SSL Remote"
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

# Inyectar funciones extras de SSL/SNI en ssh-vpn-functions.sh
if [ -f /tmp/stunnel_extra_functions.sh ]; then
    cat /tmp/stunnel_extra_functions.sh >> /root/ssh-vpn-functions.sh
    rm -f /tmp/stunnel_extra_functions.sh
fi

# restart_all_services ahora incluye SNI y SSL Remote
cat >> /root/ssh-vpn-functions.sh <<'EXTRASVC'

# Sobrescribir restart_all_services con versión v106
restart_all_services() {
    echo "Reiniciando todos los servicios MSY VPN v106..."
    systemctl restart ssh              && echo "✓ OpenSSH"       || echo "✗ OpenSSH error"
    systemctl restart dropbear-2016-74 msy-wrap-143 2>/dev/null \
                                       && echo "✓ Dropbear :143" || echo "✗ Dropbear :143 error"
    systemctl restart dropbear-2019-78 msy-wrap-142 2>/dev/null \
                                       && echo "✓ Dropbear :142" || echo "⚠ Dropbear :142 no activo"
    stunnel_restart 1
    systemctl restart badvpn-udpgw    && echo "✓ BadVPN"        || echo "✗ BadVPN error"
    restart_proxies
    restore_sni_proxies
    # SSL Remote: solo si hay config guardada
    if [ -f /etc/ssh-vpn/ssl-remote.env ]; then
        ssl_remote_stop 2>/dev/null
        sleep 1
        source /etc/ssh-vpn/ssl-remote.env
        ssl_remote_start "$REMOTE_HOST" "$REMOTE_PORT" "$SNI_HOST" "$LOCAL_OUT_PORT" "$SSH_DEST_PORT"
    fi
    echo "✓ Listo"
}

# kill_all_ports v106: incluye SNI y SSL Remote
kill_all_ports() {
    echo "Liberando puertos..."
    for p in 443 444 777; do fuser -k "${p}/tcp" 2>/dev/null; done
    if [ -f /etc/stunnel/stunnel.conf ]; then
        while IFS= read -r line; do
            local p; p=$(echo "$line" | grep -oP ':\K[0-9]+$')
            [ -n "$p" ] && fuser -k "${p}/tcp" 2>/dev/null
        done < <(grep "^accept" /etc/stunnel/stunnel.conf)
    fi
    if [ -f /etc/proxy-python/proxies.conf ]; then
        while IFS='|' read -r port _rest; do
            [ -z "$port" ] && continue
            fuser -k "${port}/tcp" 2>/dev/null
        done < /etc/proxy-python/proxies.conf
    fi
    if [ -f /etc/proxy-python/sni-proxies.conf ]; then
        while IFS='|' read -r _tag local_port _rest; do
            [ -z "$local_port" ] && continue
            fuser -k "${local_port}/tcp" 2>/dev/null
        done < /etc/proxy-python/sni-proxies.conf
    fi
    [ -f /etc/ssh-vpn/ssl-remote.env ] && source /etc/ssh-vpn/ssl-remote.env
    [ -n "$LOCAL_OUT_PORT" ] && fuser -k "${LOCAL_OUT_PORT}/tcp" 2>/dev/null
    for p in 22 143 7300; do
        fuser -k "${p}/tcp" 2>/dev/null
        fuser -k "${p}/udp" 2>/dev/null
    done
    echo "✓ Puertos liberados"
}
EXTRASVC

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
${CYAN}║${NC}  ${GREEN}✓ INSTALACIÓN COMPLETADA - v106${NC}          ${CYAN}║${NC}
${CYAN}╚══════════════════════════════════════════════╝${NC}

${YELLOW}IP (IPv4):${NC} ${CYAN}$IP${NC}

${GREEN}SERVICIOS:${NC}
  ✓ OpenSSH:              puerto :22
  ✓ Dropbear 2016.74:     puerto :143  ← PRINCIPAL
  ✓ Dropbear 2019.78:     puerto :142  ← SECUNDARIO
  ✓ Stunnel SSL/TLS:      :443, :444, :777
  ✓ Proxies HTTP:         :80, :8080, :8880, :8888
  ✓ BadVPN UDPGW:         UDP :7300
  ✓ SSH Payload SNI:      Opción 5 del panel
  ✓ SSL Remote Proxy:     Opción 5 del panel
  ✓ Hysteria UDP:         Opción 8 del panel

${YELLOW}CREDENCIALES:${NC}
  Usuario:   $USER_VPN
  Password:  $PASS_VPN

${YELLOW}PANEL:${NC} comando ${CYAN}vpn-panel${NC} (auto al conectar)

${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}
"

sleep 2
/usr/local/bin/vpn-panel
