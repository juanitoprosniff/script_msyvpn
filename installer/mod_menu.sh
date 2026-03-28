#!/bin/bash
# mod_menu.sh - MSY VPN v104+
# Menú principal
# Cambios vs versión anterior:
#   - Sub-menú Dropbear (opción 7): cambiar entre 2016/2019/OpenSSH fallback
#   - Panel principal: BadVPN UDP y Hysteria UDP con estados separados
#   - curl -4 en toda IP pública → siempre muestra IPv4

# ============================================================
# HELPER: crear servicio systemd para una versión de Dropbear
# Se define aquí para que el bloque MAINSCRIPT pueda usarla
# ============================================================
cat > /root/vpn-installer.sh << 'MAINSCRIPT'
#!/bin/bash

if [ ! -f /root/ssh-vpn-functions.sh ]; then
    echo "Error: Archivo de funciones no encontrado"
    exit 1
fi

source /root/ssh-vpn-functions.sh

# ============================================================
# HELPER interno: leer archivos de estado de Dropbear
# ============================================================
_db_active_ver()  { cat /etc/dropbear-legacy/active_version.txt 2>/dev/null || echo "?"; }
_db_active_bin()  { cat /etc/dropbear-legacy/active_bin.txt     2>/dev/null || echo ""; }
_db_has_2016()    { cat /etc/dropbear-legacy/has_2016.txt        2>/dev/null || echo "0"; }
_db_has_2019()    { cat /etc/dropbear-legacy/has_2019.txt        2>/dev/null || echo "0"; }

# ============================================================
# HELPER: activar una versión de Dropbear
# ============================================================
activar_dropbear() {
    local VER=$1   # "2016", "2019", o "ssh_fallback"
    local BIN=""
    local KEYBIN=""

    case "$VER" in
        2016)
            BIN="/opt/dropbear-2016/sbin/dropbear"
            KEYBIN="/opt/dropbear-2016/bin/dropbearkey"
            ;;
        2019)
            BIN="/opt/dropbear-2019/sbin/dropbear"
            KEYBIN="/opt/dropbear-2019/bin/dropbearkey"
            ;;
        ssh_fallback)
            # Agregar puerto 143 a OpenSSH si no está
            systemctl stop dropbear-legacy 2>/dev/null
            fuser -k 143/tcp 2>/dev/null
            sleep 1
            if ! grep -q "^Port 143" /etc/ssh/sshd_config; then
                sed -i '/^Port 22/a Port 143' /etc/ssh/sshd_config
            fi
            systemctl restart ssh
            echo "ssh_fallback" > /etc/dropbear-legacy/active_version.txt
            echo ""             > /etc/dropbear-legacy/active_bin.txt
            ss -tlnp | grep -q ":143 " \
                && echo "✓ OpenSSH activo en :143" \
                || echo "✗ Falló activar OpenSSH en :143"
            return
            ;;
        *)
            echo "✗ Versión desconocida: $VER"
            return 1
            ;;
    esac

    if [ ! -f "$BIN" ]; then
        echo "✗ Binario Dropbear $VER no encontrado: $BIN"
        echo "  ¿Se compiló correctamente durante la instalación?"
        return 1
    fi

    # Generar llaves si no existen (con el keybin de la versión elegida)
    mkdir -p /etc/dropbear-legacy
    [ ! -f /etc/dropbear-legacy/dropbear_rsa_host_key ] && \
        "$KEYBIN" -t rsa -f /etc/dropbear-legacy/dropbear_rsa_host_key -s 2048 >/dev/null 2>&1
    [ ! -f /etc/dropbear-legacy/dropbear_ecdsa_host_key ] && \
        "$KEYBIN" -t ecdsa -f /etc/dropbear-legacy/dropbear_ecdsa_host_key >/dev/null 2>&1

    # Construir flags de llaves
    local KEY_FLAGS=""
    [ -f /etc/dropbear-legacy/dropbear_rsa_host_key ]   && KEY_FLAGS="$KEY_FLAGS -r /etc/dropbear-legacy/dropbear_rsa_host_key"
    [ -f /etc/dropbear-legacy/dropbear_ecdsa_host_key ] && KEY_FLAGS="$KEY_FLAGS -r /etc/dropbear-legacy/dropbear_ecdsa_host_key"

    # Detener versión anterior y liberar puerto
    systemctl stop dropbear-legacy 2>/dev/null
    pkill -9 -f "dropbear.*143" 2>/dev/null
    fuser -k 143/tcp 2>/dev/null
    sleep 1

    # Si antes usábamos OpenSSH en :143, quitarlo del sshd_config
    if grep -q "^Port 143" /etc/ssh/sshd_config 2>/dev/null; then
        sed -i '/^Port 143/d' /etc/ssh/sshd_config
        systemctl restart ssh 2>/dev/null
    fi

    # Escribir nuevo unit
    cat > /etc/systemd/system/dropbear-legacy.service <<DBSVC
[Unit]
Description=Dropbear SSH ${VER} - Puerto 143 (MSY VPN)
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=${BIN} -F -E \\
    -p 0.0.0.0:143 \\
    ${KEY_FLAGS} \\
    -b /etc/dropbear-legacy/banner.txt \\
    -K 60 -I 300
Restart=always
RestartSec=5
KillMode=process
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
DBSVC

    systemctl daemon-reload
    systemctl enable dropbear-legacy >/dev/null 2>&1
    systemctl restart dropbear-legacy
    sleep 2

    if systemctl is-active --quiet dropbear-legacy; then
        echo "$VER"  > /etc/dropbear-legacy/active_version.txt
        echo "$BIN"  > /etc/dropbear-legacy/active_bin.txt
        echo "✓ Dropbear $VER activo en 0.0.0.0:143"
    else
        echo "✗ Dropbear $VER no inició — log:"
        journalctl -u dropbear-legacy --no-pager -n 10 2>/dev/null || true
        echo ""
        echo "  Intento directo:"
        $BIN -F -E -p 0.0.0.0:143 $KEY_FLAGS \
            -b /etc/dropbear-legacy/banner.txt -K 60 -I 300 2>&1 | head -5
    fi
}

# ============================================================
# MENÚ PRINCIPAL
# ============================================================
menu_principal() {
    while true; do
        clear

        # IP pública siempre en IPv4
        IP=$(curl -4 -s --max-time 5 ifconfig.me 2>/dev/null \
          || curl -4 -s --max-time 5 api4.ipify.org 2>/dev/null \
          || hostname -I | tr ' ' '\n' | grep -v ':' | head -1)

        # Estados de puertos
        S_SSH=$(port_status 22 t)
        S_DB=$(port_status 143 t)
        S_SSL443=$(port_status 443 t)
        S_SSL444=$(port_status 444 t)
        S_SSL777=$(port_status 777 t)
        S_P80=$(port_status 80 t)
        S_P8080=$(port_status 8080 t)
        S_P8880=$(port_status 8880 t)
        S_P8888=$(port_status 8888 t)
        # BadVPN y Hysteria: estados separados
        S_BADVPN=$(port_status 7300 u)
        S_HYSTERIA=$(systemctl is-active --quiet hysteria 2>/dev/null && echo -e "\033[1;32mON\033[0m" || echo -e "\033[1;31mOFF\033[0m")

        # Versión activa de Dropbear
        DB_VER=$(_db_active_ver)

        echo -e "${CYAN}╔══════════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║${NC}     ${BOLD}MSY VPN PANEL - v104 Minimalista${NC}    ${CYAN}║${NC}"
        echo -e "${CYAN}╚══════════════════════════════════════════════╝${NC}"
        echo -e " ${GREEN}IP:${NC} ${YELLOW}$IP${NC}"
        echo ""
        echo -e " ${CYAN}━━━ PUERTOS ACTIVOS ━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "  SSH   :22   $S_SSH    │  DB${DB_VER}  :143  $S_DB"
        echo -e "  SSL   :443  $S_SSL443  │  SSL      :444  $S_SSL444"
        echo -e "  SSL   :777  $S_SSL777"
        echo -e "  Proxy :80   $S_P80    │  Proxy   :8080  $S_P8080"
        echo -e "  Proxy :8880 $S_P8880  │  Proxy   :8888  $S_P8888"
        echo -e " ${CYAN}━━━ UDP ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "  BadVPN UDPGW :7300  $S_BADVPN"
        echo -e "  Hysteria UDP        $S_HYSTERIA"
        echo -e " ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        echo -e " ${BLUE}1)${NC} Crear usuario       ${BLUE}2)${NC} Eliminar usuario"
        echo -e " ${BLUE}3)${NC} Ver conectados      ${BLUE}4)${NC} Proxies Python"
        echo -e " ${BLUE}5)${NC} Túneles SSL/TLS     ${BLUE}6)${NC} Banner HTTP proxy"
        echo -e " ${BLUE}7)${NC} Dropbear (v${DB_VER})     ${BLUE}8)${NC} Hysteria UDP"
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

                cat > /etc/ssh-vpn/users/$username.txt <<USEREOF
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
                rm -f /etc/ssh-vpn/users/$username.txt
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
                        echo "  1) Dropbear :143 (default)"
                        echo "  2) OpenSSH  :22"
                        echo "  3) Otro puerto"
                        read -p "Opción [1]: " backend
                        case $backend in
                            2) ssh_port=22 ;;
                            3) read -p "Puerto: " ssh_port ;;
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
                        echo "Config guardada:"
                        cat /etc/proxy-python/proxies.conf 2>/dev/null || echo "  Sin config"
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
                            && echo -e "${GREEN}✓ Stunnel proceso activo (PID: $(pgrep -x stunnel4 | head -1))${NC}" \
                            || echo -e "${RED}✗ Stunnel proceso NO activo${NC}"
                        read -p "ENTER..."
                        ;;
                    2)
                        clear
                        echo "AGREGAR NUEVO TÚNEL SSL"
                        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                        read -p "Nombre del túnel (ej: tunnel-8443): " tunnel_name
                        read -p "Puerto de escucha (ej: 8443): " tunnel_port
                        echo "Backend destino:"
                        echo "  22  - OpenSSH"
                        echo "  143 - Dropbear (recomendado)"
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
                # ============================================================
                while true; do
                    clear
                    DB_VER_NOW=$(_db_active_ver)
                    DB2016=$(_db_has_2016)
                    DB2019=$(_db_has_2019)

                    echo -e "${CYAN}╔══════════════════════════════════════════════╗${NC}"
                    echo -e "${CYAN}║${NC}         ${BOLD}GESTIÓN DROPBEAR SSH :143${NC}        ${CYAN}║${NC}"
                    echo -e "${CYAN}╚══════════════════════════════════════════════╝${NC}"
                    echo ""
                    echo -e " Versión activa: ${YELLOW}${DB_VER_NOW}${NC}"
                    echo ""
                    echo " Estado del puerto 143: $(port_status 143 t)"
                    echo " Servicio systemd:      $(systemctl is-active dropbear-legacy 2>/dev/null || echo inactive)"
                    echo ""
                    echo -e " ${CYAN}━━━ VERSIONES DISPONIBLES ━━━━━━━━━━━━━━━━━━${NC}"

                    # Mostrar disponibilidad con estado visual
                    if [ "$DB2016" = "1" ]; then
                        echo -e "  ${GREEN}✓${NC} Dropbear 2016.74  (/opt/dropbear-2016)"
                    else
                        echo -e "  ${RED}✗${NC} Dropbear 2016.74  (no compilado)"
                    fi
                    if [ "$DB2019" = "1" ]; then
                        echo -e "  ${GREEN}✓${NC} Dropbear 2019.78  (/opt/dropbear-2019)"
                    else
                        echo -e "  ${RED}✗${NC} Dropbear 2019.78  (no compilado)"
                    fi
                    echo -e "  ${GREEN}✓${NC} OpenSSH fallback  (siempre disponible)"
                    echo ""
                    echo -e " ${CYAN}━━━ ACCIONES ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
                    echo -e " ${BLUE}1)${NC} Activar Dropbear 2016.74"
                    echo -e " ${BLUE}2)${NC} Activar Dropbear 2019.78"
                    echo -e " ${BLUE}3)${NC} Activar OpenSSH fallback en :143"
                    echo -e " ${BLUE}4)${NC} Reiniciar Dropbear activo"
                    echo -e " ${BLUE}5)${NC} Ver log de Dropbear (últimas 20 líneas)"
                    echo -e " ${BLUE}6)${NC} Cambiar banner Dropbear"
                    echo -e " ${BLUE}7)${NC} Recompilar Dropbear 2016.74"
                    echo -e " ${BLUE}8)${NC} Recompilar Dropbear 2019.78"
                    echo -e " ${BLUE}0)${NC} Volver al menú principal"
                    echo -e " ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
                    read -p " Opción: " db_opt

                    case $db_opt in
                        1)
                            if [ "$DB2016" != "1" ]; then
                                echo "✗ Dropbear 2016.74 no está compilado"
                                echo "  Usa la opción 7 para recompilarlo"
                            else
                                activar_dropbear "2016"
                            fi
                            read -p "ENTER..."
                            ;;
                        2)
                            if [ "$DB2019" != "1" ]; then
                                echo "✗ Dropbear 2019.78 no está compilado"
                                echo "  Usa la opción 8 para recompilarlo"
                            else
                                activar_dropbear "2019"
                            fi
                            read -p "ENTER..."
                            ;;
                        3)
                            activar_dropbear "ssh_fallback"
                            read -p "ENTER..."
                            ;;
                        4)
                            echo "Reiniciando Dropbear..."
                            systemctl restart dropbear-legacy 2>/dev/null
                            sleep 2
                            systemctl is-active --quiet dropbear-legacy \
                                && echo "✓ Dropbear reiniciado" \
                                || echo "✗ Error al reiniciar — ver opción 5"
                            read -p "ENTER..."
                            ;;
                        5)
                            clear
                            echo "LOG DROPBEAR (últimas 20 líneas):"
                            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                            journalctl -u dropbear-legacy --no-pager -n 20 2>/dev/null \
                                || echo "  Sin logs disponibles"
                            echo ""
                            read -p "ENTER..."
                            ;;
                        6)
                            clear
                            echo "BANNER DROPBEAR"
                            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                            echo "Banner actual:"
                            cat /etc/dropbear-legacy/banner.txt 2>/dev/null || echo "(vacío)"
                            echo ""
                            echo "Nuevo banner (escribe FIN en línea sola para terminar):"
                            > /tmp/new_banner.txt
                            while true; do
                                read -r line
                                [ "$line" = "FIN" ] && break
                                echo "$line" >> /tmp/new_banner.txt
                            done
                            if [ -s /tmp/new_banner.txt ]; then
                                cp /tmp/new_banner.txt /etc/dropbear-legacy/banner.txt
                                systemctl restart dropbear-legacy 2>/dev/null
                                echo "✓ Banner actualizado y Dropbear reiniciado"
                            fi
                            rm -f /tmp/new_banner.txt
                            read -p "ENTER..."
                            ;;
                        7|8)
                            VER_RECOMP="2016.74"; URL_RECOMP="https://matt.ucc.asn.au/dropbear/releases/dropbear-2016.74.tar.bz2"; PREFIX_RECOMP="/opt/dropbear-2016"
                            [ "$db_opt" = "8" ] && { VER_RECOMP="2019.78"; URL_RECOMP="https://matt.ucc.asn.au/dropbear/releases/dropbear-2019.78.tar.bz2"; PREFIX_RECOMP="/opt/dropbear-2019"; }

                            clear
                            echo "RECOMPILAR Dropbear $VER_RECOMP"
                            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

                            GCC_VER_NOW=$(gcc -dumpversion 2>/dev/null | cut -d. -f1); GCC_VER_NOW=${GCC_VER_NOW:-0}
                            COMPAT_CF=""
                            [ "$GCC_VER_NOW" -ge 12 ] 2>/dev/null && \
                                COMPAT_CF="-Wno-error=implicit-function-declaration -Wno-error=implicit-int -Wno-error=int-conversion -Wno-error=incompatible-pointer-types"

                            cd /usr/src
                            TARBALL="dropbear-${VER_RECOMP}.tar.bz2"
                            [ ! -f "$TARBALL" ] || [ ! -s "$TARBALL" ] && \
                                wget -q -O "$TARBALL" "$URL_RECOMP" 2>/dev/null

                            # Mirror alternativo
                            [ ! -s "$TARBALL" ] && \
                                wget -q -O "$TARBALL" "https://dropbear.nl/mirror/releases/$TARBALL" 2>/dev/null

                            if [ ! -s "$TARBALL" ]; then
                                echo "✗ No se pudo descargar el tarball"
                                cd /root; read -p "ENTER..."; continue
                            fi

                            rm -rf "/usr/src/dropbear-${VER_RECOMP}" 2>/dev/null
                            tar xjf "$TARBALL" -C /usr/src 2>/dev/null
                            cd "/usr/src/dropbear-${VER_RECOMP}"

                            for f in sysoptions.h default_options.h options.h; do
                                [ -f "$f" ] && grep -q "LOCAL_IDENT" "$f" && \
                                    sed -i 's|#define LOCAL_IDENT.*|#define LOCAL_IDENT "SSH-2.0-ByJuanitoProSniff"|' "$f"
                            done

                            export CFLAGS="$COMPAT_CF"
                            ./configure --prefix="$PREFIX_RECOMP" \
                                --disable-zlib --disable-wtmp --disable-lastlog \
                                >/dev/null 2>&1

                            echo "Compilando... (2-4 min)"
                            if make -j$(nproc) PROGRAMS="dropbear dropbearkey" \
                                    CFLAGS="$COMPAT_CF" >/tmp/recomp_db.log 2>&1; then
                                make install PROGRAMS="dropbear dropbearkey" >/dev/null 2>&1
                                unset CFLAGS
                                if [ -f "${PREFIX_RECOMP}/sbin/dropbear" ]; then
                                    echo "✓ Dropbear $VER_RECOMP compilado"
                                    NUEVO_VER=$(echo "$VER_RECOMP" | cut -d. -f1)
                                    echo "1" > "/etc/dropbear-legacy/has_${NUEVO_VER}.txt"
                                    read -p "¿Activar ahora? (s/n): " act
                                    [[ $act == "s" || $act == "S" ]] && activar_dropbear "$NUEVO_VER"
                                else
                                    echo "✗ Compilación falló — binario no encontrado"
                                fi
                            else
                                unset CFLAGS
                                echo "✗ Compilación falló — error:"
                                tail -10 /tmp/recomp_db.log
                            fi
                            cd /root
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
                DB_VER_NOW=$(_db_active_ver)
                systemctl is-active --quiet ssh \
                    && echo -e "${GREEN}✓ OpenSSH:         Activo${NC}  (puerto 22)" \
                    || echo -e "${RED}✗ OpenSSH:         Inactivo${NC}"
                systemctl is-active --quiet dropbear-legacy 2>/dev/null \
                    && echo -e "${GREEN}✓ Dropbear ${DB_VER_NOW}:  Activo${NC}  (puerto 143)" \
                    || echo -e "${RED}✗ Dropbear ${DB_VER_NOW}:  Inactivo${NC}"
                systemctl is-active --quiet stunnel4 \
                    && echo -e "${GREEN}✓ Stunnel SSL:     Activo${NC}  (443, 444, 777)" \
                    || echo -e "${RED}✗ Stunnel SSL:     Inactivo${NC}"
                # BadVPN y Hysteria separados
                systemctl is-active --quiet badvpn-udpgw \
                    && echo -e "${GREEN}✓ BadVPN UDPGW:    Activo${NC}  (UDP :7300)" \
                    || echo -e "${RED}✗ BadVPN UDPGW:    Inactivo${NC}"
                systemctl is-active --quiet hysteria 2>/dev/null \
                    && echo -e "${GREEN}✓ Hysteria UDP:    Activo${NC}" \
                    || echo -e "${YELLOW}⚠ Hysteria UDP:    No instalado / Inactivo${NC}"
                echo ""
                active_proxies=$(screen -ls 2>/dev/null | grep -c "proxy-")
                echo -e "${YELLOW}Python Proxies activos:${NC} $active_proxies"
                echo ""
                echo -e "${YELLOW}Disco:${NC} $(df -h / | awk 'NR==2{print $3"/"$2" ("$5" usado)"}')"
                echo -e "${YELLOW}RAM:${NC}   $(free -h | awk '/^Mem/{print $3"/"$2}')"
                echo -e "${YELLOW}Swap:${NC}  $(free -h | awk '/^Swap/{print $3"/"$2}')"
                echo ""
                echo -e "${CYAN}━━━ DROPBEAR DISPONIBLES ━━━━━━━━━━━━━━━━━━━━━${NC}"
                [ "$(_db_has_2016)" = "1" ] && echo -e "  ${GREEN}✓${NC} 2016.74  /opt/dropbear-2016/sbin/dropbear" || echo -e "  ${RED}✗${NC} 2016.74  no compilado"
                [ "$(_db_has_2019)" = "1" ] && echo -e "  ${GREEN}✓${NC} 2019.78  /opt/dropbear-2019/sbin/dropbear" || echo -e "  ${RED}✗${NC} 2019.78  no compilado"
                echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
                read -p "ENTER para continuar..."
                ;;

            10)
                clear
                echo "REINICIAR SERVICIOS"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                echo "1) Reiniciar proxies HTTP"
                echo "2) Reiniciar OpenSSH"
                echo "3) Reiniciar Dropbear"
                echo "4) Reiniciar Stunnel"
                echo "5) Reiniciar BadVPN UDPGW"
                echo "6) Reiniciar Hysteria UDP"
                echo "7) Reiniciar TODO"
                echo "0) Volver"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                read -p "Opción: " restart_opt
                case $restart_opt in
                    1) restart_proxies; echo ""; read -p "ENTER..." ;;
                    2) systemctl restart ssh && echo "✓ OpenSSH reiniciado" || echo "✗ Error"; read -p "ENTER..." ;;
                    3) systemctl restart dropbear-legacy && echo "✓ Dropbear reiniciado" || echo "✗ Error"; read -p "ENTER..." ;;
                    4) stunnel_restart; read -p "ENTER..." ;;
                    5) systemctl restart badvpn-udpgw && echo "✓ BadVPN reiniciado" || echo "✗ Error"; read -p "ENTER..." ;;
                    6) systemctl restart hysteria 2>/dev/null && echo "✓ Hysteria reiniciado" || echo "✗ Hysteria no instalado"; read -p "ENTER..." ;;
                    7) restart_all_services; echo ""; read -p "ENTER..." ;;
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

                    # PASO 1: liberar puertos antes de detener servicios
                    kill_all_ports

                    # PASO 2: detener y deshabilitar todo
                    echo "Deteniendo servicios..."
                    for svc in dropbear-legacy badvpn-udpgw stunnel4 restore-proxies proxy-watchdog hysteria; do
                        systemctl stop    "$svc" 2>/dev/null
                        systemctl disable "$svc" 2>/dev/null
                    done

                    # PASO 3: matar procesos residuales
                    echo "Eliminando procesos..."
                    pkill -9 -x stunnel4            2>/dev/null
                    pkill -9 -f "stunnel4 /etc"     2>/dev/null
                    pkill -9 -f "proxy.py"          2>/dev/null
                    pkill -9 -f "badvpn-udpgw"      2>/dev/null
                    pkill -9 -f "watchdog.sh"        2>/dev/null
                    pkill -9 -f "dropbear.*143"      2>/dev/null
                    screen -ls 2>/dev/null | grep "proxy-" | awk '{print $1}' | \
                        xargs -I {} screen -X -S {} quit 2>/dev/null

                    # PASO 4: segunda liberación de puertos
                    for p in 22 80 143 443 444 777 7300 8080 8880 8888; do
                        fuser -k "${p}/tcp" 2>/dev/null
                        fuser -k "${p}/udp" 2>/dev/null
                    done

                    # Eliminar archivos systemd
                    echo "Eliminando archivos del sistema..."
                    for svcf in dropbear-legacy badvpn-udpgw restore-proxies proxy-watchdog; do
                        rm -f "/etc/systemd/system/${svcf}.service"
                    done
                    systemctl daemon-reload

                    # Eliminar binarios compilados
                    rm -rf /opt/dropbear-2016 /opt/dropbear-2019
                    rm -f  /usr/bin/badvpn-udpgw

                    # Eliminar configs y dirs del script
                    rm -rf /etc/dropbear-legacy /etc/proxy-python /etc/ssh-vpn /etc/hysteria 2>/dev/null

                    # Stunnel: eliminar conf pero no el paquete
                    rm -f /etc/stunnel/stunnel.conf /etc/stunnel/stunnel.pem \
                          /etc/stunnel/stunnel.key  /etc/stunnel/stunnel.crt
                    echo "ENABLED=0" > /etc/default/stunnel4

                    # Eliminar scripts del panel
                    rm -f /root/vpn-installer.sh /root/ssh-vpn-functions.sh \
                          /root/vpn-info.txt      /usr/local/bin/vpn-panel \
                          /usr/local/bin/vpn-manager /usr/local/bin/hysteria-manager 2>/dev/null

                    # Eliminar menú automático del bashrc
                    sed -i '/MSY VPN/,/fi/d' /root/.bashrc 2>/dev/null

                    # Eliminar fuentes descargadas
                    rm -rf /usr/src/dropbear-2016.74 /usr/src/dropbear-2019.78 \
                           /usr/src/badvpn 2>/dev/null
                    rm -f  /usr/src/dropbear-2016.74.tar.bz2 \
                           /usr/src/dropbear-2019.78.tar.bz2 2>/dev/null
                    rm -f  /root/install_agnudp.sh /root/agnudp_manager.sh 2>/dev/null

                    # Quitar Port 143 de sshd_config si se usó como fallback
                    sed -i '/^Port 143/d' /etc/ssh/sshd_config 2>/dev/null
                    systemctl restart ssh 2>/dev/null

                    # Swap (opcional)
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
                    echo "  Servicios eliminados: Dropbear 2016/2019, BadVPN, Stunnel, Proxies, Watchdog"
                    echo "  OpenSSH se mantiene activo en puerto 22"
                    echo "  Todos los puertos han sido liberados"
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
${CYAN}║${NC}  ${GREEN}✓ INSTALACIÓN COMPLETADA - v104${NC}          ${CYAN}║${NC}
${CYAN}╚══════════════════════════════════════════════╝${NC}

${YELLOW}IP (IPv4):${NC} ${CYAN}$IP${NC}

${GREEN}SERVICIOS:${NC}
  ✓ OpenSSH:           puerto 22
  ✓ Dropbear ${ACTIVE_DB_VER}:     puerto 143  (SSH-2.0-ByJuanitoProSniff)
  ✓ Stunnel SSL/TLS:   443, 444, 777
  ✓ Proxies Python:    80, 8080, 8880, 8888 → DB:143
  ✓ BadVPN UDPGW:      UDP 7300
  ✓ Hysteria UDP:      ver opción 8 del panel

${YELLOW}CREDENCIALES:${NC}
  Usuario:   $USER_VPN
  Password:  $PASS_VPN

${YELLOW}PANEL:${NC} comando ${CYAN}vpn-panel${NC} (auto al conectar)

${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}
"

cat > /root/vpn-info.txt <<INFOEOF
MSY VPN SERVER v104

IP: $IP
Dropbear activo: $ACTIVE_DB_VER

SERVICIOS:
- OpenSSH: 22
- Dropbear ${ACTIVE_DB_VER}: 143
- Stunnel: 443→DB143 | 444→SSH22 | 777→DB143
- Proxies Python: 80, 8080, 8880, 8888 → DB:143
- BadVPN UDPGW: UDP 7300

USUARIO INICIAL:
$USER_VPN / $PASS_VPN

COMANDOS:
- Panel: vpn-panel
- Desinstalar: opción D del panel
INFOEOF

sleep 2
/usr/local/bin/vpn-panel
