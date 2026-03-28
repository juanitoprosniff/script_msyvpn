#!/bin/bash
# mod_menu.sh - MSY VPN
# Menú principal, accesos directos, autostart, resumen final

# ====================
# SCRIPT MENÚ PRINCIPAL
# ====================
cat > /root/vpn-installer.sh << 'MAINSCRIPT'
#!/bin/bash

if [ ! -f /root/ssh-vpn-functions.sh ]; then
    echo "Error: Archivo de funciones no encontrado"
    exit 1
fi

source /root/ssh-vpn-functions.sh

menu_principal() {
    while true; do
        clear
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
        S_UDP=$(port_status 7300 u)

        echo -e "${CYAN}╔══════════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║${NC}     ${BOLD}MSY VPN PANEL - v104 Minimalista${NC}    ${CYAN}║${NC}"
        echo -e "${CYAN}╚══════════════════════════════════════════════╝${NC}"
        echo -e " ${GREEN}IP:${NC} ${YELLOW}$IP${NC}"
        echo ""
        echo -e " ${CYAN}━━━ PUERTOS ACTIVOS ━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "  SSH   :22   $S_SSH    │  Dropbear :143  $S_DB"
        echo -e "  SSL   :443  $S_SSL443  │  SSL      :444  $S_SSL444"
        echo -e "  SSL   :777  $S_SSL777  │  UDP/BVPN :7300 $S_UDP"
        echo -e "  Proxy :80   $S_P80    │  Proxy    :8080 $S_P8080"
        echo -e "  Proxy :8880 $S_P8880  │  Proxy    :8888 $S_P8888"
        echo -e " ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        echo -e " ${BLUE}1)${NC} Crear usuario       ${BLUE}2)${NC} Eliminar usuario"
        echo -e " ${BLUE}3)${NC} Ver conectados      ${BLUE}4)${NC} Proxies Python"
        echo -e " ${BLUE}5)${NC} Túneles SSL/TLS     ${BLUE}6)${NC} Banner HTTP proxy"
        echo -e " ${BLUE}7)${NC} Banner SSH (DB143)  ${BLUE}8)${NC} Hysteria UDP"
        echo -e " ${BLUE}9)${NC} Estado servicios   ${BLUE}10)${NC} Reiniciar servicios"
        echo -e "${RED}D)${NC} Desinstalar script  ${RED} 0)${NC} Salir"
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
                    read -p "ENTER para continuar..."
                    continue
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
                echo "✓ Usuario $username creado"
                echo "  Expira: $expiry"
                read -p "ENTER para continuar..."
                ;;
            2)
                clear
                echo "ELIMINAR USUARIO"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                read -p "Nombre de usuario a eliminar: " username

                if ! id "$username" &>/dev/null; then
                    echo "El usuario no existe"
                    read -p "ENTER para continuar..."
                    continue
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
                        read -p "Banner [MSY VPN SCRIPT]: " banner
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
                    2)
                        stop_all_proxies
                        read -p "ENTER..."
                        ;;
                    3)
                        echo "PROXIES ACTIVOS:"
                        screen -ls 2>/dev/null | grep "proxy-" | awk -F'.' '{print $2}' | while read n; do
                            port=$(echo $n | sed 's/proxy-//')
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
                        echo "Proxies activos:"
                        screen -ls 2>/dev/null | grep "proxy-" | awk '{print $1}'
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
                        if pgrep -x stunnel4 >/dev/null 2>&1; then
                            echo -e "${GREEN}✓ Stunnel proceso activo (PID: $(pgrep -x stunnel4 | head -1))${NC}"
                        else
                            echo -e "${RED}✗ Stunnel proceso NO activo${NC}"
                        fi
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
                        echo "  143 - Dropbear 2016 (recomendado)"
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
                            awk '/^\[/{n=$0} /^accept/{print n" → ",$0}'
                        echo ""
                        read -p "Puerto a desactivar (ej: 443): " rm_port
                        if [ -n "$rm_port" ]; then
                            ssl_remove_port "$rm_port"
                        else
                            echo "Cancelado."
                        fi
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
                grep "BANNER_TEXT = " /etc/proxy-python/proxy.py
                echo ""
                read -p "Nuevo texto [HTML o texto simple]: " new_banner
                new_banner=${new_banner:-'<span style="background-color: #000000;"><span style="color:#eeff01;">MSY VPN SCRIPT</span></span>'}
                sed -i "s/BANNER_TEXT = .*/BANNER_TEXT = '$new_banner'/" /etc/proxy-python/proxy.py
                echo "✓ Banner actualizado"
                echo "→ Reinicia proxies desde Opción 10"
                read -p "ENTER para continuar..."
                ;;
            7)
                clear
                echo "BANNER DROPBEAR 2016 (Puerto 143)"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                echo "Banner actual:"
                cat /etc/dropbear-legacy/banner.txt 2>/dev/null || echo "(vacío)"
                echo ""
                echo "Nuevo banner (multilínea - escribe FIN para terminar):"
                > /tmp/new_banner.txt
                while true; do
                    read -r line
                    [ "$line" = "FIN" ] && break
                    echo "$line" >> /tmp/new_banner.txt
                done
                if [ -s /tmp/new_banner.txt ]; then
                    cp /tmp/new_banner.txt /etc/dropbear-legacy/banner.txt
                    systemctl restart dropbear-legacy 2>/dev/null
                    echo "✓ Banner Dropbear 2016 actualizado"
                fi
                rm -f /tmp/new_banner.txt
                read -p "ENTER..."
                ;;
            8)
                clear
                if [ -f /usr/local/bin/hysteria-manager ]; then
                    bash /usr/local/bin/hysteria-manager
                else
                    echo "⚠ Hysteria UDP no está instalado"
                    read -p "¿Instalar ahora? (s/n): " install_hyst
                    if [[ $install_hyst == "s" || $install_hyst == "S" ]]; then
                        cd /root
                        wget -q -O install_agnudp.sh https://raw.githubusercontent.com/juanitoprosniff/script_msyvpn/main/installer/install_agnudp.sh
                        wget -q -O agnudp_manager.sh https://raw.githubusercontent.com/juanitoprosniff/script_msyvpn/main/installer/agnudp_manager.sh
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
                systemctl is-active --quiet ssh         && echo -e "${GREEN}✓ OpenSSH:         Activo${NC}  (puerto 22)"          || echo -e "${RED}✗ OpenSSH:         Inactivo${NC}"
                systemctl is-active --quiet dropbear-legacy && echo -e "${GREEN}✓ Dropbear 2016:   Activo${NC}  (puerto 143)"   || echo -e "${RED}✗ Dropbear 2016:   Inactivo${NC}"
                systemctl is-active --quiet stunnel4    && echo -e "${GREEN}✓ Stunnel:         Activo${NC}  (443, 444, 777)"      || echo -e "${RED}✗ Stunnel:         Inactivo${NC}"
                systemctl is-active --quiet badvpn-udpgw && echo -e "${GREEN}✓ BadVPN UDPGW:    Activo${NC} (UDP 7300)"          || echo -e "${RED}✗ BadVPN UDPGW:    Inactivo${NC}"
                echo ""
                local active_proxies
                active_proxies=$(screen -ls 2>/dev/null | grep -c "proxy-")
                echo -e "${YELLOW}Python Proxies activos:${NC} $active_proxies"
                echo ""
                echo -e "${YELLOW}Disco:${NC} $(df -h / | awk 'NR==2{print $3"/"$2" ("$5" usado)"}')"
                echo -e "${YELLOW}Swap:${NC}  $(free -h | awk '/Swap/{print $3"/"$2}')"
                echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
                read -p "ENTER para continuar..."
                ;;
            10)
                clear
                echo "REINICIAR SERVICIOS"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                echo "1) Reiniciar proxies HTTP"
                echo "2) Reiniciar OpenSSH"
                echo "3) Reiniciar Dropbear 2016"
                echo "4) Reiniciar Stunnel"
                echo "5) Reiniciar BadVPN"
                echo "6) Reiniciar TODO"
                echo "0) Volver"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                read -p "Opción: " restart_opt
                case $restart_opt in
                    1) restart_proxies; echo ""; read -p "ENTER..." ;;
                    2) systemctl restart ssh          && echo "✓ OpenSSH reiniciado"   || echo "✗ Error"; read -p "ENTER..." ;;
                    3) systemctl restart dropbear-legacy && echo "✓ Dropbear reiniciado" || echo "✗ Error"; read -p "ENTER..." ;;
                    4) stunnel_restart; read -p "ENTER..." ;;
                    5) systemctl restart badvpn-udpgw && echo "✓ BadVPN reiniciado"   || echo "✗ Error"; read -p "ENTER..." ;;
                    6) restart_all_services; echo ""; read -p "ENTER..." ;;
                esac
                ;;
            D|d)
                clear
                echo -e "${RED}╔══════════════════════════════════════════════╗${NC}"
                echo -e "${RED}║         DESINSTALAR MSY VPN SCRIPT           ║${NC}"
                echo -e "${RED}╚══════════════════════════════════════════════╝${NC}"
                echo ""
                echo -e "${YELLOW}Esto eliminará todos los servicios, archivos y"
                echo -e "configuraciones instaladas por este script.${NC}"
                echo ""
                read -p "¿Confirmar desinstalación? (escribe SI para confirmar): " confirm
                if [ "$confirm" = "SI" ]; then
                    echo ""
                    echo "Desinstalando MSY VPN..."

                    # PASO 1: Liberar TODOS los puertos ANTES de detener servicios
                    # (evita que queden ocupados si systemctl stop falla)
                    echo "Liberando puertos..."
                    kill_all_ports

                    # PASO 2: Detener y deshabilitar servicios
                    echo "Deteniendo servicios..."
                    systemctl stop dropbear-legacy    2>/dev/null
                    systemctl stop badvpn-udpgw       2>/dev/null
                    systemctl stop stunnel4            2>/dev/null
                    systemctl stop restore-proxies     2>/dev/null
                    systemctl stop proxy-watchdog      2>/dev/null
                    systemctl stop hysteria            2>/dev/null

                    systemctl disable dropbear-legacy  2>/dev/null
                    systemctl disable badvpn-udpgw     2>/dev/null
                    systemctl disable restore-proxies  2>/dev/null
                    systemctl disable proxy-watchdog   2>/dev/null
                    systemctl disable hysteria         2>/dev/null

                    # PASO 3: Matar procesos residuales
                    echo "Eliminando procesos..."
                    pkill -9 -x stunnel4               2>/dev/null
                    pkill -9 -f "stunnel4 /etc"        2>/dev/null
                    pkill -9 -f "proxy.py"             2>/dev/null
                    pkill -9 -f "badvpn-udpgw"         2>/dev/null
                    pkill -9 -f "watchdog.sh"          2>/dev/null
                    screen -ls 2>/dev/null | grep "proxy-" | awk '{print $1}' | \
                        xargs -I {} screen -X -S {} quit 2>/dev/null

                    # PASO 4: Segunda liberación de puertos (por si quedó algo)
                    for p in 22 80 143 443 444 777 7300 8080 8880 8888; do
                        fuser -k "${p}/tcp" 2>/dev/null
                        fuser -k "${p}/udp" 2>/dev/null
                    done

                    # Eliminar archivos de servicios systemd
                    echo "Eliminando archivos del sistema..."
                    rm -f /etc/systemd/system/dropbear-legacy.service
                    rm -f /etc/systemd/system/badvpn-udpgw.service
                    rm -f /etc/systemd/system/restore-proxies.service
                    rm -f /etc/systemd/system/proxy-watchdog.service
                    systemctl daemon-reload

                    # Eliminar binarios compilados
                    rm -rf /opt/dropbear-2016
                    rm -f /usr/bin/badvpn-udpgw

                    # Eliminar archivos de configuración
                    rm -rf /etc/dropbear-legacy
                    rm -rf /etc/proxy-python
                    rm -rf /etc/ssh-vpn
                    rm -rf /etc/hysteria 2>/dev/null

                    # Eliminar stunnel config (pero no el paquete)
                    rm -f /etc/stunnel/stunnel.conf
                    rm -f /etc/stunnel/stunnel.pem
                    rm -f /etc/stunnel/stunnel.key
                    rm -f /etc/stunnel/stunnel.crt
                    echo "ENABLED=0" > /etc/default/stunnel4

                    # Eliminar scripts del menú
                    rm -f /root/vpn-installer.sh
                    rm -f /root/ssh-vpn-functions.sh
                    rm -f /root/vpn-info.txt
                    rm -f /usr/local/bin/vpn-panel
                    rm -f /usr/local/bin/vpn-manager
                    rm -f /usr/local/bin/hysteria-manager 2>/dev/null

                    # Eliminar menú automático del bashrc
                    sed -i '/MSY VPN/,/fi/d' /root/.bashrc 2>/dev/null

                    # Eliminar fuentes descargadas
                    rm -rf /usr/src/dropbear-2016.74 2>/dev/null
                    rm -f  /usr/src/dropbear-2016.74.tar.bz2 2>/dev/null
                    rm -rf /usr/src/badvpn 2>/dev/null

                    # Eliminar scripts temporales hysteria
                    rm -f /root/install_agnudp.sh 2>/dev/null
                    rm -f /root/agnudp_manager.sh 2>/dev/null

                    # Desactivar swap del script (opcional)
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
                    echo ""
                    echo "  Servicios eliminados: Dropbear 2016, BadVPN, Stunnel, Proxies, Watchdog"
                    echo "  OpenSSH se mantiene activo en puerto 22"
                    echo "  Todos los puertos han sido liberados"
                    echo ""
                    echo "  La VPS queda limpia. Puedes instalar otra versión."
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

# Crear acceso directo
cat > /usr/local/bin/vpn-panel <<'SHORTCUT'
#!/bin/bash
bash /root/vpn-installer.sh
SHORTCUT

chmod +x /usr/local/bin/vpn-panel
ln -sf /usr/local/bin/vpn-panel /usr/local/bin/vpn-manager

# ====================
# MENÚ AUTOMÁTICO AL LOGIN
# ====================
sed -i '/MSY VPN/,/fi/d' /root/.bashrc 2>/dev/null

cat >> /root/.bashrc <<'AUTOEOF'

# MSY VPN - Menú automático
if [ -t 0 ] && [ -f /usr/local/bin/vpn-panel ]; then
    vpn-panel
fi
AUTOEOF

# ====================
# INICIAR PROXIES
# ====================
echo "Iniciando proxies por defecto..."
source /root/ssh-vpn-functions.sh
restore_proxies

# ====================
# RESUMEN FINAL
# ====================
IP=$(curl -4 -s --max-time 5 ifconfig.me 2>/dev/null \
  || curl -4 -s --max-time 5 api4.ipify.org 2>/dev/null \
  || hostname -I | tr ' ' '\n' | grep -v ':' | head -1)

# Recuperar credenciales del usuario inicial si no están en el entorno
if [ -z "$USER_VPN" ]; then
    USER_VPN=$(ls /etc/ssh-vpn/users/*.txt 2>/dev/null | head -1 | xargs basename 2>/dev/null | sed 's/.txt//')
    PASS_VPN=$(grep "Contraseña:" /etc/ssh-vpn/users/${USER_VPN}.txt 2>/dev/null | awk '{print $2}')
fi

CYAN='\033[1;36m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

clear
echo -e "
${CYAN}╔══════════════════════════════════════════════╗${NC}
${CYAN}║${NC}  ${GREEN}✓ INSTALACIÓN COMPLETADA - v104${NC}          ${CYAN}║${NC}
${CYAN}╚══════════════════════════════════════════════╝${NC}

${YELLOW}IP:${NC} ${CYAN}$IP${NC}

${GREEN}SERVICIOS:${NC}
  ✓ OpenSSH:          puerto 22
  ✓ Dropbear 2016:    puerto 143  (SSH-2.0-ByJuanitoProSniff)
  ✓ Stunnel SSL/TLS:  443, 444, 777
  ✓ Proxies Python:   80, 8080, 8880, 8888 → DB 143
  ✓ BadVPN UDPGW:     UDP 7300

${YELLOW}CREDENCIALES:${NC}
  Usuario:   $USER_VPN
  Password:  $PASS_VPN

${YELLOW}PANEL:${NC} ejecutar ${CYAN}vpn-panel${NC} (auto al conectar)

${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}
"

# Guardar info
cat > /root/vpn-info.txt <<INFOEOF
MSY VPN SERVER v104

IP: $IP

SERVICIOS:
- OpenSSH: 22
- Dropbear 2016: 143
- Stunnel: 443 → DB143 | 444 → SSH22 | 777 → DB143
- Proxies Python: 80, 8080, 8880, 8888 → DB 143
- BadVPN UDPGW: UDP 7300

USUARIO INICIAL:
$USER_VPN / $PASS_VPN

COMANDOS:
- Panel: vpn-panel
- Desinstalar: desde el menú opción D

INFOEOF

sleep 2
/usr/local/bin/vpn-panel
