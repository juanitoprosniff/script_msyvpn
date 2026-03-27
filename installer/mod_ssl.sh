#!/bin/bash
# mod_ssl.sh - MSY VPN v104+
# SSL/TLS: Stunnel mejorado
# Fixes aplicados:
#   - Bug grupo stunnel4 no creado en Ubuntu 20/22
#   - systemctl restart stunnel4 falla (active exited) → fallback a init.d + binario directo
#   - Desactivar/eliminar puertos SSL sin reiniciar a mano
#   - Liberar puertos al desinstalar

# ============================================================
# FUNCIÓN: reinicio robusto de stunnel
# Documentado en github.com/sous-chefs/stunnel issue #87:
# /etc/init.d/stunnel4 restart es más confiable que systemctl
# en Ubuntu 18-22 porque el wrapper SysV maneja el PID file
# correctamente donde el unit nativo falla.
# ============================================================
stunnel_restart() {
    local quiet=${1:-0}

    # 1. Matar proceso real (systemctl stop a veces no lo mata)
    pkill -9 -x stunnel4       2>/dev/null
    pkill -9 -f "stunnel4 /etc" 2>/dev/null
    sleep 1

    # 2. Liberar TODOS los puertos configurados en el conf
    if [ -f /etc/stunnel/stunnel.conf ]; then
        while IFS= read -r line; do
            puerto=$(echo "$line" | grep -oP ':\K[0-9]+$')
            [ -n "$puerto" ] && fuser -k ${puerto}/tcp 2>/dev/null
        done < <(grep "^accept" /etc/stunnel/stunnel.conf)
    fi
    # Siempre liberar los puertos base por si el conf estaba vacío
    for p in 443 444 777; do
        fuser -k ${p}/tcp 2>/dev/null
    done
    sleep 1

    # 3. Asegurar directorio PID con permisos correctos
    mkdir -p /var/run/stunnel4
    if getent group stunnel4 >/dev/null 2>&1; then
        chown stunnel4:stunnel4 /var/run/stunnel4 2>/dev/null
    else
        chown nobody:nogroup /var/run/stunnel4 2>/dev/null
    fi
    chmod 755 /var/run/stunnel4

    # 4. Primer intento: init.d (más confiable en Ubuntu 20/22)
    if [ -f /etc/init.d/stunnel4 ]; then
        /etc/init.d/stunnel4 stop  2>/dev/null
        sleep 1
        /etc/init.d/stunnel4 start 2>/dev/null
        sleep 2
    fi

    # 5. Segundo intento: systemctl
    if ! pgrep -x stunnel4 >/dev/null 2>&1; then
        systemctl daemon-reload 2>/dev/null
        systemctl restart stunnel4 2>/dev/null
        sleep 2
    fi

    # 6. Último recurso: invocar el binario directamente
    if ! pgrep -x stunnel4 >/dev/null 2>&1; then
        /usr/bin/stunnel4 /etc/stunnel/stunnel.conf 2>/dev/null &
        sleep 2
    fi

    if pgrep -x stunnel4 >/dev/null 2>&1; then
        [ "$quiet" = "0" ] && echo "✓ Stunnel activo (PID: $(pgrep -x stunnel4 | head -1))"
        return 0
    else
        [ "$quiet" = "0" ] && echo "✗ Stunnel no pudo iniciar"
        return 1
    fi
}

# ============================================================
# INSTALAR STUNNEL
# ============================================================
echo "Configurando Stunnel SSL..."

DEBIAN_FRONTEND=noninteractive apt-get install -y -q stunnel4 2>/dev/null

# FIX: crear grupo/usuario stunnel4 si faltó durante la instalación
# (bug documentado en Ubuntu 20/22 cuando dbus no responde al postinst)
if ! getent group stunnel4 >/dev/null 2>&1; then
    echo "  Creando grupo stunnel4 (fix compatibilidad)..."
    groupadd --system stunnel4 2>/dev/null || true
fi
if ! getent passwd stunnel4 >/dev/null 2>&1; then
    echo "  Creando usuario stunnel4 (fix compatibilidad)..."
    useradd --system --no-create-home --shell /usr/sbin/nologin \
            --gid stunnel4 stunnel4 2>/dev/null || true
fi

mkdir -p /var/run/stunnel4 /var/log/stunnel4
if getent passwd stunnel4 >/dev/null 2>&1; then
    chown -R stunnel4:stunnel4 /var/run/stunnel4 /var/log/stunnel4 2>/dev/null
else
    chown -R nobody:nogroup   /var/run/stunnel4 /var/log/stunnel4 2>/dev/null
fi
chmod 755 /var/run/stunnel4

# ============================================================
# CERTIFICADO SSL AUTOFIRMADO (10 años)
# ============================================================
cat > /tmp/openssl-stunnel.cnf <<'SSLCONF'
[req]
default_bits       = 2048
prompt             = no
default_md         = sha256
distinguished_name = dn
x509_extensions    = v3_ca

[dn]
C  = US
ST = California
L  = Los Angeles
O  = MSY-VPN
CN = msyvpn.server

[v3_ca]
subjectAltName     = @alt_names
keyUsage           = digitalSignature, keyEncipherment
extendedKeyUsage   = serverAuth, clientAuth

[alt_names]
DNS.1 = localhost
DNS.2 = *.msyvpn.com
IP.1  = 127.0.0.1
SSLCONF

openssl req -new -x509 -days 3650 -nodes \
    -config /tmp/openssl-stunnel.cnf \
    -keyout /etc/stunnel/stunnel.key \
    -out    /etc/stunnel/stunnel.crt >/dev/null 2>&1

cat /etc/stunnel/stunnel.crt /etc/stunnel/stunnel.key > /etc/stunnel/stunnel.pem
chmod 600 /etc/stunnel/stunnel.pem /etc/stunnel/stunnel.key
chmod 644 /etc/stunnel/stunnel.crt
rm -f /tmp/openssl-stunnel.cnf

# ============================================================
# CONFIGURACIÓN STUNNEL
# NOTA: NO usamos setuid/setgid globales para evitar el bug
# de permisos en Ubuntu 20/22. El proceso corre como root
# (mismo que antes, solo que sin la directiva que lo rompe
# cuando el usuario no existe).
# ============================================================
cat > /etc/stunnel/stunnel.conf <<'STUNNELCONF'
; MSY VPN - Stunnel SSL/TLS
; Compatible Ubuntu 20.04 / 22.04 x86_64

foreground = no
pid        = /var/run/stunnel4/stunnel.pid

; setuid/setgid omitidos intencionalmente:
; causan fallo de arranque en Ubuntu 20/22 si el grupo
; no fue creado correctamente por el postinst del paquete.

socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
socket = l:SO_KEEPALIVE=1
socket = r:SO_KEEPALIVE=1

TIMEOUTclose   = 3
TIMEOUTidle    = 86400
TIMEOUTbusy    = 300
TIMEOUTconnect = 15

sslVersion = all
options    = NO_SSLv2
options    = NO_SSLv3
options    = NO_TLSv1
options    = NO_TLSv1_1
options    = CIPHER_SERVER_PREFERENCE
options    = NO_COMPRESSION

ciphers = ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-GCM-SHA384:HIGH:!aNULL:!eNULL:!EXPORT:!MD5:!RC4

[dropbear-ssl-443]
client      = no
accept      = 0.0.0.0:443
connect     = 127.0.0.1:143
cert        = /etc/stunnel/stunnel.pem
verify      = 0
TIMEOUTidle = 86400

[openssh-ssl-444]
client      = no
accept      = 0.0.0.0:444
connect     = 127.0.0.1:22
cert        = /etc/stunnel/stunnel.pem
verify      = 0
TIMEOUTidle = 86400

[dropbear-ssl-777]
client      = no
accept      = 0.0.0.0:777
connect     = 127.0.0.1:143
cert        = /etc/stunnel/stunnel.pem
verify      = 0
TIMEOUTidle = 86400
STUNNELCONF

echo "ENABLED=1"                     > /etc/default/stunnel4
echo 'FILES="/etc/stunnel/*.conf"'  >> /etc/default/stunnel4

systemctl daemon-reload 2>/dev/null
systemctl enable stunnel4 2>/dev/null

stunnel_restart

if pgrep -x stunnel4 >/dev/null 2>&1; then
    echo "✓ Stunnel activo en puertos 443, 444, 777"
else
    echo "⚠ Stunnel no inició — diagnóstico: stunnel4 /etc/stunnel/stunnel.conf"
fi

# ============================================================
# GUARDAR FUNCIÓN stunnel_restart para ssh-vpn-functions.sh
# mod_tools.sh la inyectará en el archivo de funciones del menú
# ============================================================
cat > /tmp/stunnel_extra_functions.sh <<'EXTRAFUNC'

# -----------------------------------------------------------
# stunnel_restart_menu: wrapper para llamadas desde el menú
# -----------------------------------------------------------
stunnel_restart() {
    local quiet=${1:-0}
    pkill -9 -x stunnel4       2>/dev/null
    pkill -9 -f "stunnel4 /etc" 2>/dev/null
    sleep 1
    if [ -f /etc/stunnel/stunnel.conf ]; then
        while IFS= read -r line; do
            local p; p=$(echo "$line" | grep -oP ':\K[0-9]+$')
            [ -n "$p" ] && fuser -k ${p}/tcp 2>/dev/null
        done < <(grep "^accept" /etc/stunnel/stunnel.conf)
    fi
    for p in 443 444 777; do fuser -k ${p}/tcp 2>/dev/null; done
    sleep 1
    mkdir -p /var/run/stunnel4
    if getent group stunnel4 >/dev/null 2>&1; then
        chown stunnel4:stunnel4 /var/run/stunnel4 2>/dev/null
    else
        chown nobody:nogroup /var/run/stunnel4 2>/dev/null
    fi
    chmod 755 /var/run/stunnel4
    if [ -f /etc/init.d/stunnel4 ]; then
        /etc/init.d/stunnel4 stop 2>/dev/null; sleep 1
        /etc/init.d/stunnel4 start 2>/dev/null; sleep 2
    fi
    if ! pgrep -x stunnel4 >/dev/null 2>&1; then
        systemctl daemon-reload 2>/dev/null
        systemctl restart stunnel4 2>/dev/null; sleep 2
    fi
    if ! pgrep -x stunnel4 >/dev/null 2>&1; then
        /usr/bin/stunnel4 /etc/stunnel/stunnel.conf 2>/dev/null &; sleep 2
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
# ssl_remove_port: elimina un túnel del conf por número de puerto
# y reinicia. Uso: ssl_remove_port 443
# -----------------------------------------------------------
ssl_remove_port() {
    local target_port=$1
    local conf=/etc/stunnel/stunnel.conf

    if [ -z "$target_port" ]; then
        echo "✗ Indica el puerto a eliminar"
        return 1
    fi

    # Encontrar el nombre de sección que escucha en ese puerto
    local section
    section=$(awk -v port=":${target_port}" '
        /^\[/ { sec=substr($0,2,length($0)-2) }
        /^accept/ && index($0, port) { print sec; exit }
    ' "$conf")

    if [ -z "$section" ]; then
        echo "✗ No se encontró túnel en puerto $target_port"
        return 1
    fi

    # Eliminar bloque usando python3 (disponible en todos los sistemas objetivo)
    python3 - "$conf" "$section" "$target_port" <<'PYREMOVE'
import sys, re
conf_path, section, port = sys.argv[1], sys.argv[2], sys.argv[3]
with open(conf_path, 'r') as f:
    content = f.read()
# Elimina desde [section] hasta el inicio del siguiente bloque o fin de archivo
pattern = r'\n\[' + re.escape(section) + r'\].*?(?=\n\[|\Z)'
new_content = re.sub(pattern, '', content, flags=re.DOTALL)
with open(conf_path, 'w') as f:
    f.write(new_content)
print(f"✓ Túnel [{section}] (puerto {port}) eliminado")
PYREMOVE

    stunnel_restart
}

# -----------------------------------------------------------
# ssl_add_port: agrega un nuevo túnel al conf
# Uso: ssl_add_port <nombre> <puerto_entrada> <puerto_destino>
# -----------------------------------------------------------
ssl_add_port() {
    local nombre=$1 entrada=$2 destino=$3
    local conf=/etc/stunnel/stunnel.conf

    # Verificar que el puerto no exista ya
    if grep -q ":${entrada}$" "$conf" 2>/dev/null; then
        echo "✗ El puerto $entrada ya está en uso en stunnel"
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

EXTRAFUNC
