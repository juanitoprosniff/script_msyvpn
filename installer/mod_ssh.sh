#!/bin/bash
# mod_ssh.sh - MSY VPN v104+
# Protocolos SSH: OpenSSH (22) + Dropbear legacy (143)
#
# COMPATIBILIDAD:
#   Ubuntu 20.04 x86_64 — OK (compilación normal)
#   Ubuntu 22.04 x86_64 — OK (compilación normal)
#   Ubuntu 24.04 x86_64 — Dropbear 2016 compila con CFLAGS especiales; inestable → usa Dropbear moderno
#   Ubuntu 25.04 x86_64 — Dropbear 2016 falla por GCC 14 (-Werror=implicit); usa Dropbear moderno
#
# ESTRATEGIA PARA DROPBEAR EN :143:
#   1. Intentar compilar Dropbear 2016.74 (con CFLAGS compatibles GCC 14)
#   2. Si falla o OS >= Ubuntu 24 → instalar Dropbear moderno via apt (más estable)
#   3. Si apt también falla → usar OpenSSH como fallback en :143 (siempre funciona)
#
# FORZAR IPv4:
#   - curl -4 para obtener IP pública
#   - sshd_config: AddressFamily inet
#   - Dropbear: escucha solo en 0.0.0.0 (IPv4)
#   - Stunnel: accept = 0.0.0.0:puerto (explícito, sin ambigüedad IPv6)

# ============================================================
# DETECTAR VERSIÓN DE OS Y GCC
# ============================================================
OS_VER=$(lsb_release -rs 2>/dev/null \
    || grep -oP '(?<=VERSION_ID=")[^"]+' /etc/os-release 2>/dev/null \
    || echo "0")
OS_MAJOR=$(echo "$OS_VER" | cut -d. -f1)
ARCH=$(uname -m)

GCC_VER=$(gcc -dumpversion 2>/dev/null | cut -d. -f1)
GCC_VER=${GCC_VER:-0}

echo "=========================================="
echo " SSH/Dropbear Setup"
echo " OS: Ubuntu $OS_VER | Arch: $ARCH | GCC: $GCC_VER"
echo "=========================================="

# ============================================================
# OPENSSH (PUERTO 22) — forzar solo IPv4
# ============================================================
echo "Configurando OpenSSH en puerto 22..."

cat > /etc/ssh/banner.txt <<'EOF'
═══════════════════════════
t.me/FREEINTERNETVPNMSY
═══════════════════════════
EOF

cat > /etc/ssh/sshd_config <<'EOF'
Port 22
AddressFamily inet
ListenAddress 0.0.0.0
Banner /etc/ssh/banner.txt
PermitRootLogin yes
PubkeyAuthentication yes
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
PrintMotd no
PrintLastLog yes
X11Forwarding yes
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
ClientAliveInterval 120
ClientAliveCountMax 3
TCPKeepAlive yes
MaxStartups 100:30:200
MaxSessions 100
Compression no
EOF

systemctl enable ssh >/dev/null 2>&1
systemctl restart ssh
if systemctl is-active --quiet ssh; then
    echo "✓ OpenSSH activo en 0.0.0.0:22 (solo IPv4)"
else
    echo "✗ OpenSSH no inició — revisar sshd_config"
fi

# ============================================================
# FUNCIÓN: instalar Dropbear moderno via apt (fallback principal)
# Más estable que compilar 2016 en Ubuntu 24/25
# ============================================================
instalar_dropbear_moderno() {
    echo "  Instalando Dropbear moderno via apt..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q dropbear-bin 2>/dev/null \
        || DEBIAN_FRONTEND=noninteractive apt-get install -y -q dropbear 2>/dev/null

    local db_bin
    db_bin=$(command -v dropbear 2>/dev/null \
          || command -v /usr/sbin/dropbear 2>/dev/null \
          || command -v /usr/bin/dropbear 2>/dev/null)

    if [ -z "$db_bin" ]; then
        echo "  ✗ Dropbear moderno no se pudo instalar"
        return 1
    fi

    local db_ver; db_ver=$($db_bin -V 2>&1 | head -1)
    echo "  ✓ Dropbear instalado: $db_ver → $db_bin"

    # Guardar ruta del binario para el servicio
    DROPBEAR_BIN="$db_bin"
    DROPBEAR_MODE="moderno"
    return 0
}

# ============================================================
# FUNCIÓN: compilar Dropbear 2016.74 desde fuente
# Usa CFLAGS especiales para GCC 12+ / GCC 14
# ============================================================
compilar_dropbear_2016() {
    echo "  Compilando Dropbear 2016.74 desde fuente..."
    cd /usr/src

    if [ ! -f dropbear-2016.74.tar.bz2 ]; then
        echo "  Descargando Dropbear 2016.74..."
        wget -q https://github.com/juanitoprosniff/script_msyvpn/raw/refs/heads/main/installer/dropbear-2016.74.tar.bz2
        if [ ! -f dropbear-2016.74.tar.bz2 ]; then
            echo "  ✗ No se pudo descargar el tarball"
            return 1
        fi
    fi

    rm -rf dropbear-2016.74 2>/dev/null
    tar xjf dropbear-2016.74.tar.bz2 2>/dev/null
    if [ ! -d dropbear-2016.74 ]; then
        echo "  ✗ No se pudo extraer el tarball"
        return 1
    fi
    cd dropbear-2016.74

    # Personalizar identificador SSH
    for f in sysoptions.h default_options.h; do
        [ -f "$f" ] && \
            sed -i 's|#define LOCAL_IDENT.*|#define LOCAL_IDENT "SSH-2.0-ByJuanitoProSniff"|' "$f" 2>/dev/null || true
    done

    # CFLAGS compatibles con GCC 14 (Ubuntu 25) y GCC 12 (Ubuntu 24)
    # GCC 14 convirtió implicit-function-declaration e implicit-int en errores
    EXTRA_CFLAGS=""
    if [ "$GCC_VER" -ge 12 ] 2>/dev/null; then
        EXTRA_CFLAGS="-Wno-error=implicit-function-declaration -Wno-error=implicit-int -Wno-error=int-conversion"
        echo "  Aplicando CFLAGS para GCC $GCC_VER: $EXTRA_CFLAGS"
    fi

    # Exportar para que configure y make los usen
    export CFLAGS="$EXTRA_CFLAGS"

    ./configure --prefix=/opt/dropbear-2016 \
        --disable-zlib \
        --disable-wtmp \
        --disable-lastlog \
        >/dev/null 2>&1

    echo "  Compilando... (puede tardar 2-3 min)"
    if ! make -j$(nproc) PROGRAMS="dropbear dropbearkey" \
            CFLAGS="$EXTRA_CFLAGS" >/dev/null 2>&1; then
        echo "  ✗ make falló"
        cd /root
        return 1
    fi

    make install PROGRAMS="dropbear dropbearkey" >/dev/null 2>&1

    unset CFLAGS

    if [ ! -f /opt/dropbear-2016/sbin/dropbear ]; then
        echo "  ✗ Binario no encontrado tras compilar"
        cd /root
        return 1
    fi

    echo "  ✓ Dropbear 2016.74 compilado OK"
    DROPBEAR_BIN="/opt/dropbear-2016/sbin/dropbear"
    DROPBEAR_KEY_BIN="/opt/dropbear-2016/bin/dropbearkey"
    DROPBEAR_MODE="2016"
    cd /root
    return 0
}

# ============================================================
# FUNCIÓN: fallback final — OpenSSH también en :143
# Cuando todo lo demás falla, SSH en dos puertos funciona
# con la mayoría de los clientes VPN
# ============================================================
instalar_fallback_ssh143() {
    echo "  ⚠ Usando OpenSSH como fallback en puerto 143..."

    # Agregar puerto 143 a sshd_config si no existe
    if ! grep -q "^Port 143" /etc/ssh/sshd_config; then
        sed -i '/^Port 22/a Port 143' /etc/ssh/sshd_config
    fi
    systemctl restart ssh
    if ss -tlnp | grep -q ":143 "; then
        echo "  ✓ OpenSSH escuchando también en :143"
        DROPBEAR_MODE="ssh_fallback"
        return 0
    else
        echo "  ✗ Fallback SSH:143 también falló"
        return 1
    fi
}

# ============================================================
# LÓGICA DE SELECCIÓN: qué versión de Dropbear usar
# ============================================================
DROPBEAR_BIN=""
DROPBEAR_KEY_BIN=""
DROPBEAR_MODE=""

echo ""
echo "Configurando Dropbear SSH en puerto 143..."

if [ "$OS_MAJOR" -ge 25 ] 2>/dev/null; then
    # Ubuntu 25+: GCC 14, Dropbear 2016 muy problemático
    # Intentar compilar con fixes, pero preferir moderno
    echo "Ubuntu $OS_VER detectado (GCC $GCC_VER) — intentando compilación con CFLAGS fix..."
    if compilar_dropbear_2016; then
        echo "  Compilación exitosa en Ubuntu $OS_VER"
    else
        echo "  Compilación falló — usando Dropbear moderno (más estable)"
        instalar_dropbear_moderno || instalar_fallback_ssh143
    fi

elif [ "$OS_MAJOR" -ge 24 ] 2>/dev/null; then
    # Ubuntu 24: compila pero es inestable → preferir moderno
    echo "Ubuntu $OS_VER detectado — Dropbear moderno (más estable en Ubuntu 24)..."
    if instalar_dropbear_moderno; then
        echo "  Usando Dropbear moderno para mejor estabilidad"
    else
        # Intentar 2016 como segundo recurso
        echo "  apt falló — intentando compilar Dropbear 2016..."
        compilar_dropbear_2016 || instalar_fallback_ssh143
    fi

else
    # Ubuntu 20/22: compilar 2016 funciona bien
    echo "Ubuntu $OS_VER — compilando Dropbear 2016.74 (método estándar)..."
    compilar_dropbear_2016 || instalar_dropbear_moderno || instalar_fallback_ssh143
fi

# ============================================================
# GENERAR LLAVES Y CONFIGURAR SERVICIO SYSTEMD
# ============================================================
if [ "$DROPBEAR_MODE" = "ssh_fallback" ]; then
    echo "✓ Puerto 143 cubierto por OpenSSH (fallback)"
    # No se necesita servicio adicional

elif [ -n "$DROPBEAR_BIN" ] && [ "$DROPBEAR_MODE" != "ssh_fallback" ]; then

    # --- Directorio de llaves ---
    mkdir -p /etc/dropbear-legacy

    # Banner
    cat > /etc/dropbear-legacy/banner.txt <<'BANEOF'
t.me/FREEINTERNETVPNMSY
BANEOF

    # --- Generar llaves según la versión ---
    if [ "$DROPBEAR_MODE" = "2016" ]; then
        # Llaves con dropbearkey del 2016
        local_key="${DROPBEAR_KEY_BIN:-/opt/dropbear-2016/bin/dropbearkey}"
        [ ! -f /etc/dropbear-legacy/dropbear_rsa_host_key ] && \
            $local_key -t rsa   -f /etc/dropbear-legacy/dropbear_rsa_host_key   -s 2048 >/dev/null 2>&1
        [ ! -f /etc/dropbear-legacy/dropbear_ecdsa_host_key ] && \
            $local_key -t ecdsa -f /etc/dropbear-legacy/dropbear_ecdsa_host_key          >/dev/null 2>&1
        KEY_FLAGS="-r /etc/dropbear-legacy/dropbear_rsa_host_key -r /etc/dropbear-legacy/dropbear_ecdsa_host_key"

    else
        # Dropbear moderno: genera sus propias llaves automáticamente
        # Solo necesitamos asegurarnos del directorio de llaves
        mkdir -p /etc/dropbear
        local_key=$(command -v dropbearkey 2>/dev/null \
                 || command -v /usr/bin/dropbearkey 2>/dev/null \
                 || command -v /usr/sbin/dropbearkey 2>/dev/null)
        if [ -n "$local_key" ]; then
            [ ! -f /etc/dropbear-legacy/dropbear_rsa_host_key ] && \
                $local_key -t rsa   -f /etc/dropbear-legacy/dropbear_rsa_host_key   -s 2048 >/dev/null 2>&1
            [ ! -f /etc/dropbear-legacy/dropbear_ecdsa_host_key ] && \
                $local_key -t ecdsa -f /etc/dropbear-legacy/dropbear_ecdsa_host_key          >/dev/null 2>&1
            KEY_FLAGS="-r /etc/dropbear-legacy/dropbear_rsa_host_key -r /etc/dropbear-legacy/dropbear_ecdsa_host_key"
        else
            KEY_FLAGS=""
        fi
    fi

    # --- Servicio systemd ---
    # Nota: escucha en 0.0.0.0:143 explícitamente para forzar IPv4
    # -s: deshabilitar X11 forwarding (innecesario en servidor VPN)
    # -g: deshabilitar autenticación como root por contraseña vacía
    # -K 60: keepalive cada 60 segundos
    # -I 300: timeout inactividad 5 min
    cat > /etc/systemd/system/dropbear-legacy.service <<DBSVC
[Unit]
Description=Dropbear SSH Legacy en puerto 143 (MSY VPN)
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=${DROPBEAR_BIN} -F -E -p 0.0.0.0:143 \\
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
    systemctl start dropbear-legacy
    sleep 2

    if systemctl is-active --quiet dropbear-legacy; then
        DB_VER=""
        [ "$DROPBEAR_MODE" = "2016" ] && DB_VER=" (2016.74, SSH-2.0-ByJuanitoProSniff)"
        echo "✓ Dropbear activo en 0.0.0.0:143$DB_VER"
    else
        echo "⚠ Dropbear no inició — diagnóstico:"
        echo "  journalctl -u dropbear-legacy --no-pager | tail -20"
        # Segundo intento: lanzar directamente para ver el error real
        echo "  Intentando arranque directo para ver error..."
        $DROPBEAR_BIN -F -E -p 0.0.0.0:143 $KEY_FLAGS -b /etc/dropbear-legacy/banner.txt -K 60 -I 300 &
        sleep 2
        if ss -tlnp | grep -q ":143 "; then
            echo "  ✓ Puerto 143 activo (proceso directo)"
        else
            echo "  ✗ Puerto 143 no disponible — usando OpenSSH como fallback"
            instalar_fallback_ssh143
        fi
    fi
fi

cd /root

# ============================================================
# GUARDAR MODO DROPBEAR para uso del menú
# (informativo, lo usa el panel de estado)
# ============================================================
echo "$DROPBEAR_MODE" > /etc/dropbear-legacy/mode.txt
echo "$DROPBEAR_BIN"  > /etc/dropbear-legacy/bin.txt

# ============================================================
# USUARIO INICIAL VPN
# ============================================================
echo ""
echo "Creando usuario VPN inicial..."
USER_VPN="vpnuser"
PASS_VPN="msy$(openssl rand -hex 4)"

if id "$USER_VPN" &>/dev/null; then
    userdel -r "$USER_VPN" 2>/dev/null
fi

useradd -m -s /bin/bash "$USER_VPN"
echo "$USER_VPN:$PASS_VPN" | chpasswd

mkdir -p /etc/ssh-vpn/users
cat > /etc/ssh-vpn/users/$USER_VPN.txt <<USEREOF
Usuario: $USER_VPN
Contraseña: $PASS_VPN
Fecha creación: $(date +%Y-%m-%d)
Fecha expiración: Ilimitado
Estado: Activo
Dropbear modo: $DROPBEAR_MODE
USEREOF

echo "✓ Usuario: $USER_VPN / $PASS_VPN"
export USER_VPN PASS_VPN
