#!/bin/bash
# mod_ssh.sh - MSY VPN v104+
# SSH: OpenSSH :22 + Dropbear legacy :143
#
# VERSIONES DISPONIBLES EN :143 (selección manual desde el panel):
#   - Dropbear 2016.74  ← identificador personalizado SSH-2.0-ByJuanitoProSniff
#   - Dropbear 2019.78  ← más compatible con OpenSSL moderno, mismo identificador
#   - OpenSSH fallback  ← siempre funciona si la compilación falla
#
# COMPATIBILIDAD DE COMPILACIÓN:
#   Ubuntu 20.04 GCC 9  → 2016 y 2019 compilan OK
#   Ubuntu 22.04 GCC 11 → 2016 y 2019 compilan OK
#   Ubuntu 24.04 GCC 13 → CFLAGS especiales necesarios, ambos compilan
#   Ubuntu 25.04 GCC 14 → CFLAGS especiales obligatorios, 2019 más estable
#
# NOTA Ubuntu 20 + SSL: si stunnel no arranca, revisar que el grupo
#   stunnel4 existe: getent group stunnel4. Si no, correr:
#   groupadd --system stunnel4 && /etc/init.d/stunnel4 start

# ============================================================
# DETECCIÓN DE ENTORNO
# ============================================================
OS_VER=$(lsb_release -rs 2>/dev/null \
    || grep -oP '(?<=VERSION_ID=")[^"]+' /etc/os-release 2>/dev/null \
    || echo "0")
OS_MAJOR=$(echo "$OS_VER" | cut -d. -f1)
ARCH=$(uname -m)
GCC_VER=$(gcc -dumpversion 2>/dev/null | cut -d. -f1); GCC_VER=${GCC_VER:-0}

echo "=========================================="
echo " SSH/Dropbear Setup"
echo " OS: Ubuntu $OS_VER | Arch: $ARCH | GCC: $GCC_VER"
echo "=========================================="

# ============================================================
# OPENSSH (PUERTO 22) — forzar solo IPv4
# ============================================================
echo ""
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
systemctl is-active --quiet ssh \
    && echo "✓ OpenSSH activo en 0.0.0.0:22 (solo IPv4)" \
    || echo "✗ OpenSSH no inició"

# ============================================================
# CFLAGS PARA GCC 12+ / GCC 14
# (Dropbear 2016 usa funciones implícitas que GCC 14 rechaza)
# ============================================================
if [ "$GCC_VER" -ge 12 ] 2>/dev/null; then
    COMPAT_CFLAGS="-Wno-error=implicit-function-declaration -Wno-error=implicit-int -Wno-error=int-conversion -Wno-error=incompatible-pointer-types"
    echo "  GCC $GCC_VER detectado — CFLAGS de compatibilidad activados"
else
    COMPAT_CFLAGS=""
fi

# ============================================================
# FUNCIÓN GENÉRICA: compilar una versión de Dropbear
# Uso: compilar_dropbear <version> <url_tarball> <prefix>
# ============================================================
compilar_dropbear() {
    local VER=$1
    local URL=$2
    local PREFIX=$3
    local TARBALL="dropbear-${VER}.tar.bz2"
    local SRCDIR="/usr/src/dropbear-${VER}"
    local KEYBIN="${PREFIX}/bin/dropbearkey"
    local SRVRBIN="${PREFIX}/sbin/dropbear"

    echo ""
    echo "  ── Compilando Dropbear $VER ──"
    echo "  Prefix: $PREFIX"

    cd /usr/src

    # Descargar tarball si no existe
    if [ ! -f "$TARBALL" ]; then
        echo "  Descargando $TARBALL..."
        wget -q -O "$TARBALL" "$URL" 2>/dev/null
        # Mirror alternativo si falla
        if [ ! -f "$TARBALL" ] || [ ! -s "$TARBALL" ]; then
            echo "  Mirror alternativo..."
            wget -q -O "$TARBALL" \
                "https://dropbear.nl/mirror/releases/$TARBALL" 2>/dev/null
        fi
        if [ ! -f "$TARBALL" ] || [ ! -s "$TARBALL" ]; then
            echo "  ✗ No se pudo descargar Dropbear $VER"
            return 1
        fi
    fi

    # Limpiar y extraer
    rm -rf "$SRCDIR" 2>/dev/null
    tar xjf "$TARBALL" -C /usr/src 2>/dev/null
    if [ ! -d "$SRCDIR" ]; then
        echo "  ✗ Error extrayendo $TARBALL"
        return 1
    fi

    cd "$SRCDIR"

    # Personalizar identificador SSH en todos los archivos donde aparece
    for f in sysoptions.h default_options.h options.h; do
        if [ -f "$f" ]; then
            # Reemplazar o insertar el LOCAL_IDENT
            if grep -q "LOCAL_IDENT" "$f"; then
                sed -i 's|#define LOCAL_IDENT.*|#define LOCAL_IDENT "SSH-2.0-ByJuanitoProSniff"|' "$f"
            fi
        fi
    done
    # Para 2019: IDENT_VERSION_PART si existe
    if grep -rq "IDENT_VERSION_PART" . 2>/dev/null; then
        find . -name "*.h" | xargs grep -l "IDENT_VERSION_PART" 2>/dev/null | while read hf; do
            sed -i 's|#define IDENT_VERSION_PART.*|#define IDENT_VERSION_PART "ByJuanitoProSniff"|' "$hf"
        done
    fi

    # Configurar — sin zlib para reducir dependencias, sin wtmp/lastlog
    export CFLAGS="$COMPAT_CFLAGS"
    ./configure \
        --prefix="$PREFIX" \
        --disable-zlib \
        --disable-wtmp \
        --disable-lastlog \
        >/dev/null 2>&1

    # Compilar — pasar CFLAGS también a make por si configure no los heredó
    echo "  Compilando... (2-4 min según CPU)"
    if ! make -j$(nproc) \
            PROGRAMS="dropbear dropbearkey" \
            CFLAGS="$COMPAT_CFLAGS" \
            2>/tmp/dropbear_build_${VER}.log; then
        echo "  ✗ make falló — log: /tmp/dropbear_build_${VER}.log"
        echo "  Últimas líneas del error:"
        tail -8 /tmp/dropbear_build_${VER}.log
        unset CFLAGS
        cd /root
        return 1
    fi

    make install PROGRAMS="dropbear dropbearkey" >/dev/null 2>&1
    unset CFLAGS

    if [ ! -f "$SRVRBIN" ]; then
        echo "  ✗ Binario no encontrado: $SRVRBIN"
        cd /root
        return 1
    fi

    local compiled_ver
    compiled_ver=$("$SRVRBIN" -V 2>&1 | head -1)
    echo "  ✓ Dropbear $VER compilado: $compiled_ver"
    cd /root
    return 0
}

# ============================================================
# COMPILAR AMBAS VERSIONES (2016 y 2019)
# Se instalan en prefijos separados para poder alternar
# ============================================================
echo ""
echo "══════════════════════════════════════════"
echo " Compilando Dropbear 2016.74..."
echo "══════════════════════════════════════════"
compilar_dropbear "2016.74" \
    "https://matt.ucc.asn.au/dropbear/releases/dropbear-2016.74.tar.bz2" \
    "/opt/dropbear-2016"

DB2016_OK=0
[ -f /opt/dropbear-2016/sbin/dropbear ] && DB2016_OK=1

echo ""
echo "══════════════════════════════════════════"
echo " Compilando Dropbear 2019.78..."
echo "══════════════════════════════════════════"
compilar_dropbear "2019.78" \
    "https://matt.ucc.asn.au/dropbear/releases/dropbear-2019.78.tar.bz2" \
    "/opt/dropbear-2019"

DB2019_OK=0
[ -f /opt/dropbear-2019/sbin/dropbear ] && DB2019_OK=1

echo ""
echo "══════════════════════════════════════════"
echo " Resultado compilaciones:"
[ "$DB2016_OK" = "1" ] && echo "  ✓ Dropbear 2016.74 disponible" || echo "  ✗ Dropbear 2016.74 falló"
[ "$DB2019_OK" = "1" ] && echo "  ✓ Dropbear 2019.78 disponible" || echo "  ✗ Dropbear 2019.78 falló"
echo "══════════════════════════════════════════"

# ============================================================
# SELECCIONAR VERSIÓN ACTIVA POR DEFECTO
# Prioridad: 2016 → 2019 → OpenSSH fallback
# El usuario puede cambiarla desde el panel (Opción 7 → sub-opción)
# ============================================================
ACTIVE_DB_BIN=""
ACTIVE_DB_VER=""
ACTIVE_DB_KEYBIN=""

if [ "$DB2016_OK" = "1" ]; then
    ACTIVE_DB_BIN="/opt/dropbear-2016/sbin/dropbear"
    ACTIVE_DB_KEYBIN="/opt/dropbear-2016/bin/dropbearkey"
    ACTIVE_DB_VER="2016"
elif [ "$DB2019_OK" = "1" ]; then
    ACTIVE_DB_BIN="/opt/dropbear-2019/sbin/dropbear"
    ACTIVE_DB_KEYBIN="/opt/dropbear-2019/bin/dropbearkey"
    ACTIVE_DB_VER="2019"
fi

# ============================================================
# GENERAR LLAVES SSH PARA DROPBEAR
# ============================================================
mkdir -p /etc/dropbear-legacy

cat > /etc/dropbear-legacy/banner.txt <<'BANEOF'
t.me/FREEINTERNETVPNMSY
BANEOF

if [ -n "$ACTIVE_DB_KEYBIN" ]; then
    echo "Generando llaves Dropbear..."
    [ ! -f /etc/dropbear-legacy/dropbear_rsa_host_key ] && \
        "$ACTIVE_DB_KEYBIN" -t rsa   -f /etc/dropbear-legacy/dropbear_rsa_host_key   -s 2048 >/dev/null 2>&1 \
        && echo "  ✓ Llave RSA generada"
    [ ! -f /etc/dropbear-legacy/dropbear_ecdsa_host_key ] && \
        "$ACTIVE_DB_KEYBIN" -t ecdsa -f /etc/dropbear-legacy/dropbear_ecdsa_host_key >/dev/null 2>&1 \
        && echo "  ✓ Llave ECDSA generada"
fi

# ============================================================
# FUNCIÓN: generar servicio systemd para una versión específica
# ============================================================
generar_servicio_dropbear() {
    local BIN=$1
    local VER=$2

    # Flags de llaves solo si existen los archivos
    local KEY_FLAGS=""
    [ -f /etc/dropbear-legacy/dropbear_rsa_host_key ]   && KEY_FLAGS="$KEY_FLAGS -r /etc/dropbear-legacy/dropbear_rsa_host_key"
    [ -f /etc/dropbear-legacy/dropbear_ecdsa_host_key ] && KEY_FLAGS="$KEY_FLAGS -r /etc/dropbear-legacy/dropbear_ecdsa_host_key"

    cat > /etc/systemd/system/dropbear-legacy.service <<DBSVC
[Unit]
Description=Dropbear SSH $VER - Puerto 143 (MSY VPN)
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
}

# ============================================================
# ARRANCAR DROPBEAR ACTIVO
# ============================================================
if [ -n "$ACTIVE_DB_BIN" ]; then
    echo ""
    echo "Activando Dropbear $ACTIVE_DB_VER en :143..."
    generar_servicio_dropbear "$ACTIVE_DB_BIN" "$ACTIVE_DB_VER"
    systemctl restart dropbear-legacy
    sleep 2

    if systemctl is-active --quiet dropbear-legacy; then
        echo "✓ Dropbear $ACTIVE_DB_VER activo en 0.0.0.0:143"
    else
        # Mostrar el error real
        echo "⚠ Dropbear no inició — error directo:"
        "$ACTIVE_DB_BIN" -F -E -p 0.0.0.0:143 \
            -b /etc/dropbear-legacy/banner.txt -K 60 -I 300 \
            2>&1 | head -10 &
        sleep 3
        kill $! 2>/dev/null

        if ss -tlnp | grep -q ":143 "; then
            echo "✓ Puerto 143 activo (proceso directo)"
        else
            # Fallback: OpenSSH en :143
            echo "⚠ Usando OpenSSH como fallback en :143"
            if ! grep -q "^Port 143" /etc/ssh/sshd_config; then
                sed -i '/^Port 22/a Port 143' /etc/ssh/sshd_config
                systemctl restart ssh
            fi
            ss -tlnp | grep -q ":143 " \
                && echo "✓ OpenSSH escuchando también en :143" \
                || echo "✗ Puerto 143 no disponible"
            ACTIVE_DB_VER="ssh_fallback"
        fi
    fi
else
    echo "⚠ Ninguna versión de Dropbear compiló — usando OpenSSH en :143"
    if ! grep -q "^Port 143" /etc/ssh/sshd_config; then
        sed -i '/^Port 22/a Port 143' /etc/ssh/sshd_config
        systemctl restart ssh
    fi
    ACTIVE_DB_VER="ssh_fallback"
fi

# Guardar estado para el panel
echo "$ACTIVE_DB_VER"  > /etc/dropbear-legacy/active_version.txt
echo "$ACTIVE_DB_BIN"  > /etc/dropbear-legacy/active_bin.txt
echo "$DB2016_OK"      > /etc/dropbear-legacy/has_2016.txt
echo "$DB2019_OK"      > /etc/dropbear-legacy/has_2019.txt

# ============================================================
# USUARIO INICIAL VPN
# ============================================================
echo ""
echo "Creando usuario VPN inicial..."
USER_VPN="vpnuser"
PASS_VPN="msy$(openssl rand -hex 4)"

id "$USER_VPN" &>/dev/null && userdel -r "$USER_VPN" 2>/dev/null

useradd -m -s /bin/bash "$USER_VPN"
echo "$USER_VPN:$PASS_VPN" | chpasswd

mkdir -p /etc/ssh-vpn/users
cat > /etc/ssh-vpn/users/$USER_VPN.txt <<USEREOF
Usuario: $USER_VPN
Contraseña: $PASS_VPN
Fecha creación: $(date +%Y-%m-%d)
Fecha expiración: Ilimitado
Estado: Activo
Dropbear activo: $ACTIVE_DB_VER
USEREOF

echo "✓ Usuario: $USER_VPN / $PASS_VPN"
export USER_VPN PASS_VPN ACTIVE_DB_VER
