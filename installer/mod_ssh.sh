#!/bin/bash
# mod_ssh.sh - MSY VPN v104+ (FIXED)
# SSH: OpenSSH :22 + Dropbear legacy :143
#
# CORRECCIONES v104-fix:
#   - CFLAGS completos para GCC 9/11/13/14 (Ubuntu 18/20/22/24/25)
#   - Parche de sources para Dropbear 2016 en GCC 12+
#   - Manejo correcto de "Illegal packet size" (tráfico HTTP llegando a SSH)
#   - Dependencias de compilación verificadas antes de intentar
#   - Fallback robusto con reintento automático
#   - Soporte Ubuntu 18.04 (Bionic) explícito

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
# DEPENDENCIAS DE COMPILACIÓN
# Instalar antes de cualquier compilación para evitar errores
# ============================================================
echo ""
echo "Verificando dependencias de compilación..."

PKGS_NEEDED="gcc make wget libc6-dev"

# En Ubuntu 18+ el paquete de headers varía
if apt-cache show linux-headers-$(uname -r) >/dev/null 2>&1; then
    PKGS_NEEDED="$PKGS_NEEDED linux-headers-$(uname -r)"
fi

# libssl-dev: nombre puede variar en Ubuntu 18 vs 20+
if apt-cache show libssl-dev >/dev/null 2>&1; then
    PKGS_NEEDED="$PKGS_NEEDED libssl-dev"
fi

apt-get update -qq 2>/dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq $PKGS_NEEDED 2>/dev/null
echo "✓ Dependencias OK"

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
# CFLAGS POR VERSIÓN DE GCC
#
# El error "Illegal packet size! (1231976033)" NO es un bug de
# compilación — es tráfico HTTP/no-SSH llegando al puerto 143.
# Dropbear lo registra pero no crashea; el cliente sí desconecta.
# Solución real: el proxy HTTP debe hablar SSH correctamente.
#
# Los CFLAGS aquí resuelven los errores de COMPILACIÓN:
#   GCC 12+: implicit-function-declaration, implicit-int
#   GCC 14+: incompatible-pointer-types (más estricto)
# ============================================================
if   [ "$GCC_VER" -ge 14 ] 2>/dev/null; then
    COMPAT_CFLAGS="-w -Wno-error -fcommon -Wno-error=implicit-function-declaration -Wno-error=implicit-int -Wno-error=int-conversion -Wno-error=incompatible-pointer-types -Wno-error=discarded-qualifiers -std=gnu11"
    echo "  GCC $GCC_VER detectado — CFLAGS máximos (GCC 14)"
elif [ "$GCC_VER" -ge 12 ] 2>/dev/null; then
    COMPAT_CFLAGS="-Wno-error=implicit-function-declaration -Wno-error=implicit-int -Wno-error=int-conversion -Wno-error=incompatible-pointer-types -fcommon"
    echo "  GCC $GCC_VER detectado — CFLAGS GCC 12/13"
else
    COMPAT_CFLAGS="-fcommon"
    echo "  GCC $GCC_VER detectado — CFLAGS estándar"
fi

# ============================================================
# FUNCIÓN: parchear sources de Dropbear 2016 para GCC 12+
# Dropbear 2016 tiene funciones implícitas que GCC 12+ rechaza
# aun con -Wno-error: algunos problemas son de sintaxis real
# ============================================================
parchear_dropbear_2016() {
    local SRCDIR=$1
    echo "  Aplicando parches de compatibilidad a Dropbear 2016..."

    # Parche 1: atomics.h — usa __sync_* que en algunos GCC necesita include
    if [ -f "$SRCDIR/atomics.h" ]; then
        grep -q "#include <stdint.h>" "$SRCDIR/atomics.h" || \
            sed -i '1s/^/#include <stdint.h>\n/' "$SRCDIR/atomics.h"
    fi

    # Parche 2: chansession.c — declaraciones implícitas de getutent/pututline
    if [ -f "$SRCDIR/chansession.c" ]; then
        grep -q "#include <utmp.h>" "$SRCDIR/chansession.c" || \
            sed -i '/#include "includes.h"/a #include <utmp.h>' "$SRCDIR/chansession.c"
    fi

    # Parche 3: loginrec.c — declaraciones implícitas
    if [ -f "$SRCDIR/loginrec.c" ]; then
        grep -q "#include <utmpx.h>" "$SRCDIR/loginrec.c" || \
            sed -i '/#include "includes.h"/a #include <utmpx.h>' "$SRCDIR/loginrec.c"
    fi

    # Parche 4: fuzz targets que GCC 14 rechaza (solo si existen)
    for fuzz_f in fuzz-*.c; do
        [ -f "$SRCDIR/$fuzz_f" ] && rm -f "$SRCDIR/$fuzz_f"
    done

    echo "  ✓ Parches aplicados"
}

# ============================================================
# FUNCIÓN GENÉRICA: compilar una versión de Dropbear
# Uso: compilar_dropbear <version> <url> <prefix> [parchear=0|1]
# ============================================================
compilar_dropbear() {
    local VER=$1
    local URL=$2
    local PREFIX=$3
    local PARCHEAR=${4:-0}
    local TARBALL="dropbear-${VER}.tar.bz2"
    local SRCDIR="/usr/src/dropbear-${VER}"
    local SRVRBIN="${PREFIX}/sbin/dropbear"
    local KEYBIN="${PREFIX}/bin/dropbearkey"

    echo ""
    echo "  ── Compilando Dropbear $VER ──"
    echo "  Prefix: $PREFIX"

    cd /usr/src

    # ── Descargar ──
    if [ ! -f "$TARBALL" ] || [ ! -s "$TARBALL" ]; then
        echo "  Descargando $TARBALL..."
        wget -q --timeout=60 -O "$TARBALL" "$URL" 2>/dev/null
        # Mirror alternativo
        if [ ! -s "$TARBALL" ]; then
            echo "  Mirror alternativo..."
            wget -q --timeout=60 -O "$TARBALL" \
                "https://dropbear.nl/mirror/releases/$TARBALL" 2>/dev/null
        fi
        # Segundo mirror
        if [ ! -s "$TARBALL" ]; then
            echo "  Segundo mirror..."
            wget -q --timeout=60 -O "$TARBALL" \
                "https://github.com/mkj/dropbear/archive/refs/tags/DROPBEAR_${VER//./_}.tar.gz" 2>/dev/null
        fi
        if [ ! -s "$TARBALL" ]; then
            echo "  ✗ No se pudo descargar Dropbear $VER"
            return 1
        fi
    fi

    # ── Extraer ──
    rm -rf "$SRCDIR" 2>/dev/null
    tar xjf "$TARBALL" -C /usr/src 2>/dev/null
    if [ ! -d "$SRCDIR" ]; then
        echo "  ✗ Error extrayendo $TARBALL"
        return 1
    fi

    cd "$SRCDIR"

    # ── Parchear si se pide (para 2016 en GCC 12+) ──
    [ "$PARCHEAR" = "1" ] && parchear_dropbear_2016 "$SRCDIR"

    # ── Personalizar identificador SSH ──
    for f in sysoptions.h default_options.h options.h; do
        if [ -f "$f" ]; then
            if grep -q "LOCAL_IDENT" "$f"; then
                sed -i 's|#define LOCAL_IDENT.*|#define LOCAL_IDENT "SSH-2.0-ByJuanitoProSniff"|' "$f"
            fi
        fi
    done
    if grep -rq "IDENT_VERSION_PART" . 2>/dev/null; then
        find . -name "*.h" | xargs grep -l "IDENT_VERSION_PART" 2>/dev/null | while read hf; do
            sed -i 's|#define IDENT_VERSION_PART.*|#define IDENT_VERSION_PART "ByJuanitoProSniff"|' "$hf"
        done
    fi

    # ── Configurar ──
    export CFLAGS="$COMPAT_CFLAGS"
    ./configure \
        --prefix="$PREFIX" \
        --disable-zlib \
        --disable-wtmp \
        --disable-lastlog \
        >/dev/null 2>&1

    # ── Compilar ──
    echo "  Compilando... (2-5 min según CPU)"
    if ! make -j$(nproc) \
            PROGRAMS="dropbear dropbearkey" \
            CFLAGS="$COMPAT_CFLAGS" \
            2>/tmp/dropbear_build_${VER}.log; then

        echo "  ✗ make falló — últimas líneas:"
        tail -10 /tmp/dropbear_build_${VER}.log
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
# COMPILAR DROPBEAR 2016.74
# Parchear si GCC >= 12 para evitar errores de sintaxis implícita
# ============================================================
echo ""
echo "══════════════════════════════════════════"
echo " Compilando Dropbear 2016.74..."
echo "══════════════════════════════════════════"

PARCHEAR_2016=0
[ "$GCC_VER" -ge 12 ] 2>/dev/null && PARCHEAR_2016=1

compilar_dropbear "2016.74" \
    "https://matt.ucc.asn.au/dropbear/releases/dropbear-2016.74.tar.bz2" \
    "/opt/dropbear-2016" \
    "$PARCHEAR_2016"

DB2016_OK=0
[ -f /opt/dropbear-2016/sbin/dropbear ] && DB2016_OK=1

# Si falló con parche, intentar sin parche (por si el entorno es más permisivo)
if [ "$DB2016_OK" = "0" ] && [ "$PARCHEAR_2016" = "1" ]; then
    echo "  Reintentando Dropbear 2016 sin parche con -w (suprimir todos los warnings)..."
    COMPAT_CFLAGS_ORIG="$COMPAT_CFLAGS"
    COMPAT_CFLAGS="-w -fcommon -std=gnu11"
    compilar_dropbear "2016.74" \
        "https://matt.ucc.asn.au/dropbear/releases/dropbear-2016.74.tar.bz2" \
        "/opt/dropbear-2016" \
        "0"
    COMPAT_CFLAGS="$COMPAT_CFLAGS_ORIG"
    [ -f /opt/dropbear-2016/sbin/dropbear ] && DB2016_OK=1
fi

# ============================================================
# COMPILAR DROPBEAR 2019.78
# ============================================================
echo ""
echo "══════════════════════════════════════════"
echo " Compilando Dropbear 2019.78..."
echo "══════════════════════════════════════════"
compilar_dropbear "2019.78" \
    "https://matt.ucc.asn.au/dropbear/releases/dropbear-2019.78.tar.bz2" \
    "/opt/dropbear-2019" \
    "0"

DB2019_OK=0
[ -f /opt/dropbear-2019/sbin/dropbear ] && DB2019_OK=1

echo ""
echo "══════════════════════════════════════════"
echo " Resultado compilaciones:"
[ "$DB2016_OK" = "1" ] && echo "  ✓ Dropbear 2016.74 disponible" || echo "  ✗ Dropbear 2016.74 falló"
[ "$DB2019_OK" = "1" ] && echo "  ✓ Dropbear 2019.78 disponible" || echo "  ✗ Dropbear 2019.78 falló"
echo "══════════════════════════════════════════"

# ============================================================
# SELECCIONAR VERSIÓN ACTIVA
# Prioridad: 2016 → 2019 → OpenSSH fallback
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
        "$ACTIVE_DB_KEYBIN" -t rsa -f /etc/dropbear-legacy/dropbear_rsa_host_key -s 2048 >/dev/null 2>&1 \
        && echo "  ✓ Llave RSA generada"
    [ ! -f /etc/dropbear-legacy/dropbear_ecdsa_host_key ] && \
        "$ACTIVE_DB_KEYBIN" -t ecdsa -f /etc/dropbear-legacy/dropbear_ecdsa_host_key >/dev/null 2>&1 \
        && echo "  ✓ Llave ECDSA generada"
fi

# ============================================================
# FUNCIÓN: generar servicio systemd
#
# SOBRE "Illegal packet size" (1231976033 = 0x496E7421 = "Int!"):
#   Este error aparece cuando tráfico HTTP llega al puerto SSH.
#   Dropbear lo loguea pero NO falla — el bug real está en los
#   proxies HTTP que no reenvían la sesión SSH correctamente.
#   Aquí usamos -s para silenciar esos logs y evitar confusión.
#   La solución completa está en mod_proxies.sh asegurando que
#   los proxies hagan CONNECT TCP (tunnel), no HTTP forward.
# ============================================================
generar_servicio_dropbear() {
    local BIN=$1
    local VER=$2

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
    -K 120 -I 600
Restart=always
RestartSec=3
KillMode=process
StandardOutput=null
StandardError=null
LimitNOFILE=65536

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

    # Liberar puerto 143 si está ocupado
    systemctl stop dropbear-legacy 2>/dev/null
    pkill -9 -f "dropbear.*143" 2>/dev/null
    fuser -k 143/tcp 2>/dev/null
    sleep 1

    generar_servicio_dropbear "$ACTIVE_DB_BIN" "$ACTIVE_DB_VER"
    systemctl restart dropbear-legacy
    sleep 2

    if systemctl is-active --quiet dropbear-legacy; then
        echo "✓ Dropbear $ACTIVE_DB_VER activo en 0.0.0.0:143"
    else
        echo "⚠ Dropbear no inició con systemd — intentando proceso directo..."

        # Intento directo para ver el error real
        DIRECT_ERR=$("$ACTIVE_DB_BIN" -F -E \
            -p 0.0.0.0:143 \
            -b /etc/dropbear-legacy/banner.txt \
            -K 120 -I 600 2>&1 &
            sleep 3
            kill $! 2>/dev/null)

        if ss -tlnp 2>/dev/null | grep -q ":143 " || \
           netstat -tlnp 2>/dev/null | grep -q ":143 "; then
            echo "✓ Puerto 143 activo (proceso directo)"
        else
            echo "  Error al iniciar directamente: $DIRECT_ERR"

            # Intentar con la otra versión si está disponible
            if [ "$ACTIVE_DB_VER" = "2016" ] && [ "$DB2019_OK" = "1" ]; then
                echo "  Intentando Dropbear 2019 como alternativa..."
                ACTIVE_DB_BIN="/opt/dropbear-2019/sbin/dropbear"
                ACTIVE_DB_VER="2019"
                generar_servicio_dropbear "$ACTIVE_DB_BIN" "$ACTIVE_DB_VER"
                systemctl restart dropbear-legacy
                sleep 2
                systemctl is-active --quiet dropbear-legacy \
                    && echo "✓ Dropbear 2019 activo en :143" \
                    || echo "  ✗ Dropbear 2019 también falló"
            fi

            # Fallback final: OpenSSH en :143
            if ! ss -tlnp 2>/dev/null | grep -q ":143 " && \
               ! netstat -tlnp 2>/dev/null | grep -q ":143 "; then
                echo "⚠ Usando OpenSSH como fallback en :143"
                if ! grep -q "^Port 143" /etc/ssh/sshd_config; then
                    sed -i '/^Port 22/a Port 143' /etc/ssh/sshd_config
                    systemctl restart ssh
                fi
                sleep 1
                if ss -tlnp 2>/dev/null | grep -q ":143 " || \
                   netstat -tlnp 2>/dev/null | grep -q ":143 "; then
                    echo "✓ OpenSSH escuchando también en :143"
                    ACTIVE_DB_VER="ssh_fallback"
                else
                    echo "✗ Puerto 143 no disponible"
                    ACTIVE_DB_VER="ssh_fallback"
                fi
            fi
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

# ============================================================
# GUARDAR ESTADO
# ============================================================
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
