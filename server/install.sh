#!/usr/bin/env bash
# Install the WireGuard enrollment service on the Oracle Ubuntu server.
#
#   sudo ./install.sh [PUBLIC_IP]
#
# PUBLIC_IP is the address ESP32 devices use to reach this server
# (default 168.110.106.47). Safe to run again: existing config, tokens,
# certificate and device database are kept.
set -euo pipefail

PUBLIC_IP="${1:-168.110.106.47}"
IFACE="wg0"
API_PORT=8443
ETC=/etc/wg-enroll
HERE="$(cd "$(dirname "$0")" && pwd)"

if [ "$(id -u)" -ne 0 ]; then
    echo "run as root: sudo $0 $*" >&2
    exit 1
fi
for cmd in wg python3 openssl iptables systemctl; do
    command -v "$cmd" >/dev/null || { echo "missing command: $cmd" >&2; exit 1; }
done
if ! wg show "$IFACE" >/dev/null 2>&1; then
    echo "WireGuard interface $IFACE is not up (sudo systemctl start wg-quick@$IFACE)" >&2
    exit 1
fi

echo "[1/5] program -> /usr/local/bin/wg_enroll.py"
install -m 755 "$HERE/wg_enroll.py" /usr/local/bin/wg_enroll.py
install -d -m 700 "$ETC"

echo "[2/5] config -> $ETC/config.json"
if [ ! -f "$ETC/config.json" ]; then
    WG_PORT="$(wg show "$IFACE" listen-port)"
    PUBLIC_IP="$PUBLIC_IP" WG_PORT="$WG_PORT" IFACE="$IFACE" API_PORT="$API_PORT" ETC="$ETC" python3 - <<'EOF'
import json, os, secrets
etc = os.environ["ETC"]
cfg = {
    "interface": os.environ["IFACE"],
    "listen_port": int(os.environ["API_PORT"]),
    "cert": f"{etc}/server.crt",
    "key": f"{etc}/server.key",
    "db": f"{etc}/devices.json",
    "tokens": [secrets.token_urlsafe(24)],
    "endpoint": os.environ["PUBLIC_IP"],
    "endpoint_port": int(os.environ["WG_PORT"]),
    "pool_start": "10.10.0.10",
    "pool_end": "10.10.0.250",
    "netmask": "255.255.255.0",
    "keepalive": 25,
    "rate_limit_per_min": 10,
}
path = f"{etc}/config.json"
with open(path, "w") as f:
    json.dump(cfg, f, indent=2)
os.chmod(path, 0o600)
EOF
else
    echo "      existing config kept"
fi

echo "[3/5] certificate -> $ETC/server.crt (ECDSA P-256, 10 years, IP $PUBLIC_IP)"
if [ ! -f "$ETC/server.crt" ]; then
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
        -days 3650 -subj "/CN=wg-enroll" -addext "subjectAltName=IP:$PUBLIC_IP" \
        -keyout "$ETC/server.key" -out "$ETC/server.crt" 2>/dev/null
    chmod 600 "$ETC/server.key"
else
    echo "      existing certificate kept"
fi

echo "[4/5] systemd service wg-enroll"
install -m 644 "$HERE/wg-enroll.service" /etc/systemd/system/wg-enroll.service
systemctl daemon-reload
systemctl enable wg-enroll >/dev/null
systemctl restart wg-enroll

echo "[5/5] firewall: allow TCP $API_PORT"
if ! iptables -C INPUT -p tcp --dport "$API_PORT" -j ACCEPT 2>/dev/null; then
    iptables -I INPUT -p tcp --dport "$API_PORT" -j ACCEPT
fi
if command -v netfilter-persistent >/dev/null; then
    netfilter-persistent save >/dev/null 2>&1 || true
else
    echo "      WARNING: netfilter-persistent not found; the rule is lost on reboot" >&2
    echo "      (sudo apt install iptables-persistent)" >&2
fi

sleep 1
systemctl --no-pager --lines=3 status wg-enroll || true

TOKEN="$(python3 -c "import json;print(json.load(open('$ETC/config.json'))['tokens'][0])")"
cat <<EOF

================ 설치 완료 ================
[1] 등록 토큰 (비밀) -> idf.py menuconfig > WireGuard VPN Client > Enrollment token
    $TOKEN

[2] 서버 인증서 (공개) -> WireGuardvpn/main/certs/enroll_server.pem 에 그대로 저장
$(cat "$ETC/server.crt")

[3] OCI 콘솔 > VCN > 보안 목록 > 수신 규칙: TCP $API_PORT (소스 0.0.0.0/0) 추가

관리 명령: sudo wg_enroll.py list | revoke <MAC> | reset <MAC> | delete <MAC> | token-new
===========================================
EOF
