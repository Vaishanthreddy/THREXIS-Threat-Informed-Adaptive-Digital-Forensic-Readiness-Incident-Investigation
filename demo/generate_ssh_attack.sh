#!/bin/bash
# THREXIS Real Network Attack Simulation Script
# Execute this script inside the Ubuntu VM, from host, or from another machine on your network.

TARGET_HOST="${1:-127.0.0.1}"
TARGET_USER="${2:-admin_test}"
ATTEMPTS="${3:-4}"

echo "=================================================="
echo " THREXIS Live SSH Authentication Failure Sequence "
echo " Target: $TARGET_USER@$TARGET_HOST"
echo " Total Attempts: $ATTEMPTS"
echo "=================================================="

for i in $(seq 1 "$ATTEMPTS"); do
    echo "[$i/$ATTEMPTS] Generating authentication failure for $TARGET_USER@$TARGET_HOST..."
    if command -v sshpass >/dev/null 2>&1; then
        sshpass -p "IncorrectPassword123!" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 -o NumberOfPasswordPrompts=1 "$TARGET_USER@$TARGET_HOST" 2>/dev/null || true
    else
        # Fallback when sshpass is not installed: sends wrong password through stdin/pty simulation
        ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no -o ConnectTimeout=2 -o NumberOfPasswordPrompts=1 "$TARGET_USER@$TARGET_HOST" 2>/dev/null << 'EOF' || true
WrongPassword123!
EOF
    fi
    sleep 1
done

echo ""
echo "[*] Attack burst generated against $TARGET_HOST."
echo "[*] OpenSSH records the failure in systemd journal / auth.log."
echo "[*] THREXIS Collector streams telemetry live to the workstation."
