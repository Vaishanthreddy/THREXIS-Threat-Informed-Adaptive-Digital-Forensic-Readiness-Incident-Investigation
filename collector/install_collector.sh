#!/bin/bash
# THREXIS Collector Installation Script for Ubuntu VM
set -e

echo "=================================================="
echo " Installing THREXIS Ubuntu Telemetry Collector   "
echo "=================================================="

INSTALL_DIR="/opt/threxis-collector"
sudo mkdir -p "$INSTALL_DIR"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
sudo cp "$SCRIPT_DIR/threxis_collector.py" "$INSTALL_DIR/"
sudo cp "$SCRIPT_DIR/config.json" "$INSTALL_DIR/"
sudo chmod +x "$INSTALL_DIR/threxis_collector.py"

# Configure systemd service
sudo cp "$SCRIPT_DIR/threxis-collector.service" /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable threxis-collector
sudo systemctl restart threxis-collector

echo "[*] THREXIS Collector installed and started!"
echo "[*] Check status with: sudo systemctl status threxis-collector"
