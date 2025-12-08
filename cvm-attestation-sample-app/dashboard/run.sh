#!/usr/bin/env bash
set -e

BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
APP_DIR="$BASE_DIR"
CLIENT_DIR="$(cd "$BASE_DIR/.." && pwd)"
ATTESTATION_CLIENT="$CLIENT_DIR/AttestationClient"

echo "===================================================================="
echo "  Confidential VM Attestation Dashboard - Setup & Run"
echo "===================================================================="
echo "BASE_DIR: $BASE_DIR"
echo "CLIENT_DIR: $CLIENT_DIR"
echo "AttestationClient path: $ATTESTATION_CLIENT"
echo ""

if [ ! -f "$ATTESTATION_CLIENT" ]; then
    echo "[ERROR] AttestationClient not found at:"
    echo "        $ATTESTATION_CLIENT"
    exit 1
fi

# Python venv 생성
if [ ! -d "$APP_DIR/venv" ]; then
    echo "[INFO] Creating Python venv..."
    python3 -m venv "$APP_DIR/venv"
fi

# 라이브러리 설치
echo "[INFO] Installing Python dependencies..."
source "$APP_DIR/venv/bin/activate"
pip install --upgrade pip
pip install -r "$APP_DIR/requirements.txt"

# Flask 실행
echo ""
echo "[INFO] Starting Flask Dashboard..."
export ATTESTATION_CLIENT="$ATTESTATION_CLIENT"
python "$APP_DIR/app.py"