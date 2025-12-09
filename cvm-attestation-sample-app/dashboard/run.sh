#!/bin/bash

set -e

echo "===================================================================="
echo "  Confidential VM Attestation Dashboard - Setup & Run"
echo "===================================================================="

# 현재 스크립트가 있는 디렉토리
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLIENT_DIR="$(dirname "$BASE_DIR")"

echo "BASE_DIR: $BASE_DIR"
echo "CLIENT_DIR: $CLIENT_DIR"

# AttestationClient 경로 설정
if [ -z "$ATTESTATION_CLIENT" ]; then
    export ATTESTATION_CLIENT="$CLIENT_DIR/AttestationClient"
fi

echo "AttestationClient path: $ATTESTATION_CLIENT"
echo ""

# Python 가상환경 생성 및 활성화
if [ ! -d "$BASE_DIR/venv" ]; then
    echo "[INFO] Creating Python virtual environment..."
    python3 -m venv "$BASE_DIR/venv"
fi

source "$BASE_DIR/venv/bin/activate"

# 패키지 설치
echo "[INFO] Installing Python dependencies..."
pip install --upgrade pip > /dev/null 2>&1
pip install -r "$BASE_DIR/requirements.txt"

echo ""

# Public IP 조회 함수
get_public_ip() {
    # Azure Load Balancer Metadata를 통한 Public IP 조회
    local public_ip=$(curl -s -H "Metadata: true" \
        "http://169.254.169.254/metadata/loadbalancer?api-version=2020-10-01" 2>/dev/null | \
        python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('loadbalancer', {}).get('publicIpAddresses', [{}])[0].get('frontendIpAddress', ''))" 2>/dev/null)
    
    # Load Balancer에서 못 가져오면 다른 방법 시도
    if [ -z "$public_ip" ]; then
        public_ip=$(curl -s -H "Metadata: true" \
            "http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAddress/0/publicIpAddress?api-version=2021-02-01&format=text" 2>/dev/null)
    fi
    
    # 그래도 없으면 외부 서비스 이용
    if [ -z "$public_ip" ]; then
        public_ip=$(curl -s ifconfig.me 2>/dev/null || curl -s icanhazip.com 2>/dev/null || echo "")
    fi
    
    echo "$public_ip"
}

# 종료 핸들러 등록
cleanup() {
    echo ""
    echo "[INFO] Shutting down Flask server..."
    if [ ! -z "$FLASK_PID" ]; then
        kill $FLASK_PID 2>/dev/null || true
        wait $FLASK_PID 2>/dev/null || true
    fi
    echo "[INFO] Server stopped."
    exit 0
}

trap cleanup SIGINT SIGTERM

# Public IP 조회
PUBLIC_IP=$(get_public_ip)

echo "[INFO] Starting Flask Dashboard..."
echo ""

# Flask 앱을 백그라운드로 실행하고 PID 저장
python3 "$BASE_DIR/app.py" &
FLASK_PID=$!

# Flask 서버가 시작될 때까지 대기
sleep 2

echo ""
echo "===================================================================="
echo "  Dashboard is now running!"
echo "===================================================================="
echo ""
echo "  Access the dashboard at:"
echo "  - Local:   http://127.0.0.1:5000"
echo "  - Network: http://10.1.0.4:5000 (Private IP)"

if [ -n "$PUBLIC_IP" ] && [ "$PUBLIC_IP" != "N/A" ]; then
    echo "  - Public:  http://$PUBLIC_IP:5000"
    echo ""
    echo "  Note: Make sure port 5000 is open in your NSG/Firewall"
fi

echo ""
echo "  Press Ctrl+C to stop the server"
echo "===================================================================="
echo ""

# Flask 프로세스가 종료될 때까지 대기
wait $FLASK_PID