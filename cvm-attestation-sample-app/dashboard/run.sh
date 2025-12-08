#!/bin/bash

set -e

echo "==================================="
echo "CVM Attestation Dashboard Launcher"
echo "==================================="
echo ""

# 현재 스크립트 디렉토리로 이동
cd "$(dirname "$0")"

# Python3 설치 확인
if ! command -v python3 &> /dev/null; then
    echo "❌ Error: python3 is not installed."
    echo "Please install python3 first: sudo apt-get install python3 python3-pip"
    exit 1
fi

# pip3 설치 확인
if ! command -v pip3 &> /dev/null; then
    echo "❌ Error: pip3 is not installed."
    echo "Installing pip3..."
    sudo apt-get update
    sudo apt-get install -y python3-pip
fi

# 필수 Python 패키지 설치
echo "📦 Installing required Python packages..."
pip3 install --quiet flask pyjwt requests 2>/dev/null || {
    echo "⚠ Warning: Could not install packages for current user, trying with --user flag..."
    pip3 install --user --quiet flask pyjwt requests
}

echo "✓ Dependencies installed successfully"
echo ""

# AttestationClient 존재 확인
ATTESTATION_CLIENT="../AttestationClient"
if [ ! -f "$ATTESTATION_CLIENT" ]; then
    echo "⚠ Warning: AttestationClient not found at $ATTESTATION_CLIENT"
    echo "Make sure you have built the AttestationClient first."
    echo ""
fi

# Flask 앱 실행
echo "🚀 Starting Dashboard on http://0.0.0.0:5000"
echo "Press Ctrl+C to stop the server"
echo ""

sudo python3 app.py