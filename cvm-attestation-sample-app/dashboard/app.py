import os
import subprocess
import datetime
import json
import socket

import jwt
import requests
from flask import Flask, render_template_string

app = Flask(__name__)

# ─────────────────────────────────────────────
# 경로 설정: ../AttestationClient
# ─────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CLIENT_PATH = os.environ.get(
    "ATTESTATION_CLIENT",
    os.path.join(os.path.dirname(BASE_DIR), "AttestationClient")
)

# ─────────────────────────────────────────────
# Azure Metadata 조회
# ─────────────────────────────────────────────
def get_metadata(path: str) -> str:
    try:
        url = f"http://169.254.169.254/metadata/instance/{path}?api-version=2021-02-01&format=text"
        headers = {"Metadata": "true"}
        r = requests.get(url, headers=headers, timeout=2)
        return r.text.strip() if r.status_code == 200 else "N/A"
    except:
        return "N/A"

# ─────────────────────────────────────────────
# LB 기반 Public IP 조회(frontendIpAddress)
# ─────────────────────────────────────────────
def get_lb_public_ip() -> str:
    try:
        url = "http://169.254.169.254/metadata/loadbalancer?api-version=2020-10-01"
        headers = {"Metadata": "true"}
        r = requests.get(url, headers=headers, timeout=2)
        if r.status_code != 200:
            return "N/A"

        data = r.json()
        public_list = data.get("loadbalancer", {}).get("publicIpAddresses", [])
        if public_list and "frontendIpAddress" in public_list[0]:
            return public_list[0]["frontendIpAddress"]
    except:
        pass
    return "N/A"

# ─────────────────────────────────────────────
# VM 정보 표시
# ─────────────────────────────────────────────
def get_vm_info() -> dict:
    return {
        "hostname": socket.gethostname(),
        "name": get_metadata("compute/name"),
        "vmSize": get_metadata("compute/vmSize"),
        "subscriptionId": get_metadata("compute/subscriptionId"),
        "resourceGroup": get_metadata("compute/resourceGroupName"),
        "location": get_metadata("compute/location"),
        "privateIp": get_metadata("network/interface/0/ipv4/ipAddress/0/privateIpAddress"),
        "publicIp": get_lb_public_ip(),
    }

# ─────────────────────────────────────────────
# 시간 변환
# ─────────────────────────────────────────────
def human_time(ts):
    try:
        ts_int = int(ts)
        dt = datetime.datetime.utcfromtimestamp(ts_int) + datetime.timedelta(hours=9)
        return dt.strftime("%Y-%m-%d %H:%M:%S KST")
    except:
        return "N/A"

# ─────────────────────────────────────────────
# AttestationClient stdout → JWT 토큰 추출
# ─────────────────────────────────────────────
def run_attestation():
    if not os.path.exists(CLIENT_PATH):
        return {"error": f"AttestationClient not found: {CLIENT_PATH}",
                "header": {}, "payload": {}, "raw_token": None}

    try:
        p = subprocess.run(
            [CLIENT_PATH, "-o", "token"],
            cwd=os.path.dirname(CLIENT_PATH),
            capture_output=True,
            text=True,
            timeout=20,
        )
    except Exception as e:
        return {"error": f"AttestationClient execution failed: {e}",
                "header": {}, "payload": {}, "raw_token": None}

    if p.returncode != 0:
        return {"error": f"AttestationClient exited with {p.returncode}\n{p.stdout}\n{p.stderr}",
                "header": {}, "payload": {}, "raw_token": None}

    combined = (p.stdout or "") + "\n" + (p.stderr or "")
    lines = [l.strip() for l in combined.splitlines() if l.strip()]

    raw = ""
    for line in reversed(lines):
        if len(line.split(".")) == 3:
            raw = line
            break

    if not raw:
        return {"error": "JWT token not found in AttestationClient output.",
                "header": {}, "payload": {}, "raw_token": None}

    try:
        header = jwt.get_unverified_header(raw)
        payload = jwt.decode(raw, options={"verify_signature": False})
    except Exception as e:
        return {"error": f"JWT decode error: {e}",
                "header": {}, "payload": {}, "raw_token": raw}

    return {"error": None, "header": header, "payload": payload, "raw_token": raw}

# ─────────────────────────────────────────────
# TEE 정보 추출 (x-ms-isolation-tee 반영)
# ─────────────────────────────────────────────
def extract_tee_info(payload: dict) -> dict:
    """
    토큰 페이로드에서 TEE 관련 정보를 추출한다.
    - 바깥 x-ms-tee-type / x-ms-attestation-type
    - x-ms-isolation-tee 내부의 x-ms-attestation-type (sevsnpvm 등)
      및 x-ms-compliance-status(azure-compliant-cvm 등)
    를 기반으로 실질적인 TEE 타입과 CVM 여부를 계산한다.
    """
    outer_tee = payload.get("x-ms-tee-type") or ""
    outer_att = payload.get("x-ms-attestation-type") or ""

    isolation = payload.get("x-ms-isolation-tee") or {}
    inner_tee = isolation.get("x-ms-tee-type") or ""  # 있을 수도 있고 없을 수도 있음
    inner_att = isolation.get("x-ms-attestation-type") or ""  # sevsnpvm 등
    compliance = isolation.get("x-ms-compliance-status") or ""

    # UI에 보여줄 "실질적인" TEE / Attestation 타입
    # 우선순위: outer_tee > inner_tee > inner_att > outer_att
    effective_tee = outer_tee or inner_tee or inner_att or outer_att
    # Attestation Type은 바깥쪽이 없으면 inner_att 사용
    effective_att = outer_att or inner_att or outer_tee

    # CVM 여부 판정
    joined = " ".join([outer_tee, outer_att, inner_tee, inner_att, compliance]).lower()
    is_confidential = any(
        key in joined
        for key in ["sevsnp", "tdx", "sgx", "cvm", "confidential"]
    )

    return {
        "tee_type": effective_tee,
        "att_type": effective_att,
        "compliance": compliance,
        "is_confidential": is_confidential,
    }

# ─────────────────────────────────────────────
# HTML UI
# ─────────────────────────────────────────────
TEMPLATE = r"""
<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8" />
<title>Confidential VM Attestation Dashboard</title>
<style>
body{background:#020617;color:#e5e7eb;font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;margin:0;}
header{background:#0b1120;padding:16px 32px;border-bottom:1px solid #1f2937;}
h1{margin:0;font-size:20px;}
.container{max-width:1100px;margin:24px auto;padding:0 16px 40px;}
.card{background:#020617;border-radius:16px;padding:16px 20px;border:1px solid #1f2937;margin-bottom:16px;box-shadow:0 10px 25px rgba(15,23,42,0.7);}
pre{background:#020617;border:1px solid #1f2937;padding:12px;border-radius:8px;overflow-x:auto;font-size:12px;}
.btn{background:#2563eb;color:#fff;border-radius:999px;padding:8px 16px;text-decoration:none;font-size:14px;border:none;cursor:pointer;}
.btn:hover{background:#1d4ed8;}
.btn-container{text-align:right;margin-bottom:20px;}
.warn{background:#451a03;color:#fed7aa;border:1px solid #f97316;border-radius:8px;padding:8px 12px;margin-top:8px;font-size:13px;}
.ok{background:#064e3b;color:#bbf7d0;border:1px solid #16a34a;border-radius:8px;padding:8px 12px;margin-top:8px;font-size:13px;}
.badge{display:inline-block;border-radius:999px;padding:2px 8px;font-size:11px;font-weight:600;}
.badge-green{background:#022c22;color:#6ee7b7;border:1px solid #16a34a;}
.badge-amber{background:#451a03;color:#fed7aa;border:1px solid #f59e0b;}
.badge-red{background:#450a0a;color:#fecaca;border:1px solid #ef4444;}
.badge-blue{background:#0b1120;color:#93c5fd;border:1px solid #3b82f6;}
.badge-slate{background:#020617;color:#cbd5f5;border:1px solid #4b5563;}
.label{font-weight:bold;color:#60a5fa;}
ul{margin:0;padding-left:18px;font-size:14px;list-style-type:none;}
ul li{margin-bottom:4px;}
.section-title{font-size:15px;font-weight:600;margin-bottom:6px;}
.sub{font-size:13px;color:#cbd5e1;margin-bottom:12px;line-height:1.6;padding:8px 12px;background:#0f172a;border-left:3px solid #3b82f6;border-radius:4px;}
details{margin-top:12px;}
details summary{cursor:pointer;user-select:none;font-size:15px;font-weight:600;padding:8px 0;color:#93c5fd;}
details summary:hover{color:#60a5fa;}
details[open] summary{margin-bottom:8px;}
.tooltip{position:relative;display:inline-block;cursor:help;border-bottom:1px dotted #60a5fa;}
.tooltip .tooltiptext{visibility:hidden;width:280px;background-color:#1e293b;color:#e2e8f0;text-align:left;border-radius:8px;padding:10px;position:absolute;z-index:1;bottom:125%;left:50%;margin-left:-140px;opacity:0;transition:opacity 0.3s;font-size:12px;line-height:1.5;border:1px solid #334155;box-shadow:0 4px 6px rgba(0,0,0,0.3);}
.tooltip .tooltiptext::after{content:"";position:absolute;top:100%;left:50%;margin-left:-5px;border-width:5px;border-style:solid;border-color:#1e293b transparent transparent transparent;}
.tooltip:hover .tooltiptext{visibility:visible;opacity:1;}
</style>
</head>

<body>

<header>
  <h1>Confidential VM Attestation Dashboard</h1>
</header>

<div class="container">

  <div class="btn-container">
    <a href="/" class="btn">Attest Now</a>
  </div>

  <!-- VM 정보 -->
  <div class="card">
    <div class="section-title">🔹 VM 정보</div>
    <ul>
      <li><span class="label">Hostname</span>: {{ vm.hostname }}</li>
      <li><span class="label">VM Name</span>: {{ vm.name }}</li>
      <li>
        <span class="label">VM Size</span>:
        <span class="badge badge-blue">{{ vm.vmSize }}</span>
      </li>
      <li><span class="label">Location</span>: {{ vm.location }}</li>
      <li><span class="label">Resource Group</span>: {{ vm.resourceGroup }}</li>
      <li>
        <span class="label">Private IP</span>:
        <span class="badge badge-slate">{{ vm.privateIp }}</span>
      </li>
      <li>
        <span class="label">Public IP</span>:
        {% if vm.publicIp != "N/A" %}
          <span class="badge badge-blue">{{ vm.publicIp }}</span>
        {% else %}
          <span class="badge badge-slate">N/A</span>
        {% endif %}
      </li>
    </ul>
  </div>

  {% if error %}
    <div class="card warn"><span class="label">오류:</span> {{ error }}</div>
  {% endif %}

  {% if raw_token %}
  <div class="card">
    <div class="section-title">🔹 Attestation 요약</div>
    <div class="sub">
      JWT 토큰에서 추출한 핵심 정보입니다.<br>
      발급 기관, 유효 기간, TEE 타입 및 Confidential VM 지원 여부를 확인할 수 있습니다.
    </div>
    <ul>
      <li>
        <span class="label tooltip">Issuer
          <span class="tooltiptext">JWT 토큰을 발급한 Azure Attestation 서비스의 URL입니다. 토큰의 신뢰성을 검증하는 데 사용됩니다.</span>
        </span>: {{ payload.get("iss") }}
      </li>
      <li>
        <span class="label tooltip">발급 시각
          <span class="tooltiptext">JWT 토큰이 생성된 시각입니다. Unix timestamp를 KST 시간대로 변환하여 표시합니다.</span>
        </span>: {{ iat }}
      </li>
      <li>
        <span class="label tooltip">만료 시각
          <span class="tooltiptext">JWT 토큰이 유효하지 않게 되는 시각입니다. 이 시각 이후에는 토큰을 신뢰할 수 없습니다.</span>
        </span>: {{ exp }}
      </li>
      <li>
        <span class="label tooltip">TEE Type
          <span class="tooltiptext">Trusted Execution Environment의 종류입니다. SEV-SNP(AMD), TDX(Intel), SGX 등 하드웨어 기반 보안 환경을 나타냅니다.</span>
        </span>:
        {% if tee_type_display != "없음" and is_confidential %}
          <span class="badge badge-green">{{ tee_type_display }}</span>
        {% elif tee_type_display != "없음" %}
          <span class="badge badge-amber">{{ tee_type_display }}</span>
        {% else %}
          <span class="badge badge-slate">없음</span>
        {% endif %}
      </li>
      <li>
        <span class="label tooltip">Attestation Type
          <span class="tooltiptext">증명(attestation) 방식의 유형입니다. sevsnpvm, azurevmgs 등 Azure에서 사용하는 증명 프로토콜을 나타냅니다.</span>
        </span>:
        {% if att_type_display != "없음" %}
          <span class="badge badge-blue">{{ att_type_display }}</span>
        {% else %}
          <span class="badge badge-slate">없음</span>
        {% endif %}
      </li>
      <li>
        <span class="label tooltip">Compliance Status
          <span class="tooltiptext">Azure Confidential VM 규정 준수 상태입니다. azure-compliant-cvm 값은 Microsoft의 보안 기준을 충족함을 의미합니다.</span>
        </span>:
        {% if compliance_display != "없음" %}
          <span class="badge badge-green">{{ compliance_display }}</span>
        {% else %}
          <span class="badge badge-slate">없음</span>
        {% endif %}
      </li>
      <li>
        <span class="label tooltip">Secure Boot
          <span class="tooltiptext">UEFI Secure Boot 활성화 여부입니다. 부팅 시 서명되지 않은 코드 실행을 방지하여 루트킷 등의 공격을 차단합니다.</span>
        </span>:
        {% if secureboot_on %}
          <span class="badge badge-green">Enabled</span>
        {% elif payload.get("secureboot") is not none %}
          <span class="badge badge-amber">Disabled</span>
        {% else %}
          <span class="badge badge-slate">N/A</span>
        {% endif %}
      </li>
    </ul>

    {% if not is_confidential %}
      <div class="warn">
        ⚠ 이 VM은 Confidential VM(SEV-SNP/TDX/SGX)으로 감지되지 않았습니다.<br>
        (TEE Type: {{ tee_type_display or "없음" }}, Attestation Type: {{ att_type_display or "없음" }},
         Compliance: {{ compliance_display or "없음" }})
      </div>
    {% else %}
      <div class="ok">
        ✓ Confidential VM 환경이 감지되었습니다.<br>
        (TEE Type: {{ tee_type_display or "알 수 없음" }},
         Compliance: {{ compliance_display or "알 수 없음" }})
      </div>
    {% endif %}
  </div>

  <div class="card">
    <div class="section-title">🔹 Azure Attestation 확장 Claim (x-ms-*)</div>
    <div class="sub">Azure 전용 클레임 정보입니다. x-ms-* 접두사로 시작하는 속성들을 확인할 수 있습니다.</div>
    <pre>{{ azure_claims_pretty }}</pre>
  </div>

  <div class="card">
    <details>
      <summary>🔹 JWT Payload RAW (Claim)</summary>
      <pre>{{ payload_pretty }}</pre>
    </details>
  </div>

  <div class="card">
    <details>
      <summary>🔹 Raw JWT Token</summary>
      <pre>{{ raw_token }}</pre>
    </details>
  </div>

  {% endif %}
</div>

</body>
</html>
"""

# ─────────────────────────────────────────────
# 라우터
# ─────────────────────────────────────────────
@app.route("/")
def index():
    vm = get_vm_info()
    result = run_attestation()
    payload = result["payload"]

    # 시간 변환
    iat = human_time(payload.get("iat"))
    exp = human_time(payload.get("exp"))

    # Confidential VM 여부 및 TEE 정보 추출
    tee_info = extract_tee_info(payload)
    is_confidential = tee_info["is_confidential"]
    tee = tee_info["tee_type"]
    att = tee_info["att_type"]
    compliance = tee_info["compliance"]

    # Secure Boot 상태
    secureboot_val = payload.get("secureboot")
    secureboot_on = False
    if secureboot_val is not None:
        s = str(secureboot_val).lower()
        secureboot_on = s in ["true", "1", "enabled", "yes"]

    # x-ms-* claim만 모아서 출력
    azure_claims = {k: v for k, v in payload.items() if k.startswith("x-ms-")}

    return render_template_string(
        TEMPLATE,
        vm=vm,
        error=result["error"],
        raw_token=result["raw_token"],
        payload=payload,
        iat=iat,
        exp=exp,
        azure_claims_pretty=json.dumps(azure_claims, indent=2, ensure_ascii=False),
        payload_pretty=json.dumps(payload, indent=2, ensure_ascii=False),
        is_confidential=is_confidential,
        tee_type_display=tee or "없음",
        att_type_display=att or "없음",
        compliance_display=compliance or "없음",
        secureboot_on=secureboot_on,
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
