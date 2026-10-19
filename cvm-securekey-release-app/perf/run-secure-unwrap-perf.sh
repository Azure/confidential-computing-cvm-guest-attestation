#!/usr/bin/env bash
# Sweep the secure unwrap perf harness (`AzureAttestSKR -P`) across disk counts,
# concurrency levels, and connection-reuse modes on a confidential VM, and
# collect a summary CSV.
#
# Usage (on the CVM):
#   sudo -E KEK_URL=https://myakv.vault.azure.net/keys/cde-perf-rsa/<version> \
#        MAA_URL=https://sharedeus2.eus2.attest.azure.net \
#        BATCH=./secure-unwrap-batch.json \
#        ./run-secure-unwrap-perf.sh
#
# Optional env:
#   SKR_BIN       path to AzureAttestSKR (default ./AzureAttestSKR)
#   ALG           secure unwrap algorithm (default RSA-OAEP-256)
#   CRED          imds (default) | sp
#   DISKS         disk counts to test (default "1 4 8 16 32")
#   CONCURRENCY   concurrency levels (default "1 4 8 16 32"; levels > disks are skipped)
#   REUSE         connection reuse modes (default "on off")
#   ITERATIONS    measured iterations per cell (default 20)
#   WARMUP        warmup iterations per cell (default 2)
#   OUT_DIR       results directory (default ./perf-results-<timestamp>)
#
# Baseline (existing flow: one SKR release + local unwrap of N keys), optional:
#   BASELINE_KEK_URL  exportable RSA key URL for `-B`
#   BASELINE_BATCH    `-B` batch JSON ({"keys":[{"id","wrapped":base64}]})
set -euo pipefail

: "${KEK_URL:?Set KEK_URL to the secure-unwrap key URL (including version)}"
: "${MAA_URL:?Set MAA_URL to the attestation endpoint}"
: "${BATCH:?Set BATCH to the batch JSON from setup-secure-unwrap-key.sh}"
SKR_BIN="${SKR_BIN:-./AzureAttestSKR}"
ALG="${ALG:-RSA-OAEP-256}"
CRED="${CRED:-imds}"
DISKS="${DISKS:-1 4 8 16 32}"
CONCURRENCY="${CONCURRENCY:-1 4 8 16 32}"
REUSE="${REUSE:-on off}"
ITERATIONS="${ITERATIONS:-20}"
WARMUP="${WARMUP:-2}"
OUT_DIR="${OUT_DIR:-./perf-results-$(date +%Y%m%d-%H%M%S)}"

command -v jq > /dev/null || { echo "jq is required" >&2; exit 1; }
mkdir -p "$OUT_DIR"
CSV="$OUT_DIR/summary.csv"
echo "mode,disks,concurrency,reuse,iterations,run_failures,key_failures,retries,http_429,total_p50,total_p95,total_p99,total_max,maa_p50,token_p50,unwrap_phase_p50,unwrap_phase_p95,key_http_p50,key_http_p95,key_tpm_p50,key_tpm_wait_p50" > "$CSV"

{
    echo "host=$(hostname) kernel=$(uname -r) date=$(date -Is)"
    echo "kek=$KEK_URL alg=$ALG maa=$MAA_URL"
    curl -s -H Metadata:true --max-time 2 \
        "http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01" |
        jq -c '{vmSize, location, securityProfile}' 2> /dev/null || true
} > "$OUT_DIR/environment.txt"

for disks in $DISKS; do
    for conc in $CONCURRENCY; do
        if ((conc > disks)); then
            continue
        fi
        for reuse in $REUSE; do
            name="secure_n${disks}_j${conc}_reuse-${reuse}"
            reuse_flag=()
            [[ "$reuse" == "off" ]] && reuse_flag=(-X)
            echo "=== $name" >&2
            if ! "$SKR_BIN" -a "$MAA_URL" -k "$KEK_URL" -c "$CRED" -A "$ALG" \
                -P "$BATCH" -N "$disks" -j "$conc" -i "$ITERATIONS" -W "$WARMUP" \
                "${reuse_flag[@]}" > "$OUT_DIR/$name.json" 2> "$OUT_DIR/$name.log"; then
                echo "    failed (see $OUT_DIR/$name.log)" >&2
                continue
            fi
            jq -r --arg d "$disks" --arg c "$conc" --arg r "$reuse" '
                .summary as $s | [
                    "secure", ($d | tonumber), ($c | tonumber), $r, .config.iterations,
                    $s.run_failures, $s.key_failures, $s.retries, ($s.http_status_counts["429"] // 0),
                    $s.total_ms.p50, $s.total_ms.p95, $s.total_ms.p99, $s.total_ms.max,
                    $s.maa_ms.p50, $s.access_token_ms.p50,
                    $s.unwrap_phase_ms.p50, $s.unwrap_phase_ms.p95,
                    $s.per_key_http_ms.p50, $s.per_key_http_ms.p95,
                    $s.per_key_tpm_ms.p50, $s.per_key_tpm_wait_ms.p50
                ] | @csv' "$OUT_DIR/$name.json" >> "$CSV"
        done
    done
done

if [[ -n "${BASELINE_KEK_URL:-}" && -n "${BASELINE_BATCH:-}" ]]; then
    echo "=== baseline (-B: one SKR release + local unwrap)" >&2
    samples="$OUT_DIR/baseline_ms.txt"
    : > "$samples"
    for ((i = 0; i < WARMUP + ITERATIONS; i++)); do
        start=$(date +%s%N)
        if "$SKR_BIN" -a "$MAA_URL" -k "$BASELINE_KEK_URL" -c "$CRED" -B "$BASELINE_BATCH" > /dev/null 2>> "$OUT_DIR/baseline.log"; then
            end=$(date +%s%N)
            if ((i >= WARMUP)); then
                echo $(((end - start) / 1000000)) >> "$samples"
            fi
        fi
    done
    disks=$(jq '.keys | length' "$BASELINE_BATCH")
    sort -n "$samples" | awk -v d="$disks" -v it="$ITERATIONS" '
        { v[NR] = $1 }
        END {
            if (NR == 0) { exit }
            i50 = int(0.50 * NR + 0.999); i95 = int(0.95 * NR + 0.999); i99 = int(0.99 * NR + 0.999)
            printf "\"baseline\",%s,1,\"n/a\",%s,%d,0,0,0,%s,%s,%s,%s,,,,,,,,\n", d, it, it - NR, v[i50], v[i95], v[i99], v[NR]
        }' >> "$CSV"
fi

echo "Results: $OUT_DIR" >&2
column -s, -t < "$CSV" >&2 || cat "$CSV" >&2
