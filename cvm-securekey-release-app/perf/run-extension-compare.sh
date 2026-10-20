#!/usr/bin/env bash
# Extension-equivalent comparison: time AzureAttestSKR exactly the way the CDE
# extension invokes it (one process per batch, batch JSON on stdin,
# IMDS_MSI_RES_ID identity, CWD = binary dir), for:
#
#   cde-skr       today's CDE flow: -B - (one SKR release of an exportable RSA
#                 KEK + local RSA-OAEP unwrap of every disk key)
#   secure-lib    -S - secure unwrap, library TPM Decrypt() per key (-K)
#   secure-reuse  -S - secure unwrap, one reused TPM ephemeral key per batch
#
# Every iteration verifies all keys came back (and, for secure unwrap, that
# each key matches its SHA-256 from the batch file).
#
# Required env:
#   MAA_URL, IMDS_MSI_RES_ID
#   SKR_KEK, SKR_BATCH            exportable RSA KEK + `-B` batch ({"keys":[{"id","wrapped":base64}]})
#   SECURE_KEK, SECURE_BATCH      secure-unwrap key + batch from setup-secure-unwrap-key.sh
# Optional env:
#   LABEL         backend label for the CSV (default: host of SECURE_KEK)
#   SECURE_ALG    default RSA-OAEP-256
#   SKR_HASH      -H value for -B (default sha256)
#   CONCURRENCY   -j for secure modes (default 2)
#   DISKS         default "1 4 8 16 32"
#   MODES         default "cde-skr secure-lib secure-reuse"
#   ITERATIONS    default 20, WARMUP default 2
#   SKR_BIN       default ./AzureAttestSKR
#   SKR_BIN_BEFORE  binary for cde-skr mode (default SKR_BIN), e.g. the build CDE ships
#   OUT           CSV path (default ./extension-compare.csv; appended if it exists)
set -euo pipefail

: "${MAA_URL:?}" "${IMDS_MSI_RES_ID:?}" "${SKR_KEK:?}" "${SKR_BATCH:?}" "${SECURE_KEK:?}" "${SECURE_BATCH:?}"
SKR_BIN="$(readlink -f "${SKR_BIN:-./AzureAttestSKR}")"
SKR_BIN_BEFORE="$(readlink -f "${SKR_BIN_BEFORE:-$SKR_BIN}")"
SKR_BATCH="$(readlink -f "$SKR_BATCH")"
SECURE_BATCH="$(readlink -f "$SECURE_BATCH")"
SECURE_ALG="${SECURE_ALG:-RSA-OAEP-256}"
SKR_HASH="${SKR_HASH:-sha256}"
CONCURRENCY="${CONCURRENCY:-2}"
DISKS="${DISKS:-1 4 8 16 32}"
MODES="${MODES:-cde-skr secure-lib secure-reuse}"
ITERATIONS="${ITERATIONS:-20}"
WARMUP="${WARMUP:-2}"
OUT="$(readlink -f "${OUT:-./extension-compare.csv}")"
LABEL="${LABEL:-$(sed -E 's#^https?://([^/]+).*#\1#' <<< "$SECURE_KEK")}"
export IMDS_MSI_RES_ID

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

[[ -f "$OUT" ]] || echo "label,mode,disks,concurrency,iterations,failures,p50,p95,p99,max,mean" > "$OUT"

b64url_sha256() { tr -- '-_' '+/' | awk '{ while (length($0) % 4) $0 = $0 "="; print }' | base64 -d | sha256sum | cut -d' ' -f1; }

for n in $DISKS; do
    jq --argjson n "$n" '{keys: [.keys[] ] | .[0:$n]}' "$SKR_BATCH" > "$TMP/skr.json"
    # Replicate secure keys cyclically if the batch has fewer than n keys.
    jq --argjson n "$n" '.keys as $k | {keys: [range(0; $n) as $i | $k[$i % ($k | length)] | .id += "#\($i)"]}' \
        "$SECURE_BATCH" > "$TMP/secure.json"
    jq -r '.keys[] | "\(.id) \(.sha256 // "")"' "$TMP/secure.json" | sort > "$TMP/expected.txt"

    for mode in $MODES; do
        case "$mode" in
            cde-skr)      cmd=("$SKR_BIN_BEFORE" -B - -a "$MAA_URL" -k "$SKR_KEK" -H "$SKR_HASH"); input="$TMP/skr.json"; conc=1 ;;
            secure-lib)   cmd=("$SKR_BIN" -S - -a "$MAA_URL" -k "$SECURE_KEK" -A "$SECURE_ALG" -j "$CONCURRENCY" -K); input="$TMP/secure.json"; conc=$CONCURRENCY ;;
            secure-reuse) cmd=("$SKR_BIN" -S - -a "$MAA_URL" -k "$SECURE_KEK" -A "$SECURE_ALG" -j "$CONCURRENCY"); input="$TMP/secure.json"; conc=$CONCURRENCY ;;
            *) echo "unknown mode $mode" >&2; exit 1 ;;
        esac
        : > "$TMP/samples"
        fails=0
        echo "=== $LABEL $mode n=$n" >&2
        for ((i = 0; i < WARMUP + ITERATIONS; i++)); do
            start=$(date +%s%N)
            rc=0
            (cd "$(dirname "${cmd[0]}")" && "${cmd[@]}" < "$input" > "$TMP/out.json" 2> "$TMP/err.txt") || rc=$?
            end=$(date +%s%N)
            ok=0
            if ((rc == 0)); then
                if [[ "$mode" == cde-skr ]]; then
                    got=$(jq '[.results[] | select(has("unwrapped"))] | length' "$TMP/out.json" 2> /dev/null || echo 0)
                    ((got == n)) && ok=1
                else
                    jq -r '.results[] | select(has("unwrapped")) | "\(.id) \(.unwrapped)"' "$TMP/out.json" 2> /dev/null |
                        while read -r id val; do echo "$id $(printf '%s' "$val" | b64url_sha256)"; done | sort > "$TMP/got.txt"
                    cmp -s "$TMP/got.txt" "$TMP/expected.txt" && ok=1
                fi
            fi
            : > "$TMP/out.json"
            if ((i < WARMUP)); then continue; fi
            if ((ok)); then
                echo $(((end - start) / 1000000)) >> "$TMP/samples"
            else
                fails=$((fails + 1))
                echo "    iteration $i failed (rc=$rc): $(tail -c 300 "$TMP/err.txt")" >&2
            fi
        done
        sort -n "$TMP/samples" | awk -v l="$LABEL" -v m="$mode" -v n="$n" -v c="$conc" -v it="$ITERATIONS" -v f="$fails" '
            { v[NR] = $1; t += $1 }
            END {
                if (NR == 0) { printf "%s,%s,%d,%d,%d,%d,,,,,\n", l, m, n, c, it, f; exit }
                printf "%s,%s,%d,%d,%d,%d,%d,%d,%d,%d,%.1f\n", l, m, n, c, it, f,
                    v[int(0.50 * NR + 0.999)], v[int(0.95 * NR + 0.999)], v[int(0.99 * NR + 0.999)], v[NR], t / NR
            }' >> "$OUT"
    done
done
echo "Results: $OUT" >&2
column -s, -t < "$OUT" >&2 || cat "$OUT" >&2
