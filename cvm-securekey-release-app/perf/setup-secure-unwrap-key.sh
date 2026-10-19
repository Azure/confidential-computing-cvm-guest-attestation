#!/usr/bin/env bash
# Create a non-exportable secure-unwrap key in AKV Premium (RSA-HSM) or
# Managed HSM (RSA-HSM / oct-HSM), wrap COUNT random 256-bit test DEKs with it,
# and write a batch JSON consumable by `AzureAttestSKR -S/-P`.
#
# The plaintext DEKs are never written to disk; only their SHA-256 digests are
# stored so the perf harness can verify correctness.
#
# Requirements: az (logged in), jq, openssl, curl, xxd.
#
# Usage:
#   VAULT_URL=https://myakv.vault.azure.net \
#   KEY_NAME=cde-perf-rsa \
#   MAA_AUTHORITY=https://sharedeus2.eus2.attest.azure.net \
#   ./setup-secure-unwrap-key.sh
#
# Optional env:
#   KEY_TYPE      RSA-HSM (default) | oct-HSM (Managed HSM only)
#   KEY_SIZE      2048 (default) / 3072 / 4096 for RSA, 256 for oct
#   ALG           RSA-OAEP-256 (default for RSA) | A256KWPAD (default for oct)
#   COUNT         number of wrapped DEKs to generate (default 32)
#   OUT           output batch JSON path (default ./secure-unwrap-batch.json)
#   API_VERSION   key create/wrap API version (default 2026-07-01-preview)
#   SKIP_CREATE   1 to reuse an existing key
set -euo pipefail

: "${VAULT_URL:?Set VAULT_URL, e.g. https://myakv.vault.azure.net}"
: "${KEY_NAME:?Set KEY_NAME}"
KEY_TYPE="${KEY_TYPE:-RSA-HSM}"
COUNT="${COUNT:-32}"
OUT="${OUT:-./secure-unwrap-batch.json}"
API_VERSION="${API_VERSION:-2026-07-01-preview}"
SKIP_CREATE="${SKIP_CREATE:-0}"

if [[ "$KEY_TYPE" == "oct-HSM" ]]; then
    KEY_SIZE="${KEY_SIZE:-256}"
    ALG="${ALG:-A256KWPAD}"
else
    KEY_SIZE="${KEY_SIZE:-2048}"
    ALG="${ALG:-RSA-OAEP-256}"
fi

VAULT_URL="${VAULT_URL%/}"
if [[ "$VAULT_URL" == *".managedhsm.azure.net"* ]]; then
    RESOURCE="https://managedhsm.azure.net"
elif [[ "$VAULT_URL" == *".vault.azure.net"* ]]; then
    RESOURCE="https://vault.azure.net"
    if [[ "$KEY_TYPE" == "oct-HSM" ]]; then
        echo "oct-HSM keys are only supported on Managed HSM" >&2
        exit 1
    fi
else
    echo "VAULT_URL must be a *.vault.azure.net or *.managedhsm.azure.net URL" >&2
    exit 1
fi

b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }

TOKEN="$(az account get-access-token --resource "$RESOURCE" --query accessToken -o tsv)"
kv_post() { # path body
    curl -sS --fail-with-body -X POST "$VAULT_URL$1" \
        -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d "$2"
}

if [[ "$SKIP_CREATE" != "1" ]]; then
    : "${MAA_AUTHORITY:?Set MAA_AUTHORITY, e.g. https://sharedeus2.eus2.attest.azure.net}"
    POLICY="$(jq -cn --arg auth "$MAA_AUTHORITY" '{
        version: "1.0.0",
        anyOf: [{
            authority: $auth,
            anyOf: [
                {allOf: [
                    {claim: "x-ms-isolation-tee.x-ms-attestation-type", equals: "sevsnpvm"},
                    {claim: "x-ms-isolation-tee.x-ms-compliance-status", equals: "azure-compliant-cvm"}
                ]},
                {allOf: [
                    {claim: "x-ms-isolation-tee.x-ms-attestation-type", equals: "tdxvm"},
                    {claim: "x-ms-isolation-tee.x-ms-compliance-status", equals: "azure-compliant-cvm"}
                ]}
            ]
        }]
    }')"
    POLICY_B64URL="$(printf '%s' "$POLICY" | b64url)"

    if [[ "$KEY_TYPE" == "oct-HSM" ]]; then
        SIZE_FIELD="$(jq -cn --argjson s "$KEY_SIZE" '{key_size: $s}')"
    else
        SIZE_FIELD="$(jq -cn --argjson s "$KEY_SIZE" '{key_size: $s, public_exponent: 65537}')"
    fi
    CREATE_BODY="$(jq -cn --arg kty "$KEY_TYPE" --arg policy "$POLICY_B64URL" --argjson size "$SIZE_FIELD" '
        {kty: $kty,
         key_ops: ["wrapKey", "unwrapKey", "secureUnwrapKey"],
         attributes: {enabled: true, exportable: false},
         release_policy: {contentType: "application/json; charset=utf-8", data: $policy}} + $size')"

    echo "Creating $KEY_TYPE/$KEY_SIZE key '$KEY_NAME' in $VAULT_URL (api-version $API_VERSION)" >&2
    kv_post "/keys/$KEY_NAME/create?api-version=$API_VERSION" "$CREATE_BODY" > /dev/null
fi

KID="$(curl -sS --fail-with-body "$VAULT_URL/keys/$KEY_NAME?api-version=$API_VERSION" \
    -H "Authorization: Bearer $TOKEN" | jq -r '.key.kid')"
KEY_VERSION="${KID##*/}"
echo "Key: $KID" >&2

echo "Wrapping $COUNT random 256-bit DEKs with $ALG" >&2
KEYS_JSON="[]"
for ((i = 0; i < COUNT; i++)); do
    DEK_HEX="$(openssl rand -hex 32)"
    DEK_B64URL="$(printf '%s' "$DEK_HEX" | xxd -r -p | b64url)"
    DEK_SHA256="$(printf '%s' "$DEK_HEX" | xxd -r -p | openssl dgst -sha256 -r | cut -d' ' -f1)"
    WRAPPED="$(kv_post "/keys/$KEY_NAME/$KEY_VERSION/wrapkey?api-version=$API_VERSION" \
        "$(jq -cn --arg alg "$ALG" --arg v "$DEK_B64URL" '{alg: $alg, value: $v}')" | jq -r '.value')"
    unset DEK_HEX DEK_B64URL
    KEYS_JSON="$(jq -c --arg id "$(printf 'disk%02d' "$i")" --arg w "$WRAPPED" --arg h "$DEK_SHA256" \
        '. + [{id: $id, wrapped: $w, sha256: $h}]' <<< "$KEYS_JSON")"
done

jq -n --arg kid "$KID" --arg alg "$ALG" --argjson keys "$KEYS_JSON" \
    '{kid: $kid, alg: $alg, keys: $keys}' > "$OUT"
echo "Wrote $OUT" >&2
echo >&2
echo "Next: grant the CVM's managed identity data-plane access to secure unwrap with $KID," >&2
echo "copy $OUT to the CVM, and run run-secure-unwrap-perf.sh with KEK_URL=$KID ALG=$ALG." >&2
