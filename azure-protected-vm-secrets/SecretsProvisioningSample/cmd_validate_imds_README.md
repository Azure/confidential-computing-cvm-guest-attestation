# validate-imds-metadata

Reads a full IMDS JSON blob from stdin and performs two-level cryptographic
verification to confirm the blob is genuine and has not been tampered with by
the host.

## Usage

```sh
curl -s -H "Metadata:true" \
  "http://169.254.169.254/metadata/instance?api-version=2025-01-01" \
  | azure-protected-secrets-tool validate-imds-metadata
```

Exit code `0` = all fields verified. Exit code `1` = any failure.

The verification policy is fixed internally to `AllowUnencrypted` (a signature is
always required; the IMDS SigningOnly token is signed but never encrypted). This
command takes no arguments - the IMDS blob is read from stdin only - so the
signature check cannot be relaxed by the caller. Passing any argument (including
`--policy`) is rejected with the error
`no arguments allowed for validate-imds-metadata` (exit code `1`).

---

## IMDS Blob Structure

The IMDS endpoint returns a JSON object. IMDS exposes the CPS signature envelope
as a base64 string at `compute.signatureInfo` (camelCase, nested under `compute`)
on the signed-metadata API version:

```json
{
  "compute": {
    "vmId":     "abc12345-1234-1234-1234-abcdef123456",
    "location": "eastus",
    "vmSize":   "Standard_DC4as_v5",
    "signatureInfo": "<base64-encoded signatureInfo JSON — see below>",
    ...
  },
  "network": {
    ...
  }
}
```

---

## signatureInfo Structure

`compute.signatureInfo` is a base64-encoded JSON object. Its exact shape is the
CRP authoritative contract (`Compute-CPlat-Core`: `SignatureInfo.cs`,
`CanonicalJsonHelper.cs`, `InVMArtifactsProfileBuilderBase.cs`):

```json
{
  "certChain": "",
  "signature": "{\"<compositeHashKey>\":\"<CPS JWT>\"}",
  "metadata": {
    "publicKeys":     "e3b0c4...  (SHA256 hex)",
    "subscriptionId": "9bc2d4...  (SHA256 hex)",
    "userData":       "f7a031...  (SHA256 hex)",
    "vmId":           "a3f1e2...  (SHA256 hex)"
  }
}
```

### Fields

| Field | Description |
|---|---|
| `certChain` | Empty string. Cert chain is embedded inside the JWT `x5c` header, so this field is ignored by the guest. |
| `signature` | `SerializeToString(JwtTokens)` - a JSON object mapping CPS SensitiveData key(s) to the issued JWT token(s), NOT a bare JWT. The guest parses it and takes the token value. The JWT is SIGNED, NOT ENCRYPTED (CRP calls CPS with `signingRequired:true, encryptionRequired:false`); cert chain in `x5c`, payload is the composite hash of `metadata`. |
| `metadata` | Flat map of the four signed field names (`publicKeys`, `subscriptionId`, `userData`, `vmId`, lexicographical order) to SHA256 hex of the canonical JSON of that field. Keys are FLAT names, NOT dotted paths; each value is read from the IMDS `compute` object. |

### The four signed fields (CRP `SigningFieldNames`)

| Catalog key | IMDS source | Hash input |
|---|---|---|
| `vmId` | `compute.vmId` | `SHA256(canonical_json(vmId))` - GUID hyphenated lowercase |
| `subscriptionId` | `compute.subscriptionId` | `SHA256(canonical_json(subscriptionId))` - GUID hyphenated lowercase |
| `userData` | `compute.userData` | `SHA256(canonical_json(userData))` - base64 string as served; ABSENT means treat as `""`, never `not_found` |
| `publicKeys` | `compute.publicKeys` | `SHA256(canonical_publicKeys)` - order-independent, see array handling |

---

## Sample Full IMDS Blob (Concrete Example)

This is what the complete IMDS JSON looks like on the wire. The `compute` and
`network` fields are the standard Azure IMDS response; `compute.signatureInfo` is
the base64-encoded envelope IMDS exposes for the signed-metadata feature.

```json
{
  "compute": {
    "azEnvironment": "AzurePublicCloud",
    "location": "eastus",
    "name": "my-cvm-01",
    "offer": "0001-com-ubuntu-confidential-vm-jammy",
    "osType": "Linux",
    "placementGroupId": "",
    "plan": { "name": "", "product": "", "publisher": "" },
    "platformFaultDomain": "0",
    "platformUpdateDomain": "0",
    "publisher": "Canonical",
    "resourceGroupName": "my-rg",
    "resourceId": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/my-rg/providers/Microsoft.Compute/virtualMachines/my-cvm-01",
    "publicKeys": [
      {
        "path": "/home/azureuser/.ssh/authorized_keys",
        "keyData": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD..."
      },
      {
        "path": "/home/111",
        "keyData": "ssh-rsa 222..."
      }
    ],
    "securityProfile": {
      "encryptionAtHost": "false",
      "secureBootEnabled": "true",
      "securityType": "ConfidentialVM",
      "virtualTpmEnabled": "true"
    },
    "sku": "22_04-lts-cvm",
    "storageProfile": {
      "osDisk": {
        "diskSizeGB": "30",
        "managedDisk": { "storageAccountType": "Premium_LRS" }
      }
    },
    "subscriptionId": "00000000-0000-0000-0000-000000000000",
    "tags": "",
    "version": "22.04.202401010",
    "vmId": "abc12345-1234-1234-1234-abcdef123456",
    "vmSize": "Standard_DC4as_v5",
    "zone": "",
    "signatureInfo": "<base64 of the certChain/signature/metadata JSON shown below>"
  },
  "network": {
    "interface": [
      {
        "ipv4": {
          "ipAddress": [ { "privateIpAddress": "10.0.0.4", "publicIpAddress": "" } ],
          "subnet":    [ { "address": "10.0.0.0", "prefix": "24" } ]
        },
        "macAddress": "000D3A123456"
      }
    ]
  }
}
```

`compute.signatureInfo` base64-decodes to:

```json
{
  "certChain": "",
  "signature": "{\"compositeHash\":\"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsIng1YyI6Wy4uLl0sInByb3RlY3Rpb25TZXR0aW5ncyI6eyJtb2RlIjoiU2lnbmluZ09ubHkifX0.eyJzaWduZWREaWdlc3QiOiI8Y29tcG9zaXRlIGhhc2g-In0.XXXX\"}",
  "metadata": {
    "publicKeys":     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "subscriptionId": "9bc2d4f7a031e568a3f1e27a9b4c8de560f1234567890abcdef12345678901a",
    "userData":       "f7a031e568a3f1e27a9b4c8de560f1234567890abcdef1234567890abcde1234",
    "vmId":           "a3f1e27a9b4c8de560f1234567890abcdef1234567890abcdef1234567890ab12"
  }
}
```

The `signature` JWT is signed **SigningOnly** (header
`protectionSettings.mode = "SigningOnly"`). After `unprotect_secret()` verifies
the signature it returns the `signedData` claim, which for the IMDS flow equals
`SHA256(canonical_json(metadata))` — confirming the catalog was produced by CPS
and not tampered with by the host.

---

## Two-Level Verification

### Level 1 — Catalog Integrity (signature-backed)

Proves the `metadata` hash catalog was produced by Azure CPS and not by the host.

```
unprotect_secret(SigningOnly JWT)  ->  signedData (trusted_hash)
SHA256(canonical_json(metadata))   ->  computed_hash
assert trusted_hash == computed_hash
```

`unprotect_secret()` verifies the JWT signature against the `x5c` cert chain
(subject-suffix pinned to CPS) and, for a SigningOnly token, returns the
`signedData` claim directly — no decryption. `signedData` is the caller-supplied
value CPS signed verbatim; for the IMDS flow CRP sets it to the composite hash
(bare lowercase hex) of the canonical `metadata` catalog, which is compared
exactly to the recomputed hash.

### Level 2 — Per-Field Verification

Proves each individual IMDS field value matches what CPS recorded. Catalog keys
are the four flat CRP-signed field names; each value is read from `compute`.

```
for each flat field name in metadata (publicKeys, subscriptionId, userData, vmId):
    value      = imds["compute"][field]          (userData absent => "")
    field_hash = SHA256(canonical_json(value))    (publicKeys: order-independent)
    assert field_hash == metadata[field]
```

---

## Output

```json
{"validated": true, "fields": {"vmId": "valid", "subscriptionId": "valid", "userData": "valid", "publicKeys": "valid"}}
```

| `fields[key]` value | Meaning |
|---|---|
| `"valid"` | Field hash matched |
| `"invalid"` | Field hash did not match — value may have been tampered |
| `"not_found"` | Field listed in catalog but not present in IMDS JSON |
| `"invalid_type"` | Catalog entry for this field is not a string |

---

## Canonical JSON Serialization

Both CRP (when producing the SignatureInfo) and the guest (when verifying) must
agree on the same serialization. **RFC 8785 (JCS)** is the confirmed canonical
form — compact (no extra whitespace), keys sorted alphabetically at every level
of nesting.

`cmd_validate_imds.cpp` implements this via `rfc8785_sort()` which recursively
rebuilds JSON objects with alphabetically sorted keys before calling
`nlohmann::json::dump()`. This is safe because `nlohmann::json` uses `std::map`
internally (alphabetical by default when parsed), but programmatically
constructed objects may have insertion-ordered keys — the sort makes it
explicit and correct in all cases.

The mock CRP script (`test_scripts/gen_imds_blob.sh`) mirrors this by using
`dict(sorted(d.items()))` in Python before serializing.

Field values are hashed as their **JSON serialization**, not as raw strings:

| IMDS field value | Canonical form hashed |
|---|---|
| string `eastus` | `"eastus"` (7 bytes, with quotes) |
| integer `4` | `4` |
| object `{"b":2,"a":1}` | `{"a":1,"b":2}` (keys alphabetically sorted) |
| array of objects `[{"path":"...","keyData":"..."}]` | `[{"keyData":"...","path":"..."}]` (keys sorted within each element) |

### Array handling

**Arrays in general** RFC 8785 preserve element order (only object keys are
sorted). **`publicKeys` is a special case:** to match CRP
(`CanonicalJsonHelper.BuildCanonicalPublicKeyBytes`), the guest treats the
`publicKeys` array as **order-INDEPENDENT** — each element is projected to
`{keyData, path}`, its keys sorted, and the elements are then **sorted by their
canonical UTF-8 bytes** before hashing. This makes the `publicKeys` hash
identical regardless of the element order IMDS happens to serve.

Concretely for `compute.publicKeys`:

```json
// SAME hash — only key order within each object differs:
[{"path":"/home/u","keyData":"ssh-rsa AAA..."}]
[{"keyData":"ssh-rsa AAA...","path":"/home/u"}]

// ALSO the SAME hash — element order differs but publicKeys elements are sorted:
[{"keyData":"AAA...","path":"/home/azureuser"},{"keyData":"222...","path":"/home/111"}]
[{"keyData":"222...","path":"/home/111"},{"keyData":"AAA...","path":"/home/azureuser"}]
```

An absent or empty `publicKeys` (or a `null` SSH key list on the CRP side)
canonicalizes to the empty array `[]`; both sides hash `SHA256("[]")`.

---

## Hashing Algorithm

**SHA-256** is used at both levels (per-field and catalog integrity), confirmed
against CRP's `CanonicalJsonHelper` (`ComputeSha256Hex` / `ComputeCanonicalSha256Hex`).
The DPS SigningOnly `signedData` claim carries an arbitrary caller-supplied
string (non-empty, bounded by `MaxSignValueLength`); for the IMDS flow CRP sets
it to the SHA-256 composite hash of the metadata catalog, which
`validate-imds-metadata` compares exactly to its recomputed hash.

SHA-256 is implemented cross-platform:
- **Windows**: `BCryptOpenAlgorithmProvider(BCRYPT_SHA256_ALGORITHM)` via BCrypt
- **Linux**: `EVP_DigestInit_ex(ctx, EVP_sha256())` via OpenSSL

## Implementation Notes

- `UnprotectSecretFn` typedef in `cmd_validate_imds.h` mirrors the real C API
  signature of `unprotect_secret()` in `SecretsProvisioningLibrary.h` exactly.
  It exists solely to allow mock injection in unit tests without TPM dependency.
- `certChain` is accepted but ignored — CRP sets it to the empty string `""`
  because the cert chain is carried inside the JWT `x5c` header, which is what
  the library verifies during `unprotect_secret`.
- `signature` is a JSON map of CPS-issued JWT token(s) (keyed by CRP's
  `compositeHash` SensitiveData key), not a bare JWT string; the guest parses it
  and takes the token value. For a SigningOnly token the library verifies the
  signature and returns the `signedData` claim without any decryption.
