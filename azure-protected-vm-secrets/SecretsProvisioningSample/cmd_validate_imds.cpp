// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "cmd_validate_imds.h"
#include "cli_common.h"
#include "SecretsProvisioningLibrary.h"
#include <nlohmann/json.hpp>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <string>
#include <vector>
#include <algorithm>
#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#else
#include <openssl/evp.h>
#endif

using json = nlohmann::json;

// ---------------------------------------------------------------------------
// Self-contained base64 decode (no Boost / JsonWebToken dependency)
// ---------------------------------------------------------------------------
static const char kB64Chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static std::vector<unsigned char> base64_decode_impl(const std::string& in)
{
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; ++i) T[(unsigned char)kB64Chars[i]] = i;
    std::vector<unsigned char> out;
    unsigned int val = 0;
    int valb = -8;
    for (unsigned char c : in) {
        if (T[c] == -1) {
            if (c == '=' || isspace(c)) continue;
            throw std::runtime_error("Invalid base64 character");
        }
        val = (val << 6) + static_cast<unsigned int>(T[c]);
        valb += 6;
        if (valb >= 0) {
            out.push_back(static_cast<unsigned char>((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    if (valb > 0) throw std::runtime_error("Invalid base64 input length");
    return out;
}

// ---------------------------------------------------------------------------
// SHA256 helpers
// ---------------------------------------------------------------------------

#ifdef _WIN32
static std::string sha256_hex(const std::string& data)
{
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    std::string result;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0)
        return result;

    DWORD hashLen = 0, cbData = 0;
    BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hashLen), sizeof(DWORD), &cbData, 0);
    std::vector<unsigned char> hash(hashLen);

    if (BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0) == 0) {
        if (BCryptHashData(hHash,
                reinterpret_cast<PUCHAR>(const_cast<char*>(data.data())),
                static_cast<ULONG>(data.size()), 0) == 0 &&
            BCryptFinishHash(hHash, hash.data(), hashLen, 0) == 0) {
            std::ostringstream oss;
            for (unsigned char b : hash)
                oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
            result = oss.str();
        }
        BCryptDestroyHash(hHash);
    }
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return result;
}
#else
static std::string sha256_hex(const std::string& data)
{
    std::string result;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return result;

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashLen = 0;
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) &&
        EVP_DigestUpdate(ctx, data.data(), data.size()) &&
        EVP_DigestFinal_ex(ctx, hash, &hashLen))
    {
        std::ostringstream oss;
        for (unsigned int i = 0; i < hashLen; ++i)
            oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
        result = oss.str();
    }
    EVP_MD_CTX_free(ctx);
    return result;
}
#endif

// ---------------------------------------------------------------------------
// RFC 8785 (JCS) canonical JSON: compact, no extra whitespace, keys sorted
// at every level of nesting. Matches CRP's CanonicalJsonHelper.WriteCanonical
// (keys sorted by Unicode codepoint; std::string's unsigned byte-wise operator<
// over UTF-8 yields the same order as CRP's StringComparer.Ordinal).
// nlohmann::json uses std::map internally so parsed objects are already
// sorted. Programmatically-constructed objects may not be, so we recursively
// rebuild the object with sorted keys to be safe.
//
// NOTE: this GENERIC canonicalizer preserves array element order (only object
// keys are sorted), matching RFC 8785. The `publicKeys` field is a special
// case that IS order-independent and is handled separately by
// canonical_public_keys() below (per CRP BuildCanonicalPublicKeyBytes).
// ---------------------------------------------------------------------------
static json rfc8785_sort(const json& j)
{
    if (j.is_object()) {
        std::vector<std::string> keys;
        for (auto it = j.begin(); it != j.end(); ++it)
            keys.push_back(it.key());
        std::sort(keys.begin(), keys.end());
        json sorted = json::object();
        for (const auto& k : keys)
            sorted[k] = rfc8785_sort(j[k]);
        return sorted;
    }
    if (j.is_array()) {
        json sorted_arr = json::array();
        for (const auto& elem : j)
            sorted_arr.push_back(rfc8785_sort(elem));
        return sorted_arr;
    }
    return j;
}

static std::string canonical_json(const json& j)
{
    // ensure_ascii=false so non-ASCII code points are emitted as raw UTF-8
    // (RFC 8785 3.2.2.2 / CRP UnsafeRelaxedJsonEscaping), not \uXXXX.
    return rfc8785_sort(j).dump(-1, ' ', /*ensure_ascii=*/false);
}

// ---------------------------------------------------------------------------
// publicKeys canonicalization (order-INDEPENDENT), matching CRP
// CanonicalJsonHelper.BuildCanonicalPublicKeyBytes:
//   - Each element is projected to exactly {"keyData":..., "path":...}
//   - Element keys are canonically sorted (keyData < path)
//   - Array ELEMENTS are sorted lexicographically by their canonical UTF-8
//     bytes, making the array hash independent of input element order.
// The guest hashes SHA256(canonical_publicKeys_array).
// ---------------------------------------------------------------------------
static std::string canonical_public_keys(const json& arr)
{
    std::vector<std::string> element_canon;
    if (arr.is_array()) {
        for (const auto& elem : arr) {
            json projected = json::object();
            projected["keyData"] = elem.contains("keyData") && elem["keyData"].is_string()
                ? elem["keyData"].get<std::string>() : std::string();
            projected["path"] = elem.contains("path") && elem["path"].is_string()
                ? elem["path"].get<std::string>() : std::string();
            element_canon.push_back(canonical_json(projected));
        }
    }
    // Sort by canonical UTF-8 bytes (std::string operator< is unsigned byte-wise,
    // matching CRP's Utf8LexicographicByteComparer).
    std::sort(element_canon.begin(), element_canon.end());

    std::string out = "[";
    for (size_t i = 0; i < element_canon.size(); ++i) {
        if (i > 0) out += ",";
        out += element_canon[i];
    }
    out += "]";
    return out;
}

// ---------------------------------------------------------------------------
// The four CRP-signed fields live directly under "compute" in the IMDS blob.
// The SignatureInfo.metadata catalog keys are the FLAT field names below
// (NOT dotted paths like "compute.vmId").
// ---------------------------------------------------------------------------
static const char* kSignedFieldPublicKeys     = "publicKeys";
static const char* kSignedFieldSubscriptionId = "subscriptionId";
static const char* kSignedFieldUserData       = "userData";
static const char* kSignedFieldVmId           = "vmId";

// Computes the guest-side canonical SHA-256 hex for one signed field, reading
// its value from the IMDS "compute" object. Returns false only if the field is
// genuinely absent AND absence is not permitted (userData absence => "").
static bool compute_signed_field_hash(const json& imds,
                                      const std::string& field,
                                      std::string& out_hash,
                                      std::string& out_state)
{
    const json* compute = nullptr;
    if (imds.contains("compute") && imds["compute"].is_object())
        compute = &imds["compute"];

    const bool present = compute && compute->contains(field);

    if (field == kSignedFieldPublicKeys) {
        // Absent publicKeys canonicalizes to the empty array "[]".
        const json empty_arr = json::array();
        const json& v = present ? (*compute)[field] : empty_arr;
        if (present && !v.is_array()) { out_state = "invalid_type"; return false; }
        out_hash = sha256_hex(canonical_public_keys(v));
        return true;
    }

    if (field == kSignedFieldUserData) {
        // CRP omits userData from IMDS when null but still signs SHA256(json("")).
        // A missing userData MUST be treated as empty string, never "not_found".
        std::string value = (present && (*compute)[field].is_string())
            ? (*compute)[field].get<std::string>() : std::string();
        if (present && !(*compute)[field].is_string()) { out_state = "invalid_type"; return false; }
        out_hash = sha256_hex(canonical_json(json(value)));
        return true;
    }

    // vmId / subscriptionId: GUID strings, hyphenated lowercase (CRP contract).
    // Any other (future) catalog key is verified the same generic way:
    // SHA256(canonical_json(compute.<field>)).
    (void)kSignedFieldVmId;
    (void)kSignedFieldSubscriptionId;
    if (!present) { out_state = "not_found"; return false; }
    if (!(*compute)[field].is_string()) { out_state = "invalid_type"; return false; }
    out_hash = sha256_hex(canonical_json((*compute)[field]));
    return true;
}

// ---------------------------------------------------------------------------
// Core implementation — accepts injected unprotect_fn for testability
// ---------------------------------------------------------------------------
int cmd_validate_imds_impl(const std::string& imds_json, UnprotectSecretFn unprotect_fn, unsigned int policy)
{
    // --- Parse outer IMDS JSON ---
    json imds;
    try {
        imds = json::parse(imds_json);
    } catch (const std::exception& e) {
        std::cerr << "Failed to parse IMDS JSON: " << e.what() << "\n";
        return 1;
    }

    // --- Extract and base64-decode compute.signatureInfo ---
    // IMDS exposes the CPS SignatureInfo as a base64 string at compute.signatureInfo
    // (camelCase, nested under "compute"). It is the empty string when the signed-
    // metadata feature is off or the blob carries no SignatureInfo.
    if (!imds.contains("compute") || !imds["compute"].is_object()) {
        std::cerr << "Missing or invalid compute object in IMDS metadata\n";
        return 1;
    }
    const json& compute = imds["compute"];
    if (!compute.contains("signatureInfo") || !compute["signatureInfo"].is_string()) {
        std::cerr << "Missing or invalid compute.signatureInfo field\n";
        return 1;
    }
    std::string sig_info_b64 = compute["signatureInfo"].get<std::string>();
    if (sig_info_b64.empty()) {
        std::cerr << "compute.signatureInfo is empty (signed metadata not present)\n";
        return 1;
    }
    std::vector<unsigned char> sig_info_bytes;
    try {
        sig_info_bytes = base64_decode_impl(sig_info_b64);
    } catch (const std::exception& e) {
        std::cerr << "Failed to base64-decode compute.signatureInfo: " << e.what() << "\n";
        return 1;
    }
    std::string sig_info_str(sig_info_bytes.begin(), sig_info_bytes.end());

    // --- Parse inner SignatureInfo JSON ---
    json sig_info;
    try {
        sig_info = json::parse(sig_info_str);
    } catch (const std::exception& e) {
        std::cerr << "Failed to parse SignatureInfo JSON: " << e.what() << "\n";
        return 1;
    }

    if (!sig_info.contains("signature") || !sig_info["signature"].is_string()) {
        std::cerr << "Missing or invalid SignatureInfo.signature field\n";
        return 1;
    }
    if (!sig_info.contains("metadata") || !sig_info["metadata"].is_object()) {
        std::cerr << "Missing or invalid SignatureInfo.metadata field\n";
        return 1;
    }

    std::string signature_str = sig_info["signature"].get<std::string>();
    json metadata = sig_info["metadata"];

    // --- Extract the JWT from SignatureInfo.signature ---
    // CRP sets signature = JsonHelpers.SerializeToString(vmResult.JwtTokens), i.e.
    // a JSON object mapping the SensitiveData key(s) to CPS-issued JWT token(s)
    // (see InVMArtifactsProfileBuilderBase.TrySignInVMArtifactsProfileFields).
    // The composite-hash JWT is keyed by CompositeHashKey. Accept:
    //   - a JSON object of {key: jwt} -> take the (single) token value
    //   - a bare JWT string           -> use as-is (test fixtures / legacy)
    std::string jwt_str = signature_str;
    try {
        json sig_parsed = json::parse(signature_str);
        if (sig_parsed.is_object() && !sig_parsed.empty()) {
            // Prefer a single-token map; if multiple, take the first string value.
            for (auto it = sig_parsed.begin(); it != sig_parsed.end(); ++it) {
                if (it.value().is_string()) { jwt_str = it.value().get<std::string>(); break; }
            }
        } else if (sig_parsed.is_string()) {
            jwt_str = sig_parsed.get<std::string>();
        }
    } catch (const std::exception&) {
        // Not JSON => already a bare JWT string. Use signature_str unchanged.
    }

    // --- Level 1: verify the CPS signature over the metadata catalog ---
    // The signing request is signingRequired:true, encryptionRequired:false, so
    // the JWT is signed (cert chain embedded in the x5c header) and the payload
    // is the composite hash of the metadata catalog. unprotect_secret validates
    // the signature per the caller-supplied policy and returns the trusted hash.
    char* trusted_hash_raw = nullptr;
    unsigned int eval_policy = 0;
    long result = unprotect_fn(
        const_cast<char*>(jwt_str.data()),
        static_cast<unsigned int>(jwt_str.size()),
        policy,
        &trusted_hash_raw,
        &eval_policy);

    if (result <= 0) {
        std::cerr << "signature verification failed: " << get_error_message(result) << "\n";
        free_secret(trusted_hash_raw);
        return 1;
    }

    std::string trusted_hash(trusted_hash_raw, static_cast<size_t>(result));
    // trim any null terminator included in the count
    while (!trusted_hash.empty() && trusted_hash.back() == '\0')
        trusted_hash.pop_back();
    free_secret(trusted_hash_raw);

    // The SigningOnly "signedData" claim is returned verbatim by the library.
    // For the IMDS flow CRP signs the composite hash of the metadata catalog
    // (bare lowercase hex), so we compare it directly to our recomputed hash.
    // --- Level 1: compute hash of canonical metadata JSON and compare ---
    std::string computed_hash = sha256_hex(canonical_json(metadata));
    if (trusted_hash != computed_hash) {
        std::cerr << "Metadata hash mismatch\n";
        return 1;
    }

    // --- Level 2: verify each field in the IMDS blob against the catalog ---
    // Catalog keys are the FLAT CRP-signed field names (publicKeys,
    // subscriptionId, userData, vmId), each read from the IMDS "compute" object.
    json fields_result = json::object();
    bool all_valid = true;

    for (auto it = metadata.begin(); it != metadata.end(); ++it) {
        const std::string& field = it.key();
        std::string expected_hash;
        try {
            expected_hash = it.value().get<std::string>();
        } catch (const std::exception&) {
            std::cerr << "validation_failed: field=" << field << " reason=invalid_type\n";
            fields_result[field] = "invalid_type";
            all_valid = false;
            continue;
        }

        std::string field_hash;
        std::string field_state;
        if (!compute_signed_field_hash(imds, field, field_hash, field_state)) {
            std::cerr << "validation_failed: field=" << field << " reason=" << field_state << "\n";
            fields_result[field] = field_state;
            all_valid = false;
            continue;
        }

        if (field_hash == expected_hash) {
            fields_result[field] = "valid";
        } else {
            std::cerr << "validation_failed: field=" << field << "\n";
            fields_result[field] = "invalid";
            all_valid = false;
        }
    }

    // --- Output result JSON ---
    json output;
    output["validated"] = all_valid;
    output["fields"] = fields_result;
    std::cout << "\n" << output.dump() << "\n";
    return all_valid ? 0 : 1;
}

// ---------------------------------------------------------------------------
// CLI entry point — uses real unprotect_secret
// ---------------------------------------------------------------------------
#ifndef UNIT_TEST
int cmd_validate_imds(const CliArgs& /*args*/)
{
    std::string input = read_all_stdin();
    if (input.empty()) {
        std::cerr << "No input provided on stdin\n";
        return 1;
    }
    
    // IMDS signature validation always uses a SigningOnly token (signed, never
    // encrypted). The policy is fixed internally to AllowUnencrypted so a valid
    // signature is always required and no caller-supplied --policy can relax it
    // (e.g. AllowUnsigned / AllowLegacy would defeat the whole verification).
    // Value mirrors PolicyOption::AllowUnencrypted in Policy.h.
    constexpr unsigned int kImdsValidationPolicy = 1u; // AllowUnencrypted
    return cmd_validate_imds_impl(input, unprotect_secret, kImdsValidationPolicy);
}
#else
int cmd_validate_imds(const CliArgs& /*args*/) { return 1; }
#endif
