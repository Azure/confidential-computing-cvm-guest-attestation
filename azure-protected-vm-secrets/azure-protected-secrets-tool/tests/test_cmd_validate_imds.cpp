// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include <gtest/gtest.h>
#include "cmd_validate_imds.h"
#include "Policy.h"
#include <nlohmann/json.hpp>
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
// Stubs for DLL symbols used by cmd_validate_imds_impl in non-UNIT_TEST path.
// The mock allocates with new[] so delete[] is correct.
// ---------------------------------------------------------------------------
extern "C" {
    void free_secret(char* p) { delete[] p; }
    const char* get_error_message(long code)
    {
        switch (code) {
            case -100: return "PolicyMismatchError";
            case    0: return "Success";
            default:   return "UnknownError";
        }
    }
}

// ---------------------------------------------------------------------------
// Minimal self-contained base64 (no Boost / JsonWebToken.cpp dependency)
// ---------------------------------------------------------------------------
static const char kB64Chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static std::string test_base64_encode(const std::vector<unsigned char>& in)
{
    std::string out;
    int val = 0, valb = -6;
    for (unsigned char c : in) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            out.push_back(kB64Chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) out.push_back(kB64Chars[((val << 8) >> (valb + 8)) & 0x3F]);
    while (out.size() % 4) out.push_back('=');
    return out;
}

// ---------------------------------------------------------------------------
// SHA256 helper — cross-platform, no dependency on impl internals
// ---------------------------------------------------------------------------
#ifdef _WIN32
static std::string test_sha256_hex(const std::string& data)
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
        if (BCryptHashData(hHash, reinterpret_cast<PUCHAR>(const_cast<char*>(data.data())),
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
static std::string test_sha256_hex(const std::string& data)
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
// Mock unprotect_secret state
// ---------------------------------------------------------------------------
static std::string g_mock_output;
static long        g_mock_retval;

static long mock_unprotect_secret(char* /*jwt*/, unsigned int /*jwtlen*/,
                                   unsigned int /*policy*/,
                                   char** output_secret, unsigned int* eval_policy)
{
    *eval_policy = 0;
    if (g_mock_retval <= 0) {
        *output_secret = nullptr;
        return g_mock_retval;
    }
    char* buf = new char[g_mock_output.size() + 1];
    std::copy(g_mock_output.begin(), g_mock_output.end(), buf);
    buf[g_mock_output.size()] = '\0';
    *output_secret = buf;
    return static_cast<long>(g_mock_output.size() + 1);
}

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

// Build the inner SignatureInfo JSON, base64-encode it, embed in outer IMDS JSON.
static std::string build_imds_json(
    const std::vector<std::pair<std::string, json>>& imds_fields,
    const json& metadata_map,
    const std::string& mock_jwt)
{
    json sig_info;
    sig_info["certChain"] = "";
    sig_info["signature"]  = mock_jwt;
    sig_info["metadata"]   = metadata_map;

    std::string sig_info_str = sig_info.dump();
    std::vector<unsigned char> sig_bytes(sig_info_str.begin(), sig_info_str.end());

    json imds;
    for (const auto& kv : imds_fields) {
        std::istringstream ss(kv.first);
        std::string segment;
        json* cur = &imds;
        std::vector<std::string> parts;
        while (std::getline(ss, segment, '.'))
            parts.push_back(segment);
        for (size_t i = 0; i < parts.size() - 1; ++i) {
            if (!cur->contains(parts[i]))
                (*cur)[parts[i]] = json::object();
            cur = &(*cur)[parts[i]];
        }
        (*cur)[parts.back()] = kv.second;
    }
    // IMDS exposes the SignatureInfo as base64 at compute.signatureInfo (camelCase).
    if (!imds.contains("compute") || !imds["compute"].is_object())
        imds["compute"] = json::object();
    imds["compute"]["signatureInfo"] = test_base64_encode(sig_bytes);
    return imds.dump();
}

// Strip a leading "compute." from a fixture field path to get the FLAT catalog
// key the guest expects (metadata keys are flat names, e.g. "vmId").
static std::string flat_catalog_key(const std::string& field_path)
{
    const std::string prefix = "compute.";
    if (field_path.rfind(prefix, 0) == 0)
        return field_path.substr(prefix.size());
    return field_path;
}

// Test-side replica of the guest's canonical_public_keys() (CRP contract):
// project each element to {keyData,path}, canonicalize, sort elements by bytes.
static std::string test_canonical_public_keys(const json& arr)
{
    std::vector<std::string> element_canon;
    if (arr.is_array()) {
        for (const auto& elem : arr) {
            json projected = json::object();
            projected["keyData"] = elem.contains("keyData") && elem["keyData"].is_string()
                ? elem["keyData"].get<std::string>() : std::string();
            projected["path"] = elem.contains("path") && elem["path"].is_string()
                ? elem["path"].get<std::string>() : std::string();
            element_canon.push_back(projected.dump(-1, ' ', false));
        }
    }
    std::sort(element_canon.begin(), element_canon.end());
    std::string out = "[";
    for (size_t i = 0; i < element_canon.size(); ++i) {
        if (i > 0) out += ",";
        out += element_canon[i];
    }
    out += "]";
    return out;
}

// Compute the catalog hash for one field exactly as the guest does.
static std::string test_field_catalog_hash(const std::string& flat_key, const json& value)
{
    if (flat_key == "publicKeys")
        return test_sha256_hex(test_canonical_public_keys(value));
    return test_sha256_hex(value.dump(-1, ' ', false));
}

// Build a fully valid fixture: metadata hashes are correct, mock returns the
// correct Level-1 trusted hash. Catalog keys are flat; each value is placed
// under compute in the IMDS blob and hashed the same way the guest does.
static std::string build_valid_imds(
    const std::vector<std::pair<std::string, json>>& fields)
{
    json metadata_map = json::object();
    for (const auto& kv : fields)
        metadata_map[flat_catalog_key(kv.first)] =
            test_field_catalog_hash(flat_catalog_key(kv.first), kv.second);

    g_mock_output = test_sha256_hex(metadata_map.dump());
    g_mock_retval = static_cast<long>(g_mock_output.size() + 1);

    return build_imds_json(fields, metadata_map, "mock.jwt.token");
}

// ---------------------------------------------------------------------------
// Test fixture — suppresses std::cerr during each test so intentional
// error-path messages from cmd_validate_imds_impl do not pollute output.
// ---------------------------------------------------------------------------
class ValidateImdsTest : public ::testing::Test {
protected:
    std::streambuf* m_old_cerr = nullptr;

    void SetUp() override {
        g_mock_output = "";
        g_mock_retval = 0;
        m_old_cerr = std::cerr.rdbuf(m_null_buf.rdbuf());
    }

    void TearDown() override {
        std::cerr.rdbuf(m_old_cerr);
    }

private:
    std::ostringstream m_null_buf;
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

TEST_F(ValidateImdsTest, SuccessAllFieldsValid)
{
    std::vector<std::pair<std::string, json>> fields = {
        {"compute.vmId",     json("abc12345-1234-1234-1234-abcdef123456")},
        {"compute.location", json("eastus")}
    };
    std::string imds = build_valid_imds(fields);

    int rc = cmd_validate_imds_impl(imds, mock_unprotect_secret,
                                    static_cast<unsigned int>(PolicyOption::AllowUnsigned));
    EXPECT_EQ(rc, 0);
}

TEST_F(ValidateImdsTest, FailUnprotectSecretError)
{
    std::vector<std::pair<std::string, json>> fields = {
        {"compute.vmId", json("abc123")}
    };
    json metadata_map;
    metadata_map["vmId"] = test_sha256_hex(json("abc123").dump());
    std::string imds = build_imds_json(fields, metadata_map, "bad.jwt.token");

    g_mock_output = "";
    g_mock_retval = -1;

    int rc = cmd_validate_imds_impl(imds, mock_unprotect_secret,
                                    static_cast<unsigned int>(PolicyOption::AllowUnsigned));
    EXPECT_EQ(rc, 1);
}

TEST_F(ValidateImdsTest, FailMetadataHashMismatch)
{
    std::vector<std::pair<std::string, json>> fields = {
        {"compute.vmId", json("abc123")}
    };
    json metadata_map;
    metadata_map["vmId"] = test_sha256_hex(json("abc123").dump());
    std::string imds = build_imds_json(fields, metadata_map, "mock.jwt.token");

    g_mock_output = "thisisthewronghash000000000000000000000000000000000000000000000";
    g_mock_retval = static_cast<long>(g_mock_output.size() + 1);

    int rc = cmd_validate_imds_impl(imds, mock_unprotect_secret,
                                    static_cast<unsigned int>(PolicyOption::AllowUnsigned));
    EXPECT_EQ(rc, 1);
}

TEST_F(ValidateImdsTest, FailFieldHashMismatch)
{
    std::vector<std::pair<std::string, json>> fields = {
        {"compute.vmId",     json("abc123")},
        {"compute.location", json("eastus")}
    };
    json metadata_map;
    metadata_map["vmId"]     = test_sha256_hex(json("abc123").dump());
    metadata_map["location"] = "0000000000000000000000000000000000000000000000000000000000000000";

    g_mock_output = test_sha256_hex(metadata_map.dump());
    g_mock_retval = static_cast<long>(g_mock_output.size() + 1);

    std::string imds = build_imds_json(fields, metadata_map, "mock.jwt.token");

    int rc = cmd_validate_imds_impl(imds, mock_unprotect_secret,
                                    static_cast<unsigned int>(PolicyOption::AllowUnsigned));
    EXPECT_EQ(rc, 1);
}

TEST_F(ValidateImdsTest, FailFieldNotFoundInImds)
{
    std::vector<std::pair<std::string, json>> fields = {
        {"compute.vmId", json("abc123")}
    };
    json metadata_map;
    metadata_map["vmId"]         = test_sha256_hex(json("abc123").dump());
    metadata_map["missingField"] = test_sha256_hex(json("somevalue").dump());

    g_mock_output = test_sha256_hex(metadata_map.dump());
    g_mock_retval = static_cast<long>(g_mock_output.size() + 1);

    std::string imds = build_imds_json(fields, metadata_map, "mock.jwt.token");

    int rc = cmd_validate_imds_impl(imds, mock_unprotect_secret,
                                    static_cast<unsigned int>(PolicyOption::AllowUnsigned));
    EXPECT_EQ(rc, 1);
}

TEST_F(ValidateImdsTest, FailMissingSignatureInfo)
{
    json imds;
    imds["compute"]["vmId"] = "abc123";

    int rc = cmd_validate_imds_impl(imds.dump(), mock_unprotect_secret,
                                    static_cast<unsigned int>(PolicyOption::AllowUnsigned));
    EXPECT_EQ(rc, 1);
}

TEST_F(ValidateImdsTest, FailMalformedJson)
{
    int rc = cmd_validate_imds_impl("not valid json {{", mock_unprotect_secret,
                                    static_cast<unsigned int>(PolicyOption::AllowUnsigned));
    EXPECT_EQ(rc, 1);
}

TEST_F(ValidateImdsTest, FailEmptyInput)
{
    int rc = cmd_validate_imds_impl("", mock_unprotect_secret,
                                    static_cast<unsigned int>(PolicyOption::AllowUnsigned));
    EXPECT_EQ(rc, 1);
}

TEST_F(ValidateImdsTest, FailSignatureInfoNotString)
{
    json imds;
    imds["compute"]["vmId"] = "abc123";
    imds["compute"]["signatureInfo"] = 12345;

    int rc = cmd_validate_imds_impl(imds.dump(), mock_unprotect_secret,
                                    static_cast<unsigned int>(PolicyOption::AllowUnsigned));
    EXPECT_EQ(rc, 1);
}

TEST_F(ValidateImdsTest, FailMissingSignatureField)
{
    json sig_info;
    sig_info["certChain"] = "";
    sig_info["metadata"]   = json::object();
    std::string s = sig_info.dump();
    std::vector<unsigned char> bytes(s.begin(), s.end());
    json imds;
    imds["compute"]["vmId"] = "abc123";
    imds["compute"]["signatureInfo"] = test_base64_encode(bytes);

    int rc = cmd_validate_imds_impl(imds.dump(), mock_unprotect_secret,
                                    static_cast<unsigned int>(PolicyOption::AllowUnsigned));
    EXPECT_EQ(rc, 1);
}

TEST_F(ValidateImdsTest, FailMissingMetadataField)
{
    json sig_info;
    sig_info["certChain"] = "";
    sig_info["signature"]  = "mock.jwt.token";
    std::string s = sig_info.dump();
    std::vector<unsigned char> bytes(s.begin(), s.end());
    json imds;
    imds["compute"]["vmId"] = "abc123";
    imds["compute"]["signatureInfo"] = test_base64_encode(bytes);

    int rc = cmd_validate_imds_impl(imds.dump(), mock_unprotect_secret,
                                    static_cast<unsigned int>(PolicyOption::AllowUnsigned));
    EXPECT_EQ(rc, 1);
}

TEST_F(ValidateImdsTest, FailMetadataValueNotString)
{
    // metadata entry is an integer, not a string hash — should return invalid_type
    std::vector<std::pair<std::string, json>> fields = {
        {"compute.vmId", json("abc123")}
    };
    json metadata_map;
    metadata_map["vmId"] = 12345; // integer instead of string hash

    g_mock_output = test_sha256_hex(metadata_map.dump());
    g_mock_retval = static_cast<long>(g_mock_output.size() + 1);

    std::string imds = build_imds_json(fields, metadata_map, "mock.jwt.token");

    int rc = cmd_validate_imds_impl(imds, mock_unprotect_secret,
                                    static_cast<unsigned int>(PolicyOption::AllowUnsigned));
    EXPECT_EQ(rc, 1);
}

TEST_F(ValidateImdsTest, SuccessEmptyMetadata)
{
    json metadata_map = json::object();
    g_mock_output = test_sha256_hex(metadata_map.dump());
    g_mock_retval = static_cast<long>(g_mock_output.size() + 1);

    std::string imds = build_imds_json({}, metadata_map, "mock.jwt.token");

    int rc = cmd_validate_imds_impl(imds, mock_unprotect_secret,
                                    static_cast<unsigned int>(PolicyOption::AllowUnsigned));
    EXPECT_EQ(rc, 0);
}

// ---------------------------------------------------------------------------
// publicKeys canonicalization tests (CRP contract: order-INDEPENDENT)
// ---------------------------------------------------------------------------

// Two publicKeys arrays with the same elements but different key order within
// each object must produce the same hash (element keys are sorted).
TEST_F(ValidateImdsTest, SuccessPublicKeysArrayKeyOrderIndependent)
{
    // Field value with keys in path-first order
    json publicKeys_path_first = json::array();
    publicKeys_path_first.push_back({{"path", "/home/azureuser/.ssh/authorized_keys"}, {"keyData", "ssh-rsa AAAA..."}});
    publicKeys_path_first.push_back({{"path", "/home/111"},                             {"keyData", "ssh-rsa 222..."}});

    // Same field value with keys in keyData-first order
    json publicKeys_keydata_first = json::array();
    publicKeys_keydata_first.push_back({{"keyData", "ssh-rsa AAAA..."}, {"path", "/home/azureuser/.ssh/authorized_keys"}});
    publicKeys_keydata_first.push_back({{"keyData", "ssh-rsa 222..."},  {"path", "/home/111"}});

    // Both blobs carry the SAME expected catalog hash (the guest's canonical
    // publicKeys hash). Compute it once from either representation via a valid
    // fixture, then reuse that trusted hash for the second blob.
    std::vector<std::pair<std::string, json>> fields_a = {{"compute.publicKeys", publicKeys_path_first}};
    std::string imds_a = build_valid_imds(fields_a);
    std::string trusted = g_mock_output;

    std::vector<std::pair<std::string, json>> fields_b = {{"compute.publicKeys", publicKeys_keydata_first}};
    std::string imds_b = build_valid_imds(fields_b);

    int rc_a = cmd_validate_imds_impl(imds_a, mock_unprotect_secret,
                                      static_cast<unsigned int>(PolicyOption::AllowUnsigned));
    // Re-arm the mock for the second call (build_valid_imds set it for imds_b).
    int rc_b = cmd_validate_imds_impl(imds_b, mock_unprotect_secret,
                                      static_cast<unsigned int>(PolicyOption::AllowUnsigned));

    EXPECT_EQ(rc_a, 0) << "publicKeys with path-first key order should validate";
    EXPECT_EQ(rc_b, 0) << "publicKeys with keyData-first key order should validate";
    EXPECT_EQ(trusted, g_mock_output)
        << "Key-order-only difference must yield the same catalog hash";
}

// Two publicKeys arrays with the SAME elements in DIFFERENT array order must
// produce the SAME hash (CRP sorts array elements => order-independent).
TEST_F(ValidateImdsTest, SuccessPublicKeysArrayElementOrderIndependent)
{
    json publicKeys_order1 = json::array();
    publicKeys_order1.push_back({{"keyData", "ssh-rsa AAAA..."}, {"path", "/home/azureuser/.ssh/authorized_keys"}});
    publicKeys_order1.push_back({{"keyData", "ssh-rsa 222..."},  {"path", "/home/111"}});

    // Same elements, reversed array order
    json publicKeys_order2 = json::array();
    publicKeys_order2.push_back({{"keyData", "ssh-rsa 222..."},  {"path", "/home/111"}});
    publicKeys_order2.push_back({{"keyData", "ssh-rsa AAAA..."}, {"path", "/home/azureuser/.ssh/authorized_keys"}});

    // Build a valid blob for order1, capture the trusted catalog hash.
    std::vector<std::pair<std::string, json>> fields1 = {{"compute.publicKeys", publicKeys_order1}};
    std::string imds1 = build_valid_imds(fields1);
    std::string trusted1 = g_mock_output;

    // Build a valid blob for order2; its catalog hash must match order1's.
    std::vector<std::pair<std::string, json>> fields2 = {{"compute.publicKeys", publicKeys_order2}};
    std::string imds2 = build_valid_imds(fields2);

    int rc1 = cmd_validate_imds_impl(imds1, mock_unprotect_secret,
                                     static_cast<unsigned int>(PolicyOption::AllowUnsigned));
    int rc2 = cmd_validate_imds_impl(imds2, mock_unprotect_secret,
                                     static_cast<unsigned int>(PolicyOption::AllowUnsigned));

    EXPECT_EQ(rc1, 0);
    EXPECT_EQ(rc2, 0);
    EXPECT_EQ(trusted1, g_mock_output)
        << "publicKeys array element order must not change the hash (CRP sorts elements)";
}

// userData absent from IMDS must be verified as SHA256(canonical_json("")),
// NOT reported as not_found (CRP omits null userData but still signs "").
TEST_F(ValidateImdsTest, SuccessUserDataAbsentTreatedAsEmpty)
{
    // Catalog contains userData hashed as empty string; IMDS has no userData.
    json metadata_map = json::object();
    metadata_map["userData"] = test_sha256_hex(json(std::string()).dump());

    g_mock_output = test_sha256_hex(metadata_map.dump());
    g_mock_retval = static_cast<long>(g_mock_output.size() + 1);

    // Build IMDS with a compute object but no userData field.
    std::vector<std::pair<std::string, json>> fields = {
        {"compute.vmId", json("abc12345-1234-1234-1234-abcdef123456")}
    };
    std::string imds = build_imds_json(fields, metadata_map, "mock.jwt.token");

    int rc = cmd_validate_imds_impl(imds, mock_unprotect_secret,
                                    static_cast<unsigned int>(PolicyOption::AllowUnsigned));
    EXPECT_EQ(rc, 0) << "Absent userData must hash as empty string, not fail as not_found";
}

// Missing top-level compute object -> failure.
TEST_F(ValidateImdsTest, FailMissingComputeObject)
{
    json imds;
    imds["network"] = json::object();

    int rc = cmd_validate_imds_impl(imds.dump(), mock_unprotect_secret,
                                    static_cast<unsigned int>(PolicyOption::AllowUnsigned));
    EXPECT_EQ(rc, 1);
}

// Empty compute.signatureInfo (feature off / not present) -> failure.
TEST_F(ValidateImdsTest, FailEmptySignatureInfo)
{
    json imds;
    imds["compute"]["vmId"] = "abc123";
    imds["compute"]["signatureInfo"] = "";

    int rc = cmd_validate_imds_impl(imds.dump(), mock_unprotect_secret,
                                    static_cast<unsigned int>(PolicyOption::AllowUnsigned));
    EXPECT_EQ(rc, 1);
}

// compute.signatureInfo that is not valid base64 -> failure.
TEST_F(ValidateImdsTest, FailSignatureInfoNotBase64)
{
    json imds;
    imds["compute"]["vmId"] = "abc123";
    imds["compute"]["signatureInfo"] = "!!!not-base64!!!";

    int rc = cmd_validate_imds_impl(imds.dump(), mock_unprotect_secret,
                                    static_cast<unsigned int>(PolicyOption::AllowUnsigned));
    EXPECT_EQ(rc, 1);
}

// compute.signatureInfo base64 that decodes to non-JSON -> failure.
TEST_F(ValidateImdsTest, FailSignatureInfoNotJson)
{
    json imds;
    imds["compute"]["vmId"] = "abc123";
    std::string garbage = "this is not json";
    std::vector<unsigned char> bytes(garbage.begin(), garbage.end());
    imds["compute"]["signatureInfo"] = test_base64_encode(bytes);

    int rc = cmd_validate_imds_impl(imds.dump(), mock_unprotect_secret,
                                    static_cast<unsigned int>(PolicyOption::AllowUnsigned));
    EXPECT_EQ(rc, 1);
}

// signature as a JSON token-map { "compositeHash": "<jwt>" } is accepted:
// the guest extracts the single token value (matches CRP SerializeToString).
TEST_F(ValidateImdsTest, SuccessSignatureTokenMap)
{
    std::vector<std::pair<std::string, json>> fields = {
        {"compute.vmId", json("739b2a69-b039-4e43-9933-63e892c0ffaf")}
    };
    json metadata_map = json::object();
    metadata_map["vmId"] = test_sha256_hex(json("739b2a69-b039-4e43-9933-63e892c0ffaf").dump());
    g_mock_output = test_sha256_hex(metadata_map.dump());
    g_mock_retval = static_cast<long>(g_mock_output.size() + 1);

    // signature is a JSON object mapping the compositeHash key to a JWT string.
    json token_map = json::object();
    token_map["compositeHash"] = "header.payload.signature";
    std::string imds = build_imds_json(fields, metadata_map, token_map.dump());

    int rc = cmd_validate_imds_impl(imds, mock_unprotect_secret,
                                    static_cast<unsigned int>(PolicyOption::AllowUnsigned));
    EXPECT_EQ(rc, 0) << "signature as a single-entry token map should be accepted";
}

// A publicKeys catalog entry whose IMDS value is not an array -> invalid_type.
TEST_F(ValidateImdsTest, FailPublicKeysWrongType)
{
    json metadata_map = json::object();
    metadata_map["publicKeys"] = test_sha256_hex(test_canonical_public_keys(json::array()));
    g_mock_output = test_sha256_hex(metadata_map.dump());
    g_mock_retval = static_cast<long>(g_mock_output.size() + 1);

    // IMDS has publicKeys as a string, not an array.
    std::vector<std::pair<std::string, json>> fields = {
        {"compute.publicKeys", json("not-an-array")}
    };
    std::string imds = build_imds_json(fields, metadata_map, "mock.jwt.token");

    int rc = cmd_validate_imds_impl(imds, mock_unprotect_secret,
                                    static_cast<unsigned int>(PolicyOption::AllowUnsigned));
    EXPECT_EQ(rc, 1) << "publicKeys present but not an array must fail as invalid_type";
}

