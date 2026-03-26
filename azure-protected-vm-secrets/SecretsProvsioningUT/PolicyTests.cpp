// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include <string>

#include "gtest/gtest.h"
#include "../Policy.h"
#include "../CommonTypes.h"

#define MOCK_JWT \
"ew0KICAiYWxnIjogIkhTMjU2IiwNCiAgInR5cCI6ICJKV1QiDQp9.ew0KICAgICJwYXlsb2FkIiA6ICJkdW1teSINCn0=."


// Mock class for testing - allows us to set specific features
class MockPolicyEvaluator : public PolicyEvaluator {
public:
    MockPolicyEvaluator(PolicyOption policy) : PolicyEvaluator(policy, MOCK_JWT, sizeof(MOCK_JWT)) {}

    // Allow test to set specific features for evaluation
    void SetFeatures(PayloadFeature features) {
        mockedFeatures = features;
    }

protected:
    // Override methods to return controlled values
    PayloadFeature GetEvaluatedPolicy() override {
        return mockedFeatures;
    }

    bool isEncrypted() override {
        return IS_POLICY_SET(mockedFeatures, PayloadFeature::Encrypted);
    }

    bool isSigned() override {
        return IS_POLICY_SET(mockedFeatures, PayloadFeature::Signed);
    }

    bool IsLegacy() override {
        return IS_POLICY_SET(mockedFeatures, PayloadFeature::Legacy);
    }

private:
    PayloadFeature mockedFeatures = PayloadFeature::None;
};

// Test fixture for policy evaluation tests
class PolicyEvaluatorTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

// Test legacy policies
TEST_F(PolicyEvaluatorTest, LegacyPolicies) {
    // Legacy allowed, legacy payload
    MockPolicyEvaluator eval1(PolicyOption::AllowLegacy);
    eval1.SetFeatures(PayloadFeature::Legacy);
    EXPECT_TRUE(eval1.IsCompliant());

    // Legacy not allowed, legacy payload
    MockPolicyEvaluator eval2(PolicyOption::RequireAll);
    eval2.SetFeatures(PayloadFeature::Legacy);
    EXPECT_FALSE(eval2.IsCompliant());

    // Legacy allowed, non-legacy payload
    MockPolicyEvaluator eval3(PolicyOption::AllowLegacy);
    eval3.SetFeatures(PayloadFeature::Encrypted | PayloadFeature::Signed);
    EXPECT_TRUE(eval3.IsCompliant());
}

// Test encryption policies
TEST_F(PolicyEvaluatorTest, EncryptionPolicies) {
    // Encrypted payload with any policy
    MockPolicyEvaluator eval1(PolicyOption::RequireAll);
    eval1.SetFeatures(PayloadFeature::Encrypted | PayloadFeature::Signed);
    EXPECT_TRUE(eval1.IsCompliant());

    // Unencrypted payload, allow unencrypted
    MockPolicyEvaluator eval2(PolicyOption::AllowUnencrypted);
    eval2.SetFeatures(PayloadFeature::Signed); // Only signed, not encrypted
    EXPECT_TRUE(eval2.IsCompliant());

    // Unencrypted payload, require encryption
    MockPolicyEvaluator eval3(PolicyOption::RequireAll);
    eval3.SetFeatures(PayloadFeature::Signed); // Only signed, not encrypted
    EXPECT_FALSE(eval3.IsCompliant());
}

// Test signature policies
TEST_F(PolicyEvaluatorTest, SignaturePolicies) {
    // Signed payload with any policy
    MockPolicyEvaluator eval1(PolicyOption::RequireAll);
    eval1.SetFeatures(PayloadFeature::Encrypted | PayloadFeature::Signed);
    EXPECT_TRUE(eval1.IsCompliant());

    // Unsigned payload, allow unsigned
    MockPolicyEvaluator eval2(PolicyOption::AllowUnsigned);
    eval2.SetFeatures(PayloadFeature::Encrypted); // Only encrypted, not signed
    EXPECT_TRUE(eval2.IsCompliant());

    // Unsigned payload, require signature
    MockPolicyEvaluator eval3(PolicyOption::RequireAll);
    eval3.SetFeatures(PayloadFeature::Encrypted); // Only encrypted, not signed
    EXPECT_FALSE(eval3.IsCompliant());
}

// Test various combinations
TEST_F(PolicyEvaluatorTest, FeatureCombinations) {
    // Modern payload with all features, strict policy
    MockPolicyEvaluator eval1(PolicyOption::RequireAll);
    eval1.SetFeatures(PayloadFeature::Encrypted | PayloadFeature::Signed);
    EXPECT_TRUE(eval1.IsCompliant());

    // Unencrypted and unsigned payload, permissive policy
    MockPolicyEvaluator eval2(PolicyOption::AllowUnencrypted | PolicyOption::AllowUnsigned);
    eval2.SetFeatures(PayloadFeature::None);
    EXPECT_TRUE(eval2.IsCompliant());

    // Unencrypted payload, policy allows unsigned but requires encryption
    MockPolicyEvaluator eval3(PolicyOption::AllowUnsigned);
    eval3.SetFeatures(PayloadFeature::None);
    EXPECT_FALSE(eval3.IsCompliant());

    // Unsigned payload, policy allows unencrypted but requires signature
    MockPolicyEvaluator eval4(PolicyOption::AllowUnencrypted);
    eval4.SetFeatures(PayloadFeature::None);
    EXPECT_FALSE(eval4.IsCompliant());
}

// Test edge cases
TEST_F(PolicyEvaluatorTest, EdgeCases) {
    // Legacy with other features set (should be ignored in IsCompliant)
    MockPolicyEvaluator eval1(PolicyOption::AllowLegacy);
    eval1.SetFeatures(PayloadFeature::Legacy | PayloadFeature::Encrypted | PayloadFeature::Signed);
    EXPECT_TRUE(eval1.IsCompliant());
    
    // Legacy with very restrictive policy that allows only legacy
    MockPolicyEvaluator eval2(PolicyOption::AllowLegacy);
    eval2.SetFeatures(PayloadFeature::Legacy);
    EXPECT_TRUE(eval2.IsCompliant());
    
    // Most permissive policy
    MockPolicyEvaluator eval3(PolicyOption::AllowLegacy | PolicyOption::AllowUnencrypted | PolicyOption::AllowUnsigned);
    eval3.SetFeatures(PayloadFeature::None);
    EXPECT_TRUE(eval3.IsCompliant());
}

TEST_F(PolicyEvaluatorTest, SanitizationDifference) {
    // Create data with invalid UTF-8 sequences
    std::vector<char> invalidData = {'J', 'W', 'T', '.', (char)0xFF, '.', 'x'};
    
    // Create equivalent wide data
    std::vector<wchar_t> wideData(invalidData.begin(), invalidData.end());
    
    // Test both paths - both should treat invalid UTF-8 as legacy
    PolicyEvaluator standardEval(PolicyOption::RequireAll, invalidData.data(), invalidData.size());
    PolicyEvaluator wideEval(PolicyOption::RequireAll, wideData.data(), wideData.size());
    
    // Both should be treated as legacy (not valid JWTs)
    EXPECT_TRUE(standardEval.IsLegacy());
    EXPECT_TRUE(wideEval.IsLegacy());
}

TEST_F(PolicyEvaluatorTest, LegacyUnicodeCharacters) {
    // Test various Unicode characters in legacy payloads
    
    // UTF-8 encoded Unicode characters
    const char* utf8Legacy = "Legacy payload with émojis 🔐 and spëcial chars ñ";
    PolicyEvaluator utf8Eval(PolicyOption::AllowLegacy, utf8Legacy, strlen(utf8Legacy));
    EXPECT_TRUE(utf8Eval.IsLegacy());
    EXPECT_TRUE(utf8Eval.IsCompliant());
    EXPECT_STREQ(utf8Eval.GetLegacyString(), utf8Legacy);
    
    // Wide character Unicode string
    const wchar_t* wideUnicode = L"Legacy payload with émojis 🔐 and spëcial chars ñ 中文";
    PolicyEvaluator wideUnicodeEval(PolicyOption::AllowLegacy, wideUnicode, wcslen(wideUnicode));
    EXPECT_TRUE(wideUnicodeEval.IsLegacy());
    EXPECT_TRUE(wideUnicodeEval.IsCompliant());
    EXPECT_STREQ(wideUnicodeEval.GetLegacyWideString(), wideUnicode);
    
    // Test with policy that doesn't allow legacy
    PolicyEvaluator restrictiveEval(PolicyOption::RequireAll, wideUnicode, wcslen(wideUnicode));
    EXPECT_TRUE(restrictiveEval.IsLegacy());
    EXPECT_FALSE(restrictiveEval.IsCompliant());
    
    // Test with mixed ASCII and Unicode
    const wchar_t* mixedContent = L"API_KEY=abc123_тест_test_🔑";
    PolicyEvaluator mixedEval(PolicyOption::AllowLegacy, mixedContent, wcslen(mixedContent));
    EXPECT_TRUE(mixedEval.IsLegacy());
    EXPECT_TRUE(mixedEval.IsCompliant());
    
    // Test with surrogate pairs (high Unicode codepoints)
    const wchar_t* surrogatePairs = L"Secret with emoji: 𝟙𝟚𝟛 and 𝕏𝕐𝕫";
    PolicyEvaluator surrogateEval(PolicyOption::AllowLegacy, surrogatePairs, wcslen(surrogatePairs));
    EXPECT_TRUE(surrogateEval.IsLegacy());
    EXPECT_TRUE(surrogateEval.IsCompliant());
    
    // Test with control characters and Unicode
    const wchar_t* controlChars = L"Secret\u0001with\u0002control\u0003chars\u2603";
    PolicyEvaluator controlEval(PolicyOption::AllowLegacy, controlChars, wcslen(controlChars));
    EXPECT_TRUE(controlEval.IsLegacy());
    EXPECT_TRUE(controlEval.IsCompliant());
}

TEST_F(PolicyEvaluatorTest, InvalidUnicodeHandling) {
    // Test handling of invalid Unicode sequences
    
    // Invalid UTF-8 sequence (char* constructor should work - no conversion needed)
    std::vector<char> invalidUtf8 = {'S', 'e', 'c', 'r', 'e', 't', (char)0xFF, (char)0xFE, 'e', 'n', 'd'};
    PolicyEvaluator invalidUtf8Eval(PolicyOption::AllowLegacy, invalidUtf8.data(), invalidUtf8.size());
    EXPECT_TRUE(invalidUtf8Eval.IsLegacy());
    EXPECT_TRUE(invalidUtf8Eval.IsCompliant());
    
    // Invalid wide character sequence (lone surrogate) - now handles gracefully on both platforms
    std::vector<wchar_t> invalidWide = {L'S', L'e', L'c', 0xD800, L'e', L't'}; // Lone high surrogate
    PolicyEvaluator invalidWideEval(PolicyOption::AllowLegacy, invalidWide.data(), invalidWide.size());
    EXPECT_TRUE(invalidWideEval.IsLegacy());
    EXPECT_TRUE(invalidWideEval.IsCompliant());
    
    // Test with null terminators in the middle - should work (null is valid Unicode)
    std::vector<wchar_t> nullInMiddle = {L'S', L'e', L'c', L'\0', L'r', L'e', L't'};
    PolicyEvaluator nullEval(PolicyOption::AllowLegacy, nullInMiddle.data(), nullInMiddle.size());
    EXPECT_TRUE(nullEval.IsLegacy());
    EXPECT_TRUE(nullEval.IsCompliant());
}

TEST_F(PolicyEvaluatorTest, UnicodeNormalization) {
    // Test different Unicode normalization forms
    
    // Composed form (NFC) - single character
    const wchar_t* composedForm = L"café";
    PolicyEvaluator composedEval(PolicyOption::AllowLegacy, composedForm, wcslen(composedForm));
    EXPECT_TRUE(composedEval.IsLegacy());
    EXPECT_TRUE(composedEval.IsCompliant());
    
    // Decomposed form (NFD) - base character + combining mark
    const wchar_t* decomposedForm = L"cafe\u0301"; // 'e' + combining acute accent
    PolicyEvaluator decomposedEval(PolicyOption::AllowLegacy, decomposedForm, wcslen(decomposedForm));
    EXPECT_TRUE(decomposedEval.IsLegacy());
    EXPECT_TRUE(decomposedEval.IsCompliant());
    
    // Both should be treated as legacy regardless of normalization
    EXPECT_TRUE(composedEval.IsLegacy());
    EXPECT_TRUE(decomposedEval.IsLegacy());
}

TEST_F(PolicyEvaluatorTest, BidirectionalUnicodeText) {
    // Test with bidirectional Unicode text (RTL/LTR)
    
    // Hebrew text (RTL)
    const wchar_t* hebrewText = L"סוד חשוב";
    PolicyEvaluator hebrewEval(PolicyOption::AllowLegacy, hebrewText, wcslen(hebrewText));
    EXPECT_TRUE(hebrewEval.IsLegacy());
    EXPECT_TRUE(hebrewEval.IsCompliant());
    
    // Arabic text (RTL)
    const wchar_t* arabicText = L"سر مهم";
    PolicyEvaluator arabicEval(PolicyOption::AllowLegacy, arabicText, wcslen(arabicText));
    EXPECT_TRUE(arabicEval.IsLegacy());
    EXPECT_TRUE(arabicEval.IsCompliant());
    
    // Mixed LTR and RTL
    const wchar_t* mixedText = L"Secret: סוד and more text";
    PolicyEvaluator mixedEval(PolicyOption::AllowLegacy, mixedText, wcslen(mixedText));
    EXPECT_TRUE(mixedEval.IsLegacy());
    EXPECT_TRUE(mixedEval.IsCompliant());
    
    // Test with bidirectional control characters
    const wchar_t* bidiControl = L"Secret\u202Eדוס\u202D"; // RLE + text + PDF
    PolicyEvaluator bidiEval(PolicyOption::AllowLegacy, bidiControl, wcslen(bidiControl));
    EXPECT_TRUE(bidiEval.IsLegacy());
    EXPECT_TRUE(bidiEval.IsCompliant());
}

TEST_F(PolicyEvaluatorTest, UnicodeEdgeCases) {
    // Test edge cases with Unicode characters
    
    // Empty Unicode string
    const wchar_t* emptyUnicode = L"";
    PolicyEvaluator emptyEval(PolicyOption::AllowLegacy, emptyUnicode, wcslen(emptyUnicode));
    EXPECT_TRUE(emptyEval.IsLegacy());
    EXPECT_TRUE(emptyEval.IsCompliant());
    
    // Single Unicode character
    const wchar_t* singleChar = L"🔐";
    PolicyEvaluator singleEval(PolicyOption::AllowLegacy, singleChar, wcslen(singleChar));
    EXPECT_TRUE(singleEval.IsLegacy());
    EXPECT_TRUE(singleEval.IsCompliant());
    
    // Very long Unicode string
    std::wstring longUnicode = L"Secret";
    for (int i = 0; i < 1000; ++i) {
        longUnicode += L"🔐";
    }
    PolicyEvaluator longEval(PolicyOption::AllowLegacy, longUnicode.c_str(), longUnicode.length());
    EXPECT_TRUE(longEval.IsLegacy());
    EXPECT_TRUE(longEval.IsCompliant());
    
    // Unicode with zero-width characters
    const wchar_t* zeroWidthChars = L"Sec\u200Bret\u200C\u200DKey";
    PolicyEvaluator zeroWidthEval(PolicyOption::AllowLegacy, zeroWidthChars, wcslen(zeroWidthChars));
    EXPECT_TRUE(zeroWidthEval.IsLegacy());
    EXPECT_TRUE(zeroWidthEval.IsCompliant());
}

TEST_F(PolicyEvaluatorTest, LegacyVsJWTWithUnicode) {
    // Test that Unicode content is properly distinguished from JWT
    
    // Unicode that might look like JWT structure but isn't
    const wchar_t* fakeJwt = L"header.payload🔐.signature";
    PolicyEvaluator fakeJwtEval(PolicyOption::AllowLegacy, fakeJwt, wcslen(fakeJwt));
    EXPECT_TRUE(fakeJwtEval.IsLegacy());
    EXPECT_TRUE(fakeJwtEval.IsCompliant());
    
    // Base64-like Unicode string
    const wchar_t* base64Like = L"SGVsbG8gV29ybGQ🔐=";
    PolicyEvaluator base64Eval(PolicyOption::AllowLegacy, base64Like, wcslen(base64Like));
    EXPECT_TRUE(base64Eval.IsLegacy());
    EXPECT_TRUE(base64Eval.IsCompliant());
    
    // JSON-like Unicode string
    const wchar_t* jsonLike = L"{\"key\": \"value🔐\", \"secret\": \"тест\"}";
    PolicyEvaluator jsonEval(PolicyOption::AllowLegacy, jsonLike, wcslen(jsonLike));
    EXPECT_TRUE(jsonEval.IsLegacy());
    EXPECT_TRUE(jsonEval.IsCompliant());
    
    // Test with restrictive policy
    PolicyEvaluator restrictiveJsonEval(PolicyOption::RequireAll, jsonLike, wcslen(jsonLike));
    EXPECT_TRUE(restrictiveJsonEval.IsLegacy());
    EXPECT_FALSE(restrictiveJsonEval.IsCompliant());
}

// Tests for RsaPaddingScheme enum
TEST(RsaPaddingSchemeTest, EnumValues) {
    EXPECT_NE(static_cast<int>(RsaPaddingScheme::Rsaes),
              static_cast<int>(RsaPaddingScheme::RsaesOaep));
}

// Tests for PolicyEvaluator::GetHeader
TEST_F(PolicyEvaluatorTest, GetHeader_ReturnsHeaderWithPadding) {
    // Build a JWT with x-az-rsa-padding in the header
    std::unique_ptr<JsonWebToken> jwt = std::make_unique<JsonWebToken>();
    json header = {
        {"alg", "RS256"},
        {"typ", "JWT"},
        {"x-az-cvm-purpose", "secrets-provisioning"},
        {"x-az-rsa-padding", "rsaes-oaep"}
    };
    jwt->SetHeader(header);
    jwt->addClaim("encryptedSecret", "dummy");
    std::string token = jwt->CreateToken();

    PolicyEvaluator pe(PolicyOption::AllowUnsigned, token.c_str(),
                       static_cast<unsigned int>(token.length()));
    ASSERT_FALSE(pe.IsLegacy());

    json h = pe.GetHeader();
    ASSERT_TRUE(h.contains("x-az-rsa-padding"));
    EXPECT_EQ(h["x-az-rsa-padding"], "rsaes-oaep");
}

TEST_F(PolicyEvaluatorTest, GetHeader_AbsentPadding) {
    // JWT without x-az-rsa-padding
    std::unique_ptr<JsonWebToken> jwt = std::make_unique<JsonWebToken>();
    json header = {
        {"alg", "RS256"},
        {"typ", "JWT"},
        {"x-az-cvm-purpose", "secrets-provisioning"}
    };
    jwt->SetHeader(header);
    jwt->addClaim("encryptedSecret", "dummy");
    std::string token = jwt->CreateToken();

    PolicyEvaluator pe(PolicyOption::AllowUnsigned, token.c_str(),
                       static_cast<unsigned int>(token.length()));
    ASSERT_FALSE(pe.IsLegacy());

    json h = pe.GetHeader();
    EXPECT_FALSE(h.contains("x-az-rsa-padding"));
}

TEST_F(PolicyEvaluatorTest, GetHeader_LegacyReturnsEmpty) {
    const char* legacy = "not a jwt";
    PolicyEvaluator pe(PolicyOption::AllowLegacy, legacy,
                       static_cast<unsigned int>(strlen(legacy)));
    EXPECT_TRUE(pe.IsLegacy());
    EXPECT_TRUE(pe.GetHeader().empty());
}
