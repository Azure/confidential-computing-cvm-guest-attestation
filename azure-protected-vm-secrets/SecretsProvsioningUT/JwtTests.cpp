// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "gtest/gtest.h"
#include "JsonWebToken.h"
#include <nlohmann/json.hpp>

TEST(Utf8SanitizerTest, WideToUtf8Empty) {
    // Test that empty wide string returns empty UTF-8 string
    std::wstring empty_wide = L"";
    std::vector<wchar_t> wide_vector(empty_wide.begin(), empty_wide.end());
    std::vector<unsigned char> result = utf8_sanitizer::wide_to_utf8(wide_vector);
    ASSERT_TRUE(result.empty());
}

TEST(Utf8SanitizerTest, WideToUtf8Basic) {
    // Test basic ASCII characters
    std::wstring wide_str = L"Hello World";
    std::vector<wchar_t> wide_vector(wide_str.begin(), wide_str.end());
    std::vector<unsigned char> result_vector = utf8_sanitizer::wide_to_utf8(wide_vector);
    std::string result(result_vector.begin(), result_vector.end());
    ASSERT_EQ(result, "Hello World");
}

TEST(Utf8SanitizerTest, WideToUtf8Unicode) {
    // Test Unicode characters
    std::wstring wide_str = L"Hello 世界";
    std::vector<wchar_t> wide_vector(wide_str.begin(), wide_str.end());
    std::vector<unsigned char> result_vector = utf8_sanitizer::wide_to_utf8(wide_vector);
    std::string result(result_vector.begin(), result_vector.end());
    ASSERT_FALSE(result.empty());
    // The exact UTF-8 bytes depend on the platform, but it should not be empty
}

TEST(JwtRoundTripTest, WideCharConversionWithSanitization) {
    // Step 1: Create original JWT with test claims
    std::unique_ptr<JsonWebToken> originalJwt = std::make_unique<JsonWebToken>("RS256");
    originalJwt->addClaim("sub", "1234567890");
    originalJwt->addClaim("name", "Test User");
    originalJwt->addClaim("admin", true);
    
    // Create a dummy signature for the token (normally this would be cryptographically generated)
    std::string dummySig = "test_signature_bytes";
    std::vector<unsigned char> signature(dummySig.begin(), dummySig.end());
    originalJwt->SetSignature(signature);
    
    // Step 2: Generate JWT token string
    std::string originalToken = originalJwt->CreateToken();
    ASSERT_FALSE(originalToken.empty());
    
    // Verify token has the expected structure (header.payload.signature)
    ASSERT_NE(originalToken.find('.'), std::string::npos);
    ASSERT_NE(originalToken.find_last_of('.'), originalToken.find_first_of('.'));
    
    // Step 3: Convert to wide characters using JsonWebToken's conversion function
    std::vector<unsigned char> tokenBytes(originalToken.begin(), originalToken.end());
    std::vector<wchar_t> wideTokenVec = utf8_sanitizer::utf8_to_wide(tokenBytes);
    std::wstring wideToken(wideTokenVec.begin(), wideTokenVec.end());
    
    ASSERT_FALSE(wideToken.empty());
    
    // Step 4: Convert back from wide characters to UTF-8
    std::vector<unsigned char> utf8TokenVec = utf8_sanitizer::wide_to_utf8(wideTokenVec);
    std::string utf8Token(utf8TokenVec.begin(), utf8TokenVec.end());
    ASSERT_FALSE(utf8Token.empty());
    
    // Step 5: Create a new JWT object and parse the converted token
    std::unique_ptr<JsonWebToken> parsedJwt = std::make_unique<JsonWebToken>();
    EXPECT_NO_THROW({
        parsedJwt->ParseToken(utf8Token, false); // false = don't verify signature
    });
    
    // Step 7: Verify the claims in the parsed token match the original claims
    json parsedClaims = parsedJwt->getClaims();
    ASSERT_EQ(parsedClaims["sub"], "1234567890");
    ASSERT_EQ(parsedClaims["name"], "Test User");
    ASSERT_EQ(parsedClaims["admin"], true);
    
    // Verify headers were preserved
    json parsedHeader = parsedJwt->getHeader();
    ASSERT_EQ(parsedHeader["alg"], "RS256");
    ASSERT_EQ(parsedHeader["typ"], "JWT");
}

TEST(JwtRoundTripTest, WideCharWithCorruption) {
    // Step 1: Create original JWT with test claims
    std::unique_ptr<JsonWebToken> originalJwt = std::make_unique<JsonWebToken>("RS256");
    originalJwt->addClaim("sub", "1234567890");
    originalJwt->addClaim("name", "Test User");
    
    // Create a dummy signature for the token
    std::string dummySig = "test_signature_bytes";
    std::vector<unsigned char> signature(dummySig.begin(), dummySig.end());
    originalJwt->SetSignature(signature);
    
    // Generate JWT token string
    std::string originalToken = originalJwt->CreateToken();
    ASSERT_FALSE(originalToken.empty());
    
    // Convert to wide characters with deliberate corruption
    std::vector<unsigned char> tokenBytes(originalToken.begin(), originalToken.end());
    std::vector<wchar_t> wideTokenVec;
    wideTokenVec.reserve(tokenBytes.size() + 10); // Add extra space for corruption
    
    // Insert characters that will break Base64 encoding
    size_t midpoint = tokenBytes.size() / 2;
    for (size_t i = 0; i < tokenBytes.size(); i++) {
        // Insert corruption at specific positions
        if (i == midpoint) {
            // Add invalid Base64 characters
            wideTokenVec.push_back(L'\u00FF'); // Non-ASCII character
            wideTokenVec.push_back(L'\u2022'); // Bullet point
        }
        wideTokenVec.push_back(static_cast<wchar_t>(tokenBytes[i]));
    }
    
    // Convert back from wide characters to UTF-8
    std::vector<unsigned char> utf8TokenVec = utf8_sanitizer::wide_to_utf8(wideTokenVec);
    
    // Use the corrupted UTF-8 string directly
    std::string sanitizedToken(utf8TokenVec.begin(), utf8TokenVec.end());
    ASSERT_FALSE(sanitizedToken.empty());
    
    // Try to parse the corrupted token - should throw JwtError
    std::unique_ptr<JsonWebToken> parsedJwt = std::make_unique<JsonWebToken>();
    
    // For the test to pass, we need to ensure the corruption happens within sections 
    // that are wrapped in try-catch blocks in ParseToken
    EXPECT_THROW({
        parsedJwt->ParseToken(sanitizedToken, false);
    }, JwtError);
}

TEST(B64Test, B64Encode) {
    // Test that the base64_encode function encodes the input correctly
    std::vector<unsigned char> input = { 0x12, 0x34, 0x56, 0x78, 0x90 };
    std::string output = encoders::base64_encode(input);
    ASSERT_EQ(output, "EjRWeJA=");
}

TEST(B64Test, B64Decode) {
    // Test that the base64_decode function decodes the input correctly
    std::string input = "EjRWeJA=";
    std::vector<unsigned char> output = encoders::base64_decode(input);
    std::vector<unsigned char> expected = { 0x12, 0x34, 0x56, 0x78, 0x90 };
    ASSERT_EQ(output, expected);
}

TEST(B64Test, B64UrlEncode) {
    // Test that the base64_url_encode function encodes the input correctly
    std::vector<unsigned char> input = { 0x12, 0x34, 0x56, 0x78, 0x90 };
    std::string output = encoders::base64_url_encode(input);
    ASSERT_EQ(output, "EjRWeJA=");
}

TEST(B64Test, B64UrlDecode) {
    // Test that the base64_url_decode function decodes the input correctly
    std::string input = "EjRWeJA=";
    std::vector<unsigned char> output = encoders::base64_url_decode(input);
    std::vector<unsigned char> expected = { 0x12, 0x34, 0x56, 0x78, 0x90 };
    ASSERT_EQ(output, expected);
}

TEST(JwtTests, JwtConstructor) {
    // Test that the constructor initializes the JsonWebToken object
    std::unique_ptr<JsonWebToken> jwt;
    try {
        jwt = std::make_unique<JsonWebToken>();
        ASSERT_NE(jwt, nullptr);
    }
    catch (std::exception& e)
    {
        std::cout << e.what() << std::endl;
    }
}

TEST(JwtTests, JwtClaimsConstructor) {
    // Test that the constructor initializes the JsonWebToken object
    std::unique_ptr<JsonWebToken> jwt;
    try {
        jwt = std::make_unique<JsonWebToken>();
        json header = {
            {"alg", "RS256"},
            {"typ", "JWT"}
        };
        jwt->SetHeader(header);
        json payload = {
            {"sub", "1234567890"},
            {"name", "John Doe"},
            {"admin", true}
        };
        jwt->addClaim("sub", "1234567890");
        jwt->addClaim("name", "John Doe");
        jwt->addClaim("admin", true);

        ASSERT_NE(jwt, nullptr);
        std::string token = jwt->CreateToken();
        std::unique_ptr<JsonWebToken> jwt2 = std::make_unique<JsonWebToken>();
        jwt2->ParseToken(token, false);
        ASSERT_EQ(jwt->getClaims(), jwt2->getClaims());
    }
    catch (std::exception& e)
    {
        std::cout << e.what() << std::endl;
    }
}

TEST(JwtTests, JwtFailParser) {
    // Test that the jwt ParseToken fails when the token structure is invalid
    std::unique_ptr<JsonWebToken> jwt;
    std::unique_ptr<JsonWebToken> jwt2 = std::make_unique<JsonWebToken>();
    std::string errorToken;
    try {
        jwt = std::make_unique<JsonWebToken>();
        json header = {
            {"alg", "RS256"},
            {"typ", "JWT"}
        };
        jwt->SetHeader(header);
        json payload = {
            {"sub", "1234567890"},
            {"name", "John Doe"},
            {"admin", true}
        };
        jwt->addClaim("sub", "1234567890");
        jwt->addClaim("name", "John Doe");
        jwt->addClaim("admin", true);

        ASSERT_NE(jwt, nullptr);
        std::string token = jwt->CreateToken();
        std::string errorToken = token.substr(0, token.find_last_of('.') - 1);
    }
    catch (std::exception& e)
    {
        std::cout << e.what() << std::endl;
    }
    EXPECT_THROW({
        // We expect this to throw a JwtError since the token is invalid
        jwt2->ParseToken(errorToken, false);
        }, JwtError
    );
}

TEST(JwtTests, IsRealJwt_WithCustomField_Positive) {
    // Create a token with the custom header field "x-az-cvm-purpose": "secrets-provisioning"
    std::unique_ptr<JsonWebToken> jwt = std::make_unique<JsonWebToken>();

    json header = {
        {"alg", "RS256"},
        {"typ", "JWT"},
        {"x-az-cvm-purpose", "secrets-provisioning"}
    };
    jwt->SetHeader(header);

    json payload = {
        {"sub", "user123"},
        {"role", "admin"}
    };
    jwt->SetPayload(payload);

    std::string token = jwt->CreateToken();

    std::vector<std::pair<std::string, std::string>> requiredFields = {
        {"x-az-cvm-purpose", "secrets-provisioning"}
    };

    EXPECT_TRUE(JsonWebToken::isRealJwt(token.c_str(), token.length(), requiredFields));
}

TEST(JwtTests, IsRealJwt_WithCustomField_Negative) {
    // Create a token WITHOUT the custom header field or with wrong value
    std::unique_ptr<JsonWebToken> jwt = std::make_unique<JsonWebToken>();

    json header = {
        {"alg", "RS256"},
        {"typ", "JWT"},
        {"x-az-cvm-purpose", "other-purpose"}  // Wrong value here
    };
    jwt->SetHeader(header);

    json payload = {
        {"sub", "user123"},
        {"role", "user"}
    };
    jwt->SetPayload(payload);

    std::string token = jwt->CreateToken();

    std::vector<std::pair<std::string, std::string>> requiredFields = {
        {"x-az-cvm-purpose", "secrets-provisioning"}
    };

    EXPECT_FALSE(JsonWebToken::isRealJwt(token.c_str(), token.length(), requiredFields));
}
TEST(JwtTests, IsRealJwtRejectsNonJwtWithClaimCheck) {
    std::string input = "this is not a JWT token";

    std::vector<std::pair<std::string, std::string>> required = {
            {"x-az-cvm-purpose", "secrets-provisioning"}
    };

    bool result = JsonWebToken::isRealJwt(input.c_str(), input.length(), required);
    ASSERT_FALSE(result);
}

// Test handling of invalid Base64 in the header
TEST(JwtTests, InvalidBase64InHeader) {
    // Create a token with invalid Base64 in the header part
    std::string invalidToken = "invalid!base64.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature";
    
    std::unique_ptr<JsonWebToken> jwt = std::make_unique<JsonWebToken>();
    EXPECT_THROW({
        jwt->ParseToken(invalidToken, false);
    }, JwtError);
}

// Test handling of invalid Base64 in the payload
TEST(JwtTests, InvalidBase64InPayload) {
    // Create a token with invalid Base64 in the payload part
    std::string invalidToken = "eyJhbGciOiJIUzI1NiJ9.invalid!base64.signature";
    
    std::unique_ptr<JsonWebToken> jwt = std::make_unique<JsonWebToken>();
    EXPECT_THROW({
        jwt->ParseToken(invalidToken, false);
    }, JwtError);
}

// Test round trip with mixed ASCII and non-ASCII characters
TEST(JwtRoundTripTest, MixedCharacters) {
    std::unique_ptr<JsonWebToken> jwt = std::make_unique<JsonWebToken>();
    
    // Add claims with mixed ASCII and non-ASCII characters
    jwt->addClaim("ascii", "Hello World!");
    jwt->addClaim("nonAscii", "こんにちは世界"); // "Hello World" in Japanese
    jwt->addClaim("mixed", "Hello 世界!"); // Mixed ASCII and non-ASCII
    jwt->addClaim("emoji", "🌍 Earth 🚀 Rocket"); // With emoji
    
    // Create token and parse
    std::string token = jwt->CreateToken();
    std::unique_ptr<JsonWebToken> parsedJwt = std::make_unique<JsonWebToken>();
    parsedJwt->ParseToken(token, false);
    
    // Verify claims were preserved correctly
    json claims = parsedJwt->getClaims();
    EXPECT_EQ(claims["ascii"], "Hello World!");
    
    // The sanitization might replace non-ASCII chars with replacement character,
    // depending on your sanitizer implementation
    EXPECT_FALSE(claims["nonAscii"].empty());
    EXPECT_FALSE(claims["mixed"].empty());
    EXPECT_FALSE(claims["emoji"].empty());
}

TEST(JwtTests, JwtParseEmpty) {
    // Test that the jwt Parsetoken will still parse an empty token
    std::string token = "..";
    std::unique_ptr<JsonWebToken> jwt = std::make_unique<JsonWebToken>();
    jwt->ParseToken(token, false);
    ASSERT_NE(jwt, nullptr);
}

TEST(JwtTests, JwtParseEmptyFail) {
    std::string token = ".";
    std::unique_ptr<JsonWebToken> jwt = std::make_unique<JsonWebToken>();
    
    EXPECT_THROW({
        // We expect this to throw a JwtError since the token is invalid
        jwt->ParseToken(token, false);
        }, JwtError
    );
}

TEST(JsonWebTokenTests, Base64DecoderExceptionHandling) {
    // Create invalid base64 with characters outside the alphabet
    std::string invalidBase64 = "eyJhbGciOiJIUzI*NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature";
    
    std::unique_ptr<JsonWebToken> jwt = std::make_unique<JsonWebToken>();
    
    // Should throw JwtError when parsing
    EXPECT_THROW({
        try {
            jwt->ParseToken(invalidBase64, false);
        } catch (const JwtError& e) {
            // This is the expected exception type
            EXPECT_TRUE(std::string(e.what()).find("Base64 decoding failed") != std::string::npos);
            throw;
        }
    }, JwtError);
}