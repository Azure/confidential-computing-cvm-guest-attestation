// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "gtest/gtest.h"
#include "JsonWebToken.h"
#include <nlohmann/json.hpp>
#include <iostream>

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