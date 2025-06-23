// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once

#include <string>
#include <nlohmann/json.hpp>
#include "JsonWebToken.h"

using json = nlohmann::json;

enum class PayloadFeature
{
    None      = 0b00000000,
    Encrypted = 0b00000001,
    Signed    = 0b00000010,
    Legacy    = 0b00000100
};

// Enable bitwise operations
constexpr PayloadFeature operator|(PayloadFeature a, PayloadFeature b) {
    return static_cast<PayloadFeature>(
        static_cast<unsigned int>(a) | 
        static_cast<unsigned int>(b)
    );
}
constexpr PayloadFeature operator&(PayloadFeature a, PayloadFeature b) {
    return static_cast<PayloadFeature>(
        static_cast<unsigned int>(a) & 
        static_cast<unsigned int>(b)
    );
}

enum class PolicyOption {
    RequireAll       = 0b00000000,
    AllowUnencrypted = 0b00000001,
    AllowUnsigned    = 0b00000010,
    AllowLegacy      = 0b00000100
};

// Enable bitwise operations
constexpr PolicyOption operator|(PolicyOption a, PolicyOption b) {
    return static_cast<PolicyOption>(
        static_cast<unsigned int>(a) | 
        static_cast<unsigned int>(b)
    );
}
constexpr PolicyOption operator&(PolicyOption a, PolicyOption b) {
    return static_cast<PolicyOption>(
        static_cast<unsigned int>(a) & 
        static_cast<unsigned int>(b)
    );
}

#define IS_POLICY_SET(policy, flag) ((policy & flag) == flag)
#define IS_ALLOWED(allowedPolicy, evalPolicy, flag) \
    (!IS_POLICY_SET(evalPolicy, flag) || IS_POLICY_SET(allowedPolicy, flag))

class PolicyEvaluator
{
public:
    PolicyEvaluator(const PolicyOption policy, const std::string& input);
    ~PolicyEvaluator();

    virtual PayloadFeature GetEvaluatedPolicy();
    virtual bool IsLegacy();
    std::vector<unsigned char> GetLegacyString();
    bool IsCompliant();
    json GetClaims();

protected:
    virtual bool isEncrypted();
    virtual bool isSigned();

private:
    PolicyOption policy;
    std::string input;
    std::unique_ptr<JsonWebToken> jwt;
};