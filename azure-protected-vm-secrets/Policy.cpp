// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once
#include "Policy.h"
#include "JsonWebToken.h"
#include "LibraryLogger.h"
#include "ReturnCodes.h"

using namespace SecretsLogger;

PolicyEvaluator::PolicyEvaluator(const PolicyOption policy, const char* input, unsigned int inputlen) {
    this->policy = policy;
    this->input = input;
    std::vector<std::pair<std::string, std::string>> requiredFields = {
    {"x-az-cvm-purpose", "secrets-provisioning"},
    //{"x-version", "1.0"}
    };
    this->isLegacy = !JsonWebToken::isRealJwt(this->input, inputlen, requiredFields);
    
    this->wideInput = nullptr; // No wide input in this constructor
    this->inputLength = inputlen;
    if (this->IsLegacy()) {
        this->jwt = nullptr;
    }
    else {
        this->jwt = std::make_unique<JsonWebToken>();
        std::string inputStr(this->input, inputlen);
        this->jwt->ParseToken(inputStr, true);
    }
}

PolicyEvaluator::PolicyEvaluator(const PolicyOption policy, const wchar_t* input, unsigned int inputlen) {
    this->policy = policy;
    this->wideInput = input;
    this->input = nullptr; // No char input in this constructor
    this->inputLength = inputlen;

    // Check if it's a legacy format using the wide string version
    std::vector<std::pair<std::string, std::string>> requiredFields = {
        {"x-az-cvm-purpose", "secrets-provisioning"}
    };

    // Convert wide input to UTF-8 first - fail fast if conversion fails
    std::vector<wchar_t> inputWVec(this->wideInput, this->wideInput + inputlen);
    std::vector<unsigned char> inputVec = utf8_sanitizer::wide_to_utf8(inputWVec);
    
    // Check for conversion failure
    if (inputVec.empty() && inputlen > 0) {
        LIBSECRETS_LOG(LogLevel::Warning, "Policy Evaluation", 
                       "Failed to convert wide character input to UTF-8, treating as legacy data");
        this->isLegacy = true;
        this->jwt = nullptr;
        return;
    }
    
    // Convert to string for JWT validation
    std::string inputStr(inputVec.begin(), inputVec.end());
    
    // Use the regular JWT validation (remove isRealJwtWide)
    this->isLegacy = !JsonWebToken::isRealJwt(inputStr.c_str(), 
                                              static_cast<unsigned int>(inputStr.length()), 
                                              requiredFields);

    if (this->IsLegacy()) {
        this->jwt = nullptr;
    }
    else {
        this->jwt = std::make_unique<JsonWebToken>();
        this->jwt->ParseToken(inputStr, true);
    }
}

PolicyEvaluator::~PolicyEvaluator() {
    // Destructor
}

PayloadFeature PolicyEvaluator::GetEvaluatedPolicy() {
    PayloadFeature evaluatedPolicy = PayloadFeature::None;

    if (isEncrypted()) {
        evaluatedPolicy = evaluatedPolicy | PayloadFeature::Encrypted;
    }
    if (isSigned()) {
        evaluatedPolicy = evaluatedPolicy | PayloadFeature::Signed;
    }
    if (IsLegacy()) {
        evaluatedPolicy = evaluatedPolicy | PayloadFeature::Legacy;
    }
    LIBSECRETS_LOG(LogLevel::Debug, "Evaluated Policy\n", "Evaluated policy: %d", static_cast<unsigned int>(evaluatedPolicy));
    return evaluatedPolicy;
}

bool PolicyEvaluator::isEncrypted() {
    // Check if the policy is encrypted
    if (this->IsLegacy()) {
        return false;
    }

    json claims = this->jwt->getClaims();
    if (claims.contains("encryptedSecret")) {
        return true;
    }

    return false;
}

bool PolicyEvaluator::isSigned() {
    // Check if the policy is signed
    if (this->IsLegacy()) {
        return false;
    }

    std::vector<unsigned char> signature = this->jwt->getSignature();
    if (signature.size() > 0) {
        return true;
    }

    return false;
}

bool PolicyEvaluator::IsLegacy() {
    return isLegacy;
}

const char* PolicyEvaluator::GetLegacyString(){
    return this->input;
}

const wchar_t* PolicyEvaluator::GetLegacyWideString(){
    return this->wideInput;
}

bool PolicyEvaluator::IsCompliant() {
    PayloadFeature evalFeatures = GetEvaluatedPolicy();
    
    // If Legacy is present, only check if it's allowed
    if (IS_POLICY_SET(evalFeatures, PayloadFeature::Legacy)) {
        return IS_POLICY_SET(policy, PolicyOption::AllowLegacy);
    }
    
    // For modern payloads, check encryption status
    if (!IS_POLICY_SET(evalFeatures, PayloadFeature::Encrypted) && 
        !IS_POLICY_SET(policy, PolicyOption::AllowUnencrypted)) {
        return false; // Unencrypted not allowed
    }
    
    // Check signature status
    if (!IS_POLICY_SET(evalFeatures, PayloadFeature::Signed) && 
        !IS_POLICY_SET(policy, PolicyOption::AllowUnsigned)) {
        return false; // Unsigned not allowed
    }
    
    return true;
}

json PolicyEvaluator::GetClaims(){
    // Get the claims from the JWT
    if (this->IsLegacy()) {
        return json();
    }
    return this->jwt->getClaims();
}