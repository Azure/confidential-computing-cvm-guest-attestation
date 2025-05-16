#pragma once
#include "Policy.h"
#include "JsonWebToken.h"
#include "LibraryLogger.h"

using namespace SecretsLogger;

PolicyEvaluator::PolicyEvaluator(const PolicyOption policy, const std::string& input) {
    this->policy = policy;
    this->input = input;
    if (this->IsLegacy()) {
        this->jwt = nullptr;
    }
    else {
        this->jwt = std::make_unique<JsonWebToken>();
        this->jwt->ParseToken(input, true);
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
    // Check if the policy is legacy
    // This is a placeholder implementation
    // Until the legacy header is defined
    return false;
}

std::vector<unsigned char> PolicyEvaluator::GetLegacyString(){
    // Get the legacy string
    // This is a placeholder implementation
    // Until the legacy header is defined
    return std::vector<unsigned char>();
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