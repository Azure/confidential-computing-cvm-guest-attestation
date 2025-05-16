#include "gtest/gtest.h"
#include "../Policy.h"
#include <string>

#define MOCK_JWT \
"ew0KICAiYWxnIjogIkhTMjU2IiwNCiAgInR5cCI6ICJKV1QiDQp9.ew0KICAgICJwYXlsb2FkIiA6ICJkdW1teSINCn0=."


// Mock class for testing - allows us to set specific features
class MockPolicyEvaluator : public PolicyEvaluator {
public:
    MockPolicyEvaluator(PolicyOption policy) : PolicyEvaluator(policy, MOCK_JWT) {}

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