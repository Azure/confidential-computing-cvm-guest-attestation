// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "gtest/gtest.h"
#include "../SecretsProvisioningSample/SecretsProvisioningSample.h"
#include "../SecretsProvisioningLibrary.h"
#include "../JsonWebToken.h"
#include "../Policy.h"


/**
 * @class FunctionalityTests
 * @brief A test fixture class for testing functionality requiring key
 * generation and removal.
 *
 * This class inherits from ::testing::Test and provides setup and teardown
 * functionality for tests that require key generation and removal.
 *
 * @protected
 * @var bool testGenerateKey
 * Indicates whether a key was generated during the setup phase.
 *
 * @protected
 * @fn void SetUp() override
 * Sets up the test environment. If a key is not present, it generates a key
 * and sets the testGenerateKey flag to true.
 *
 * @protected
 * @fn void TearDown() override
 * Tears down the test environment. If a key was generated during the setup
 * phase, it removes the key.
 */
class FunctionalityTests: public ::testing::Test
{
protected:
	bool testGenerateKey = false;
	void SetUp() override {
		if (!IsKeyPresent()) {
		    GenerateKey();
			testGenerateKey = true;
		}
	}

	void TearDown() override {
		if (testGenerateKey) {
			RemoveKey();
		}
	}

};

/**
 * @brief Test case to verify the successful encryption and decryption of a
 * secret.
 *
 * This test checks the success case of the unprotect_secret function.
 * It does the following:
 * 1. Encrypt a sample secret data.
 * 2. Decrypt the encrypted data using the unprotect_secret function.
 * 3. Perform assertions.
 * 
 * Assertions:
 * - The unprotect_secret function returns the length of the secret.
 * - The original protected data is correctly decrypted.
 */
TEST_F(FunctionalityTests, SuccessfulEncryptDecrypt) {
	char data[] = "Test Secret info";

	std::string encrypted_data = Encrypt(data);
	char* output_secret = nullptr;
	unsigned int policy = 0;
	policy = static_cast<unsigned int>(PolicyOption::AllowUnsigned);
	unsigned int eval_policy = 0;
	long result = unprotect_secret(
		(char *)encrypted_data.c_str(), encrypted_data.length(), policy,
		&output_secret, &eval_policy
	);
	ASSERT_EQ(result, strlen(data) + 1);
	ASSERT_EQ(strcmp(data, output_secret), 0);
	if (output_secret) {
		free_secret(output_secret);
	}
}

/**
 * @brief Test case to verify the failure scenario of the unprotect_secret
 * function with an invalid token that has a modified nonce.
 *
 * This test checks the behavior of the unprotect_secret function when provided
 * with an invalid JWT where the nonce has been replaces with a zero vector.
 * The test will pass if the unprotect_secret function returns a value less
 * than or equal to 0 and the output_secret is set to nullptr, indicating that
 * the decryption failed as expected.
 *
 * Steps:
 * 1. Encrypt a sample secret data.
 * 2. Modify the JWT by adding a claim with a base64 encoded nonce of the zero
 *    vector.
 * 3. Attempt to unprotect the modified JWT.
 * 4. Perform assertions.
 * 
 * Assertions:
 * - The unprotect_secret function returns a value less than or equal to 0.
 * - The output_secret is nullptr.
 */
TEST_F(FunctionalityTests, FailureEncryptDecrypt) {
	char data[] = "Test Secret info";

	std::string encrypted_data = Encrypt(data);

	// Modify jwt
	std::unique_ptr<JsonWebToken> jwt = std::make_unique<JsonWebToken>();
	jwt->ParseToken(encrypted_data, false);
    jwt->addClaim(
		"dataNonce",
		encoders::base64_encode(std::vector<unsigned char>(32, 0))
	);
	std::string modfied_data = jwt->CreateToken();

	unsigned int policy = 0;
	policy = static_cast<unsigned int>(PolicyOption::AllowUnsigned);
	unsigned int eval_policy = 0;
	char* output_secret = nullptr;
	long result = unprotect_secret(
		(char *)modfied_data.c_str(), modfied_data.length(), policy,
		&output_secret, &eval_policy
	);
	ASSERT_LE(result, 0);
	ASSERT_EQ(output_secret, nullptr);
	if (output_secret) {
		free_secret(output_secret);
	}
}

/**
 * @brief Tests the failure case of the unprotect_secret function with an
 * invalid ECDH private key.
 *
 * This test verifies that the unprotect_secret function returns -1 when
 * provided with an invalid ECDH private key. It simulates a potentially
 * malformed JWT, specifically modifying the guestPrivateKey to be invalid.
 * It replaces the original ECDH private key with a base64 encoded string of
 * zeros.
 *
 * Test Steps:
 * 1. Encrypt a sample secret data.
 * 2. Parse the encrypted data into a JWT.
 * 3. Modify the JWT by setting the "encryptedGuestEcdhPrivateKey" claim to an
 *    invalid value.
 * 4. Attempt to unprotect the secret using the modified JWT.
 * 5. Perform assertions to verify the expected behavior. 
 *
 * Assertions:
 * - The unprotect_secret function returns -1.
 * - The output_secret is nullptr.
 */
TEST_F(FunctionalityTests, FailureInvalidEcdhPrivateKey) {
	char data[] = "Test Secret info";

	std::string encrypted_data = Encrypt(data);

	// Modify jwt
	std::unique_ptr<JsonWebToken> jwt = std::make_unique<JsonWebToken>();
	jwt->ParseToken(encrypted_data, false);
    jwt->addClaim(
		"encryptedGuestEcdhPrivateKey",
		encoders::base64_encode(
			std::vector<unsigned char>(
				jwt->getClaims()["encryptedGuestEcdhPrivateKey"].dump().length(),
				0
			)
		)
	);
	std::string modfied_data = jwt->CreateToken();

	unsigned int policy = 0;
	policy = static_cast<unsigned int>(PolicyOption::AllowUnsigned);
	unsigned int eval_policy = 0;
	char* output_secret = nullptr;
	long result = unprotect_secret(
		(char *)modfied_data.c_str(), modfied_data.length(), policy,
		&output_secret, &eval_policy
	);
	ASSERT_LE(result, 0);
	ASSERT_EQ(output_secret, nullptr);
	if (output_secret) {
		free_secret(output_secret);
	}
}

/**
 * @brief Unit test for the ParseToken function to check failure case.
 *
 * This test verifies that the ParseToken function correctly handles invalid
 * tokens. It encrypts a sample data to generate a valid token, then modifies
 * the token to make it invalid. The test asserts that the ParseToken function
 * returns false for the invalid token.
 *
 * Test Steps:
 * 1. Encrypt sample data to generate a valid token.
 * 2. Modify the token to make it invalid by removing the "dataNonce" claim.
 * 3. Attempt to parse the modified token using the unprotect_secret function.
 * 4. Perform Assertions.
 *
 * Assertions:
 * - The unprotect_secret function returns a value less than or equal to 0.
 * - The output_secret is nullptr.
 */
TEST_F(FunctionalityTests, FailureParseToken) {
	char data[] = "Test Secret info";

	// Encrypt data to get a valid token
	std::string encrypted_data = Encrypt(data);

	// Modify the token to make it invalid
	std::unique_ptr<JsonWebToken> jwt = std::make_unique<JsonWebToken>();
	jwt->ParseToken(encrypted_data, false);
	auto body = jwt->getClaims();
	body.erase("dataNonce");
	jwt->SetPayload(body);
	std::string modfied_data = jwt->CreateToken();
	
	// Parse the modified token
	unsigned int policy = 0;
	policy = static_cast<unsigned int>(PolicyOption::AllowUnsigned);
	unsigned int eval_policy = 0;
	char* output_secret = nullptr;
	long result = unprotect_secret(
		(char *)modfied_data.c_str(), modfied_data.length(), policy,
		&output_secret, &eval_policy
	);
	ASSERT_LE(result, 0);
	ASSERT_EQ(output_secret, nullptr);
	if (output_secret) {
		free_secret(output_secret);
	}
}

/**
 * @brief Test case to verify a Library failure on an invalid policy.
 *
 * This test checks the success case of the unprotect_secret function.
 * It does the following:
 * 1. Encrypt a sample secret data.
 * 2. Decrypt the encrypted data using the unprotect_secret function.
 * 3. Perform assertions.
 * 
 * Assertions:
 * - The unprotect_secret function returns the length of the secret.
 * - The original protected data is correctly decrypted.
 */
TEST_F(FunctionalityTests, FailPolicyError) {
	char data[] = "Test Secret info";

	std::string encrypted_data = Encrypt(data);
	char* output_secret = nullptr;
	unsigned int policy = 0;
	unsigned int eval_policy = 0;
	long result = unprotect_secret(
		(char *)encrypted_data.c_str(), encrypted_data.length(), policy,
		&output_secret, &eval_policy
	);
	ASSERT_EQ(result, (long)ErrorCode::PolicyMismatchError);
	ASSERT_EQ(eval_policy, static_cast<unsigned int>(PayloadFeature::Encrypted));
}