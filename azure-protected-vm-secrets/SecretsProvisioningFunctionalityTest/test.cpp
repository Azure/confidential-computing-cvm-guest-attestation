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
		if (is_secrets_provisioning_enabled() <= 0) {
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
	ASSERT_STRNE(get_error_message(result), "Success");
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
	ASSERT_STREQ(get_error_message(result), "CryptographyError_AES_decryptError");
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
	ASSERT_STREQ(get_error_message(result), "ParsingError_Jwt_missingFieldError");
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
	ASSERT_STREQ(get_error_message(result), "PolicyMismatchError");
	ASSERT_EQ(eval_policy, static_cast<unsigned int>(PayloadFeature::Encrypted));
}

TEST_F(FunctionalityTests, SuccessfulEncryptDecryptWide) {
    // Create test data as wide string
    const wchar_t* data = L"Test Wide Character Secret";
    
    // Encrypt data using EncryptWide function
    std::string encrypted_jwt = EncryptWide(data);
    
    // Convert JWT to wide characters for the wide API
    std::vector<unsigned char> encrypted_utf8(encrypted_jwt.begin(), encrypted_jwt.end());
    std::vector<wchar_t> wide_encrypted = utf8_sanitizer::utf8_to_wide(encrypted_utf8);
    
    // Set up parameters for unprotect_secret_wide
    wchar_t* output_secret = nullptr;
    unsigned int policy = static_cast<unsigned int>(PolicyOption::AllowUnsigned);
    unsigned int eval_policy = 0;
    
    // Call unprotect_secret_wide
    long result = unprotect_secret_wide(
        wide_encrypted.data(), 
        static_cast<unsigned int>(wide_encrypted.size()), 
        policy,
        &output_secret, 
        &eval_policy
    );
    
    // Verify result
    ASSERT_GT(result, 0);
    ASSERT_TRUE(output_secret != nullptr);
    
    if (output_secret) {
        // Compare the decrypted data with the original
        ASSERT_EQ(wcscmp(data, output_secret), 0);
        
        // Free the output memory
        free_secret_wide(output_secret);
    }
}

TEST_F(FunctionalityTests, WideStringLengthHandling) {
    // Create a known-length string
    const wchar_t testStr[] = L"Test123";
    size_t charCount = wcslen(testStr);  // 7 characters, excludes null
    size_t fullLength = charCount + 1;   // 8 characters, includes null
    size_t byteLength = fullLength * sizeof(wchar_t);
    
    // Create parameters
    wchar_t* output_secret = nullptr;
    unsigned int policy = static_cast<unsigned int>(PolicyOption::AllowUnsigned);
    unsigned int eval_policy = 0;
    
    // Encrypt with known string
    std::string encrypted_data = EncryptWide(testStr);
    std::vector<unsigned char> encrypted_utf8(encrypted_data.begin(), encrypted_data.end());
    std::vector<wchar_t> wide_encrypted = utf8_sanitizer::utf8_to_wide(encrypted_utf8);
    
    // Call function
    long result = unprotect_secret_wide(
        wide_encrypted.data(),
        static_cast<unsigned int>(wide_encrypted.size()),
        policy,
        &output_secret,
        &eval_policy
    );
    
    // Verify using each possible interpretation
    ASSERT_TRUE(result == charCount || result == fullLength || result == byteLength);
    
    if (output_secret) {
        free_secret_wide(output_secret);
    }
}

/**
 * @brief Test case to verify the failure scenario of the unprotect_secret_wide
 * function with an invalid token that has a modified nonce.
 *
 * This test checks the behavior of the unprotect_secret_wide function when provided
 * with an invalid JWT where the nonce has been replaced with a zero vector.
 * The test will pass if the unprotect_secret_wide function returns a value less
 * than or equal to 0 and the output_secret is set to nullptr, indicating that
 * the decryption failed as expected.
 */
TEST_F(FunctionalityTests, FailureEncryptDecryptWide) {
    // Create test data
    char data[] = "Test Wide Character Secret";
    
    // Encrypt data
    std::string encrypted_data = Encrypt(data);
    
    // Modify jwt
    std::unique_ptr<JsonWebToken> jwt = std::make_unique<JsonWebToken>();
    jwt->ParseToken(encrypted_data, false);
    jwt->addClaim(
        "dataNonce",
        encoders::base64_encode(std::vector<unsigned char>(32, 0))
    );
    std::string modified_data = jwt->CreateToken();
    
    // Convert to wide characters
    std::vector<unsigned char> modified_utf8(modified_data.begin(), modified_data.end());
    std::vector<wchar_t> wide_modified_vec = utf8_sanitizer::utf8_to_wide(modified_utf8);
    
    // Set up parameters
    wchar_t* output_secret = nullptr;
    unsigned int policy = static_cast<unsigned int>(PolicyOption::AllowUnsigned);
    unsigned int eval_policy = 0;
    // Call unprotect_secret_wide with modified token
    long result = unprotect_secret_wide(
        wide_modified_vec.data(), 
        static_cast<unsigned int>(wide_modified_vec.size()), 
        policy,
        &output_secret, 
        &eval_policy
    );
    
    // Verify failure
    ASSERT_LE(result, 0);
    ASSERT_STREQ(get_error_message(result), "CryptographyError_AES_decryptError");
    ASSERT_EQ(output_secret, nullptr);
    
    if (output_secret) {
        free_secret_wide(output_secret);
    }
}

/**
 * @brief Test case to verify the handling of Unicode characters in wide string secrets.
 *
 * This test verifies that the unprotect_secret_wide function correctly handles
 * Unicode characters in the secret data. It encrypts data containing Unicode characters,
 * converts it to wide characters, and then verifies that the decryption produces
 * the correct Unicode characters.
 */
TEST_F(FunctionalityTests, UnicodeHandlingWide) {
    // Create test data with Unicode characters as wide string
    const wchar_t* unicode_data = L"Unicode Test: こんにちは 世界 🌍";
    
    // Encrypt data using EncryptWide function
    std::string encrypted_jwt = EncryptWide(unicode_data);
    
    // Convert JWT to wide characters for the wide API
    std::vector<unsigned char> encrypted_utf8(encrypted_jwt.begin(), encrypted_jwt.end());
    std::vector<wchar_t> wide_encrypted_vec = utf8_sanitizer::utf8_to_wide(encrypted_utf8);
    
    // Set up parameters
    wchar_t* output_secret = nullptr;
    unsigned int policy = static_cast<unsigned int>(PolicyOption::AllowUnsigned);
    unsigned int eval_policy = 0;
    
    // Call unprotect_secret_wide
    long result = unprotect_secret_wide(
        wide_encrypted_vec.data(), 
        static_cast<unsigned int>(wide_encrypted_vec.size()), 
        policy,
        &output_secret, 
        &eval_policy
    );
    
    // Verify result
    ASSERT_GT(result, 0);
    ASSERT_TRUE(output_secret != nullptr);
    
    if (output_secret) {
        // Compare the decrypted data with the original
        ASSERT_EQ(wcscmp(unicode_data, output_secret), 0);
        
        // Free the output memory
        free_secret_wide(output_secret);
    }
}

/**
 * @brief Test case to verify policy validation in unprotect_secret_wide.
 *
 * This test verifies that the unprotect_secret_wide function correctly validates
 * the policy requirements. It attempts to decrypt with an invalid policy and
 * verifies that the function returns a policy mismatch error.
 */
TEST_F(FunctionalityTests, PolicyMismatchErrorWide) {
    // Create test data
    char data[] = "Test Wide Character Secret";
    
    // Encrypt data
    std::string encrypted_data = Encrypt(data);
    
    // Convert to wide characters
    std::vector<unsigned char> encrypted_utf8(encrypted_data.begin(), encrypted_data.end());
    std::vector<wchar_t> wide_encrypted_vec = utf8_sanitizer::utf8_to_wide(encrypted_utf8);
    
    // Set up parameters with an invalid policy (0)
    wchar_t* output_secret = nullptr;
    unsigned int policy = 0;  // Invalid policy
    unsigned int eval_policy = 0;
    // Call unprotect_secret_wide
    long result = unprotect_secret_wide(
        wide_encrypted_vec.data(), 
        static_cast<unsigned int>(wide_encrypted_vec.size()), 
        policy,
        &output_secret, 
        &eval_policy
    );
    
    // Verify policy error
    ASSERT_EQ(result, (long)ErrorCode::PolicyMismatchError);
    ASSERT_STREQ(get_error_message(result), "PolicyMismatchError");
    ASSERT_EQ(eval_policy, static_cast<unsigned int>(PayloadFeature::Encrypted));
    ASSERT_EQ(output_secret, nullptr);
}

/**
 * @brief Test case for legacy data with AllowLegacy policy using standard char API
 * 
 * This test verifies that legacy (non-JWT) data is properly detected and allowed
 * when using the AllowLegacy policy option.
 */
TEST_F(FunctionalityTests, LegacyDataAllowedStandard) {
    // Create legacy data (non-JWT format) - any non-JWT string will do
    std::string legacy_data = "LEGACY: This is not a JWT token";
    
    // Set up parameters with AllowLegacy policy
    char* output_secret = nullptr;
    unsigned int policy = static_cast<unsigned int>(PolicyOption::AllowLegacy);
    unsigned int eval_policy = 0;
    
    // Call unprotect_secret with legacy data
    long result = unprotect_secret(
        (char*)legacy_data.c_str(), legacy_data.length(), policy,
        &output_secret, &eval_policy
    );
    
    // Verify legacy feature was detected
    ASSERT_TRUE(eval_policy & static_cast<unsigned int>(PayloadFeature::Legacy));
    
    // Legacy should be compliant with AllowLegacy policy
    ASSERT_NE(result, (long)ErrorCode::PolicyMismatchError);
    
    // Clean up if needed
    if (output_secret) {
        free_secret(output_secret);
    }
}

/**
 * @brief Test case for legacy data with RequireAll policy using standard char API
 * 
 * This test verifies that legacy (non-JWT) data is properly detected and rejected
 * when using a strict policy that doesn't allow legacy format.
 */
TEST_F(FunctionalityTests, LegacyDataRejectedStandard) {
    // Create legacy data (non-JWT format) - simple non-JWT string
    std::string legacy_data = "This is not a JWT token";
    
    // Set up parameters with strict policy (RequireAll)
    char* output_secret = nullptr;
    unsigned int policy = static_cast<unsigned int>(PolicyOption::RequireAll);
    unsigned int eval_policy = 0;
    
    // Call unprotect_secret with legacy data
    long result = unprotect_secret(
        (char*)legacy_data.c_str(), legacy_data.length(), policy,
        &output_secret, &eval_policy
    );
    
    // Verify legacy feature was detected
    ASSERT_TRUE(eval_policy & static_cast<unsigned int>(PayloadFeature::Legacy));
    
    // Policy should reject legacy data
    ASSERT_EQ(result, (long)ErrorCode::PolicyMismatchError);
    ASSERT_STREQ(get_error_message(result), "PolicyMismatchError");
    ASSERT_EQ(output_secret, nullptr);
}

/**
 * @brief Test case for legacy data with AllowLegacy policy using wide char API
 * 
 * This test verifies that legacy data is properly detected and allowed when
 * passed through the wide character interface with AllowLegacy policy option.
 */
TEST_F(FunctionalityTests, LegacyDataAllowedWide) {
    // Create legacy data - simple wide string
    const wchar_t* legacy_wstr = L"LEGACY_WIDE: This is not a JWT token";
    std::vector<wchar_t> wide_legacy(legacy_wstr, legacy_wstr + wcslen(legacy_wstr));
    
    // Set up parameters with AllowLegacy policy
    wchar_t* output_secret = nullptr;
    unsigned int policy = static_cast<unsigned int>(PolicyOption::AllowLegacy);
    unsigned int eval_policy = 0;
    
    // Call unprotect_secret_wide with legacy data
    long result = unprotect_secret_wide(
        wide_legacy.data(), static_cast<unsigned int>(wide_legacy.size()),
        policy, &output_secret, &eval_policy
    );
    
    // Verify legacy feature was detected
    ASSERT_TRUE(eval_policy & static_cast<unsigned int>(PayloadFeature::Legacy));
    
    // Legacy should be compliant with AllowLegacy policy
    ASSERT_NE(result, (long)ErrorCode::PolicyMismatchError);
    
    // Clean up if needed
    if (output_secret) {
        free_secret_wide(output_secret);
    }
}

/**
 * @brief Test case for legacy data with RequireAll policy using wide char API
 * 
 * This test verifies that legacy data is properly detected and rejected when
 * passed through the wide character interface with RequireAll policy.
 */
TEST_F(FunctionalityTests, LegacyDataRejectedWide) {
    // Create legacy data - direct wide string literal
    const wchar_t* legacy_wstr = L"This is not a JWT token";
    std::vector<wchar_t> wide_legacy(legacy_wstr, legacy_wstr + wcslen(legacy_wstr));
    
    // Set up parameters with strict policy
    wchar_t* output_secret = nullptr;
    unsigned int policy = static_cast<unsigned int>(PolicyOption::RequireAll);
    unsigned int eval_policy = 0;
    
    // Call unprotect_secret_wide with legacy data
    long result = unprotect_secret_wide(
        wide_legacy.data(), static_cast<unsigned int>(wide_legacy.size()),
        policy, &output_secret, &eval_policy
    );
    
    // Verify legacy feature was detected
    ASSERT_TRUE(eval_policy & static_cast<unsigned int>(PayloadFeature::Legacy));
    
    // Policy should reject legacy data
    ASSERT_EQ(result, (long)ErrorCode::PolicyMismatchError);
    ASSERT_STREQ(get_error_message(result), "PolicyMismatchError");
    ASSERT_EQ(output_secret, nullptr);
}

/**
 * @brief Test case for legacy detection with ambiguous data
 * 
 * This test verifies that data with dots but invalid Base64 encoding is
 * still correctly identified as legacy format.
 */
TEST_F(FunctionalityTests, AmbiguousLegacyData) {
    // Create data with dots to mimic JWT format but with invalid Base64
    std::string ambiguous_data = "header.payload.signature";
    
    // Set up parameters
    char* output_secret = nullptr;
    unsigned int policy = static_cast<unsigned int>(PolicyOption::AllowLegacy);
    unsigned int eval_policy = 0;
    
    // Call unprotect_secret
    long result = unprotect_secret(
        (char*)ambiguous_data.c_str(), ambiguous_data.length(),
        policy, &output_secret, &eval_policy
    );
    
    // Should be detected as legacy because Base64 decoding will fail
    ASSERT_TRUE(eval_policy & static_cast<unsigned int>(PayloadFeature::Legacy));
    
    if (output_secret) {
        free_secret(output_secret);
    }
}

/**
 * @brief Test case for missing required fields
 * 
 * This test verifies that a well-formed JWT without the required x-az-cvm-purpose
 * field is correctly identified as legacy format.
 */
TEST_F(FunctionalityTests, MissingRequiredFields) {
    // Create a valid JWT but without the required field
    std::unique_ptr<JsonWebToken> jwt = std::make_unique<JsonWebToken>("RS256");
    jwt->addClaim("sub", "1234567890");
    // Not adding the required x-az-cvm-purpose field to header
    
    std::string token = jwt->CreateToken();
    
    // Set up parameters
    char* output_secret = nullptr;
    unsigned int policy = static_cast<unsigned int>(PolicyOption::AllowLegacy);
    unsigned int eval_policy = 0;
    
    // Call unprotect_secret
    long result = unprotect_secret(
        (char*)token.c_str(), token.length(),
        policy, &output_secret, &eval_policy
    );
    
    // Should be detected as legacy because of missing required field
    ASSERT_TRUE(eval_policy & static_cast<unsigned int>(PayloadFeature::Legacy));
    
    if (output_secret) {
        free_secret(output_secret);
    }
}

/**
 * @brief Test case for legacy detection consistency
 * 
 * This test verifies that the same data is detected as legacy whether
 * passed through standard or wide character APIs.
 */
TEST_F(FunctionalityTests, LegacyDetectionConsistency) {
    // Create test data - simple non-JWT string
    std::string legacy_str = "This is not a JWT token";
    
    // Convert to wide
    std::vector<unsigned char> legacy_bytes(legacy_str.begin(), legacy_str.end());
    std::vector<wchar_t> wide_legacy = utf8_sanitizer::utf8_to_wide(legacy_bytes);
    
    // Test standard API
    char* std_output = nullptr;
    unsigned int std_policy = static_cast<unsigned int>(PolicyOption::AllowLegacy);
    unsigned int std_eval_policy = 0;
    unprotect_secret(
        (char*)legacy_str.c_str(), legacy_str.length(),
        std_policy, &std_output, &std_eval_policy
    );
    
    // Test wide API
    wchar_t* wide_output = nullptr;
    unsigned int wide_policy = static_cast<unsigned int>(PolicyOption::AllowLegacy);
    unsigned int wide_eval_policy = 0;
    unprotect_secret_wide(
        wide_legacy.data(), static_cast<unsigned int>(wide_legacy.size()),
        wide_policy, &wide_output, &wide_eval_policy
    );
    
    // Both should be detected as legacy
    ASSERT_TRUE(std_eval_policy & static_cast<unsigned int>(PayloadFeature::Legacy));
    ASSERT_TRUE(wide_eval_policy & static_cast<unsigned int>(PayloadFeature::Legacy));
    
    // Legacy detection should be consistent between APIs
    ASSERT_EQ(std_eval_policy & static_cast<unsigned int>(PayloadFeature::Legacy), 
              wide_eval_policy & static_cast<unsigned int>(PayloadFeature::Legacy));
    
    // Clean up
    if (std_output) free_secret(std_output);
    if (wide_output) free_secret_wide(wide_output);
}

/**
 * @brief Test case for empty wide string handling
 */
TEST_F(FunctionalityTests, EmptyWideStringHandling) {
    const wchar_t* empty_data = L"";
    
    std::string encrypted_jwt = EncryptWide(empty_data);
    std::vector<unsigned char> encrypted_utf8(encrypted_jwt.begin(), encrypted_jwt.end());
    std::vector<wchar_t> wide_encrypted_vec = utf8_sanitizer::utf8_to_wide(encrypted_utf8);
    
    wchar_t* output_secret = nullptr;
    unsigned int policy = static_cast<unsigned int>(PolicyOption::AllowUnsigned);
    unsigned int eval_policy = 0;
    
    long result = unprotect_secret_wide(
        wide_encrypted_vec.data(), 
        static_cast<unsigned int>(wide_encrypted_vec.size()), 
        policy,
        &output_secret, 
        &eval_policy
    );
    
    ASSERT_GT(result, 0);
    ASSERT_TRUE(output_secret != nullptr);
    
    if (output_secret) {
        ASSERT_EQ(wcscmp(empty_data, output_secret), 0);
        free_secret_wide(output_secret);
    }
}

/**
 * @brief Test case for various Unicode character ranges
 */
TEST_F(FunctionalityTests, UnicodeRangesWide) {
    // Test different Unicode ranges
    const wchar_t* test_cases[] = {
        L"ASCII only test",
        L"Latin: café résumé naïve",
        L"Cyrillic: Привет мир", 
        L"CJK: 你好世界",
        L"Emoji: 🚀🌟💻🎉",
        L"Mixed: Hello世界🌍Привет"
    };
    
    for (const wchar_t* test_data : test_cases) {
        std::string encrypted_jwt = EncryptWide(test_data);
        std::vector<unsigned char> encrypted_utf8(encrypted_jwt.begin(), encrypted_jwt.end());
        std::vector<wchar_t> wide_encrypted_vec = utf8_sanitizer::utf8_to_wide(encrypted_utf8);
        
        wchar_t* output_secret = nullptr;
        unsigned int policy = static_cast<unsigned int>(PolicyOption::AllowUnsigned);
        unsigned int eval_policy = 0;
        
        long result = unprotect_secret_wide(
            wide_encrypted_vec.data(), 
            static_cast<unsigned int>(wide_encrypted_vec.size()), 
            policy,
            &output_secret, 
            &eval_policy
        );
        
        ASSERT_GT(result, 0);
        ASSERT_TRUE(output_secret != nullptr);
        
        if (output_secret) {
            ASSERT_EQ(wcscmp(test_data, output_secret), 0);
            free_secret_wide(output_secret);
        }
    }
}

/**
 * @brief Test API consistency between regular and wide character versions
 */
TEST_F(FunctionalityTests, ApiConsistencyRegularVsWide) {
    // Test with ASCII data that should work identically in both APIs
    const char* ascii_data = "Test ASCII Data 123!@#";
    const wchar_t* wide_data = L"Test ASCII Data 123!@#";
    
    // Encrypt with both methods
    std::string regular_encrypted = Encrypt(ascii_data);
    std::string wide_encrypted = EncryptWide(wide_data);
    
    // Both should produce valid JWTs (though different due to encryption randomness)
    ASSERT_FALSE(regular_encrypted.empty());
    ASSERT_FALSE(wide_encrypted.empty());
    
    // Test regular decryption
    char* regular_output = nullptr;
    unsigned int policy = static_cast<unsigned int>(PolicyOption::AllowUnsigned);
    unsigned int regular_eval_policy = 0;
    
    long regular_result = unprotect_secret(
        (char*)regular_encrypted.c_str(), regular_encrypted.length(), policy,
        &regular_output, &regular_eval_policy
    );
    
    // Test wide decryption
    std::vector<unsigned char> wide_encrypted_utf8(wide_encrypted.begin(), wide_encrypted.end());
    std::vector<wchar_t> wide_encrypted_vec = utf8_sanitizer::utf8_to_wide(wide_encrypted_utf8);
    
    wchar_t* wide_output = nullptr;
    unsigned int wide_eval_policy = 0;
    
    long wide_result = unprotect_secret_wide(
        wide_encrypted_vec.data(), 
        static_cast<unsigned int>(wide_encrypted_vec.size()), 
        policy,
        &wide_output, 
        &wide_eval_policy
    );
    
    // Both should succeed
    ASSERT_GT(regular_result, 0);
    ASSERT_GT(wide_result, 0);
    
    // Content should match
    ASSERT_EQ(strcmp(ascii_data, regular_output), 0);
    ASSERT_EQ(wcscmp(wide_data, wide_output), 0);
    
    // Clean up
    if (regular_output) free_secret(regular_output);
    if (wide_output) free_secret_wide(wide_output);
}

/**
 * @brief Test null pointer handling in wide API
 */
TEST_F(FunctionalityTests, NullPointerHandlingWide) {
    wchar_t* output_secret = nullptr;
    unsigned int policy = static_cast<unsigned int>(PolicyOption::AllowUnsigned);
    unsigned int eval_policy = 0;
    
    // Test with null input
    long result = unprotect_secret_wide(
        nullptr, 0, policy, &output_secret, &eval_policy
    );
    
    ASSERT_LE(result, 0);
    ASSERT_STREQ(get_error_message(result), "PolicyMismatchError");
    ASSERT_EQ(output_secret, nullptr);
}

/**
 * @brief Test very long Unicode strings
 */
TEST_F(FunctionalityTests, LongUnicodeStringWide) {
    // Create a long Unicode string
    std::wstring long_unicode = L"Long Unicode Test: ";
    for (int i = 0; i < 100; i++) {
        long_unicode += L"こんにちは世界🌍 ";
    }
    
    std::string encrypted_jwt = EncryptWide(long_unicode.c_str());
    std::vector<unsigned char> encrypted_utf8(encrypted_jwt.begin(), encrypted_jwt.end());
    std::vector<wchar_t> wide_encrypted_vec = utf8_sanitizer::utf8_to_wide(encrypted_utf8);
    
    wchar_t* output_secret = nullptr;
    unsigned int policy = static_cast<unsigned int>(PolicyOption::AllowUnsigned);
    unsigned int eval_policy = 0;
    
    long result = unprotect_secret_wide(
        wide_encrypted_vec.data(), 
        static_cast<unsigned int>(wide_encrypted_vec.size()), 
        policy,
        &output_secret, 
        &eval_policy
    );
    
    ASSERT_GT(result, 0);
    ASSERT_TRUE(output_secret != nullptr);
    
    if (output_secret) {
        ASSERT_EQ(wcscmp(long_unicode.c_str(), output_secret), 0);
        free_secret_wide(output_secret);
    }
}

/**
 * @brief Test UTF-8 conversion round-trip consistency
 */
TEST_F(FunctionalityTests, Utf8ConversionRoundTrip) {
    // Test various Unicode strings to ensure they survive the round-trip
    const wchar_t* test_strings[] = {
        L"Basic ASCII",
        L"Special chars: !@#$%^&*()",
        L"Unicode: こんにちは",
        L"Emoji: 🌍🚀💻",
        L"Mixed: Hello世界🌟Test"
    };
    
    for (const wchar_t* original : test_strings) {
        // Convert wide -> UTF-8 -> wide
        std::vector<wchar_t> wide_vec(original, original + wcslen(original) + 1);
        std::vector<unsigned char> utf8_vec = utf8_sanitizer::wide_to_utf8(wide_vec);
        std::vector<wchar_t> restored_wide = utf8_sanitizer::utf8_to_wide(utf8_vec);
        
        // Should be identical (excluding null terminator handling)
        ASSERT_EQ(wcslen(original), restored_wide.size() > 0 ? restored_wide.size() - 1 : 0);
        
        if (!restored_wide.empty()) {
            // Ensure content matches
            bool matches = true;
            for (size_t i = 0; i < wcslen(original); i++) {
                if (original[i] != restored_wide[i]) {
                    matches = false;
                    break;
                }
            }
            ASSERT_TRUE(matches);
        }
    }
}

/**
 * @brief Test maximum length strings
 */
TEST_F(FunctionalityTests, MaxLengthStringWide) {
    // Test with a very large string (but reasonable for real-world use)
    const size_t large_size = 10000;
    std::wstring large_string(large_size, L'A');
    large_string += L" Unicode: 世界";  // Add some Unicode at the end
    
    try {
        std::string encrypted_jwt = EncryptWide(large_string.c_str());
        std::vector<unsigned char> encrypted_utf8(encrypted_jwt.begin(), encrypted_jwt.end());
        std::vector<wchar_t> wide_encrypted_vec = utf8_sanitizer::utf8_to_wide(encrypted_utf8);
        
        wchar_t* output_secret = nullptr;
        unsigned int policy = static_cast<unsigned int>(PolicyOption::AllowUnsigned);
        unsigned int eval_policy = 0;
        
        long result = unprotect_secret_wide(
            wide_encrypted_vec.data(), 
            static_cast<unsigned int>(wide_encrypted_vec.size()), 
            policy,
            &output_secret, 
            &eval_policy
        );
        
        if (result > 0 && output_secret) {
            ASSERT_EQ(wcscmp(large_string.c_str(), output_secret), 0);
            free_secret_wide(output_secret);
        } else {
            // If it fails, it should fail gracefully
            ASSERT_EQ(output_secret, nullptr);
        }
    } catch (...) {
        // Large string tests may legitimately fail due to memory or other limits
        // SUCCEED() << "Large string test failed gracefully";
        FAIL();
    }
}

/**
 * @brief Test single character Unicode strings
 */
TEST_F(FunctionalityTests, SingleCharacterUnicodeWide) {
    const wchar_t* single_chars[] = {
        L"A",      // ASCII
        L"世",     // CJK
        L"🌍",     // Emoji
        L"é",      // Latin extended
        L"Ω"       // Greek
    };
    
    for (const wchar_t* single_char : single_chars) {
        std::string encrypted_jwt = EncryptWide(single_char);
        std::vector<unsigned char> encrypted_utf8(encrypted_jwt.begin(), encrypted_jwt.end());
        std::vector<wchar_t> wide_encrypted_vec = utf8_sanitizer::utf8_to_wide(encrypted_utf8);
        
        wchar_t* output_secret = nullptr;
        unsigned int policy = static_cast<unsigned int>(PolicyOption::AllowUnsigned);
        unsigned int eval_policy = 0;
        
        long result = unprotect_secret_wide(
            wide_encrypted_vec.data(), 
            static_cast<unsigned int>(wide_encrypted_vec.size()), 
            policy,
            &output_secret, 
            &eval_policy
        );
        
        ASSERT_GT(result, 0);
        ASSERT_TRUE(output_secret != nullptr);
        
        if (output_secret) {
            ASSERT_EQ(wcscmp(single_char, output_secret), 0);
            free_secret_wide(output_secret);
        }
    }
}

/**
 * @brief Test malformed wide character input
 */
TEST_F(FunctionalityTests, MalformedWideInputHandling) {
    // Create malformed wide character data (simulating corruption)
    std::vector<wchar_t> malformed_data = {0xD800, 0xD800, 0x0041, 0x0000}; // Invalid surrogate pair + 'A' + null
    
    wchar_t* output_secret = nullptr;
    unsigned int policy = static_cast<unsigned int>(PolicyOption::AllowLegacy); // Use legacy to bypass JWT parsing
    unsigned int eval_policy = 0;
    
    long result = unprotect_secret_wide(
        malformed_data.data(), 
        static_cast<unsigned int>(malformed_data.size()), 
        policy,
        &output_secret, 
        &eval_policy
    );
    
    // With our updated UTF-8 conversion handling, malformed Unicode should be
    // treated as legacy data and succeed when AllowLegacy policy is used
    ASSERT_GT(result, 0);  // Should succeed
    ASSERT_TRUE(output_secret != nullptr);
    ASSERT_TRUE(eval_policy & static_cast<unsigned int>(PayloadFeature::Legacy)); // Should be detected as legacy
    
    if (output_secret) {
        free_secret_wide(output_secret);
    }
}

/**
 * @brief Test Unicode equivalence with explicit code points
 */
TEST_F(FunctionalityTests, UnicodeEquivalenceExplicitCodePoints) {
    // Use explicit Unicode code points to avoid source encoding issues
    // U+00E9 is 'é' which should be 0xC3 0xA9 in UTF-8
    const char utf8_data[] = "Unicode: caf\xC3\xA9";  // Explicit UTF-8 bytes for 'é'
    const wchar_t wide_data[] = L"Unicode: caf\u00E9"; // Explicit Unicode code point for 'é'
    
    // Test conversion consistency - include null terminator in wide vector for realistic API usage
    std::vector<wchar_t> wide_vec(wide_data, wide_data + wcslen(wide_data) + 1);
    std::vector<unsigned char> converted_utf8 = utf8_sanitizer::wide_to_utf8(wide_vec);
    
    // Compare byte-by-byte, excluding null terminator from comparison
    size_t utf8_data_len = strlen(utf8_data);
    size_t converted_content_len = converted_utf8.size();
    
    // If converted UTF-8 has null terminator, exclude it from comparison
    if (converted_content_len > 0 && converted_utf8[converted_content_len - 1] == 0) {
        converted_content_len--;
    }
    
    // Verify UTF-8 conversion is working correctly
    ASSERT_EQ(utf8_data_len, converted_content_len);
    
    for (size_t i = 0; i < utf8_data_len; i++) {
        ASSERT_EQ((unsigned char)utf8_data[i], converted_utf8[i]);
    }
    
    // Test both APIs with equivalent Unicode content
    std::string regular_encrypted = Encrypt(utf8_data);
    std::string wide_encrypted = EncryptWide(wide_data);
    
    // Decrypt with both APIs
    char* regular_output = nullptr;
    wchar_t* wide_output = nullptr;
    unsigned int policy = static_cast<unsigned int>(PolicyOption::AllowUnsigned);
    unsigned int regular_eval_policy = 0, wide_eval_policy = 0;
    
    // Regular API decryption
    long regular_result = unprotect_secret(
        (char*)regular_encrypted.c_str(), regular_encrypted.length(), policy,
        &regular_output, &regular_eval_policy
    );
    
    // Wide API decryption
    std::vector<unsigned char> wide_encrypted_utf8(wide_encrypted.begin(), wide_encrypted.end());
    std::vector<wchar_t> wide_encrypted_vec = utf8_sanitizer::utf8_to_wide(wide_encrypted_utf8);
    
    long wide_result = unprotect_secret_wide(
        wide_encrypted_vec.data(), 
        static_cast<unsigned int>(wide_encrypted_vec.size()), 
        policy, &wide_output, &wide_eval_policy
    );
    
    // Verify both APIs succeeded
    ASSERT_GT(regular_result, 0);
    ASSERT_GT(wide_result, 0);
    ASSERT_TRUE(regular_output != nullptr);
    ASSERT_TRUE(wide_output != nullptr);
    
    // First, verify each API produced the expected result
    ASSERT_EQ(strcmp(utf8_data, regular_output), 0);
    ASSERT_EQ(wcscmp(wide_data, wide_output), 0);
    
    // Convert regular output to wide for cross-API comparison
    size_t regular_content_len = strlen(regular_output);
    std::vector<unsigned char> regular_utf8(regular_output, regular_output + regular_content_len);
    std::vector<wchar_t> regular_as_wide = utf8_sanitizer::utf8_to_wide(regular_utf8);
    
    ASSERT_FALSE(regular_as_wide.empty());
    
    // Ensure regular_as_wide is null-terminated for comparison
    if (regular_as_wide.empty() || regular_as_wide.back() != L'\0') {
        regular_as_wide.push_back(L'\0');
    }
    
    // Verify Unicode content equivalence between APIs
    ASSERT_EQ(wcscmp(wide_output, regular_as_wide.data()), 0);
    
    // Clean up
    if (regular_output) free_secret(regular_output);
    if (wide_output) free_secret_wide(wide_output);
}
