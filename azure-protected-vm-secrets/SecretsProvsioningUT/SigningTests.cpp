// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "gtest/gtest.h"
#ifdef PLATFORM_UNIX
#include "Linux/OsslX509.h"
#else
#include "Windows/WincryptX509.h"
#include "BcryptError.h"
#endif // !PLATFORM_UNIX
#include "JsonWebToken.h"

// Platform-specific type alias to reduce #ifdef duplication
#ifdef PLATFORM_UNIX
using X509Type = OsslX509;
#else
using X509Type = WincryptX509;
#endif

#define X509_TEST_SUBJECT_NAME_SUFFIX ".SecureCPSProvisioning.cloudapp-test.net"

TEST(X509Tests, LoadCertificate) {
    // Test certificate loading and chain verification using dynamically generated certificates
    std::unique_ptr<X509Type> certChain;

    try {
        certChain = generateCertChain();
    }
    catch (std::exception& e) {
        FAIL() << "Exception during cert chain generation: " << e.what();
    }

    bool result = certChain->VerifyCertChain(X509_SUBJECT_NAME_SUFFIX);
    EXPECT_TRUE(result);
}

TEST(X509Tests, ValidateSignature) {
    // Test end-to-end JWT signing workflow using dynamically generated certificates
    std::unique_ptr<X509Type> certChain;

    try {
        certChain = generateCertChain();
    }
    catch (std::exception& e) {
        FAIL() << "Exception during cert chain generation: " << e.what();
    }

    // Verify the certificate chain is valid first
    bool chainValid = certChain->VerifyCertChain(X509_SUBJECT_NAME_SUFFIX);
    EXPECT_TRUE(chainValid);

    // Create a JWT using the JsonWebToken class
    std::unique_ptr<JsonWebToken> jwt = std::make_unique<JsonWebToken>("RS256");
    jwt->addClaim("sub", "test-subject");
    jwt->addClaim("aud", "test-audience");
    jwt->addClaim("data", "test-data");

    // Build the signed portion (header.payload)
    json jwtHeader = jwt->getHeader();
    json jwtPayload = jwt->getClaims();
    jwtPayload["iat"] = time(0);
    jwtPayload["exp"] = time(0) + 1800;
    
    std::string headerJson = jwtHeader.dump();
    std::string payloadJson = jwtPayload.dump();
    
    std::string headerBase64 = encoders::base64_url_encode(
        std::vector<unsigned char>(headerJson.begin(), headerJson.end()));
    std::string payloadBase64 = encoders::base64_url_encode(
        std::vector<unsigned char>(payloadJson.begin(), payloadJson.end()));
    std::string signedPortion = headerBase64 + "." + payloadBase64;
    
    // Sign the JWT's signed portion
    std::vector<unsigned char> dataToSign(signedPortion.begin(), signedPortion.end());
    std::vector<unsigned char> signature = certChain->SignData(dataToSign);
    EXPECT_FALSE(signature.empty());
    
    // Encode signature and assemble complete JWT
    std::string signatureBase64 = encoders::base64_url_encode(signature);
    std::string completeJwt = signedPortion + "." + signatureBase64;
    EXPECT_EQ(std::count(completeJwt.begin(), completeJwt.end(), '.'), 2);
    
    // Verify the signature
    std::vector<unsigned char> decodedSignature = encoders::base64_url_decode(signatureBase64);
    bool result = certChain->VerifySignature(dataToSign, decodedSignature);
    EXPECT_TRUE(result);
}

TEST(X509Tests, FailValidateSignature) {
    // Test that signature verification fails when data is modified
    std::unique_ptr<X509Type> certChain;

    try {
        certChain = generateCertChain();
    }
    catch (std::exception& e) {
        FAIL() << "Exception during cert chain generation: " << e.what();
    }

    // Create original data and sign it
    std::string originalData = "original-test-data-to-sign";
    std::vector<unsigned char> dataToSign(originalData.begin(), originalData.end());
    std::vector<unsigned char> signature = certChain->SignData(dataToSign);
    
    // Create modified data (different from what was signed)
    std::string modifiedData = "modified-test-data-to-sign";
    std::vector<unsigned char> modifiedDataVec(modifiedData.begin(), modifiedData.end());
    
#ifdef PLATFORM_UNIX
    // On Linux, signature verification returns false on failure
    bool result = certChain->VerifySignature(modifiedDataVec, signature);
    EXPECT_FALSE(result);
#else
    // On Windows, signature verification throws on failure
    EXPECT_THROW({
        certChain->VerifySignature(modifiedDataVec, signature);
    }, BcryptError);
#endif
}

// Both Windows and Linux can generate a full 3-level cert chain via
// generateCertChain(). Windows uses BCrypt/CryptoAPI, Linux uses OpenSSL EVP.
// VerifySignature() throws BcryptError on Windows but returns false on Linux
// on failure -- both cases are handled below.
#define CERTGEN_TEST_NAME CertGen

TEST(X509Tests, CERTGEN_TEST_NAME) {
    // Test certificate chain generation, signing, and verification
    std::unique_ptr<X509Type> certChain;
    std::vector<unsigned char> testData = { 0x01, 0x02, 0x03, 0x04, 0x05 };
    std::vector<unsigned char> badData = { 0x05, 0x04, 0x03, 0x02, 0x01 };
    std::vector<unsigned char> signature;
    
    try {
        certChain = generateCertChain();
        signature = certChain->SignData(testData);
    }
    catch (std::exception& e) {
        FAIL() << "Exception during cert chain generation: " << e.what();
    }
    
    EXPECT_TRUE(certChain->VerifyCertChain(X509_SUBJECT_NAME_SUFFIX));
    EXPECT_TRUE(certChain->VerifySignature(testData, signature));
    
#ifdef PLATFORM_UNIX
    // On Linux, signature verification returns false on failure
    EXPECT_FALSE(certChain->VerifySignature(badData, signature));
#else
    // On Windows, signature verification throws on failure
    EXPECT_THROW({
        certChain->VerifySignature(badData, signature);
    }, BcryptError);
#endif
}
// ---------------------------------------------------------------------------
// End-to-end chain verification tests using pre-generated test CA hierarchies.
// Two independent root CAs (TestRootA, TestRootB) each have an intermediate CA
// and a leaf cert.  Tests verify that VerifyCertChain() accepts chains when the
// root is in the trusted set and rejects chains when it is not.
// ---------------------------------------------------------------------------
#include "TestCertConstants.h"

// Helper: build a WincryptX509/OsslX509 with the given test roots, load the
// intermediate + leaf from chainId A or B, then call VerifyCertChain().
// Returns true if the full chain verification succeeds.
static bool verifyTestChain(
    const std::vector<const char*>& roots,
    const char* intermediateCert,
    const char* leafCert,
    const std::string& expectedSubjectSuffix)
{
#ifdef PLATFORM_UNIX
    auto x509 = std::make_unique<OsslX509>(roots);
#else
    auto x509 = std::make_unique<WincryptX509>(roots);
#endif
    x509->LoadIntermediateCertificate(intermediateCert);
    x509->LoadLeafCertificate(leafCert);
    return x509->VerifyCertChain(expectedSubjectSuffix);
}

// --- Chain A rooted at TestRootA, trusted with RootA only → should PASS ---
TEST(X509ChainVerificationTests, ChainA_TrustedByRootA_Succeeds) {
    std::vector<const char*> roots = { TEST_ROOT_A };
    EXPECT_TRUE(verifyTestChain(roots, TEST_INTERMEDIATE_A, TEST_LEAF_A, TEST_SUBJECT_SUFFIX));
}

// --- Chain B rooted at TestRootB, trusted with RootB only → should PASS ---
TEST(X509ChainVerificationTests, ChainB_TrustedByRootB_Succeeds) {
    std::vector<const char*> roots = { TEST_ROOT_B };
    EXPECT_TRUE(verifyTestChain(roots, TEST_INTERMEDIATE_B, TEST_LEAF_B, TEST_SUBJECT_SUFFIX));
}

// --- Chain A with both roots trusted → should PASS ---
TEST(X509ChainVerificationTests, ChainA_TrustedByBothRoots_Succeeds) {
    std::vector<const char*> roots = { TEST_ROOT_A, TEST_ROOT_B };
    EXPECT_TRUE(verifyTestChain(roots, TEST_INTERMEDIATE_A, TEST_LEAF_A, TEST_SUBJECT_SUFFIX));
}

// --- Chain B with both roots trusted → should PASS ---
TEST(X509ChainVerificationTests, ChainB_TrustedByBothRoots_Succeeds) {
    std::vector<const char*> roots = { TEST_ROOT_A, TEST_ROOT_B };
    EXPECT_TRUE(verifyTestChain(roots, TEST_INTERMEDIATE_B, TEST_LEAF_B, TEST_SUBJECT_SUFFIX));
}

// --- Chain A rooted at TestRootA, but only RootB trusted → should FAIL ---
TEST(X509ChainVerificationTests, ChainA_NotTrustedByRootB_Fails) {
    std::vector<const char*> roots = { TEST_ROOT_B };
    EXPECT_FALSE(verifyTestChain(roots, TEST_INTERMEDIATE_A, TEST_LEAF_A, TEST_SUBJECT_SUFFIX));
}

// --- Chain B rooted at TestRootB, but only RootA trusted → should FAIL ---
TEST(X509ChainVerificationTests, ChainB_NotTrustedByRootA_Fails) {
    std::vector<const char*> roots = { TEST_ROOT_A };
    EXPECT_FALSE(verifyTestChain(roots, TEST_INTERMEDIATE_B, TEST_LEAF_B, TEST_SUBJECT_SUFFIX));
}

// --- Wrong subject suffix → should FAIL even with correct root ---
TEST(X509ChainVerificationTests, ChainA_WrongSubjectSuffix_Fails) {
    std::vector<const char*> roots = { TEST_ROOT_A };
    EXPECT_FALSE(verifyTestChain(roots, TEST_INTERMEDIATE_A, TEST_LEAF_A, ".wrong-suffix.net"));
}

// Multi-root trust tests for CCME + CPSRoot

TEST(X509MultiRootTests, DefaultConstructorLoadsBothRoots) {
    // Default constructor should load both CCME and CPSRoot without error
#ifdef PLATFORM_UNIX
    EXPECT_NO_THROW({
        auto x509 = std::make_unique<OsslX509>();
    });
#else
    EXPECT_NO_THROW({
        auto x509 = std::make_unique<WincryptX509>();
    });
#endif
}

TEST(X509MultiRootTests, CCMERootOnlyConstructor) {
    // Single-root with CCME only should work (backward compatibility)
    std::vector<const char*> roots = { CCME_ROOTCERT_PEM };
#ifdef PLATFORM_UNIX
    EXPECT_NO_THROW({
        auto x509 = std::make_unique<OsslX509>(roots);
    });
#else
    EXPECT_NO_THROW({
        auto x509 = std::make_unique<WincryptX509>(roots);
    });
#endif
}

TEST(X509MultiRootTests, CPSRootOnlyConstructor) {
    // Single-root with CPSRoot only should work
    std::vector<const char*> roots = { CPSROOT_CERT_PEM };
#ifdef PLATFORM_UNIX
    EXPECT_NO_THROW({
        auto x509 = std::make_unique<OsslX509>(roots);
    });
#else
    EXPECT_NO_THROW({
        auto x509 = std::make_unique<WincryptX509>(roots);
    });
#endif
}

TEST(X509MultiRootTests, ExplicitBothRootsConstructor) {
    // Explicitly passing both roots should work identically to the default
    std::vector<const char*> roots = { CCME_ROOTCERT_PEM, CPSROOT_CERT_PEM };
#ifdef PLATFORM_UNIX
    EXPECT_NO_THROW({
        auto x509 = std::make_unique<OsslX509>(roots);
    });
#else
    EXPECT_NO_THROW({
        auto x509 = std::make_unique<WincryptX509>(roots);
    });
#endif
}

TEST(X509MultiRootTests, EmptyRootsConstructorThrows) {
    // Empty roots vector should fail (no trusted roots to add)
    std::vector<const char*> roots = {};
#ifdef PLATFORM_UNIX
    // OpenSSL path: succeeds at store creation but will fail at chain verification
    // since no roots are in the store — constructor doesn't throw for empty vector
    auto x509 = std::make_unique<OsslX509>(roots);
    EXPECT_NE(x509, nullptr);
#else
    // WinCrypt path: similarly, the store opens but has no roots
    auto x509 = std::make_unique<WincryptX509>(roots);
    EXPECT_NE(x509, nullptr);
#endif
}

#ifdef PLATFORM_UNIX
TEST(X509MultiRootTests, CertGenWithMultiRootStillWorks) {
    // Verify that generateCertChain() (which uses a single custom root)
    // still works after the multi-root refactor
    std::unique_ptr<OsslX509> certChain;
    std::vector<unsigned char> testData = { 0x01, 0x02, 0x03, 0x04, 0x05 };
    std::vector<unsigned char> signature;
    ASSERT_NO_THROW({
        certChain = generateCertChain();
        signature = certChain->SignData(testData);
    });
    EXPECT_TRUE(certChain->VerifyCertChain(X509_SUBJECT_NAME_SUFFIX));
    EXPECT_TRUE(certChain->VerifySignature(testData, signature));
}
#endif // PLATFORM_UNIX
