//#include "ECDiffieHellman.h"
#include "../LibraryLogger.h"
#include "OsslECDiffieHellman.h"
#include "OsslError.h"
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <stdexcept>
#include <iostream>
#include <vector>

using namespace SecretsLogger;

// ASN.1 constants. The unknown ASN.1 bytes are referenced in other
// implementations of ECDiffieHellman, but the definitions could not
// be found in the Windows API documentation.
#define EC_UNCOMPRESSED_BLOB 0x04
#define EC_UNKNOWN_ASN_BYTE  0x06
#define EC_UNKNOWN_ASN_BYTE2 0x07

#define EC_PUBLIC_NUM_COMPONENTS  2
#define EC_PRIVATE_NUM_COMPONENTS 3

void handleOpenSSLError() {
    unsigned long errCode;
    while ((errCode = ERR_get_error())) {
        char *err = ERR_error_string(errCode, NULL);
        std::cerr << "OpenSSL Error: " << err << std::endl;
    }
}

OsslECDiffieHellman::OsslECDiffieHellman() 
    : keyPair(nullptr, &EVP_PKEY_free), pctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL), &EVP_PKEY_CTX_free)
{
    if (!pctx) {
        throw std::runtime_error("Failed to create ECDH context");
    }
}

OsslECDiffieHellman::~OsslECDiffieHellman()
{
}

void OsslECDiffieHellman::GenerateKeyPair() {
    if (EVP_PKEY_paramgen_init(pctx.get()) <= 0) {
        throw OsslError(ERR_get_error(), "Failed to initialize ECDH parameters");
    }
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx.get(), NID_X9_62_prime256v1) <= 0) {
        throw OsslError(ERR_get_error(), "Failed to set ECDH curve");
    }
        // Generate the parameters
    EVP_PKEY *params = nullptr;
    if (EVP_PKEY_paramgen(pctx.get(), &params) <= 0) {
        throw OsslError(ERR_get_error(), "Failed to generate parameters");
    }
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> params_ptr(params, &EVP_PKEY_free);
    // Create a context for the key generation
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> kctx(EVP_PKEY_CTX_new(params_ptr.get(), NULL), &EVP_PKEY_CTX_free);
    if (!kctx) {
        throw OsslError(ERR_get_error(), "Failed to create context for key generation");
    }
    // Initialize the context for key generation
    if (EVP_PKEY_keygen_init(kctx.get()) <= 0) {
        throw OsslError(ERR_get_error(), "Failed to initialize key generation");
    }
    // Generate the key pair
    EVP_PKEY* keyPairRef = keyPair.get();
    if (EVP_PKEY_keygen(kctx.get(), &keyPairRef) <= 0) {
        throw OsslError(ERR_get_error(), "Failed to generate key pair");
    }
    keyPair.reset(keyPairRef);
}

void OsslECDiffieHellman::ImportPkcs8PrivateKey(std::vector<unsigned char> const&derPrivateKey)
{
    const unsigned char* keyData = derPrivateKey.data();
    EVP_PKEY* privateKey = d2i_PrivateKey(EVP_PKEY_EC, NULL, &keyData, derPrivateKey.size());
    if (!privateKey) {
        throw OsslError(ERR_get_error(), "Failed to import PKCS#8 private key");
    }
    keyPair.reset(privateKey);
}

void OsslECDiffieHellman::ImportSubjectPublicKeyInfo(std::vector<unsigned char> const&derPublicKey) {
    const unsigned char* keyData = derPublicKey.data();
    EVP_PKEY* publicKey = d2i_PUBKEY(NULL, &keyData, derPublicKey.size());
    if (!publicKey) {
        throw OsslError(ERR_get_error(), "Failed to import SubjectPublicKeyInfo");
    }
    keyPair.reset(publicKey);
}

std::vector<unsigned char> OsslECDiffieHellman::ExportPkcs8PrivateKey() const
{
    unsigned char* keyData = NULL;
    int len = i2d_PrivateKey(keyPair.get(), &keyData);
    if (len <= 0) {
        throw OsslError(ERR_get_error(), "Failed to export PKCS#8 private key");
    }
    std::vector<unsigned char> privateKey(keyData, keyData + len);
    OPENSSL_free(keyData);
    return privateKey;
}

std::vector<unsigned char> OsslECDiffieHellman::ExportSubjectPublicKeyInfo() const
{
    unsigned char* keyData = NULL;
    int len = i2d_PUBKEY(keyPair.get(), &keyData);
    if (len <= 0) {
        throw OsslError(ERR_get_error(), "Failed to export SubjectPublicKeyInfo");
    }
    std::vector<unsigned char> publicKey(keyData, keyData + len);
    OPENSSL_free(keyData);
    return publicKey;
}

std::vector<unsigned char> OsslECDiffieHellman::DeriveSecret(ECDiffieHellman &key2)
{
    const OsslECDiffieHellman& osslOtherParty = static_cast<const OsslECDiffieHellman&>(key2);
    EVP_PKEY* peerKey = osslOtherParty.GetPublicKeyHandle();

    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> derivationCtx(EVP_PKEY_CTX_new(keyPair.get(), NULL), &EVP_PKEY_CTX_free);
    if (!derivationCtx) {
        throw OsslError(ERR_get_error(), "Failed to create derivation context");
    }

    if (EVP_PKEY_derive_init(derivationCtx.get()) <= 0) {
        throw OsslError(ERR_get_error(), "Failed to initialize derivation context");
    }

    if (EVP_PKEY_derive_set_peer(derivationCtx.get(), peerKey) <= 0) {
        throw OsslError(ERR_get_error(), "Failed to set peer public key");
    }

    size_t secretLen;
    if (EVP_PKEY_derive(derivationCtx.get(), NULL, &secretLen) <= 0) {
        throw OsslError(ERR_get_error(), "Failed to determine secret length");
    }

    std::vector<unsigned char> sharedSecret(secretLen);
    if (EVP_PKEY_derive(derivationCtx.get(), sharedSecret.data(), &secretLen) <= 0) {
        throw OsslError(ERR_get_error(), "Failed to derive shared secret");
    }
    return sharedSecret;
}

EVP_PKEY* OsslECDiffieHellman::GetPublicKeyHandle(void) const {
    return this->keyPair.get();
}