// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
// #include "X509.h"
#include "OsslX509.h"
#include "OsslError.h"
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdio.h>
#include "../JsonWebToken.h"
#include <iostream>
#include <vector>
#include <string.h>
#include <memory>
#include "../LibraryLogger.h"
#include "../ReturnCodes.h"
#include "../DebugInfo.h"

#include <openssl/conf.h>
#include <openssl/x509v3.h>

using namespace SecretsLogger;

#define MY_ENCODING_TYPE (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)
#define TEMPBUF_SIZE 1024
#define SELFSIGNEDCERTNAME L"CN=SelfSignedCert"
#define KEY_CONTAINER_NAME L"SelfSignedCertKeyContainer"
#define DEBUG_SEPARATOR ", "

std::string printBIO(BIO* bio) {
    char buffer[256];
    int len;
    std::ostringstream ss;
    while ((len = BIO_read(bio, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[len] = '\0';
        ss << buffer;
    }
    BIO_reset(bio);
    return ss.str();
}

// Format certificate subject and issuer details
std::string printCertInfo(X509* cert, const std::string& label) {
    std::ostringstream ss;
    X509_NAME* subject = X509_get_subject_name(cert);
    X509_NAME* issuer = X509_get_issuer_name(cert);
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int n;
    if (X509_digest(cert, EVP_sha1(), md, &n)) {
        ss << "Thumbprint (SHA1): " << formatHexBuffer(md, n) << DEBUG_SEPARATOR;
    }
    
    char* subjectStr = X509_NAME_oneline(subject, nullptr, 0);
    char* issuerStr = X509_NAME_oneline(issuer, nullptr, 0);
    ss << label << " Certificate Details: ";
    ss << "Subject: " << subjectStr << DEBUG_SEPARATOR;
    ss << "Issuer:  " << issuerStr << DEBUG_SEPARATOR;
    // Format validity period
    ASN1_TIME* not_before = X509_get_notBefore(cert);
    ASN1_TIME* not_after = X509_get_notAfter(cert);
    BIO* bio = BIO_new(BIO_s_mem());
    ss << "Valid from: ";
    ASN1_TIME_print(bio, not_before);
    ss << printBIO(bio) << DEBUG_SEPARATOR;
    ss << "Valid until: ";
    ASN1_TIME_print(bio, not_after);
    ss << printBIO(bio) << DEBUG_SEPARATOR;
    BIO_free(bio);
    OPENSSL_free(subjectStr);
    OPENSSL_free(issuerStr);
    return ss.str();
}

// Generate a new RSA key pair
std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> generateKey(int bits = 2048) {
   EVP_PKEY* pkey = EVP_PKEY_new();
   EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
   if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_free(pkey);
        throw OsslError(ERR_get_error(), "Failed to initialize key generation");
   }
   if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw OsslError(ERR_get_error(), "Failed to set key size");
   }
   if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw OsslError(ERR_get_error(), "Failed to generate key pair");
   }
   EVP_PKEY_CTX_free(ctx);
   return std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>(pkey, &EVP_PKEY_free);
}

// Create a certificate signing request (CSR)
std::unique_ptr<X509_REQ, decltype(&X509_REQ_free)> generateCSR(EVP_PKEY* pkey, const std::string& commonName) {
   std::unique_ptr<X509_REQ, decltype(&X509_REQ_free)> req(X509_REQ_new(), &X509_REQ_free);
   std::unique_ptr<X509_NAME, decltype(&X509_NAME_free)> name(X509_NAME_new(), &X509_NAME_free);
   // Set the subject name fields
    if (!X509_NAME_add_entry_by_txt(name.get(), "C", MBSTRING_ASC,
       (const unsigned char*)"US", -1, -1, 0)) {
         throw OsslError(ERR_get_error(), "Failed to set country");
    }
    if (!X509_NAME_add_entry_by_txt(name.get(), "ST", MBSTRING_ASC,
        (const unsigned char*)"State", -1, -1, 0)) {
        throw OsslError(ERR_get_error(), "Failed to set state");
    }
    if (!X509_NAME_add_entry_by_txt(name.get(), "O", MBSTRING_ASC,
        (const unsigned char*)"Organization", -1, -1, 0)) {
        throw OsslError(ERR_get_error(), "Failed to set organization");
    }
    if (!X509_NAME_add_entry_by_txt(name.get(), "CN", MBSTRING_ASC,
        (const unsigned char*)commonName.c_str(), -1, -1, 0)) {
        throw OsslError(ERR_get_error(), "Failed to set common name");
    }
    if (!X509_REQ_set_subject_name(req.get(), name.get()) 
        || !X509_REQ_set_pubkey(req.get(), pkey)) {
        throw OsslError(ERR_get_error(), "Failed to set subject name or public key");
    }
    if (!X509_REQ_sign(req.get(), pkey, EVP_sha256())) {
        throw OsslError(ERR_get_error(), "Failed to sign CSR");
    }
    return req;
}

// Add certificate extensions
void addExtensions(X509* cert, X509* issuer, int is_ca, int pathlen = -1) {
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, issuer, cert, NULL, NULL, 0);

    // Add Basic Constraints
    std::string bc;
    if (is_ca) {
        bc = "critical,CA:TRUE";
        if (pathlen >= 0) {
            bc += ",pathlen:" + std::to_string(pathlen);
        }
    } else {
        bc = "critical,CA:FALSE";
    }
    std::unique_ptr<X509_EXTENSION, decltype(&X509_EXTENSION_free)> ex(
        X509V3_EXT_conf_nid(NULL, &ctx, NID_basic_constraints, bc.c_str()), &X509_EXTENSION_free);
    if (!ex || X509_add_ext(cert, ex.get(), -1) != 1) {
        throw OsslError(ERR_get_error(), "Failed to add Basic Constraints extension");
    }

    std::string ku = is_ca ? "critical,keyCertSign,cRLSign" : "critical,digitalSignature,keyEncipherment";
    ex.reset(X509V3_EXT_conf_nid(NULL, &ctx, NID_key_usage, ku.c_str()));
    if (!ex || X509_add_ext(cert, ex.get(), -1) != 1) {
        throw OsslError(ERR_get_error(), "Failed to add Key Usage extension");
    }

    ex.reset(X509V3_EXT_conf_nid(NULL, &ctx, NID_subject_key_identifier, "hash"));
    if (!ex || X509_add_ext(cert, ex.get(), -1) != 1) {
        throw OsslError(ERR_get_error(), "Failed to add Subject Key Identifier extension");
    }

    if (issuer != NULL && issuer != cert) {
        ex.reset(X509V3_EXT_conf_nid(NULL, &ctx, NID_authority_key_identifier, "keyid:always"));
        if (!ex || X509_add_ext(cert, ex.get(), -1) != 1) {
            throw OsslError(ERR_get_error(), "Failed to add Authority Key Identifier extension");
        }
    }
}

// Create and sign a certificate
std::unique_ptr<X509, decltype(&X509_free)> signCertificate(X509_REQ* req, EVP_PKEY* issuerKey, X509* issuerCert,
                     long serial, int days, int is_ca, int pathlen = -1) {
   std::unique_ptr<X509, decltype(&X509_free)> cert(X509_new(), &X509_free);
   // Set version to X509v3
    if (X509_set_version(cert.get(), 2) != 1) {
        throw OsslError(ERR_get_error(), "Failed to set certificate version");
    }
    // Set serial number
    if (ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), serial) != 1) {
        throw OsslError(ERR_get_error(), "Failed to set serial number");
    }
    // Set validity period
    if (X509_gmtime_adj(X509_get_notBefore(cert.get()), 0) == NULL) {
        throw OsslError(ERR_get_error(), "Failed to set notBefore time");
    }
    if (X509_gmtime_adj(X509_get_notAfter(cert.get()), (long)60*60*24*days) == NULL) {
        throw OsslError(ERR_get_error(), "Failed to set notAfter time");
    }
    // Set subject from CSR
    if (X509_set_subject_name(cert.get(), X509_REQ_get_subject_name(req)) != 1) {
        throw OsslError(ERR_get_error(), "Failed to set subject name");
    }
    // Set issuer
    if (issuerCert == NULL) {
        // Self-signed: issuer = subject
        if (X509_set_issuer_name(cert.get(), X509_REQ_get_subject_name(req)) != 1) {
            throw OsslError(ERR_get_error(), "Failed to set issuer name for self-signed certificate");
        }
    } else {
        if (X509_set_issuer_name(cert.get(), X509_get_subject_name(issuerCert)) != 1) {
            throw OsslError(ERR_get_error(), "Failed to set issuer name");
        }
    }
    // Set public key from CSR
    EVP_PKEY* pubkey = X509_REQ_get0_pubkey(req);
    if (pubkey == NULL || X509_set_pubkey(cert.get(), pubkey) != 1) {
        throw OsslError(ERR_get_error(), "Failed to set public key");
    }
    // Add extensions
    try {
        addExtensions(cert.get(), (issuerCert == NULL) ? cert.get() : issuerCert, is_ca, pathlen);
    } catch (const OsslError& e) {
        throw;
    }
    // Sign the certificate
    if (X509_sign(cert.get(), issuerKey, EVP_sha256()) == 0) {
        throw OsslError(ERR_get_error(), "Failed to sign certificate");
    }
   return cert;
}
 
std::string getDerEncodedCertificate(X509* cert) {
    int len = i2d_X509(cert, nullptr);
    if (len < 0) {
        throw OsslError(ERR_get_error(), "Failed to get DER encoded length");
    }

    std::vector<unsigned char> der(len);
    unsigned char* p = der.data();
    len = i2d_X509(cert, &p);
    if (len < 0) {
        throw OsslError(ERR_get_error(), "Failed to encode certificate to DER");
    }

    return encoders::base64_encode(der);
}

// Create a self-signed certificate
std::unique_ptr<OsslX509> generateCertChain() {
    // Generate root CA
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> rootKey = generateKey();
    std::unique_ptr<X509_REQ, decltype(&X509_REQ_free)> rootReq = generateCSR(rootKey.get(), "Root CA");
    std::unique_ptr<X509, decltype(&X509_free)> rootCert = signCertificate(rootReq.get(), rootKey.get(), NULL, 1, 3650, 1, 1);
    LIBSECRETS_LOG(
            LogLevel::Info,
            "Certificate chain verification.",
            "Certificate chain verification with cert %s",
            printCertInfo(rootCert.get(), "Root").c_str());
    // Generate intermediate CA
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> intermediateKey = generateKey();
    std::unique_ptr<X509_REQ, decltype(&X509_REQ_free)> intermediateReq = generateCSR(intermediateKey.get(), "Intermediate CA");
    std::unique_ptr<X509, decltype(&X509_free)> intermediateCert = signCertificate(intermediateReq.get(), rootKey.get(), rootCert.get(), 2, 1825, 1, 0);
    LIBSECRETS_LOG(
            LogLevel::Info,
            "Certificate chain verification.",
            "Certificate chain verification with cert %s",
            printCertInfo(intermediateCert.get(), "Inter CA").c_str());
    // Generate leaf certificate
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> leafKey = generateKey();
    std::unique_ptr<X509_REQ, decltype(&X509_REQ_free)> leafReq = generateCSR(leafKey.get(), "example.com");
    std::unique_ptr<X509, decltype(&X509_free)> leafCert = signCertificate(leafReq.get(), intermediateKey.get(), intermediateCert.get(), 3, 365, 0);
    LIBSECRETS_LOG(
            LogLevel::Info,
            "Certificate chain verification.",
            "Certificate chain verification with cert %s",
            printCertInfo(leafCert.get(), "Leaf").c_str());
    

    std::unique_ptr<OsslX509> retCertChain;
    try{
        retCertChain = std::make_unique<OsslX509>((const char *)getDerEncodedCertificate(rootCert.get()).c_str());
        retCertChain->LoadIntermediateCertificate((const char *)getDerEncodedCertificate(intermediateCert.get()).c_str());
        retCertChain->LoadLeafCertificate((const char *)getDerEncodedCertificate(leafCert.get()).c_str());
        retCertChain->SetLeafKey(leafKey.release());
    } catch (const OsslError& e) {
        throw e;
    }
    return retCertChain;
}

OsslX509::OsslX509(const char *rootCert)
    : leaf_cert(nullptr, &X509_free), intermediate_certs(sk_X509_new_null()), leaf_key(nullptr, &EVP_PKEY_free)
{
    // Linux-specific code for loading the root certificate using OpenSSL
    this->store = X509_STORE_new();
    if (!this->store) {
        throw std::runtime_error("Failed to create X509_STORE");
    }

    if (!intermediate_certs) {
        throw std::runtime_error("Failed to create stack of X509 certificates");
    }

    auto root_cert = this->LoadCertificate(encoders::base64_decode(rootCert));
    if (X509_STORE_add_cert(this->store, root_cert.get()) != 1) {
        throw std::runtime_error("Failed to add root certificate to store");
    }
    LIBSECRETS_LOG(
            LogLevel::Info,
            "Certificate chain verification.",
            "Certificate chain verification with cert %s",
            printCertInfo(root_cert.get(), "Root").c_str());

    X509_STORE_set_flags(this->store, X509_V_FLAG_X509_STRICT);
}

OsslX509::~OsslX509()
{
    if (this->store != NULL) {
        X509_STORE_free(this->store);
    }
    if (this->intermediate_certs != NULL) {
        sk_X509_pop_free(this->intermediate_certs, &X509_free);
    }
    if (this->leaf_cert != NULL) {
        this->leaf_cert.reset();
    }
}

void OsslX509::SetLeafKey(EVP_PKEY* key)
{
    this->leaf_key.reset(key);
}

std::vector<unsigned char> OsslX509::SignData(const std::vector<unsigned char>& data) {
    std::vector<unsigned char> signature;
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> mdctx(EVP_MD_CTX_new(), &EVP_MD_CTX_free);
    if (!mdctx) {
        throw OsslError(ERR_get_error(), "Failed to create EVP_MD_CTX");
    }

    if (EVP_DigestSignInit(mdctx.get(), nullptr, EVP_sha256(), nullptr, this->leaf_key.get()) != 1) {
        throw OsslError(ERR_get_error(), "Failed to initialize DigestSign");
    }

    if (EVP_DigestSignUpdate(mdctx.get(), data.data(), data.size()) != 1) {
        throw OsslError(ERR_get_error(), "Failed to update DigestSign");
    }

    size_t siglen = 0;
    if (EVP_DigestSignFinal(mdctx.get(), nullptr, &siglen) != 1) {
        throw OsslError(ERR_get_error(), "Failed to finalize DigestSign (get length)");
    }

    signature.resize(siglen);
    if (EVP_DigestSignFinal(mdctx.get(), signature.data(), &siglen) != 1) {
        throw OsslError(ERR_get_error(), "Failed to finalize DigestSign");
    }

    return signature;
}

bool OsslX509::VerifySignature(std::vector<unsigned char> const&signedData, std::vector<unsigned char> const&signature)
{
// Linux-specific code for verifying a signature using OpenSSL

    EVP_PKEY* pubkey = X509_get_pubkey(this->leaf_cert.get());
    if (!pubkey) {
        throw OsslError(ERR_get_error(), "Failed to get public key from leaf certificate");
    }

    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pubkey_ptr(pubkey, &EVP_PKEY_free);
    auto ctx = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!ctx) {
        throw OsslError(ERR_get_error(), "Failed to create EVP_MD_CTX");
    }

    if (EVP_DigestVerifyInit(ctx.get(), nullptr, EVP_sha256(), nullptr, pubkey) != 1) {
        throw OsslError(ERR_get_error(), "Failed to initialize digest verify");
    }

    if (EVP_DigestVerifyUpdate(ctx.get(), signedData.data(), signedData.size()) != 1) {
        throw OsslError(ERR_get_error(), "Failed to update digest verify");
    }

    int result = EVP_DigestVerifyFinal(ctx.get(), signature.data(), signature.size());

    if (result == 1) {
        LIBSECRETS_LOG(
            LogLevel::Debug,
            "Signature verified successfully.",
            ""
        );
        return true;
    } else {
        LIBSECRETS_LOG(
            LogLevel::Debug,
            "Signature failed verification.",
            ""
        );
        return false;
    }
}

std::unique_ptr<X509, decltype(&X509_free)> OsslX509::LoadCertificate(const std::vector<unsigned char>& cert_buffer)
{
    const unsigned char* p = cert_buffer.data();
    X509* cert = d2i_X509(nullptr, &p, cert_buffer.size());
    if (!cert) {
        throw std::runtime_error("Failed to load certificate from buffer");
    }
    return std::unique_ptr<X509, decltype(&X509_free)>(cert, &X509_free);
}

void OsslX509::LoadLeafCertificate(const char* cert)
{
    auto leaf_cert_buffer = encoders::base64_decode(cert);
    this->leaf_cert = this->LoadCertificate(leaf_cert_buffer);
    LIBSECRETS_LOG(
            LogLevel::Info,
            "Certificate chain verification.",
            "Certificate chain verification with cert %s",
            printCertInfo(leaf_cert.get(), "Leaf").c_str());
}

void OsslX509::LoadIntermediateCertificate(const char* cert)
{
    auto inter_cert = this->LoadCertificate(encoders::base64_decode(cert));
    LIBSECRETS_LOG(
            LogLevel::Info,
            "Certificate chain verification.",
            "Certificate chain verification with cert %s",
            printCertInfo(inter_cert.get(), "Intermediate CA").c_str());
    X509* inter_cert_ptr = inter_cert.release();
    if (!sk_X509_push(this->intermediate_certs, inter_cert_ptr)) {
        throw std::runtime_error("Failed to push intermediate certificate onto stack");
    }
}

bool OsslX509::VerifyCertChain()
{
    bool ret = false;
    auto ctx = std::unique_ptr<X509_STORE_CTX, decltype(&X509_STORE_CTX_free)>(X509_STORE_CTX_new(), &X509_STORE_CTX_free);
    if (!ctx) {
        throw std::runtime_error("Failed to create X509_STORE_CTX");
    }

    if (X509_STORE_CTX_init(ctx.get(), this->store, this->leaf_cert.get(), this->intermediate_certs) != 1) {
        throw std::runtime_error("Failed to initialize X509_STORE_CTX");
    }

    X509_STORE_CTX_set_flags(ctx.get(), X509_V_FLAG_CHECK_SS_SIGNATURE);

    int result = X509_verify_cert(ctx.get());
    if (result == 1) {
        LIBSECRETS_LOG(
            LogLevel::Debug,
            "Certificate chain verified successfully.",
            "");
        ret = true;
    } else {
        int error = X509_STORE_CTX_get_error(ctx.get());
        int depth = X509_STORE_CTX_get_error_depth(ctx.get());
        X509* cert = X509_STORE_CTX_get_current_cert(ctx.get());
        std::string certInfo = printCertInfo(cert, "Failed");
        LIBSECRETS_LOG(
            LogLevel::Error,
            "Certificate chain failed to verify.",
            "Certificate chain verification failed with error code %s at depth %d for certificate %s",
            X509_verify_cert_error_string(error),
            depth, certInfo.c_str());
        ret = false;
    }
    return ret;
}