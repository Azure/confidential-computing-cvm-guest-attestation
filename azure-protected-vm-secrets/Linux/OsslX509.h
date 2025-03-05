#pragma once
#include <openssl/x509.h>
#include <vector>
#include <string>
#include <memory>
#include "../BaseX509.h"

class OsslX509: public BaseX509<std::unique_ptr<X509, decltype(&X509_free)>>
{
public:
    OsslX509(const char *rootCert = ROOTCERT);
    ~OsslX509();
    std::unique_ptr<X509, decltype(&X509_free)> LoadCertificate(const std::vector<unsigned char>& cert_buffer);
    void LoadLeafCertificate(const char* cert);
    void LoadIntermediateCertificate(const char* cert);
    bool VerifyCertChain();
    bool VerifySignature(std::vector<unsigned char> const&signedData, std::vector<unsigned char> const&signature);
    std::vector<unsigned char> SignData(const std::vector<unsigned char>& data);
    void SetLeafKey(EVP_PKEY* key);

private:
    X509_STORE* store;
    STACK_OF(X509) *intermediate_certs;
    std::unique_ptr<X509, decltype(&X509_free)> leaf_cert;
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> leaf_key;
};

std::unique_ptr<OsslX509> generateCertChain();