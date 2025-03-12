#pragma once
#include "Windows.h"
#include "wincrypt.h"
#include <vector>
#include <string>
#include "..\BaseX509.h"

std::string generate_root_cert();

class WincryptX509: public BaseX509<PCCERT_CONTEXT>
{
public:
    WincryptX509(const char *rootCert = ROOTCERT);
    ~WincryptX509();
    PCCERT_CONTEXT LoadCertificate(const std::vector<unsigned char>& cert);
    void LoadLeafCertificate(const char* cert);
    void LoadIntermediateCertificate(const char* cert);
    bool VerifyCertChain();
    bool VerifySignature(std::vector<unsigned char> const&signedData, std::vector<unsigned char> const&signature);

private:
#ifndef PLATFORM_UNIX
    PCCERT_CONTEXT pLeafCertContext;
    BCRYPT_KEY_HANDLE hKey;
    HCERTSTORE hStore;
    CERT_CHAIN_PARA chainPara;
    PCCERT_CHAIN_CONTEXT chainContext;
#else
    X509_STORE* store;
    std::vector<unsigned char> leaf_cert_buffer;
    std::unique_ptr<X509, decltype(&X509_free)> leaf_cert;
#endif
};