// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once
#include "Windows.h"
#include "wincrypt.h"
#include "bcrypt.h"
#include <vector>
#include <string>
#include <memory>
#include "..\BaseX509.h"

class WincryptX509: public BaseX509<PCCERT_CONTEXT>
{
public:
    WincryptX509(const char *rootCert = ROOTCERT);
    WincryptX509(const std::vector<const char*>& rootCerts);
    ~WincryptX509();
    PCCERT_CONTEXT LoadCertificate(const std::vector<unsigned char>& cert);
    void LoadLeafCertificate(const char* cert);
    void LoadIntermediateCertificate(const char* cert);
    bool VerifyCertChain(const std::string& expectedSubjectSuffix);
    bool VerifySignature(std::vector<unsigned char> const&signedData, std::vector<unsigned char> const&signature);
    
    // Methods for certificate generation and signing (for testing)
    void SetLeafKey(BCRYPT_KEY_HANDLE key);
    std::vector<unsigned char> SignData(const std::vector<unsigned char>& data);

protected:
    // Subject/Signer verification methods
    std::string GetSubjectName() const;
    std::string GetCommonName() const;
    bool VerifySubjectSuffix(const std::string& expectedSuffix) const;

private:
    bool VerifyChainTerminatesAtRoot();
    std::string ExtractFieldFromDN(const std::string& dn, const std::string& field) const;
    PCCERT_CONTEXT pLeafCertContext;
    std::vector<PCCERT_CONTEXT> rootCertContexts;
    BCRYPT_KEY_HANDLE hKey;
    BCRYPT_KEY_HANDLE leafPrivateKey;  // Private key for signing
    HCERTSTORE hStore;
    CERT_CHAIN_PARA chainPara;
    PCCERT_CHAIN_CONTEXT chainContext;
    std::vector<unsigned char> leaf_cert_buffer;
};

// Generate a complete certificate chain for testing (Root -> Intermediate -> Leaf)
std::unique_ptr<WincryptX509> generateCertChain();