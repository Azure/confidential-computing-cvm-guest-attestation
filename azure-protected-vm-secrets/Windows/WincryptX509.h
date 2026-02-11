// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
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
    bool VerifyCertChain(const std::string& expectedSubjectSuffix);
    bool VerifySignature(std::vector<unsigned char> const&signedData, std::vector<unsigned char> const&signature);

protected:
    // Subject/Signer verification methods
    std::string GetSubjectName() const;
    std::string GetCommonName() const;
    bool VerifySubjectSuffix(const std::string& expectedSuffix) const;

private:
    bool VerifyChainTerminatesAtRoot();
    std::string ExtractFieldFromDN(const std::string& dn, const std::string& field) const;
    PCCERT_CONTEXT pLeafCertContext;
    PCCERT_CONTEXT pRootCertContext;
    BCRYPT_KEY_HANDLE hKey;
    HCERTSTORE hStore;
    CERT_CHAIN_PARA chainPara;
    PCCERT_CHAIN_CONTEXT chainContext;
    std::vector<unsigned char> leaf_cert_buffer;
};