// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "..\BaseX509.h"
#include "Windows.h"
#include "wincrypt.h"
#include "bcrypt.h"
#include "ntstatus.h"
#include "..\BcryptError.h"
#include <stdio.h>
#include "..\JsonWebToken.h"
#include <iostream>
#include <vector>
#include <string.h>
#include <algorithm>
#include "..\LibraryLogger.h"
#include "..\ReturnCodes.h"
#include "..\DebugInfo.h"
#include "WincryptX509.h"

using namespace SecretsLogger;

#define MY_ENCODING_TYPE (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)
#define TEMPBUF_SIZE 1024
#define SELFSIGNEDCERTNAME L"CN=SelfSignedCert"
#define KEY_CONTAINER_NAME L"SelfSignedCertKeyContainer"
#define DEBUG_SEPARATOR ", "

// For WinX509CertStore.cpp - Windows equivalent to printCertInfo()
std::string printCertInfo(PCCERT_CONTEXT pCertContext, const std::string& label) {
    std::ostringstream ss;
    
    // 1. Get thumbprint (SHA-256)
    BYTE hashBytes[32] = {0};  // SHA-256 is 32 bytes
    DWORD hashSize = sizeof(hashBytes);
    if (CertGetCertificateContextProperty(pCertContext, CERT_SHA256_HASH_PROP_ID, 
                                         hashBytes, &hashSize)) {
        ss << "Thumbprint (SHA256): " << formatHexBuffer(hashBytes, hashSize) << DEBUG_SEPARATOR;
    }
    
    // 2. Subject name
    char szSubjectName[256] = {0};
    if (CertGetNameStringA(pCertContext, CERT_NAME_RDN_TYPE, 0, nullptr, 
                         szSubjectName, sizeof(szSubjectName))) {
        ss << label << " Certificate Details: ";
        ss << "Subject: " << szSubjectName << DEBUG_SEPARATOR;
    }
    
    // 3. Issuer name
    char szIssuerName[256] = {0};
    if (CertGetNameStringA(pCertContext, CERT_NAME_RDN_TYPE, 
                         CERT_NAME_ISSUER_FLAG, nullptr, szIssuerName, sizeof(szIssuerName))) {
        ss << "Issuer:  " << szIssuerName << DEBUG_SEPARATOR;
    }
    
    // 4. Validity period
    SYSTEMTIME stNotBefore, stNotAfter;
    FileTimeToSystemTime(&pCertContext->pCertInfo->NotBefore, &stNotBefore);
    FileTimeToSystemTime(&pCertContext->pCertInfo->NotAfter, &stNotAfter);
    
    char szNotBefore[64] = {0};
    char szNotAfter[64] = {0};
    sprintf_s(szNotBefore, sizeof(szNotBefore), "%04d-%02d-%02d %02d:%02d:%02d",
             stNotBefore.wYear, stNotBefore.wMonth, stNotBefore.wDay,
             stNotBefore.wHour, stNotBefore.wMinute, stNotBefore.wSecond);
    sprintf_s(szNotAfter, sizeof(szNotAfter), "%04d-%02d-%02d %02d:%02d:%02d",
             stNotAfter.wYear, stNotAfter.wMonth, stNotAfter.wDay,
             stNotAfter.wHour, stNotAfter.wMinute, stNotAfter.wSecond);
    
    ss << "Valid from: " << szNotBefore << DEBUG_SEPARATOR;
    ss << "Valid until: " << szNotAfter << DEBUG_SEPARATOR;
    
    return ss.str();
}

std::string generate_root_cert() {
    std::string encoded_cert;
    HCRYPTPROV hProv;
    BYTE bEncoded[TEMPBUF_SIZE];
    DWORD dwEncoded = TEMPBUF_SIZE;
    PCCERT_CONTEXT pc = NULL;
    DWORD dwError;

    if (!CertStrToName(X509_ASN_ENCODING,
        SELFSIGNEDCERTNAME,
        CERT_X500_NAME_STR,
        NULL,
        bEncoded,
        &dwEncoded,
        NULL)) {
        throw WinCryptError("CertStrToName failed.", GetLastError());
    }

    WCHAR* pszKeyContainerName = (WCHAR *)KEY_CONTAINER_NAME;

    if (!CryptAcquireContext(&hProv, pszKeyContainerName, MS_STRONG_PROV, PROV_RSA_FULL, CRYPT_NEWKEYSET | CRYPT_MACHINE_KEYSET))
    {
        dwError = GetLastError();
        if (dwError == NTE_EXISTS) {
            if (!CryptAcquireContext(&hProv, pszKeyContainerName, MS_STRONG_PROV, PROV_RSA_FULL, CRYPT_MACHINE_KEYSET))
            {
                throw WinCryptError("CryptAcquireContext failed.", GetLastError());
            }
		}
        else {
            throw WinCryptError("CryptAcquireContext failed.", GetLastError());
        }
	}

    HCRYPTKEY hKey = NULL;
    DWORD keyLength = 0x08000000; // upper 16 bits is 2048 which is our requested key length
    if (!CryptGenKey(hProv, AT_SIGNATURE, keyLength | CRYPT_EXPORTABLE, &hKey))
    {
		throw WinCryptError("CryptGenKey failed.", GetLastError());
    }

    CRYPT_KEY_PROV_INFO kpi;
    ZeroMemory(&kpi, sizeof(kpi));
    kpi.pwszContainerName = pszKeyContainerName;
    kpi.pwszProvName = (LPWSTR)MS_STRONG_PROV;
    kpi.dwProvType = PROV_RSA_FULL;
    kpi.dwFlags = CERT_SET_KEY_CONTEXT_PROP_ID | CRYPT_MACHINE_KEYSET;
    kpi.dwKeySpec = AT_SIGNATURE;

    SYSTEMTIME et;
    GetSystemTime(&et);

    // We need to add 5 years to the current date to come up with the expiration time
    // This is the way MSDN recommends
    FILETIME ft;

    if (!SystemTimeToFileTime(&et, &ft))
    {
		throw WinCryptError("SystemTimeToFileTime failed.", GetLastError());
    }

    ULARGE_INTEGER bigInt;
    ZeroMemory(&bigInt, sizeof(bigInt));
    bigInt.HighPart = ft.dwHighDateTime;
    bigInt.LowPart = ft.dwLowDateTime;

    //                 5 years * 365 days * 24 hours * 60 minutes * 60 seconds * 1,000,000,000 nanoseconds / 100 (100-nanoseconds)
    bigInt.QuadPart += 1576800000000000; // 5 years in 100-nanosecond intervals
    ft.dwHighDateTime = bigInt.HighPart;
    ft.dwLowDateTime = bigInt.LowPart;
    if (!FileTimeToSystemTime(&ft, &et))
    {
		throw WinCryptError("FileTimeToSystemTime failed.", GetLastError());
    }

    LPSTR lpEKU[1] = { 0 };
    lpEKU[0] = const_cast<LPSTR> (szOID_PKIX_KP_CODE_SIGNING);
    CERT_ENHKEY_USAGE certEKU;
    certEKU.cUsageIdentifier = 1;
    certEKU.rgpszUsageIdentifier = &lpEKU[0];

    DWORD cbEncodedEKU = 0;
    PBYTE pbEncodedEKU = NULL;
    CERT_NAME_BLOB sib;
    sib.cbData = dwEncoded;
    sib.pbData = bEncoded;


    // encode the key usage definition for use in the cert extension.
    if (!CryptEncodeObjectEx(X509_ASN_ENCODING,
        szOID_ENHANCED_KEY_USAGE,
        &certEKU,
        CRYPT_ENCODE_ALLOC_FLAG,
        NULL,
        &pbEncodedEKU,
        &cbEncodedEKU))
    {
		throw WinCryptError("CryptEncodeObjectEx failed.", GetLastError());
    }

    // place the encoded key usage in the cert extension
    CERT_EXTENSIONS certExts;
    CERT_EXTENSION certExt[1];
    certExt[0].pszObjId = (LPSTR)szOID_ENHANCED_KEY_USAGE;
    certExt[0].fCritical = FALSE;
    certExt[0].Value.cbData = cbEncodedEKU;
    certExt[0].Value.pbData = pbEncodedEKU;

    certExts.cExtension = 1;
    certExts.rgExtension = certExt;

    CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm;
    ZeroMemory(&SignatureAlgorithm, sizeof(SignatureAlgorithm));
    SignatureAlgorithm.pszObjId = (LPSTR)szOID_RSA_SHA256RSA;

    // create the self signed certificate
    pc = CertCreateSelfSignCertificate(hProv, &sib, 0, &kpi, &SignatureAlgorithm, NULL, &et, &certExts);

	BYTE* pbEncodedCert = NULL;
	DWORD cbEncodedCert = 0;

	CertSerializeCertificateStoreElement(pc, 0, NULL, &cbEncodedCert);
    std::vector<unsigned char> cert = std::vector<unsigned char>(pc->pbCertEncoded, pc->pbCertEncoded + pc->cbCertEncoded);
	encoded_cert = encoders::base64_encode(cert);

    if (hKey != NULL)
        CryptDestroyKey(hKey);
	if (pbEncodedEKU != NULL) {
		LocalFree(pbEncodedEKU);
	}
    CertFreeCertificateContext(pc);
    CryptReleaseContext(hProv, 0);
    return encoded_cert;
}

std::vector<unsigned char*> generate_cert_chain() {
	return std::vector<unsigned char*>();
}

WincryptX509::WincryptX509(const std::vector<const char*>& rootCerts)
{
    this->hStore = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, NULL, 0, NULL);
    if (this->hStore == NULL)
    {
		// LibraryError, WinCrypt subclass, certStoreError
        throw WinCryptError("CertOpenStore failed.", GetLastError(),
            ErrorCode::LibraryError_WinCrypt_certStoreError);
    }
    for (const auto& rootCert : rootCerts) {
        PCCERT_CONTEXT pRootCtx = LoadCertificate(encoders::base64_decode(rootCert));
        if (!CertAddCertificateContextToStore(this->hStore, pRootCtx, CERT_STORE_ADD_ALWAYS, NULL)) {
            // LibraryError, WinCrypt subclass, certStoreError
            throw WinCryptError("CertAddCertificateContextToStore - Root Cert - failed.", GetLastError(),
                ErrorCode::LibraryError_WinCrypt_certStoreError);
        }
        LIBSECRETS_LOG(
                LogLevel::Info,
                "Certificate chain verification.",
                "Certificate chain verification with cert %s",
                printCertInfo(pRootCtx, "Root").c_str());
        rootCertContexts.push_back(pRootCtx);
    }
}

WincryptX509::~WincryptX509()
{
    if (this->hStore != NULL)
    {
        CertCloseStore(hStore, 0);
    }
}

bool WincryptX509::VerifySignature(std::vector<unsigned char> const&signedData, std::vector<unsigned char> const&signature)
{
    // Display the certificate
    DWORD dwData;
    void* pvData;

    BCRYPT_KEY_HANDLE hKey;
    CryptImportPublicKeyInfoEx2(
        this->pLeafCertContext->dwCertEncodingType,
        &this->pLeafCertContext->pCertInfo->SubjectPublicKeyInfo,
        0,
        nullptr,
        &hKey
    );
    if (hKey == NULL)
    {
		// LibraryError, WinCrypt subclass, certLoadError
        throw WinCryptError("CryptImportPublicKeyInfoEx2 failed.", GetLastError(),
            ErrorCode::LibraryError_Bcrypt_keyError);
    }
    
    BCRYPT_ALG_HANDLE hHashAlg = NULL;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hHashAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (status != STATUS_SUCCESS)
    {
		// LibraryError, Bcrypt subclass, providerError
        throw BcryptError(status, "BCryptOpenAlgorithmProvider - Hash Algorithm",
            ErrorCode::LibraryError_Bcrypt_providerError);
    }

    PUCHAR pbHash = (PUCHAR)malloc(32);
    DWORD cbHash = 32;

    status = BCryptHash(hHashAlg, NULL, 0, (PUCHAR)signedData.data(), signedData.size(), pbHash, 32);
    if (status != STATUS_SUCCESS)
    {
		// CryptographyError, Hash subclass, hashError
        free(pbHash);
        BCryptCloseAlgorithmProvider(hHashAlg, 0);
        throw BcryptError(status, "X509 Signature Verification Hash Calculation",
            ErrorCode::CryptographyError_Hash_hashError);
    }
    BCRYPT_PKCS1_PADDING_INFO paddingInfo = { 0 };
    paddingInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;
    status = BCryptVerifySignature(hKey, &paddingInfo, pbHash, 32, (PUCHAR)signature.data(), signature.size(), BCRYPT_PAD_PKCS1);
    if (status != STATUS_SUCCESS)
    {
        // CryptographyError, Signing subclass, verificationError
        free(pbHash);
        BCryptCloseAlgorithmProvider(hHashAlg, 0);
        throw BcryptError(status, "X509 Signature Verification",
            ErrorCode::CryptographyError_Signing_verifyError);
    }
    if (pbHash != NULL) {
        free(pbHash);
    }
    BCryptCloseAlgorithmProvider(hHashAlg, 0);
    if (hKey != NULL) {
        BCryptDestroyKey(hKey);
    }
    return true;
}

PCCERT_CONTEXT WincryptX509::LoadCertificate(const std::vector<unsigned char>& cert)
{
    // Load the certificate
    PCCERT_CONTEXT pCertContext = NULL;
    NTSTATUS status = 0;
    
    //std::vector<unsigned char> derData = encoders::base64_decode(std::string(cert.data()));

    pCertContext = CertCreateCertificateContext(
        MY_ENCODING_TYPE, (const BYTE*)cert.data(), cert.size());

    if (pCertContext == NULL)
    {
		// LibraryError, WinCrypt subclass, certLoadError
        throw WinCryptError("CertCreateCertificateContext failed.", GetLastError(),
            ErrorCode::LibraryError_WinCrypt_certLoadError);
    }

    return pCertContext;
}

void WincryptX509::LoadLeafCertificate(const char* cert)
{
    this->pLeafCertContext = LoadCertificate(encoders::base64_decode(cert));
    LIBSECRETS_LOG(
            LogLevel::Info,
            "Certificate chain verification.",
            "Certificate chain verification with cert %s",
            printCertInfo(this->pLeafCertContext, "Leaf").c_str());
    CERT_CHAIN_PARA chainPara = {};
    chainPara.cbSize = sizeof(chainPara);
    // chainPara.dwUrlRetrievalTimeout = 4000; // Requires CERT_CHAIN_PARA_HAS_EXTRA_FIELDS; not needed while all URL retrieval flags are disabled
    this->chainContext = nullptr;
    if (!CertGetCertificateChain(NULL, this->pLeafCertContext, NULL, this->hStore, &chainPara,
            CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL | CERT_CHAIN_DISABLE_AIA
            | CERT_CHAIN_DISABLE_AUTH_ROOT_AUTO_UPDATE |
            CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY, NULL, &(this->chainContext))) {
		// LibraryError, WinCrypt subclass, certChainError
        throw WinCryptError("CertGetCertificateChain failed.", GetLastError(),
            ErrorCode::LibraryError_WinCrypt_certChainError);
    }
}

void WincryptX509::LoadIntermediateCertificate(const char* cert)
{
    PCCERT_CONTEXT pInterCertContext = LoadCertificate(encoders::base64_decode(cert));
    LIBSECRETS_LOG(
            LogLevel::Info,
            "Certificate chain verification.",
            "Certificate chain verification with cert %s",
            printCertInfo(pInterCertContext, "Intermediate CA").c_str());
    if (!CertAddCertificateContextToStore(this->hStore, pInterCertContext, CERT_STORE_ADD_ALWAYS, NULL)) {
		// LibraryError, WinCrypt subclass, certStoreError
        throw WinCryptError("CertAddCertificateContextToStore - Intermediate - failed.", GetLastError(),
            ErrorCode::LibraryError_WinCrypt_certStoreError);
    }
}

bool WincryptX509::VerifyCertChain(const std::string& expectedSubjectSuffix)
{
    bool ret = false;
    if (this->chainContext == nullptr) {
        LIBSECRETS_LOG(LogLevel::Error, "Certificate chain verification failed.",
                       "Certificate chain is not loaded.");
        return ret;
    }
    
    // Debug: Log what suffix we're actually using
    LIBSECRETS_LOG(LogLevel::Debug, "VerifyCertChain Debug", 
                  "Using expectedSubjectSuffix: '%s'", expectedSubjectSuffix.c_str());

    CERT_CHAIN_POLICY_PARA policyPara = { sizeof(policyPara) };
    CERT_CHAIN_POLICY_STATUS policyStatus = { sizeof(policyStatus) };
    
 
    policyPara.dwFlags = CERT_CHAIN_POLICY_ALLOW_UNKNOWN_CA_FLAG;

    if (!CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_BASE, this->chainContext, &policyPara, &policyStatus)) {
        throw WinCryptError("CertVerifyCertificateChainPolicy failed.", GetLastError(),
            ErrorCode::CryptographyError_Signing_certChainError);
    }

    // Additional check: Verify the chain actually reaches a trusted root
    if (policyStatus.dwError != 0) {
        LIBSECRETS_LOG(
            LogLevel::Error,
            "Certificate chain failed to verify.",
            "Certificate chain verification failed with error code 0x%08X",
            policyStatus.dwError);
        
        // Log specific error details
        if (policyStatus.dwError == CERT_E_UNTRUSTEDROOT) {
            LIBSECRETS_LOG(LogLevel::Error, "Chain does not terminate at trusted root", "");
        }
        ret = false;
    }
    else {
        // Additional verification: Check if chain actually terminates at root
        ret = VerifyChainTerminatesAtRoot();
        if (ret && !VerifySubjectSuffix(expectedSubjectSuffix)) {
            LIBSECRETS_LOG(LogLevel::Error, "Security Subject Chain Verification Failed",
                          "Certificate chain valid but subject suffix validation failed");
            ret = false;
        } else if (ret) {
            LIBSECRETS_LOG(LogLevel::Debug, "Security Subject Chain Verification Success",
                          "Certificate chain and subject suffix validation successful");
        }
    }
    return ret;
}

// Helper method to verify chain terminates at trusted root
bool WincryptX509::VerifyChainTerminatesAtRoot()
{
    if (!this->chainContext || this->chainContext->cChain == 0) {
        LIBSECRETS_LOG(LogLevel::Error, "Invalid Cert Chain Context", "");
        return false;
    }
    
    // Get the first (and typically only) simple chain
    PCERT_SIMPLE_CHAIN pSimpleChain = this->chainContext->rgpChain[0];
    if (!pSimpleChain || pSimpleChain->cElement == 0) {
        LIBSECRETS_LOG(LogLevel::Error, "Unable to reach SimpleChain", "");
        return false;
    }
    
    // Get the root certificate (last element in the chain)
    PCERT_CHAIN_ELEMENT pRootElement = pSimpleChain->rgpElement[pSimpleChain->cElement - 1];
    if (!pRootElement) {
        LIBSECRETS_LOG(LogLevel::Error, "Missing Root element in SimpleChain", "");
        return false;
    }
    
    // Check if the root certificate is trusted
    DWORD dwFlags = pRootElement->TrustStatus.dwErrorStatus;
    
    if (dwFlags & CERT_TRUST_IS_PARTIAL_CHAIN) {
        LIBSECRETS_LOG(LogLevel::Error, "Chain is incomplete", "");
        return false;
    }
    
    // Verify the root is self-signed (characteristic of root CAs)
    PCCERT_CONTEXT pRootCert = pRootElement->pCertContext;
    if (CertCompareCertificateName(pRootCert->dwCertEncodingType,
                                   &pRootCert->pCertInfo->Subject,
                                   &pRootCert->pCertInfo->Issuer)) {
        LIBSECRETS_LOG(LogLevel::Debug, "Chain terminates at self-signed root certificate", "");
    }
    else
    { 
        LIBSECRETS_LOG(LogLevel::Warning, "Root certificate is not self-signed", "");
		return false;
    }

    // Get the last certificate in the chain
    PCCERT_CONTEXT actualRoot = pSimpleChain->rgpElement[pSimpleChain->cElement - 1]->pCertContext;
    if (!actualRoot) {
        return false;
    }

	// Check if the chain root matches any of the trusted root certificates
	bool rootMatched = false;
	for (const auto& pRootCertContext : rootCertContexts) {
		if (actualRoot->dwCertEncodingType == pRootCertContext->dwCertEncodingType &&
		    CertComparePublicKeyInfo(actualRoot->dwCertEncodingType,
		                               &actualRoot->pCertInfo->SubjectPublicKeyInfo,
		                               &pRootCertContext->pCertInfo->SubjectPublicKeyInfo) &&
		    CertCompareCertificate(actualRoot->dwCertEncodingType,
		                             actualRoot->pCertInfo,
		                             pRootCertContext->pCertInfo))
		{
			rootMatched = true;
			break;
		}
	}

	if (!rootMatched)
	{
		// Root certificate does not match any expected root certificate
		LIBSECRETS_LOG(LogLevel::Error, "Root certificate does not match any expected root certificate",
		              "Actual Root Cert: %s",
		              printCertInfo(actualRoot, "Actual Root").c_str());

		return false;
	}

    return true;
}

// Verify the certificate subject ends with expected suffix
bool WincryptX509::VerifySubjectSuffix(const std::string& expectedSuffix) const {
    std::string commonName = GetCommonName();
    if (commonName.empty()) {
        LIBSECRETS_LOG(LogLevel::Error, "Security Subject Suffix Verification", 
                      "Could not retrieve certificate common name");
        return false;
    }

    // Case-insensitive suffix check
    std::string lowerCommonName = commonName;
    std::string lowerSuffix = expectedSuffix;
    std::transform(lowerCommonName.begin(), lowerCommonName.end(), lowerCommonName.begin(), ::tolower);
    std::transform(lowerSuffix.begin(), lowerSuffix.end(), lowerSuffix.begin(), ::tolower);

    bool matches = (lowerCommonName.length() >= lowerSuffix.length() &&
                   lowerCommonName.substr(lowerCommonName.length() - lowerSuffix.length()) == lowerSuffix);
    
    if (matches) {
        LIBSECRETS_LOG(LogLevel::Debug, "Security Subject Suffix Verification Success", 
                      "Subject '%s' ends with expected suffix '%s'", commonName.c_str(), expectedSuffix.c_str());
    } else {
        LIBSECRETS_LOG(LogLevel::Error, "Security Subject Suffix Verification Failed", 
                      "Subject '%s' does not end with expected suffix '%s'", commonName.c_str(), expectedSuffix.c_str());
    }
    
    return matches;
}

// Get the certificate subject name (who the certificate was issued to)
std::string WincryptX509::GetSubjectName() const {
    if (!pLeafCertContext) {
        LIBSECRETS_LOG(LogLevel::Error, "Security Certificate Subject Access", 
                      "Certificate context is null");
        return "";
    }

    DWORD dwSize = CertNameToStrA(pLeafCertContext->dwCertEncodingType,
                                &pLeafCertContext->pCertInfo->Subject,
                                CERT_X500_NAME_STR, NULL, 0);
    
    if (dwSize <= 1) {
        LIBSECRETS_LOG(LogLevel::Error, "Security Certificate Subject Parse", 
                      "Failed to get subject name size");
        return "";
    }

    // Use a vector<char> or unique_ptr<char[]> instead of std::wstring for the buffer
    std::vector<char> subjectBuffer(dwSize);
    CertNameToStrA(pLeafCertContext->dwCertEncodingType,
                  &pLeafCertContext->pCertInfo->Subject,
                  CERT_X500_NAME_STR, subjectBuffer.data(), dwSize);

    // Convert to std::string, excluding the null terminator
    std::string subjectName(subjectBuffer.data(), dwSize - 1);

    LIBSECRETS_LOG(LogLevel::Debug, "Security Certificate Subject Retrieved", 
                  "Subject: %s", subjectName.c_str());
    return subjectName;
}

// Extract a specific field from Distinguished Name (DN)
std::string WincryptX509::ExtractFieldFromDN(const std::string& dn, const std::string& field) const {
    std::string searchField = field + "=";
    size_t fieldPos = dn.find(searchField);
    if (fieldPos == std::string::npos) {
        return "";
    }
    
    size_t startPos = fieldPos + searchField.length();
    size_t endPos = dn.find(',', startPos);
    if (endPos == std::string::npos) {
        endPos = dn.length();
    }
    
    return dn.substr(startPos, endPos - startPos);
}

// Get the Common Name (CN) from the certificate subject
std::string WincryptX509::GetCommonName() const {
    std::string subjectName = GetSubjectName();
    if (subjectName.empty()) {
        return "";
    }
    
    std::string commonName = ExtractFieldFromDN(subjectName, "CN");
    LIBSECRETS_LOG(LogLevel::Debug, "Security Certificate Common Name", 
                  "CN: %s", commonName.c_str());
    return commonName;
}