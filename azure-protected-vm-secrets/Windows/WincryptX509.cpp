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

void WincryptX509::SetLeafKey(BCRYPT_KEY_HANDLE key)
{
    this->leafPrivateKey = key;
}

std::vector<unsigned char> WincryptX509::SignData(const std::vector<unsigned char>& data)
{
    if (this->leafPrivateKey == NULL) {
        throw WinCryptError("Leaf private key is not set.", 0,
            ErrorCode::LibraryError_Bcrypt_keyError);
    }

    // Open SHA-256 algorithm
    BCRYPT_ALG_HANDLE hHashAlg = NULL;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hHashAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (status != STATUS_SUCCESS) {
        throw BcryptError(status, "BCryptOpenAlgorithmProvider - Hash Algorithm",
            ErrorCode::LibraryError_Bcrypt_providerError);
    }

    // Hash the data
    std::vector<unsigned char> hash(32);
    status = BCryptHash(hHashAlg, NULL, 0, (PUCHAR)data.data(), (ULONG)data.size(), hash.data(), 32);
    BCryptCloseAlgorithmProvider(hHashAlg, 0);
    
    if (status != STATUS_SUCCESS) {
        throw BcryptError(status, "BCryptHash",
            ErrorCode::CryptographyError_Hash_hashError);
    }

    // Get signature size
    BCRYPT_PKCS1_PADDING_INFO paddingInfo = { 0 };
    paddingInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;
    
    DWORD signatureSize = 0;
    status = BCryptSignHash(this->leafPrivateKey, &paddingInfo, hash.data(), 32, 
                           NULL, 0, &signatureSize, BCRYPT_PAD_PKCS1);
    if (status != STATUS_SUCCESS) {
        throw BcryptError(status, "BCryptSignHash - Get Size",
            ErrorCode::CryptographyError_Signing_verifyError);
    }

    // Sign the hash
    std::vector<unsigned char> signature(signatureSize);
    status = BCryptSignHash(this->leafPrivateKey, &paddingInfo, hash.data(), 32,
                           signature.data(), signatureSize, &signatureSize, BCRYPT_PAD_PKCS1);
    if (status != STATUS_SUCCESS) {
        throw BcryptError(status, "BCryptSignHash",
            ErrorCode::CryptographyError_Signing_verifyError);
    }

    return signature;
}

// ============================================================================
// Test Certificate Chain Generation (Root -> Intermediate -> Leaf)
// These functions are for unit testing only and generate fresh certificates
// at runtime to avoid expiration issues with hardcoded test certificates.
// ============================================================================

// Helper struct to hold a generated certificate and its key
struct GeneratedCert {
    PCCERT_CONTEXT cert;
    HCRYPTPROV hProv;
    HCRYPTKEY hKey;
    std::wstring containerName;
    
    GeneratedCert() : cert(nullptr), hProv(0), hKey(0) {}
    ~GeneratedCert() {
        if (cert) CertFreeCertificateContext(cert);
        if (hKey) CryptDestroyKey(hKey);
        if (hProv) CryptReleaseContext(hProv, 0);
        // Delete the key container
        if (!containerName.empty()) {
            HCRYPTPROV hTempProv = 0;
            CryptAcquireContextW(&hTempProv, containerName.c_str(), MS_STRONG_PROV_W,
                                PROV_RSA_FULL, CRYPT_DELETEKEYSET);
        }
    }
};

// Helper function to compute expiry time
static SYSTEMTIME computeExpiryTime(int days) {
    SYSTEMTIME stNow, stExpiry;
    GetSystemTime(&stNow);
    
    FILETIME ftNow, ftExpiry;
    SystemTimeToFileTime(&stNow, &ftNow);
    
    ULARGE_INTEGER uliExpiry;
    uliExpiry.LowPart = ftNow.dwLowDateTime;
    uliExpiry.HighPart = ftNow.dwHighDateTime;
    uliExpiry.QuadPart += (ULONGLONG)days * 24 * 60 * 60 * 10000000ULL;
    ftExpiry.dwLowDateTime = uliExpiry.LowPart;
    ftExpiry.dwHighDateTime = uliExpiry.HighPart;
    FileTimeToSystemTime(&ftExpiry, &stExpiry);
    
    return stExpiry;
}

// Helper function to create a key pair and crypto context
static void createKeyPair(const std::wstring& containerName, HCRYPTPROV& hProv, HCRYPTKEY& hKey) {
    // Delete existing container if present
    CryptAcquireContextW(&hProv, containerName.c_str(), MS_STRONG_PROV_W,
                        PROV_RSA_FULL, CRYPT_DELETEKEYSET);
    
    if (!CryptAcquireContextW(&hProv, containerName.c_str(), MS_STRONG_PROV_W,
                              PROV_RSA_FULL, CRYPT_NEWKEYSET)) {
        throw WinCryptError("CryptAcquireContext failed.", GetLastError());
    }
    
    // Generate 2048-bit RSA key
    DWORD keyLength = 0x08000000; // 2048 bits in upper 16 bits
    if (!CryptGenKey(hProv, AT_SIGNATURE, keyLength | CRYPT_EXPORTABLE, &hKey)) {
        CryptReleaseContext(hProv, 0);
        hProv = 0;
        throw WinCryptError("CryptGenKey failed.", GetLastError());
    }
}

// Helper function to create a self-signed root CA certificate
static std::unique_ptr<GeneratedCert> createRootCACert(const std::wstring& subjectName, int validityDays) {
    auto result = std::make_unique<GeneratedCert>();
    result->containerName = L"TestRootCAContainer";
    
    createKeyPair(result->containerName, result->hProv, result->hKey);
    
    // Encode subject name
    BYTE bEncoded[TEMPBUF_SIZE];
    DWORD dwEncoded = TEMPBUF_SIZE;
    if (!CertStrToNameW(X509_ASN_ENCODING, subjectName.c_str(), CERT_X500_NAME_STR,
                        NULL, bEncoded, &dwEncoded, NULL)) {
        throw WinCryptError("CertStrToName failed for root CA.", GetLastError());
    }
    
    CERT_NAME_BLOB subjectBlob = { dwEncoded, bEncoded };
    SYSTEMTIME stExpiry = computeExpiryTime(validityDays);
    
    // Set up key provider info
    CRYPT_KEY_PROV_INFO kpi = {0};
    kpi.pwszContainerName = const_cast<LPWSTR>(result->containerName.c_str());
    kpi.pwszProvName = const_cast<LPWSTR>(MS_STRONG_PROV_W);
    kpi.dwProvType = PROV_RSA_FULL;
    kpi.dwFlags = 0;
    kpi.dwKeySpec = AT_SIGNATURE;
    
    // Set up signature algorithm
    CRYPT_ALGORITHM_IDENTIFIER signAlg = {0};
    signAlg.pszObjId = const_cast<LPSTR>(szOID_RSA_SHA256RSA);
    
    // Add CA basic constraints extension
    CERT_BASIC_CONSTRAINTS2_INFO basicConstraints = {0};
    basicConstraints.fCA = TRUE;
    basicConstraints.fPathLenConstraint = TRUE;
    basicConstraints.dwPathLenConstraint = 1;
    
    DWORD cbEncoded = 0;
    PBYTE pbEncoded = NULL;
    if (!CryptEncodeObjectEx(X509_ASN_ENCODING, X509_BASIC_CONSTRAINTS2,
                            &basicConstraints, CRYPT_ENCODE_ALLOC_FLAG,
                            NULL, &pbEncoded, &cbEncoded)) {
        throw WinCryptError("CryptEncodeObjectEx failed for basic constraints.", GetLastError());
    }
    
    CERT_EXTENSION certExt = {0};
    certExt.pszObjId = const_cast<LPSTR>(szOID_BASIC_CONSTRAINTS2);
    certExt.fCritical = TRUE;
    certExt.Value.cbData = cbEncoded;
    certExt.Value.pbData = pbEncoded;
    
    CERT_EXTENSIONS certExts = {0};
    certExts.cExtension = 1;
    certExts.rgExtension = &certExt;
    
    // Create self-signed certificate
    result->cert = CertCreateSelfSignCertificate(result->hProv, &subjectBlob, 0, &kpi, &signAlg,
                                                  NULL, &stExpiry, &certExts);
    LocalFree(pbEncoded);
    
    if (!result->cert) {
        throw WinCryptError("CertCreateSelfSignCertificate failed for root CA.", GetLastError());
    }
    
    LIBSECRETS_LOG(LogLevel::Info, "createRootCACert",
                  "Created root CA: %s", printCertInfo(result->cert, "Root CA").c_str());
    
    return result;
}

// Helper function to create a certificate signed by an issuer
static std::unique_ptr<GeneratedCert> createSignedCert(
    const std::wstring& subjectName,
    const std::wstring& containerName,
    GeneratedCert* issuer,
    int validityDays,
    bool isCA,
    int pathLen = -1)
{
    auto result = std::make_unique<GeneratedCert>();
    result->containerName = containerName;
    
    createKeyPair(result->containerName, result->hProv, result->hKey);
    
    // Export the public key to create CERT_PUBLIC_KEY_INFO
    DWORD cbPubKeyInfo = 0;
    if (!CryptExportPublicKeyInfo(result->hProv, AT_SIGNATURE, X509_ASN_ENCODING,
                                  NULL, &cbPubKeyInfo)) {
        throw WinCryptError("CryptExportPublicKeyInfo size failed.", GetLastError());
    }
    
    std::vector<BYTE> pubKeyInfoBuf(cbPubKeyInfo);
    PCERT_PUBLIC_KEY_INFO pPubKeyInfo = (PCERT_PUBLIC_KEY_INFO)pubKeyInfoBuf.data();
    if (!CryptExportPublicKeyInfo(result->hProv, AT_SIGNATURE, X509_ASN_ENCODING,
                                  pPubKeyInfo, &cbPubKeyInfo)) {
        throw WinCryptError("CryptExportPublicKeyInfo failed.", GetLastError());
    }
    
    // Encode subject name
    BYTE bSubjectEncoded[TEMPBUF_SIZE];
    DWORD dwSubjectEncoded = TEMPBUF_SIZE;
    if (!CertStrToNameW(X509_ASN_ENCODING, subjectName.c_str(), CERT_X500_NAME_STR,
                        NULL, bSubjectEncoded, &dwSubjectEncoded, NULL)) {
        throw WinCryptError("CertStrToName failed.", GetLastError());
    }
    
    // Build certificate info
    CERT_INFO certInfo = {0};
    certInfo.dwVersion = CERT_V3;
    
    // Serial number (simple incrementing)
    static DWORD serialNum = 2;
    BYTE serialBytes[4];
    serialBytes[0] = (BYTE)(serialNum & 0xFF);
    serialBytes[1] = (BYTE)((serialNum >> 8) & 0xFF);
    serialBytes[2] = (BYTE)((serialNum >> 16) & 0xFF);
    serialBytes[3] = (BYTE)((serialNum >> 24) & 0xFF);
    serialNum++;
    certInfo.SerialNumber.cbData = 4;
    certInfo.SerialNumber.pbData = serialBytes;
    
    // Signature algorithm
    certInfo.SignatureAlgorithm.pszObjId = const_cast<LPSTR>(szOID_RSA_SHA256RSA);
    
    // Issuer name (from issuer certificate)
    certInfo.Issuer = issuer->cert->pCertInfo->Subject;
    
    // Validity period
    SYSTEMTIME stNow;
    GetSystemTime(&stNow);
    FILETIME ftNow;
    SystemTimeToFileTime(&stNow, &ftNow);
    certInfo.NotBefore = ftNow;
    
    SYSTEMTIME stExpiry = computeExpiryTime(validityDays);
    FILETIME ftExpiry;
    SystemTimeToFileTime(&stExpiry, &ftExpiry);
    certInfo.NotAfter = ftExpiry;
    
    // Subject name
    certInfo.Subject.cbData = dwSubjectEncoded;
    certInfo.Subject.pbData = bSubjectEncoded;
    
    // Public key
    certInfo.SubjectPublicKeyInfo = *pPubKeyInfo;
    
    // Add extensions
    std::vector<CERT_EXTENSION> extensions;
    std::vector<BYTE> basicConstraintsBuf;
    
    // Basic Constraints extension
    CERT_BASIC_CONSTRAINTS2_INFO basicConstraints = {0};
    basicConstraints.fCA = isCA ? TRUE : FALSE;
    if (isCA && pathLen >= 0) {
        basicConstraints.fPathLenConstraint = TRUE;
        basicConstraints.dwPathLenConstraint = pathLen;
    }
    
    DWORD cbBasicConstraints = 0;
    PBYTE pbBasicConstraints = NULL;
    if (!CryptEncodeObjectEx(X509_ASN_ENCODING, X509_BASIC_CONSTRAINTS2,
                            &basicConstraints, CRYPT_ENCODE_ALLOC_FLAG,
                            NULL, &pbBasicConstraints, &cbBasicConstraints)) {
        throw WinCryptError("CryptEncodeObjectEx failed for basic constraints.", GetLastError());
    }
    
    CERT_EXTENSION bcExt = {0};
    bcExt.pszObjId = const_cast<LPSTR>(szOID_BASIC_CONSTRAINTS2);
    bcExt.fCritical = TRUE;
    bcExt.Value.cbData = cbBasicConstraints;
    bcExt.Value.pbData = pbBasicConstraints;
    extensions.push_back(bcExt);
    
    certInfo.cExtension = (DWORD)extensions.size();
    certInfo.rgExtension = extensions.data();
    
    // Sign the certificate with issuer's key
    DWORD cbEncodedCert = 0;
    if (!CryptSignAndEncodeCertificate(issuer->hProv, AT_SIGNATURE, X509_ASN_ENCODING,
                                       X509_CERT_TO_BE_SIGNED, &certInfo,
                                       &certInfo.SignatureAlgorithm,
                                       NULL, NULL, &cbEncodedCert)) {
        LocalFree(pbBasicConstraints);
        throw WinCryptError("CryptSignAndEncodeCertificate size failed.", GetLastError());
    }
    
    std::vector<BYTE> encodedCert(cbEncodedCert);
    if (!CryptSignAndEncodeCertificate(issuer->hProv, AT_SIGNATURE, X509_ASN_ENCODING,
                                       X509_CERT_TO_BE_SIGNED, &certInfo,
                                       &certInfo.SignatureAlgorithm,
                                       NULL, encodedCert.data(), &cbEncodedCert)) {
        LocalFree(pbBasicConstraints);
        throw WinCryptError("CryptSignAndEncodeCertificate failed.", GetLastError());
    }
    
    LocalFree(pbBasicConstraints);
    
    // Create certificate context from encoded certificate
    result->cert = CertCreateCertificateContext(X509_ASN_ENCODING, encodedCert.data(), cbEncodedCert);
    if (!result->cert) {
        throw WinCryptError("CertCreateCertificateContext failed.", GetLastError());
    }
    
    LIBSECRETS_LOG(LogLevel::Info, "createSignedCert",
                  "Created certificate: %s", printCertInfo(result->cert, isCA ? "Intermediate CA" : "Leaf").c_str());
    
    return result;
}

// Helper function to convert CryptoAPI private key to BCrypt key handle
static BCRYPT_KEY_HANDLE convertToBcryptKey(HCRYPTPROV hProv, HCRYPTKEY hCryptKey) {
    // Export the private key from CryptoAPI
    DWORD dwKeyBlobLen = 0;
    if (!CryptExportKey(hCryptKey, 0, PRIVATEKEYBLOB, 0, NULL, &dwKeyBlobLen)) {
        throw WinCryptError("CryptExportKey size failed.", GetLastError());
    }
    
    std::vector<BYTE> keyBlob(dwKeyBlobLen);
    if (!CryptExportKey(hCryptKey, 0, PRIVATEKEYBLOB, 0, keyBlob.data(), &dwKeyBlobLen)) {
        throw WinCryptError("CryptExportKey failed.", GetLastError());
    }
    
    // Import to BCrypt for signing operations
    BCRYPT_ALG_HANDLE hRsaAlg = NULL;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hRsaAlg, BCRYPT_RSA_ALGORITHM, NULL, 0);
    if (status != STATUS_SUCCESS) {
        throw BcryptError(status, "BCryptOpenAlgorithmProvider for RSA",
            ErrorCode::LibraryError_Bcrypt_providerError);
    }
    
    // Parse CryptoAPI PRIVATEKEYBLOB format
    RSAPUBKEY* rsaPubKey = (RSAPUBKEY*)(keyBlob.data() + sizeof(PUBLICKEYSTRUC));
    DWORD bitLen = rsaPubKey->bitlen;
    DWORD byteLen = bitLen / 8;
    
    // Build BCRYPT_RSAKEY_BLOB for private key
    DWORD cbHeader = sizeof(BCRYPT_RSAKEY_BLOB);
    DWORD cbPublicExp = sizeof(DWORD);
    DWORD cbModulus = byteLen;
    DWORD cbPrime1 = byteLen / 2;
    DWORD cbPrime2 = byteLen / 2;
    
    DWORD cbBcryptBlob = cbHeader + cbPublicExp + cbModulus + cbPrime1 + cbPrime2;
    std::vector<BYTE> bcryptBlob(cbBcryptBlob);
    
    BCRYPT_RSAKEY_BLOB* pBcryptBlob = (BCRYPT_RSAKEY_BLOB*)bcryptBlob.data();
    pBcryptBlob->Magic = BCRYPT_RSAPRIVATE_MAGIC;
    pBcryptBlob->BitLength = bitLen;
    pBcryptBlob->cbPublicExp = cbPublicExp;
    pBcryptBlob->cbModulus = cbModulus;
    pBcryptBlob->cbPrime1 = cbPrime1;
    pBcryptBlob->cbPrime2 = cbPrime2;
    
    // Copy public exponent (reverse byte order from little-endian to big-endian)
    BYTE* pDst = bcryptBlob.data() + cbHeader;
    DWORD pubExp = rsaPubKey->pubexp;
    for (DWORD i = 0; i < cbPublicExp; i++) {
        pDst[cbPublicExp - 1 - i] = (BYTE)(pubExp >> (i * 8));
    }
    pDst += cbPublicExp;
    
    // Pointer to data after RSAPUBKEY structure
    BYTE* pSrc = keyBlob.data() + sizeof(PUBLICKEYSTRUC) + sizeof(RSAPUBKEY);
    
    // Copy modulus (reverse byte order)
    for (DWORD i = 0; i < cbModulus; i++) {
        pDst[cbModulus - 1 - i] = pSrc[i];
    }
    pSrc += cbModulus;
    pDst += cbModulus;
    
    // Copy Prime1 (reverse byte order)
    for (DWORD i = 0; i < cbPrime1; i++) {
        pDst[cbPrime1 - 1 - i] = pSrc[i];
    }
    pSrc += cbPrime1;
    pDst += cbPrime1;
    
    // Copy Prime2 (reverse byte order)
    for (DWORD i = 0; i < cbPrime2; i++) {
        pDst[cbPrime2 - 1 - i] = pSrc[i];
    }
    
    BCRYPT_KEY_HANDLE hBcryptKey = NULL;
    status = BCryptImportKeyPair(hRsaAlg, NULL, BCRYPT_RSAPRIVATE_BLOB,
                                &hBcryptKey, bcryptBlob.data(), cbBcryptBlob, 0);
    BCryptCloseAlgorithmProvider(hRsaAlg, 0);
    
    if (status != STATUS_SUCCESS) {
        throw BcryptError(status, "BCryptImportKeyPair",
            ErrorCode::LibraryError_Bcrypt_keyError);
    }
    
    return hBcryptKey;
}

// Helper function to get base64-encoded DER certificate
static std::string getCertBase64(PCCERT_CONTEXT cert) {
    std::vector<unsigned char> der(cert->pbCertEncoded, cert->pbCertEncoded + cert->cbCertEncoded);
    return encoders::base64_encode(der);
}

std::unique_ptr<WincryptX509> generateCertChain()
{
    // Generate a complete 3-level certificate chain: Root CA -> Intermediate CA -> Leaf
    // This matches the production certificate structure and the Linux implementation.
    
    try {
        // 1. Create Root CA (self-signed, valid for 10 years)
        auto rootCA = createRootCACert(L"CN=Test Root CA", 3650);
        
        // 2. Create Intermediate CA (signed by Root, valid for 5 years)
        auto intermediateCA = createSignedCert(
            L"CN=Test Intermediate CA",
            L"TestIntermediateCAContainer",
            rootCA.get(),
            1825,  // 5 years
            true,  // is CA
            0      // pathlen = 0 (can only sign end-entity certs)
        );
        
        // 3. Create Leaf certificate (signed by Intermediate, valid for 1 year)
        // Include the expected suffix for verification
        std::wstring leafSubject = L"CN=eastus" + std::wstring(L".SecureCPSProvisioning.cloudapp.net");
        auto leafCert = createSignedCert(
            leafSubject,
            L"TestLeafCertContainer",
            intermediateCA.get(),
            365,   // 1 year
            false  // not a CA
        );
        
        // Get base64-encoded certificates
        std::string rootCertBase64 = getCertBase64(rootCA->cert);
        std::string intermediateCertBase64 = getCertBase64(intermediateCA->cert);
        std::string leafCertBase64 = getCertBase64(leafCert->cert);
        
        // Convert leaf private key to BCrypt handle for signing
        BCRYPT_KEY_HANDLE hBcryptKey = convertToBcryptKey(leafCert->hProv, leafCert->hKey);
        
        // Create WincryptX509 with the root certificate
        auto certChain = std::make_unique<WincryptX509>(std::vector<const char*>{ rootCertBase64.c_str() });
        
        // Load intermediate certificate
        certChain->LoadIntermediateCertificate(intermediateCertBase64.c_str());
        
        // Load leaf certificate
        certChain->LoadLeafCertificate(leafCertBase64.c_str());
        
        // Set the private key for signing
        certChain->SetLeafKey(hBcryptKey);
        
        LIBSECRETS_LOG(LogLevel::Info, "generateCertChain",
                      "Successfully generated 3-level test certificate chain (Root -> Intermediate -> Leaf)");
        
        return certChain;
        
    } catch (const std::exception& e) {
        LIBSECRETS_LOG(LogLevel::Error, "generateCertChain",
                      "Failed to generate certificate chain: %s", e.what());
        throw;
    }
}

WincryptX509::WincryptX509(const char* rootCert)
    : WincryptX509(std::vector<const char*>{ rootCert })
{
}

WincryptX509::WincryptX509(const std::vector<const char*>& rootCerts)
{
    this->leafPrivateKey = NULL;
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
    if (this->leafPrivateKey != NULL)
    {
        BCryptDestroyKey(this->leafPrivateKey);
    }
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