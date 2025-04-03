#include "..\pch.h"
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
#include "..\LibraryLogger.h"
#include "..\ReturnCodes.h"
#include "WincryptX509.h"

using namespace SecretsLogger;

#define MY_ENCODING_TYPE (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)
#define TEMPBUF_SIZE 1024
#define SELFSIGNEDCERTNAME L"CN=SelfSignedCert"
#define KEY_CONTAINER_NAME L"SelfSignedCertKeyContainer"

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

WincryptX509::WincryptX509(const char *rootCert)
{
    this->hStore = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, NULL, 0, NULL);
    if (this->hStore == NULL)
    {
		// LibraryError, WinCrypt subclass, certStoreError
        throw WinCryptError("CertOpenStore failed.", GetLastError(),
            ErrorCode::LibraryError_WinCrypt_certStoreError);
    }
    PCCERT_CONTEXT pRootCertContext = LoadCertificate(encoders::base64_decode(rootCert));
    if (!CertAddCertificateContextToStore(this->hStore, pRootCertContext, CERT_STORE_ADD_ALWAYS, NULL)) {
        // LibraryError, WinCrypt subclass, certStoreError
        throw WinCryptError("CertAddCertificateContextToStore - Root Cert - failed.", GetLastError(),
            ErrorCode::LibraryError_WinCrypt_certStoreError);
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
    this->chainPara = { sizeof(chainPara) };
    this->chainContext = nullptr;
    if (!CertGetCertificateChain(NULL, this->pLeafCertContext, NULL, this->hStore, &(this->chainPara), 0, NULL, &(this->chainContext))) {
		// LibraryError, WinCrypt subclass, certChainError
        throw WinCryptError("CertGetCertificateChain failed.", GetLastError(),
            ErrorCode::LibraryError_WinCrypt_certChainError);
    }
}

void WincryptX509::LoadIntermediateCertificate(const char* cert)
{
    PCCERT_CONTEXT pInterCertContext = LoadCertificate(encoders::base64_decode(cert));
    if (!CertAddCertificateContextToStore(this->hStore, pInterCertContext, CERT_STORE_ADD_ALWAYS, NULL)) {
		// LibraryError, WinCrypt subclass, certStoreError
        throw WinCryptError("CertAddCertificateContextToStore - Intermediate - failed.", GetLastError(),
            ErrorCode::LibraryError_WinCrypt_certStoreError);
    }
}

bool WincryptX509::VerifyCertChain()
{
    bool ret = false;
    if (this->chainContext == nullptr) {
        std::cerr << "Certificate chain is not loaded." << std::endl;
        return ret;
    }

    CERT_CHAIN_POLICY_PARA policyPara = { sizeof(policyPara) };
    CERT_CHAIN_POLICY_STATUS policyStatus = { sizeof(policyStatus) };
    policyPara.dwFlags = CERT_CHAIN_POLICY_ALLOW_UNKNOWN_CA_FLAG;

    if (!CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_BASE, this->chainContext, &policyPara, &policyStatus)) {
		// CryptographyError, Signing subclass, certChainError
        throw WinCryptError("CertVerifyCertificateChainPolicy failed.", GetLastError(),
            ErrorCode::CryptographyError_Signing_certChainError);
    }

    if (policyStatus.dwError != 0) {
        LIBSECRETS_LOG(
            LogLevel::Error,
            "Certificate chain failed to verify.",
            "Certificate chain verification failed with error code %p",
            policyStatus.dwError);
        ret = false;
    }
    else {
        LIBSECRETS_LOG(
            LogLevel::Debug,
            "Certificate chain verified successfully.",
            "");
        ret = true;
    }
    return ret;
}