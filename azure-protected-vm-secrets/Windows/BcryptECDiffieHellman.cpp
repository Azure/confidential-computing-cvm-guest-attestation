#include "..\pch.h"
//#ifndef PLATFORM_UNIX
#define UMDF_USING_NTSTATUS
#include "windows.h"
#ifndef _NTSTATUS_
#include "ntstatus.h"
#endif // !_NTSTATUS_
#include "bcrypt.h"
#include "wincrypt.h"
#include "..\BcryptError.h"
//#endif // !PLATFORM_UNIX
#include "..\ECDiffieHellman.h"
#include "BcryptECDiffieHellman.h"
#include "..\LibraryLogger.h"
#include "..\ReturnCodes.h"
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

BcryptECDiffieHellman::BcryptECDiffieHellman()
{
#ifndef PLATFORM_UNIX
    NTSTATUS status = STATUS_SUCCESS;
    this->hSharedSecret = nullptr;
    this->hEccKeyHandle = nullptr;
    this->hEcHandle = nullptr;
    status = BCryptOpenAlgorithmProvider(&(this->hEcHandle), BCRYPT_ECDH_P256_ALGORITHM, NULL, 0);
    if (status != STATUS_SUCCESS) {
        // LibraryError, Bcrypt subclass, providerError
		throw BcryptError(status, "BCryptOpenAlgorithmProvider failed.\n",
            ErrorCode::LibraryError_Bcrypt_providerError);
	}
#endif // !PLATFORM_UNIX
}

BcryptECDiffieHellman::~BcryptECDiffieHellman()
{
#ifndef PLATFORM_UNIX
    if (this->hSharedSecret != nullptr) {
		BCryptDestroySecret(this->hSharedSecret);
	}
    if (this->hEccKeyHandle != nullptr) {
        BCryptDestroyKey(this->hEccKeyHandle);
    }
    if (this->hEcHandle != nullptr) {
        BCryptCloseAlgorithmProvider(this->hEcHandle, 0);
    }
#endif // !PLATFORM_UNIX
}

void BcryptECDiffieHellman::GenerateKeyPair() {
#ifndef PLATFORM_UNIX
	NTSTATUS status;
	status = BCryptGenerateKeyPair(
        this->hEcHandle,
        &(this->hEccKeyHandle),
        256,
        0);
    if (status != STATUS_SUCCESS) {
		// CryptographyError, ECC subclass, keyError
		throw BcryptError(status, "BCryptGenerateKeyPair failed.\n",
            ErrorCode::CryptographyError_ECC_keyError);
	}
    status = BCryptFinalizeKeyPair(this->hEccKeyHandle, 0);
    if (status != STATUS_SUCCESS) {
        // CryptographyError, ECC subclass, keyError
        throw BcryptError(status, "BCryptFinalizeKeyPair failed.\n",
            ErrorCode::CryptographyError_ECC_keyError);
    }
#endif // !PLATFORM_UNIX
}

void BcryptECDiffieHellman::ImportPkcs8PrivateKey(std::vector<unsigned char> const&derPrivateKey)
{
#ifndef PLATFORM_UNIX
    PCRYPT_PRIVATE_KEY_INFO privateKeyInfo = nullptr;
    DWORD publicKeyInfoLen = 0;
    CRYPT_ECC_PRIVATE_KEY_INFO* eccPrivateInfo = nullptr;
    DWORD eccKeyInfoLen = 0;
    ULONG cbPubKey = 0;
    BCRYPT_ECCKEY_BLOB* pekb = nullptr;
    NTSTATUS status = STATUS_SUCCESS;
    if (!CryptDecodeObjectEx(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            PKCS_PRIVATE_KEY_INFO,
            derPrivateKey.data(), derPrivateKey.size(),
            CRYPT_DECODE_ALLOC_FLAG | CRYPT_DECODE_NOCOPY_FLAG,
            NULL,
            &privateKeyInfo, &publicKeyInfoLen))
    {
        // ParsingError, ASN subclass, x509PrivKeyError
        throw WinCryptError("CryptDecodeObjectEx 1 failed.", GetLastError(),
            ErrorCode::ParsingError_Asn1_x509PrivKeyError);
    }

    if (!CryptDecodeObjectEx(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            X509_ECC_PRIVATE_KEY,
            privateKeyInfo->PrivateKey.pbData, privateKeyInfo->PrivateKey.cbData,
            CRYPT_DECODE_ALLOC_FLAG | CRYPT_DECODE_NOCOPY_FLAG,
            NULL,
            &eccPrivateInfo, &eccKeyInfoLen))
    {
        // ParsingError, ASN subclass, x509PrivKeyError
        throw WinCryptError("CryptDecodeObjectEx 2 failed.", GetLastError(),
            ErrorCode::ParsingError_Asn1_x509PrivKeyError);
    }

    if (NULL != eccPrivateInfo->PublicKey.pbData &&
        eccPrivateInfo->PublicKey.cbData > 0)
    {
        if (
            EC_UNCOMPRESSED_BLOB != eccPrivateInfo->PublicKey.pbData[0] &&
            EC_UNKNOWN_ASN_BYTE  != eccPrivateInfo->PublicKey.pbData[0] &&
            EC_UNKNOWN_ASN_BYTE2 != eccPrivateInfo->PublicKey.pbData[0]
            )
        {
            // ParsingError, ASN subclass, x509PrivKeyError
            throw WinCryptError("Error with public key info", 0,
                ErrorCode::ParsingError_Asn1_x509PrivKeyError);
        }
        cbPubKey = (eccPrivateInfo->PublicKey.cbData - 1) / EC_PUBLIC_NUM_COMPONENTS;
    }
    else
    {
        cbPubKey = 0;
    }

    ULONG cbKey = eccPrivateInfo->PrivateKey.cbData;

    if (cbKey < eccPrivateInfo->PrivateKey.cbData ||
        cbKey < cbPubKey)
    {
        LIBSECRETS_LOG(
			LogLevel::Info,
			"EC Diffie Hellman Import",
			"Error with private key info");
    }
    LIBSECRETS_LOG(
        LogLevel::Debug,
        "EC Diffie Hellman Import",
        "Passed private validation");

    ULONG cbKeyBlob = sizeof(BCRYPT_ECCKEY_BLOB) + EC_PRIVATE_NUM_COMPONENTS * cbKey;
    pekb = (BCRYPT_ECCKEY_BLOB*)malloc(cbKeyBlob);
    if (pekb == nullptr) {
        // GenericError, Memory subclass, mallocError
        throw std::exception("ECDH - Malloc Fail");
    }
    ZeroMemory(pekb, cbKeyBlob);

    pekb->dwMagic = BCRYPT_ECDH_PRIVATE_P256_MAGIC;
    pekb->cbKey = cbKey;

    BYTE* pb = NULL;
    if (cbPubKey > 0)
    {
        if (cbKey == cbPubKey)
        {
            CopyMemory(pekb + 1, eccPrivateInfo->PublicKey.pbData + 1, EC_PUBLIC_NUM_COMPONENTS * cbKey);
        }
        else
        {
            ULONG off = 0;
            pb = (BYTE*)(pekb + 1);
            off = cbKey - cbPubKey;
            CopyMemory(pb + off, eccPrivateInfo->PublicKey.pbData + 1, cbPubKey);
            CopyMemory(pb + cbKey + off, eccPrivateInfo->PublicKey.pbData + 1 + cbPubKey, cbPubKey);
        }
    }

    pb = (BYTE*)(pekb + 1) + EC_PUBLIC_NUM_COMPONENTS * cbKey;
    CopyMemory(pb + (cbKey - eccPrivateInfo->PrivateKey.cbData),
        eccPrivateInfo->PrivateKey.pbData,
        eccPrivateInfo->PrivateKey.cbData);

    if (privateKeyInfo != nullptr) {
        LocalFree(privateKeyInfo);
    }
    
    if (eccPrivateInfo != nullptr) {
        LocalFree(eccPrivateInfo);
    }

    if (cbKeyBlob != sizeof(BCRYPT_ECCKEY_BLOB) + pekb->cbKey * EC_PRIVATE_NUM_COMPONENTS) {
        // ParsingError, ASN subclass, x509PrivKeyError
        throw WinCryptError("Invalid key blob", 0,
            ErrorCode::ParsingError_Asn1_x509PrivKeyError);
    }
    status = BCryptImportKeyPair(this->hEcHandle, NULL, BCRYPT_ECCPRIVATE_BLOB, &(this->hEccKeyHandle), (PUCHAR)(pekb), cbKeyBlob, 0);
    if (status != STATUS_SUCCESS) {
		// LibraryError, Bcrypt subclass, keyError
        throw BcryptError(status, "BCryptImportKeyPair 1 failed.\n",
            ErrorCode::LibraryError_Bcrypt_keyError);
    }
    
#endif // !PLATFORM_UNIX
}

void BcryptECDiffieHellman::ImportSubjectPublicKeyInfo(std::vector<unsigned char> const&derPublicKey) {
#ifndef PLATFORM_UNIX
    DWORD          publicKeyInfoLen = 0;
    HCRYPTPROV     hProv = 0;
    HCRYPTKEY      hKey = 0;
    CERT_PUBLIC_KEY_INFO certPubInfo{};
    ULONG cb = 0;
    NTSTATUS status;
    union {
        PVOID pvStructInfo;
        PCERT_INFO pCertInfo;
        PCERT_PUBLIC_KEY_INFO PublicKeyInfo;
    };

    if (!CryptDecodeObjectEx(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        X509_PUBLIC_KEY_INFO,
        derPublicKey.data(), derPublicKey.size(),
        CRYPT_DECODE_ALLOC_FLAG | CRYPT_DECODE_NOCOPY_FLAG,
        NULL,
        &pvStructInfo, &cb))
    {
		// ParsingError, ASN subclass, x509PubKeyError
        throw WinCryptError("CryptDecodeObjectEx 1 failed.", GetLastError(),
            ErrorCode::ParsingError_Asn1_x509PubKeyError);
    }
    LIBSECRETS_LOG(
        LogLevel::Debug,
        "EC Diffie Hellman Import",
        "Public key size: PublicKeyInfo->PublicKey.cbData %d",
        PublicKeyInfo->PublicKey.cbData);

    CRYPT_ECC_PRIVATE_KEY_INFO* eccPrivateInfo = nullptr;
    DWORD eccKeyInfoLen = 0;
    ULONG cbPubKey = 0;
    if (NULL != PublicKeyInfo->PublicKey.pbData &&
        PublicKeyInfo->PublicKey.cbData > 0
        )
    {
        if (
            EC_UNCOMPRESSED_BLOB != PublicKeyInfo->PublicKey.pbData[0] &&
            EC_UNKNOWN_ASN_BYTE  != PublicKeyInfo->PublicKey.pbData[0] &&
            EC_UNKNOWN_ASN_BYTE2 != PublicKeyInfo->PublicKey.pbData[0]
            )
        {
            LIBSECRETS_LOG(
                LogLevel::Debug,
                "EC Diffie Hellman Import",
                "Error with public key info: PublicKeyInfo->PublicKey.pbData[0] %x",
                PublicKeyInfo->PublicKey.pbData[0]);

        }

        cbPubKey = (PublicKeyInfo->PublicKey.cbData - 1) / EC_PUBLIC_NUM_COMPONENTS;
    }
    else
    {
        cbPubKey = 0;
    }

    LIBSECRETS_LOG(LogLevel::Debug, "EC Diffie Hellman Import", "Passed private validation", nullptr);

    ULONG cbKey = cbPubKey;
    ULONG cbKeyBlob = sizeof(BCRYPT_ECCKEY_BLOB) + EC_PUBLIC_NUM_COMPONENTS * cbKey;
    BCRYPT_ECCKEY_BLOB* pekb = (BCRYPT_ECCKEY_BLOB*)malloc(cbKeyBlob);
    if (pekb == NULL) {
        // GenericError, Memory subclass, mallocError
        throw std::exception("ECDH - Malloc Failed");
    }
    ZeroMemory(pekb, cbKeyBlob);

    pekb->dwMagic = BCRYPT_ECDH_PUBLIC_P256_MAGIC;
    pekb->cbKey = cbKey;
    BYTE* pb = NULL;

    if (cbPubKey > 0)
    {
        if (cbKey == cbPubKey)
        {
            CopyMemory(pekb + 1, PublicKeyInfo->PublicKey.pbData + 1, EC_PUBLIC_NUM_COMPONENTS * cbKey);
        }
        else
        {
            ULONG off = 0;
            pb = (BYTE*)(pekb + 1);
            off = cbKey - cbPubKey;
            CopyMemory(pb + off, PublicKeyInfo->PublicKey.pbData + 1, cbPubKey);
            CopyMemory(pb + cbKey + off, PublicKeyInfo->PublicKey.pbData + 1 + cbPubKey, cbPubKey);
        }
    }
    if (PublicKeyInfo != nullptr) {
        LocalFree(PublicKeyInfo);
    }

    if (cbKeyBlob != sizeof(BCRYPT_ECCKEY_BLOB) + pekb->cbKey * EC_PUBLIC_NUM_COMPONENTS) {
        // ParsingError, ASN subclass, x509PubKeyError
        throw WinCryptError("Invalid key blob", 0,
            ErrorCode::ParsingError_Asn1_x509PubKeyError);
    }

    status = BCryptImportKeyPair(this->hEcHandle, NULL, BCRYPT_ECCPUBLIC_BLOB, &(this->hEccKeyHandle), (PUCHAR)(pekb), cbKeyBlob, 0);

    if (status != STATUS_SUCCESS) {
		// LibraryError, Bcrypt subclass, keyError
        throw BcryptError(status, "BCryptImportKeyPair 1 failed.\n",
            ErrorCode::LibraryError_Bcrypt_keyError);
    }

#endif // !PLATFORM_UNIX
}

std::vector<unsigned char> BcryptECDiffieHellman::ExportPkcs8PrivateKey() const
{
	std::vector<unsigned char> result;
#ifndef PLATFORM_UNIX
	DWORD privateKeyBlobLen = 0;
	NTSTATUS status;
    CRYPT_ECC_PRIVATE_KEY_INFO eccPrivateInfo = { 0 };
    CRYPT_PRIVATE_KEY_INFO* privateKeyInfo = nullptr;
    DWORD privateKeyInfoLen = 0;
    BYTE* pbCurveParameters = nullptr;
    DWORD cbCurveParameters = 0;
    BCRYPT_ECCKEY_BLOB* pekb = nullptr;
    // Get the size of the private key blob
	status = BCryptExportKey(this->hEccKeyHandle, NULL, BCRYPT_ECCPRIVATE_BLOB, NULL, 0, &privateKeyBlobLen, 0);
    if (status != STATUS_SUCCESS) {
		// LibraryError, Bcrypt subclass, keyError
		throw BcryptError(status, "BCryptExportKey - Get Size - failed.\n",
            ErrorCode::LibraryError_Bcrypt_keyError);
	}
    unsigned char* privateKeyBlob = (unsigned char *)malloc(privateKeyBlobLen);
    // Export the private key blob
	status = BCryptExportKey(this->hEccKeyHandle, NULL, BCRYPT_ECCPRIVATE_BLOB, privateKeyBlob, privateKeyBlobLen, &privateKeyBlobLen, 0);
    if (status != STATUS_SUCCESS) {
		// LibraryError, Bcrypt subclass, keyError
		throw BcryptError(status, "BCryptExportKey - Export Key - failed.\n",
            ErrorCode::LibraryError_Bcrypt_keyError);
	}
    pekb = (BCRYPT_ECCKEY_BLOB*)privateKeyBlob;
    // Get the size of the curve parameters
    status = BCryptGetProperty(
        this->hEccKeyHandle,
        BCRYPT_ECC_PARAMETERS,
        NULL,                       // pbOutput
        0,                          // cbOutput
        &cbCurveParameters,
        0                           // dwFlags
    );
    if (status != STATUS_SUCCESS) {
		// LibraryError, Bcrypt subclass, propertyError
        throw BcryptError(status, "BCryptGetProperty Size failed.\n",
            ErrorCode::LibraryError_Bcrypt_propertyError);
    }
    // Get the curve parameters
    pbCurveParameters = (BYTE*)malloc(cbCurveParameters);
    status = BCryptGetProperty(
		this->hEccKeyHandle,
		BCRYPT_ECC_PARAMETERS,
		pbCurveParameters,
		cbCurveParameters,
		&cbCurveParameters,
		0);
    if (status != STATUS_SUCCESS) {
		// LibraryError, Bcrypt subclass, propertyError
        throw BcryptError(status, "BCryptGetProperty Value failed.\n",
            ErrorCode::LibraryError_Bcrypt_propertyError);
    }

    CRYPT_DATA_BLOB CNGECCBlob = { 0 };
	CNGECCBlob.cbData = cbCurveParameters;
    CNGECCBlob.pbData = pbCurveParameters;
    ULONG cbCurveInfo = 0;
    // Get the size of the curve info
    if (!CryptEncodeObject(
        X509_ASN_ENCODING,
        X509_ECC_PARAMETERS,
        &CNGECCBlob,
        NULL,
        &cbCurveInfo))
    {
        // ParsingError, ASN subclass, x509PrivKeyError
        throw WinCryptError("CryptEncodeObject 1 failed.", GetLastError(),
            ErrorCode::ParsingError_Asn1_x509PrivKeyError);
	}

    eccPrivateInfo.dwVersion = CRYPT_ECC_PRIVATE_KEY_INFO_v1;
    eccPrivateInfo.szCurveOid = NULL;
    eccPrivateInfo.PrivateKey.pbData = (BYTE*)(pekb + 1) + EC_PUBLIC_NUM_COMPONENTS * pekb->cbKey;
    eccPrivateInfo.PrivateKey.cbData = pekb->cbKey;
    ULONG cbPublicKey;
    BYTE* pbPublicKey;

    pbPublicKey = (BYTE*)&pekb[1];
    cbPublicKey = pekb->cbKey;

    eccPrivateInfo.PublicKey.cbData = 1 + 2 * cbPublicKey;
    eccPrivateInfo.PublicKey.cUnusedBits = 0;
	eccPrivateInfo.PublicKey.pbData = (BYTE*)malloc(eccPrivateInfo.PublicKey.cbData);
    ZeroMemory(eccPrivateInfo.PublicKey.pbData, eccPrivateInfo.PublicKey.cbData);
    eccPrivateInfo.PublicKey.pbData[0] = EC_UNCOMPRESSED_BLOB;
    CopyMemory(
        eccPrivateInfo.PublicKey.pbData + 1,
        pbPublicKey,
        cbPublicKey);
    CopyMemory(
        eccPrivateInfo.PublicKey.pbData + 1 + cbPublicKey,
        pbPublicKey + pekb->cbKey,
        cbPublicKey);
    CRYPT_BIT_BLOB CryptBitBlob = { 0 };
    CryptBitBlob.cbData = 1;
    CryptBitBlob.pbData = (BYTE*)malloc(1);
    CryptBitBlob.pbData[0] = CERT_KEY_AGREEMENT_KEY_USAGE;
    CryptBitBlob.cUnusedBits = 0;

    ULONG cbKeyUsage = 0;
    ULONG cbEncodedKey = 0;
    // Get the size of the key
    if (!CryptEncodeObjectEx(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        X509_ECC_PRIVATE_KEY,
        (BYTE*)(&eccPrivateInfo),
        0,
        NULL,
        NULL, &cbEncodedKey))
    {
        // ParsingError, ASN subclass, x509PrivKeyError
        throw WinCryptError("CryptEncodeObjectEx 1 failed.", GetLastError(),
            ErrorCode::ParsingError_Asn1_x509PrivKeyError);
    }

    ULONG cbPriKeyInfo = cbPriKeyInfo = sizeof(*privateKeyInfo) + sizeof(szOID_ECC_PUBLIC_KEY);
    if (cbKeyUsage > 0)
    {
        cbPriKeyInfo +=
            sizeof(CRYPT_ATTRIBUTES) +
            sizeof(CRYPT_ATTRIBUTE) +
            sizeof(CRYPT_ATTR_BLOB) +
            sizeof(szOID_KEY_USAGE);
    }

    cbPriKeyInfo += cbCurveInfo;
    cbPriKeyInfo += cbKeyUsage;
    cbPriKeyInfo += cbEncodedKey;

    BYTE* pb = NULL;
    privateKeyInfo = (PCRYPT_PRIVATE_KEY_INFO)malloc(cbPriKeyInfo);
    if (privateKeyInfo == NULL) {
        // GenericError, Memory subclass, mallocError
        throw std::exception("ECDH Malloc Fail");
    }
    ZeroMemory(privateKeyInfo, cbPriKeyInfo);

    if (cbKeyUsage > 0)
    {
        CRYPT_ATTRIBUTES* pAttrList = (CRYPT_ATTRIBUTES*)(privateKeyInfo + 1);
        CRYPT_ATTRIBUTE* pAttr = (CRYPT_ATTRIBUTE*)(pAttrList + 1);
        CRYPT_ATTR_BLOB* pAttrBlob = (CRYPT_ATTR_BLOB*)(pAttr + 1);

        privateKeyInfo->pAttributes = pAttrList;

        pAttrList->cAttr = 1;
        pAttrList->rgAttr = pAttr;

        pAttr->pszObjId = (PSTR)(pAttrBlob + 1);
        pAttr->cValue = 1;
        pAttr->rgValue = pAttrBlob;

        pAttrBlob->cbData = cbKeyUsage;
        pAttrBlob->pbData =
            (BYTE*)(pAttr->pszObjId + sizeof(szOID_KEY_USAGE));

        CopyMemory(
            pAttr->pszObjId,
            szOID_KEY_USAGE,
            sizeof(szOID_KEY_USAGE));

        if (!CryptEncodeObject(
            X509_ASN_ENCODING,
            X509_BITS,
            &CryptBitBlob,
            pAttrBlob->pbData,
            &pAttrBlob->cbData))
        {
            // ParsingError, ASN subclass, x509PrivKeyError
            throw WinCryptError("CryptEncodeObjectEx 2 failed.", GetLastError(),
                ErrorCode::ParsingError_Asn1_x509PrivKeyError);
        }

        pb = pAttrBlob->pbData + pAttrBlob->cbData;
    }
    else
    {
        pb = (BYTE*)(privateKeyInfo + 1);
    }

    privateKeyInfo->Algorithm.Parameters.cbData = cbCurveInfo;
    privateKeyInfo->Algorithm.Parameters.pbData = pb + cbEncodedKey;
    privateKeyInfo->Algorithm.pszObjId =
        (PSTR)(pb + cbEncodedKey + cbCurveInfo);

    privateKeyInfo->PrivateKey.cbData = cbEncodedKey;
    privateKeyInfo->PrivateKey.pbData = pb;
    // Encode the key
    if (!CryptEncodeObjectEx(
        X509_ASN_ENCODING,
        X509_ECC_PRIVATE_KEY,
        &eccPrivateInfo,
        0,
        NULL,
        privateKeyInfo->PrivateKey.pbData,
        &privateKeyInfo->PrivateKey.cbData))
    {
        // ParsingError, ASN subclass, x509PrivKeyError
        throw WinCryptError("CryptEncodeObjectEx 3 failed.", GetLastError(),
            ErrorCode::ParsingError_Asn1_x509PrivKeyError);
    }
    // Encode the curve parameters
    if (!CryptEncodeObject(
        X509_ASN_ENCODING,
        X509_ECC_PARAMETERS,
        &CNGECCBlob,
        privateKeyInfo->Algorithm.Parameters.pbData,
        &privateKeyInfo->Algorithm.Parameters.cbData))
    {
        // ParsingError, ASN subclass, x509PrivKeyError    
        throw WinCryptError("CryptEncodeObjectEx 4 failed.", GetLastError(),
            ErrorCode::ParsingError_Asn1_x509PrivKeyError);
    }

    CopyMemory(
        privateKeyInfo->Algorithm.pszObjId,
        szOID_ECC_PUBLIC_KEY,
        sizeof(szOID_ECC_PUBLIC_KEY));
    ULONG derPrivateBytesLen = 0;
    unsigned char *derPrivateBytes = nullptr;
    // Encode the private key
    if (!CryptEncodeObjectEx(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        PKCS_PRIVATE_KEY_INFO,
        (BYTE*)privateKeyInfo,
        CRYPT_ENCODE_ALLOC_FLAG,
        NULL,
        &derPrivateBytes, &derPrivateBytesLen))
    {
        // ParsingError, ASN subclass, x509PrivKeyError
        throw WinCryptError("CryptEncodeObjectEx 5 failed.", GetLastError(),
            ErrorCode::ParsingError_Asn1_x509PrivKeyError);
    }
    
	result = std::vector<unsigned char>(derPrivateBytes, derPrivateBytes + derPrivateBytesLen);
#endif // !PLATFORM_UNIX
    return result;
}

std::vector<unsigned char> BcryptECDiffieHellman::ExportSubjectPublicKeyInfo() const
{
	std::vector<unsigned char> result;
#ifndef PLATFORM_UNIX
    DWORD publicKeyBlobLen = 0;
    NTSTATUS status = STATUS_SUCCESS;
    CRYPT_ECC_PRIVATE_KEY_INFO eccPrivateInfo = { 0 };
    CRYPT_PRIVATE_KEY_INFO privateKeyInfo = { 0 };
    DWORD privateKeyInfoLen = 0;
    BYTE* pbCurveParameters = nullptr;
    DWORD cbCurveParameters = 0;
    BCRYPT_ECCKEY_BLOB* pekb = nullptr;
    CERT_PUBLIC_KEY_INFO publicKeyInfo = { 0 };
    union {
        PVOID pvStructInfo;
        PCERT_INFO pCertInfo;
        PCERT_PUBLIC_KEY_INFO PublicKeyInfo;
    };
    // Get the size of the public key blob
    status = BCryptExportKey(this->hEccKeyHandle, NULL, BCRYPT_ECCPUBLIC_BLOB, NULL, 0, &publicKeyBlobLen, 0);
    if (status != STATUS_SUCCESS) {
        // LibraryError, Bcrypt subclass, keyError
        throw BcryptError(status, "BCryptExportKey - Get Size - failed.\n",
            ErrorCode::LibraryError_Bcrypt_keyError);
    }
    unsigned char* publicKeyBlob = (unsigned char*)malloc(publicKeyBlobLen);
    if (publicKeyBlob == NULL) {
		// GenericError, Memory subclass, mallocError
        throw std::exception("ECDH - Malloc Fail");
    }
    // Export the public key blob
    status = BCryptExportKey(this->hEccKeyHandle, NULL, BCRYPT_ECCPUBLIC_BLOB, publicKeyBlob, publicKeyBlobLen, &publicKeyBlobLen, 0);
    if (status != STATUS_SUCCESS) {
		// LibraryError, Bcrypt subclass, keyError
        throw BcryptError(status, "BCryptExportKey - Export Key - failed.\n",
            ErrorCode::LibraryError_Bcrypt_keyError);
    }

    pekb = (BCRYPT_ECCKEY_BLOB*)publicKeyBlob;

    CRYPT_BIT_BLOB CryptBitBlob = { 0 };
    CryptBitBlob.cbData = 1;
    CryptBitBlob.pbData = (BYTE*)malloc(1);
    CryptBitBlob.pbData[0] = CERT_KEY_AGREEMENT_KEY_USAGE;
    CryptBitBlob.cUnusedBits = 0;
    // Get the size of the curve parameters
    status = BCryptGetProperty(
        this->hEccKeyHandle,
        BCRYPT_ECC_PARAMETERS,
        NULL,                       // pbOutput
        0,                          // cbOutput
        &cbCurveParameters,
        0                           // dwFlags
    );
    if (status != STATUS_SUCCESS) {
		// LibraryError, Bcrypt subclass, propertyError
        throw BcryptError(status, "BCryptGetProperty Size failed.\n",
            ErrorCode::LibraryError_Bcrypt_propertyError);
    }

    pbCurveParameters = (BYTE*)malloc(cbCurveParameters);
    if (pbCurveParameters == nullptr) {
        // GenericError, Memory subclass, mallocError
        throw std::exception("ECDH - Malloc Failed");
    }
    // Get the curve parameters
    status = BCryptGetProperty(
        this->hEccKeyHandle,
        BCRYPT_ECC_PARAMETERS,
        pbCurveParameters,
        cbCurveParameters,
        &cbCurveParameters,
        0);
    if (status != STATUS_SUCCESS) {
		// LibraryError, Bcrypt subclass, propertyError
        throw BcryptError(status, "BCryptGetProperty Value failed.\n",
            ErrorCode::LibraryError_Bcrypt_propertyError);
    }

    CRYPT_DATA_BLOB CNGECCBlob = { 0 };
    CNGECCBlob.cbData = cbCurveParameters;
    CNGECCBlob.pbData = pbCurveParameters;
    ULONG cbCurveInfo = 0;

    if (!CryptEncodeObject(
        X509_ASN_ENCODING,
        X509_ECC_PARAMETERS,
        &CNGECCBlob,
        NULL,
        &cbCurveInfo))
    {
        // ParsingError, ASN subclass, x509PubKeyError
        throw WinCryptError("CryptEncodeObject 1 failed.", GetLastError(),
            ErrorCode::ParsingError_Asn1_x509PubKeyError);
    }

    ULONG cbPupKeyInfo = sizeof(publicKeyInfo) + sizeof(szOID_ECC_PUBLIC_KEY);

    cbPupKeyInfo += cbCurveInfo;

    publicKeyInfo.PublicKey.cbData = pekb->cbKey * EC_PUBLIC_NUM_COMPONENTS + 1;
    publicKeyInfo.PublicKey.cUnusedBits = 0;
    publicKeyInfo.PublicKey.pbData = (BYTE*)malloc(publicKeyInfo.PublicKey.cbData);
    if (publicKeyInfo.PublicKey.pbData == NULL) {
		// GenericError, Memory subclass, mallocError
        throw std::exception("ECDH - Malloc Fail");
    }
    ZeroMemory(publicKeyInfo.PublicKey.pbData, publicKeyInfo.PublicKey.cbData);
    publicKeyInfo.PublicKey.pbData[0] = EC_UNCOMPRESSED_BLOB;
    CopyMemory(
		publicKeyInfo.PublicKey.pbData + 1, pekb + 1, pekb->cbKey * EC_PUBLIC_NUM_COMPONENTS);
    publicKeyInfo.Algorithm.Parameters.cbData = cbCurveInfo;
    publicKeyInfo.Algorithm.Parameters.pbData = (BYTE*)malloc(publicKeyInfo.Algorithm.Parameters.cbData);
    if (publicKeyInfo.Algorithm.Parameters.pbData == NULL) {
        // GenericError, Memory subclass, mallocError
        throw std::exception("ECDH - Malloc Fail");
    }
    publicKeyInfo.Algorithm.pszObjId = (LPSTR)malloc(sizeof(szOID_ECC_PUBLIC_KEY));
    if (publicKeyInfo.Algorithm.pszObjId == NULL) {
        // GenericError, Memory subclass, mallocError
        throw std::exception("ECDH - Malloc Fail");
    }
    ZeroMemory(publicKeyInfo.Algorithm.Parameters.pbData, publicKeyInfo.Algorithm.Parameters.cbData);
    if (!CryptEncodeObject(
        X509_ASN_ENCODING,
        X509_ECC_PARAMETERS,
        &CNGECCBlob,
        publicKeyInfo.Algorithm.Parameters.pbData,
        &publicKeyInfo.Algorithm.Parameters.cbData))
    {
        // ParsingError, ASN subclass, x509PubKeyError
        throw WinCryptError("CryptEncodeObject 2 failed.", GetLastError(),
            ErrorCode::ParsingError_Asn1_x509PubKeyError);
    }
    CopyMemory(
		publicKeyInfo.Algorithm.pszObjId,
		szOID_ECC_PUBLIC_KEY,
		sizeof(szOID_ECC_PUBLIC_KEY));

	ULONG derPublicBytesLen = 0;
	unsigned char* derPublicBytes = nullptr;
    if (!CryptEncodeObjectEx(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        X509_PUBLIC_KEY_INFO,
        (BYTE*)(&publicKeyInfo),
        CRYPT_ENCODE_ALLOC_FLAG,
        NULL,
        &derPublicBytes, &derPublicBytesLen))
    {
		// ParsingError, ASN subclass, x509PubKeyError
        throw WinCryptError("CryptEncodeObjectEx 1 failed.", GetLastError(),
            ErrorCode::ParsingError_Asn1_x509PubKeyError);
	}
	result = std::vector<unsigned char>(derPublicBytes, derPublicBytes + derPublicBytesLen);
#endif // !PLATFORM_UNIX
	return result;
}

BCRYPT_SECRET_HANDLE BcryptECDiffieHellman::DeriveSecret(ECDiffieHellman &otherParty)
{
#ifndef PLATFORM_UNIX
	BCRYPT_SECRET_HANDLE hSecret;
	NTSTATUS status = BCryptSecretAgreement(this->hEccKeyHandle, otherParty.GetPublicKeyHandle(), &(this->hSharedSecret), 0);
    if (status != STATUS_SUCCESS) {
		// CryptographyError, ECC subclass, keyGenerationError
		throw BcryptError(status, "BCryptSecretAgreement failed.\n",
            ErrorCode::CryptographyError_ECC_keyGenError);
	}
#endif // !PLATFORM_UNIX
    return this->hSharedSecret;
}

BCRYPT_KEY_HANDLE BcryptECDiffieHellman::GetPublicKeyHandle(void) const {
    return this->hEccKeyHandle;
}