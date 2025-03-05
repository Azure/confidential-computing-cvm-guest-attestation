#include "pch.h"
#include <memory>
#include <vector>
#include "Tpm.h"
#include "Tss2Wrapper.h"
#include "LibraryLogger.h"

using namespace SecretsLogger;

Tpm::Tpm()
{
    this->tssWrapper = std::make_unique<Tss2Wrapper>();
}

std::vector<unsigned char> Tpm::RsaDecrypt(std::vector<unsigned char> const&encryptedData) {
    
    std::vector<unsigned char> decryptedData = this->tssWrapper->Tss2RsaDecrypt(encryptedData);
    if (decryptedData.size() == 0) {
        LIBSECRETS_LOG(LogLevel::Warning, "TPM Decryption", "Decrypted data is 0 Length");
    }
    LIBSECRETS_LOG(LogLevel::Debug, "Completed Decryption", "Decrypted data: %s", decryptedData.data());
    return decryptedData;
}