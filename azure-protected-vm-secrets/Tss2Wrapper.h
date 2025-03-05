#pragma once
#include "TssCtx.h"
#include <vector>
#include <memory>
class Tss2Wrapper
{
public:
    Tss2Wrapper();
    ~Tss2Wrapper() {}
    std::vector<unsigned char> Tss2RsaDecrypt(std::vector<unsigned char> const&encryptedData);
    std::vector<unsigned char> Tss2RsaEncrypt(std::vector<unsigned char> const&plaintextData);
    TPM2B_PUBLIC* GenerateGuestKey();
    TPM2_RC RemoveKey();
    bool IsKeyPresent();

private:
    std::unique_ptr<TssCtx> ctx;

};