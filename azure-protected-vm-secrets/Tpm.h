#pragma once
#include "Tss2Wrapper.h"
#include <memory>
#include <vector>

class Tpm
{
public:
    Tpm();
    std::vector<unsigned char> RsaDecrypt(std::vector<unsigned char> const&encryptedData);

private:
    std::unique_ptr<Tss2Wrapper> tssWrapper;
};