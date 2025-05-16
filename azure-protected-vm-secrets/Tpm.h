#pragma once
#include "Tss2Wrapper.h"
#include <memory>
#include <vector>

constexpr auto HCL_REPORT_INDEX = 0x01400001;

class Tpm
{
public:
    Tpm();
    std::vector<unsigned char> RsaDecrypt(std::vector<unsigned char> const&encryptedData);
    std::vector<unsigned char> ReadHclReport();

private:
    std::unique_ptr<Tss2Wrapper> tssWrapper;
};