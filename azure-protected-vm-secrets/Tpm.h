// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once
#include <memory>
#include <vector>
#include "CommonTypes.h"
#include "Tss2Wrapper.h"

constexpr auto HCL_REPORT_INDEX = 0x01400001;

class Tpm
{
public:
    Tpm();
    std::vector<unsigned char> RsaDecrypt(std::vector<unsigned char> const&encryptedData,
                                          RsaPaddingScheme paddingScheme = RsaPaddingScheme::Rsaes);
    std::vector<unsigned char> ReadHclReport();

private:
    std::unique_ptr<Tss2Wrapper> tssWrapper;
};