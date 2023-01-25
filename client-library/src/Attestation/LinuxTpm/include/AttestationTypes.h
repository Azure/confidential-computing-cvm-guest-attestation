//-------------------------------------------------------------------------------------------------
// <copyright file="AttestationTypes.h" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------

#pragma once

#include <vector>
#include <stdint.h>

namespace attest
{

enum TpmVersion
{
    V1_2,
    V2_0
};

struct RsaPublicKey
{
    uint16_t bitLength;
    std::vector<unsigned char> exponent;
    std::vector<unsigned char> modulus;
};

enum HashAlg
{
    Sha1,
    Sha256,
    Sha384,
    Sha512,
    Sm3_256
};

using PcrList = std::vector<uint8_t>;
using Buffer = std::vector<unsigned char>;

struct PcrValue
{
    uint8_t index;
    std::vector<unsigned char> digest;
};

struct PcrSet
{
    HashAlg hashAlg;
    std::vector<PcrValue> pcrs;
};

struct PcrQuote
{
    std::vector<unsigned char> quote;
    std::vector<unsigned char> signature;
};

struct EphemeralKey
{
    std::vector<unsigned char> encryptionKey;
    std::vector<unsigned char> certifyInfo;
    std::vector<unsigned char> certifyInfoSignature;
};

} // end attest
