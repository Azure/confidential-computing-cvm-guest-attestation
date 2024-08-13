//------------------------------------------------------------------------------------------------- 
// <copyright file="Tss2Util.h" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------
#include <vector>

#include "AttestationTypes.h"
#include "Tss2Ctx.h"

class TestUtil
{
public:
    static void PopulateCurrentPcrs(Tss2Ctx& ctx, attest::PcrSet& pcrSet);

    static void SealSeedToEk(
            Tss2Ctx& ctx,
            attest::PcrSet& pcrSet,
            attest::HashAlg hashAlg,
            std::vector<unsigned char>& clearKey,
            std::vector<unsigned char>& outPub,
            std::vector<unsigned char>& outPriv,
            std::vector<unsigned char>& encryptedSeed,
            bool useStoredEk);
};
