//-------------------------------------------------------------------------------------------------
// <copyright file="Tss2Util.h" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------
#include <vector>
#include <tss2/tss2_esys.h>

#include "AttestationTypes.h"
#include "Tss2Ctx.h"
#include "Tss2Memory.h"

// TCG spec-defined constants
constexpr auto EK_CERT_INDEX = 0x01c00002;
constexpr auto EK_NONCE_INDEX = 0x01c00003;
constexpr auto EK_TEMPLATE_INDEX = 0x01c00004;
constexpr auto AIK_CERT_INDEX = 0x01C101D0;
constexpr auto HCL_REPORT_INDEX = 0x01400001;

// Index to persist ek pub after generation. Using the same index as the Windows Urchin library,
// but the decision is arbitrary.
constexpr auto EK_PUB_INDEX = 0x81010000 + 1;
constexpr auto AIK_PUB_INDEX = 0x81000000 + 3;
constexpr auto SRK_PUB_INDEX = 0x81000000 + 1;

class Tss2Util
{
public:
    /**
     * Generates the manufacturer defined EK but do not persistes it
     *
     * returns: unique_ptr to the TPM2B_PUBLIC structure containing the EKpub
     */
    static unique_c_ptr<TPM2B_PUBLIC> GenerateEk(Tss2Ctx& ctx);

    /**
     * Generates the manufacturer defined EK and persistes it to EK_PUB_INDEX
     *
     * returns: unique_ptr to the TPM2B_PUBLIC structure containing the EKpub
     */
    static unique_c_ptr<TPM2B_PUBLIC> GenerateAndPersistEk(Tss2Ctx& ctx);

    /**
     * Gets the public object at handle `index`
     */
    static std::vector<unsigned char> GetPublicObject(Tss2Ctx& ctx, TPM2_HANDLE index);

    /**
     * Reads the data at NV index `index`
     */
    static std::vector<unsigned char> NvRead(Tss2Ctx& ctx, TPM2_HANDLE index);

    /**
     * Opens an ESYS handle for a given handle index
     */
    static unique_esys_tr HandleToEsys(Tss2Ctx& ctx, TPM2_HANDLE index);

    /**
     * Converts hashAlg to libtss format
     *
     * param[in] hashAlg: A hash algorithm
     *
     * returns A hash algorithm format understood by tpm2-tss
     */
    static TPMI_ALG_HASH GetTssHashAlg(attest::HashAlg hashAlg);

    /**
     * Generates a digest of the PCR values in pcrSet by hashing each PCR digest using
     * hashAlg
     *
     * param[in] pcrSet: A list of PCR indices and their digests for a PCR bank
     * param[in] hashAlg: Hash algorithm to use to generate the digest
     *
     * returns: Digest of the PCR values in pcrSet
     */
    static unique_c_ptr<TPM2B_DIGEST> GeneratePcrDigest(
            const attest::PcrSet& pcrSet,
            attest::HashAlg hashAlg);

    /**
     * Convert pcrSet to a format tpm2-tss understands
     *
     * param[in] ctx: wrapper for the TPM2 TSS context which is passed with each TPM2 API call
     * param[in] pcrSet: The PCR indices being used.
     * param[in] hashAlg: The hash algorithm for the PCR bank the pcrSet refers to
     *
     * returns: Smart pointer to the TSS PCR selection struct
     */
    static unique_c_ptr<TPML_PCR_SELECTION> GetTssPcrSelection(
            Tss2Ctx& ctx,
            const attest::PcrSet& pcrSet,
            attest::HashAlg hashAlg);

    /**
     * Gets number of PCRs implemented by TPM
     *
     * param[in] ctx: wrapper for the TPM2 TSS context which is passed with each TPM2 API call
     *
     * returns: number of PCRs implemented by TPM chip
     */
    static uint8_t GetPcrCount(Tss2Ctx& ctx);

    /**
     * Get and populate the digest for each pcr
     *
     * param[in] ctx: wrapper for the TPM2 TSS context which is passed with each TPM2 API call
     * param[in] pcrSet: The PCR indices being used.
     *
     * returns: by reference, digest values for each pcr in pcrSet.pcrs
     */
    static void PopulateCurrentPcrs(Tss2Ctx& ctx, attest::PcrSet& pcrSet);

    /**
     * Populate the Public object to be used for the ephemeral key creation.
     *
     * param[in] ctx: wrapper for the TPM2 TSS context which is passed with each TPM2 API call.
     * param[in] pcrSet: Pcr values to be used for generating the ephemeral key policy digest.
     * param[in] inPub: The TPM2B_PUBLIC object that will be populated.
     *
     * returns: by reference, Populated inPub object
     */
    static void PopulateEphemeralKeyPublicTemplate(Tss2Ctx& ctx,
                                                   const attest::PcrSet& pcrSet,
                                                   TPM2B_PUBLIC& inPub);

    /**
     * Generate and return the policy digest to be set for creation of the ephe,eral key.
     *
     * param[in] ctx: wrapper for the TPM2 TSS context which is passed with each TPM2 API call
     * param[in] pcrSet: Pcr values to be used for generating the policy digest.
     *
     * returns: TPM2B_DIGEST object.
     */
    static unique_c_ptr<TPM2B_DIGEST> GetEphemeralKeyPolicyDigest(Tss2Ctx& ctx,
                                                                  const attest::PcrSet& pcrSet);

    /**
     * Create an ephemeral key with the given pcrSet values.
     *
     * param[in] ctx: wrapper for the TPM2 TSS context which is passed with each TPM2 API call
     * param[in] pcrSet: Pcr values to be used for generating the policy digest.
     * param[out] outPub: TPM2B_PUBIC object of the created key.
     *
     * returns: ESYS_TR handle of the created key.
     */
    static ESYS_TR CreateEphemeralKey(Tss2Ctx& ctx,
                                      const attest::PcrSet& pcrSet,
                                      TPM2B_PUBLIC** outPub);

    /**
     * Flush the context of the given handle from tpm.
     *
     * param[in] ctx: wrapper for the TPM2 TSS context which is passed with each TPM2 API call
     * param[in] handle: Handle of the object whose context needs to be flushed.
     *
     */
    static void FlushObjectContext(Tss2Ctx& ctx, ESYS_TR handle);

    /**
     * Undefines NV space at NV index 'index'
     *
     * param[in] ctx: wrapper for the TPM2 TSS context which is passed with each TPM2 API call
     * param[in] index: the NV index
     *
     */
    static void NvUndefineSpace(Tss2Ctx& ctx, TPM2_HANDLE index);

    /**
     * Defines NV space at NV index 'index'
     *
     * param[in] ctx: wrapper for the TPM2 TSS context which is passed with each TPM2 API call
     * param[in] index: the NV index
     * param[in] size: the size of the NV space
     *
     */
    static void NvDefineSpace(Tss2Ctx& ctx, TPM2_HANDLE index, int size);

    /**
     * Writes the data at NV index 'index'
     *
     * param[in] ctx: wrapper for the TPM2 TSS context which is passed with each TPM2 API call
     * param[in] index: the NV index
     * param[in] data: the data to be written on the NV index 'index'
     *
     */
    static void NvWrite(Tss2Ctx& ctx, TPM2_HANDLE index, const std::vector<unsigned char> data);
};
