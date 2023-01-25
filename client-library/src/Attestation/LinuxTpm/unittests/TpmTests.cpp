//-------------------------------------------------------------------------------------------------
// <copyright file="TpmTests.cpp" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <cstring>
#include <iostream>
#include <numeric>

#include "Exceptions.h"
#include "Tss2Util.h"
#include "TpmMocks.h"
#include "TpmMockData.h"

using ::testing::_;
using ::testing::DoAll;
using ::testing::Mock;
using ::testing::Return;
using ::testing::SetArgPointee;

// Must be global because it is accessed in mocked C functions
std::shared_ptr<TpmLibMock> tpmLibMockObj;

class TpmTest : public ::testing::Test
{
protected:
    std::shared_ptr<Tpm> tpm;

    TpmTest() {

    }
    virtual ~TpmTest() {}

    // Runs before each test case
    void SetUp() override
    {
        tpm = std::make_shared<Tpm>();
        tpmLibMockObj = std::make_shared<TpmLibMock>();
    }

    // Runs after each test case
    void TearDown() override
    {
        EXPECT_TRUE(Mock::VerifyAndClearExpectations(tpmLibMockObj.get()));
        tpm.reset();
        tpmLibMockObj.reset();
    }
};

/**
 * Tests retrieving an EK cert when one exists
 */
TEST_F(TpmTest, GetEkNvCert_positive)
{
    //
    // Mock data/functions
    //
    // Malloc packets so the GetEkNvCert code that calls free doesn't crash
    auto ek_cert_packet_1 = (TPM2B_MAX_NV_BUFFER*)calloc(1,sizeof(TPM2B_MAX_NV_BUFFER));
    auto ek_cert_packet_2 = (TPM2B_MAX_NV_BUFFER*)calloc(1,sizeof(TPM2B_MAX_NV_BUFFER));
    auto ek_cert_packet_3 = (TPM2B_MAX_NV_BUFFER*)calloc(1,sizeof(TPM2B_MAX_NV_BUFFER));
    ek_cert_packet_1->size = MOCK_EK_CERT_PACKET_SIZE;
    ek_cert_packet_2->size = MOCK_EK_CERT_PACKET_SIZE;
    ek_cert_packet_3->size = MOCK_EK_CERT_PACKET_SIZE;

    ek_cert_packet_1->buffer[0] = 1; // Make sure these buffers are actually being used

    auto ek_cert_nv_pub = (TPM2B_NV_PUBLIC*)calloc(1,sizeof(TPM2B_NV_PUBLIC));
    ek_cert_nv_pub->size = sizeof(TPMS_NV_PUBLIC);
    ek_cert_nv_pub->nvPublic.dataSize = MOCK_EK_CERT_SIZE;

    EXPECT_CALL(*tpmLibMockObj, Esys_TR_FromTPMPublic(_,EK_CERT_INDEX,ESYS_TR_NONE,ESYS_TR_NONE,ESYS_TR_NONE,_))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<5>(MOCK_HANDLE), Return(0)));

    EXPECT_CALL(*tpmLibMockObj, Esys_NV_ReadPublic(_,MOCK_HANDLE,ESYS_TR_NONE,ESYS_TR_NONE,ESYS_TR_NONE,_,_))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<5>(ek_cert_nv_pub), Return(0)));

    EXPECT_CALL(*tpmLibMockObj, Esys_NV_Read(_,_,MOCK_HANDLE,ESYS_TR_PASSWORD,ESYS_TR_NONE,ESYS_TR_NONE,_,_,_))
        .Times(MOCK_EK_CERT_SIZE/MOCK_EK_CERT_PACKET_SIZE)
        .WillOnce(DoAll(SetArgPointee<8>(ek_cert_packet_1), Return(0)))
        .WillOnce(DoAll(SetArgPointee<8>(ek_cert_packet_2), Return(0)))
        .WillOnce(DoAll(SetArgPointee<8>(ek_cert_packet_3), Return(0)));

    //
    // GetEkNvCert
    //
    auto ekCert = tpm->GetEkNvCert();
    EXPECT_EQ(ekCert.size(), MOCK_EK_CERT_SIZE);
    EXPECT_EQ(ekCert[0], 1);
    EXPECT_TRUE(std::all_of(ekCert.begin()+1, ekCert.end(), [](unsigned char c) { return c == 0; }));
}

/**
 * Test trying to get the EK cert when one does not exist on the TPM
 */
TEST_F(TpmTest, GetEkNvCert_negative)
{
    EXPECT_CALL(*tpmLibMockObj, Esys_TR_FromTPMPublic(_,_,_,_,_,_))
        .Times(1)
        .WillOnce(Return(TPM2_RC_REFERENCE_H0));

    bool success = true;
    try {
        auto ekCert = tpm->GetEkNvCert();
    } catch (Tss2Exception& e) {
        success = false;
        EXPECT_EQ(e.get_rc(), TPM2_RC_REFERENCE_H0);
    }
    EXPECT_FALSE(success);
}

/**
 * Test getting Ek public portion when it is already persisted in NVRAM
 */
TEST_F(TpmTest, GetEkPub_Exists)
{
    //
    // Mock data/functions
    //
    // malloc TPM2B_PUBLIC so it can be freed
    auto ek_pub = (TPM2B_PUBLIC*)calloc(1,sizeof(TPM2B_PUBLIC));
    ek_pub->size = MOCK_TPM_PUBLIC_SIZE;

    // Set the alg types to a specific value since Marshalling of the structure requires a valid alg to set in the structure.
    ek_pub->publicArea.type = TPM2_ALG_NULL;
    ek_pub->publicArea.nameAlg = TPM2_ALG_NULL;

    EXPECT_CALL(*tpmLibMockObj, Esys_TR_FromTPMPublic(_,EK_PUB_INDEX,ESYS_TR_NONE,ESYS_TR_NONE,ESYS_TR_NONE,_))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<5>(MOCK_HANDLE), Return(0)));

    EXPECT_CALL(*tpmLibMockObj, Esys_ReadPublic(_,MOCK_HANDLE,ESYS_TR_NONE,ESYS_TR_NONE,ESYS_TR_NONE,_,_,_))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<5>(ek_pub), Return(0)));

    // Expect no call since ekpub is in NVRAM
    EXPECT_CALL(*tpmLibMockObj, Esys_CreatePrimary(_))
            .Times(0);
    EXPECT_CALL(*tpmLibMockObj, Esys_EvictControl(_, _, _, _, _, _, _, _))
            .Times(0);

    //
    // GetEkPub
    //
    auto ekPub = tpm->GetEkPub();
    EXPECT_EQ(ekPub.size(), MOCK_TPM_PUBLIC_SIZE + sizeof(ek_pub->size));
}

/**
 * Test getting Ek Public portion when it is not yet persisted and needs to be
 * generated.
 */
TEST_F(TpmTest, GetEkPub_Generate)
{
    //
    // Mock data/functions
    //
    auto ek_pub = (TPM2B_PUBLIC*)calloc(1,sizeof(TPM2B_PUBLIC));
    ek_pub->size = MOCK_TPM_PUBLIC_SIZE;

    // Set the alg types to a specific value since Marshalling of the structure requires a valid alg to set in the structure.
    ek_pub->publicArea.type = TPM2_ALG_NULL;
    ek_pub->publicArea.nameAlg = TPM2_ALG_NULL;

    ESYS_CREATEPRIMARY_PARAMS params;
    params.outPublic = &ek_pub;

    EXPECT_CALL(*tpmLibMockObj, Esys_TR_FromTPMPublic(_,_,_,_,_,_))
        .Times(3)
        .WillOnce(Return(TPM2_RC_HANDLE)) // Fail to find ekpub
        .WillOnce(Return(TPM2_RC_HANDLE)) // Fail to find ek template
        .WillOnce(Return(TPM2_RC_HANDLE)); // Fail to find ek nonce

    // Create primary is mocked using a struct for input parameters
    EXPECT_CALL(*tpmLibMockObj, Esys_CreatePrimary(_))
        .WillOnce(DoAll(SetArgPointee<0>(params), Return(0)));

    // Evict control is mocked using a struct for input parameters
    EXPECT_CALL(*tpmLibMockObj, Esys_EvictControl(_,_,_,_,_,_,_,_))
        .WillOnce(Return(0));

    auto ekPub = tpm->GetEkPub();
    EXPECT_EQ(ekPub.size(), MOCK_TPM_PUBLIC_SIZE + sizeof(ek_pub->size));
}

/**
 * Test getting Ek Public portion when it is not yet persisted and needs to be
 * generated but generation fails.
 */
TEST_F(TpmTest, GetEkPub_FailGenerate)
{
    EXPECT_CALL(*tpmLibMockObj, Esys_TR_FromTPMPublic(_,_,_,_,_,_))
        .Times(3)
        .WillOnce(Return(TPM2_RC_HANDLE)) // Fail to find ekpub
        .WillOnce(Return(TPM2_RC_HANDLE)) // Fail to find ek template
        .WillOnce(Return(TPM2_RC_HANDLE)); // Fail to find ek nonce
    EXPECT_CALL(*tpmLibMockObj, Esys_CreatePrimary(_))
        .WillOnce(Return(1));
    EXPECT_CALL(*tpmLibMockObj, Esys_EvictControl(_, _, _, _, _, _, _, _))
        .Times(0);

    bool success = true;
    try {
        auto ekPub = tpm->GetEkPub();
    } catch (Tss2Exception& e) {
        success = false;
        EXPECT_EQ(e.get_rc(), 1);
    }
    EXPECT_FALSE(success);
}


// Helper Ek Template matcher for the following test
MATCHER(HasEkTemplate, "") {
    return arg->inPublic->publicArea.unique.rsa.buffer[0] == 1 &&
           arg->inPublic->publicArea.type == 0x10;
}

/**
 * Test getting Ek Public portion when it is not yet persisted and needs to be
 * generated. Override default inPublic with EK template and nonce in NVRAM.
 */
TEST_F(TpmTest, GetEkPub_PopulateTemplate)
{
    // NV_BUFFER packets for ek template and ek nonce
    auto ek_template_packet = (TPM2B_MAX_NV_BUFFER*)calloc(1,sizeof(TPM2B_MAX_NV_BUFFER));
    ek_template_packet->size = sizeof(TPMT_PUBLIC);

    auto ek_nonce_packet = (TPM2B_MAX_NV_BUFFER*)calloc(1,sizeof(TPM2B_MAX_NV_BUFFER));
    ek_nonce_packet->size = 1;

    // Set type to 0x10 in the TPMT_PUBLIC structure to provide a valid alg id to the structure. The
    // first byte is set since unmarshal function populates the structure in Big Endian format.
    ek_template_packet->buffer[1] = 0x10;

    // Set nonce to 1
    ek_nonce_packet->buffer[0] = 1;


    // NV_PUBLIC structures for ek nonce and ek template
    auto ek_template_nv_pub = (TPM2B_NV_PUBLIC*)calloc(1,sizeof(TPM2B_NV_PUBLIC));
    ek_template_nv_pub->size = sizeof(TPMS_NV_PUBLIC);
    ek_template_nv_pub->nvPublic.dataSize = sizeof(TPMT_PUBLIC);

    auto ek_nonce_nv_pub = (TPM2B_NV_PUBLIC*)calloc(1,sizeof(TPM2B_NV_PUBLIC));
    ek_nonce_nv_pub->size = sizeof(TPMS_NV_PUBLIC);
    ek_nonce_nv_pub->nvPublic.dataSize = 1;

    // EK pub output
    auto ek_pub = (TPM2B_PUBLIC*)calloc(1,sizeof(TPM2B_PUBLIC));
    ek_pub->size = MOCK_TPM_PUBLIC_SIZE;

    // Set the alg types to a specific value since Marshalling of the structure requires a valid alg to set in the structure.
    ek_pub->publicArea.type = TPM2_ALG_NULL;
    ek_pub->publicArea.nameAlg = TPM2_ALG_NULL;

    ESYS_CREATEPRIMARY_PARAMS params;
    params.outPublic = &ek_pub;

    EXPECT_CALL(*tpmLibMockObj, Esys_TR_FromTPMPublic(_,_,ESYS_TR_NONE,ESYS_TR_NONE,ESYS_TR_NONE,_))
        .Times(3)
        .WillOnce(Return(TPM2_RC_HANDLE)) // Fail to find ekpub
        .WillOnce(Return(0)) // Find ek template
        .WillOnce(Return(0)); // Find ek nonce

    EXPECT_CALL(*tpmLibMockObj, Esys_NV_ReadPublic(_,_,ESYS_TR_NONE,ESYS_TR_NONE,ESYS_TR_NONE,_,_))
        .Times(2)
        .WillOnce(DoAll(SetArgPointee<5>(ek_template_nv_pub), Return(0)))
        .WillOnce(DoAll(SetArgPointee<5>(ek_nonce_nv_pub), Return(0)));

    EXPECT_CALL(*tpmLibMockObj, Esys_NV_Read(_,_,_,ESYS_TR_PASSWORD,ESYS_TR_NONE,ESYS_TR_NONE,_,_,_))
        .Times(2)
        .WillOnce(DoAll(SetArgPointee<8>(ek_template_packet), Return(0)))
        .WillOnce(DoAll(SetArgPointee<8>(ek_nonce_packet), Return(0)));

    EXPECT_CALL(*tpmLibMockObj, Esys_CreatePrimary(HasEkTemplate()))
            .Times(1)
            .WillOnce(DoAll(SetArgPointee<0>(params), Return(0)));

    EXPECT_CALL(*tpmLibMockObj, Esys_EvictControl(_, _, _, _, _, _, _, _))
        .WillOnce(Return(0));

    // Don't bother validating ekPub, that is done in the Generate test
    auto ekPub = tpm->GetEkPub();
}

/**
 * Test getting Ek Public portion without persist.
 */
TEST_F(TpmTest, GetEkPub_WithoutPersisting)
{
    //
    // Mock data/functions
    //
    auto ek_pub = (TPM2B_PUBLIC*)calloc(1, sizeof(TPM2B_PUBLIC));
    ek_pub->size = MOCK_TPM_PUBLIC_SIZE;

    // Set the alg types to a specific value since Marshalling of the structure requires a valid alg to set in the structure.
    ek_pub->publicArea.type = TPM2_ALG_NULL;
    ek_pub->publicArea.nameAlg = TPM2_ALG_NULL;

    ESYS_CREATEPRIMARY_PARAMS params;
    params.outPublic = &ek_pub;

    EXPECT_CALL(*tpmLibMockObj, Esys_TR_FromTPMPublic(_, _, _, _, _, _))
        .Times(2)
        .WillOnce(Return(TPM2_RC_HANDLE)) // Fail to find ek template
        .WillOnce(Return(TPM2_RC_HANDLE)); // Fail to find ek nonce

    // Create primary is mocked using a struct for input parameters
    EXPECT_CALL(*tpmLibMockObj, Esys_CreatePrimary(_))
        .WillOnce(DoAll(SetArgPointee<0>(params), Return(0)));

    // Evict control is mocked using a struct for input parameters
    EXPECT_CALL(*tpmLibMockObj, Esys_EvictControl(_, _, _, _, _, _, _, _))
        .Times(0);

    auto ekPub = tpm->GetEkPubWithoutPersisting();
    EXPECT_EQ(ekPub.size(), MOCK_TPM_PUBLIC_SIZE + sizeof(ek_pub->size));
}

/**
 * Tests retrieving an AIK cert when one exists
 */
TEST_F(TpmTest, GetAIKCert_positive)
{
    //
    // Mock data/functions
    //
    // Malloc packets so the GetAIKCert code that calls free doesn't crash
    auto aik_cert_packet_1 = (TPM2B_MAX_NV_BUFFER*)calloc(1,sizeof(TPM2B_MAX_NV_BUFFER));
    auto aik_cert_packet_2 = (TPM2B_MAX_NV_BUFFER*)calloc(1,sizeof(TPM2B_MAX_NV_BUFFER));
    auto aik_cert_packet_3 = (TPM2B_MAX_NV_BUFFER*)calloc(1,sizeof(TPM2B_MAX_NV_BUFFER));
    aik_cert_packet_1->size = MOCK_AIK_CERT_PACKET_SIZE;
    aik_cert_packet_2->size = MOCK_AIK_CERT_PACKET_SIZE;
    aik_cert_packet_3->size = MOCK_AIK_CERT_PACKET_SIZE;

    aik_cert_packet_1->buffer[0] = 1; // Make sure these buffers are actually being used

    auto aik_cert_nv_pub = (TPM2B_NV_PUBLIC*)calloc(1,sizeof(TPM2B_NV_PUBLIC));
    aik_cert_nv_pub->size = sizeof(TPMS_NV_PUBLIC);
    aik_cert_nv_pub->nvPublic.dataSize = MOCK_AIK_CERT_SIZE;

    EXPECT_CALL(*tpmLibMockObj, Esys_TR_FromTPMPublic(_,AIK_CERT_INDEX,ESYS_TR_NONE,ESYS_TR_NONE,ESYS_TR_NONE,_))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<5>(MOCK_HANDLE), Return(0)));

    EXPECT_CALL(*tpmLibMockObj, Esys_NV_ReadPublic(_,MOCK_HANDLE,ESYS_TR_NONE,ESYS_TR_NONE,ESYS_TR_NONE,_,_))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<5>(aik_cert_nv_pub), Return(0)));

    EXPECT_CALL(*tpmLibMockObj, Esys_NV_Read(_,_,MOCK_HANDLE,ESYS_TR_PASSWORD,ESYS_TR_NONE,ESYS_TR_NONE,_,_,_))
        .Times(MOCK_AIK_CERT_SIZE/MOCK_AIK_CERT_PACKET_SIZE)
        .WillOnce(DoAll(SetArgPointee<8>(aik_cert_packet_1), Return(0)))
        .WillOnce(DoAll(SetArgPointee<8>(aik_cert_packet_2), Return(0)))
        .WillOnce(DoAll(SetArgPointee<8>(aik_cert_packet_3), Return(0)));

    //
    // GetAIKCert
    //
    auto aikCert = tpm->GetAIKCert();
    EXPECT_EQ(aikCert.size(), MOCK_AIK_CERT_SIZE);
    EXPECT_EQ(aikCert[0], 1);
    EXPECT_TRUE(std::all_of(aikCert.begin()+1, aikCert.end(), [](unsigned char c) { return c == 0; }));
}

/**
 * Test trying to get the AIK cert when one does not exist on the TPM
 */
TEST_F(TpmTest, GetAIKCert_negative)
{
    EXPECT_CALL(*tpmLibMockObj, Esys_TR_FromTPMPublic(_,_,_,_,_,_))
        .Times(1)
        .WillOnce(Return(TPM2_RC_REFERENCE_H0));

    bool success = true;
    try {
        auto aikCert = tpm->GetAIKCert();
    } catch (Tss2Exception& e) {
        success = false;
        EXPECT_EQ(e.get_rc(), TPM2_RC_REFERENCE_H0);
    }
    EXPECT_FALSE(success);
}

/**
 * Test getting AIK public portion when it is already persisted in NVRAM
 */
TEST_F(TpmTest, GetAIKPub_positive)
{
    //
    // Mock data/functions
    //
    // malloc TPM2B_PUBLIC so it can be freed
    auto aik_pub = (TPM2B_PUBLIC*)calloc(1,sizeof(TPM2B_PUBLIC));
    aik_pub->size = MOCK_TPM_PUBLIC_SIZE;

    // Set the alg types to a specific value since Marshalling of the structure requires a valid alg to set in the structure.
    aik_pub->publicArea.type = TPM2_ALG_NULL;
    aik_pub->publicArea.nameAlg = TPM2_ALG_NULL;

    EXPECT_CALL(*tpmLibMockObj, Esys_TR_FromTPMPublic(_,AIK_PUB_INDEX,ESYS_TR_NONE,ESYS_TR_NONE,ESYS_TR_NONE,_))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<5>(MOCK_HANDLE), Return(0)));

    EXPECT_CALL(*tpmLibMockObj, Esys_ReadPublic(_,MOCK_HANDLE,ESYS_TR_NONE,ESYS_TR_NONE,ESYS_TR_NONE,_,_,_))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<5>(aik_pub), Return(0)));

    //
    // GetAIKPub
    //
    auto aikPub = tpm->GetAIKPub();
    EXPECT_EQ(aikPub.size(), MOCK_TPM_PUBLIC_SIZE + sizeof(aik_pub->size));
}

/**
 * Test trying to get the AIK pub when one does not exist on the TPM
 */
TEST_F(TpmTest, GetAIKPub_negative)
{
    EXPECT_CALL(*tpmLibMockObj, Esys_TR_FromTPMPublic(_,_,_,_,_,_))
        .Times(1)
        .WillOnce(Return(TPM2_RC_REFERENCE_H0));

    bool success = true;
    try {
        auto aikPub = tpm->GetAIKPub();
    } catch (Tss2Exception& e) {
        success = false;
        EXPECT_EQ(e.get_rc(), TPM2_RC_REFERENCE_H0);
    }
    EXPECT_FALSE(success);
}

/**
 * Test trying to get the PCR quote signed by AIK pub over the given PCRs
 */
TEST_F(TpmTest, GetPCRQuote_positive)
{
    auto quote = (TPM2B_ATTEST*)calloc(1,sizeof(TPM2B_ATTEST));
    quote->size = MOCK_TPM_PUBLIC_SIZE;
    auto signature = (TPMT_SIGNATURE*)calloc(1,sizeof(TPMT_SIGNATURE));

    // Set the sigAlg to a specific value since Marshalling of the structure requires a valid alg to set in the structure.
    signature->sigAlg = TPM2_ALG_RSASSA;

    EXPECT_CALL(*tpmLibMockObj, Esys_TR_FromTPMPublic(_,AIK_PUB_INDEX,ESYS_TR_NONE,ESYS_TR_NONE,ESYS_TR_NONE,_))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<5>(MOCK_HANDLE), Return(0)));

    // TssPcrSelection calls GetCapability to get number of PCRs implemented
    auto caps = (TPMS_CAPABILITY_DATA*)calloc(1, sizeof(TPMS_CAPABILITY_DATA));
    caps->data.tpmProperties.count = 1;
    caps->data.tpmProperties.tpmProperty[0].property = TPM2_PT_PCR_COUNT;
    caps->data.tpmProperties.tpmProperty[0].value = MOCK_MAX_PCR_COUNT;

    EXPECT_CALL(*tpmLibMockObj, Esys_GetCapability(_,ESYS_TR_NONE,ESYS_TR_NONE,ESYS_TR_NONE,TPM2_CAP_TPM_PROPERTIES,TPM2_PT_PCR_COUNT,1,_,_))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<8>(caps), Return(0)));

    EXPECT_CALL(*tpmLibMockObj, Esys_Quote(_,MOCK_HANDLE,ESYS_TR_PASSWORD,ESYS_TR_NONE,ESYS_TR_NONE,_,_,_,_,_))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<8>(quote), SetArgPointee<9>(signature), Return(0)));

    //
    // GetPCRQuote
    //
    attest::PcrList pcrs;
    attest::HashAlg hashAlg = attest::HashAlg::Sha256;
    auto pcrQuote = tpm->GetPCRQuote(pcrs, hashAlg);
    EXPECT_EQ(pcrQuote.quote.size(), MOCK_TPM_PUBLIC_SIZE + sizeof(quote->size));

    EXPECT_TRUE(std::all_of(pcrQuote.quote.begin()+sizeof(quote->size), pcrQuote.quote.end(), [](unsigned char c) { return c == 0; }));
    EXPECT_TRUE(std::all_of(pcrQuote.signature.begin()+sizeof(signature->sigAlg), pcrQuote.signature.end(), [](unsigned char c) { return c == 0; }));
}

/**
 * Test trying to get the PCR quote signed by AIK pub when AIK pub does not exist on the TPM
 */
TEST_F(TpmTest, GetPCRQuote_aikfail)
{
    EXPECT_CALL(*tpmLibMockObj, Esys_TR_FromTPMPublic(_,_,_,_,_,_))
        .Times(1)
        .WillOnce(Return(TPM2_RC_REFERENCE_H0));

    bool success = true;
    try {
        attest::PcrList pcrs;
        attest::HashAlg hashAlg = attest::HashAlg::Sha256;
        auto pcrQuote = tpm->GetPCRQuote(pcrs, hashAlg);
    } catch (Tss2Exception& e) {
        success = false;
        EXPECT_EQ(e.get_rc(), TPM2_RC_REFERENCE_H0);
    }
    EXPECT_FALSE(success);
}

TEST_F(TpmTest, GetPCRQuote_invalidpcr)
{
    auto quote = (TPM2B_ATTEST*)calloc(1,sizeof(TPM2B_ATTEST));
    quote->size = MOCK_TPM_PUBLIC_SIZE;
    auto signature = (TPMT_SIGNATURE*)calloc(1,sizeof(TPMT_SIGNATURE));

    EXPECT_CALL(*tpmLibMockObj, Esys_TR_FromTPMPublic(_,AIK_PUB_INDEX,ESYS_TR_NONE,ESYS_TR_NONE,ESYS_TR_NONE,_))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<5>(MOCK_HANDLE), Return(0)));

    // TssPcrSelection calls GetCapability to get number of PCRs implemented
    auto caps = (TPMS_CAPABILITY_DATA*)calloc(1, sizeof(TPMS_CAPABILITY_DATA));
    caps->data.tpmProperties.count = 1;
    caps->data.tpmProperties.tpmProperty[0].property = TPM2_PT_PCR_COUNT;
    caps->data.tpmProperties.tpmProperty[0].value = MOCK_MAX_PCR_COUNT;

    EXPECT_CALL(*tpmLibMockObj, Esys_GetCapability(_,ESYS_TR_NONE,ESYS_TR_NONE,ESYS_TR_NONE,TPM2_CAP_TPM_PROPERTIES,TPM2_PT_PCR_COUNT,1,_,_))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<8>(caps), Return(0)));

    bool success = true;
    try {
        attest::PcrList pcrs = {0, 8, 16, 24};
        attest::HashAlg hashAlg = attest::HashAlg::Sha256;
        auto pcrQuote = tpm->GetPCRQuote(pcrs, hashAlg);
    } catch (std::exception& e) {
        success = false;
        EXPECT_STREQ(e.what(), "PCR index out of range");
    }
    EXPECT_FALSE(success);
}

/**
 * Test trying to get the PCR digest values of the given PCRs
 */
TEST_F(TpmTest, GetPCRValues_positive)
{
    // TssPcrSelection calls GetCapability to get number of PCRs implemented
    auto caps = (TPMS_CAPABILITY_DATA*)calloc(1, sizeof(TPMS_CAPABILITY_DATA));
    caps->data.tpmProperties.count = 1;
    caps->data.tpmProperties.tpmProperty[0].property = TPM2_PT_PCR_COUNT;
    caps->data.tpmProperties.tpmProperty[0].value = MOCK_MAX_PCR_COUNT;

    EXPECT_CALL(*tpmLibMockObj, Esys_GetCapability(_,ESYS_TR_NONE,ESYS_TR_NONE,ESYS_TR_NONE,TPM2_CAP_TPM_PROPERTIES,TPM2_PT_PCR_COUNT,1,_,_))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<8>(caps), Return(0)));

    // Set PcrSelect values for mask to work with getting values for PCRs 0 thru 23
    auto pcr_sel_1 = (TPML_PCR_SELECTION*)calloc(1,sizeof(TPML_PCR_SELECTION));
    auto pcr_sel_2 = (TPML_PCR_SELECTION*)calloc(1,sizeof(TPML_PCR_SELECTION));
    auto pcr_sel_3 = (TPML_PCR_SELECTION*)calloc(1,sizeof(TPML_PCR_SELECTION));
    pcr_sel_1->count = 1;
    pcr_sel_1->pcrSelections[0].sizeofSelect = MOCK_MAX_PCR_COUNT/MOCK_PCRS_READ_COUNT;
    pcr_sel_1->pcrSelections[0].pcrSelect[0] = 0xFF;
    pcr_sel_2->count = 1;
    pcr_sel_2->pcrSelections[0].sizeofSelect = MOCK_MAX_PCR_COUNT/MOCK_PCRS_READ_COUNT;
    pcr_sel_2->pcrSelections[0].pcrSelect[1] = 0xFF;
    pcr_sel_3->count = 1;
    pcr_sel_3->pcrSelections[0].sizeofSelect = MOCK_MAX_PCR_COUNT/MOCK_PCRS_READ_COUNT;
    pcr_sel_3->pcrSelections[0].pcrSelect[2] = 0xFF;

    auto pcr_values_1 = (TPML_DIGEST*)calloc(1,sizeof(TPML_DIGEST));
    auto pcr_values_2 = (TPML_DIGEST*)calloc(1,sizeof(TPML_DIGEST));
    auto pcr_values_3 = (TPML_DIGEST*)calloc(1,sizeof(TPML_DIGEST));
    pcr_values_1->count = MOCK_PCRS_READ_COUNT;
    pcr_values_2->count = MOCK_PCRS_READ_COUNT;
    pcr_values_3->count = MOCK_PCRS_READ_COUNT;

    EXPECT_CALL(*tpmLibMockObj, Esys_PCR_Read(_,ESYS_TR_NONE,ESYS_TR_NONE,ESYS_TR_NONE,_,_,_,_))
        .Times(MOCK_MAX_PCR_COUNT/MOCK_PCRS_READ_COUNT)
        .WillOnce(DoAll(SetArgPointee<6>(pcr_sel_1), SetArgPointee<7>(pcr_values_1), Return(0)))
        .WillOnce(DoAll(SetArgPointee<6>(pcr_sel_2), SetArgPointee<7>(pcr_values_2), Return(0)))
        .WillOnce(DoAll(SetArgPointee<6>(pcr_sel_3), SetArgPointee<7>(pcr_values_3), Return(0)));

    //
    // GetPCRValues
    //
    attest::PcrList pcrs(MOCK_MAX_PCR_COUNT);
    //Populate the pcrs with the increasing values.
    std::iota(pcrs.begin(), pcrs.end(), 0);

    attest::HashAlg hashAlg = attest::HashAlg::Sha256;
    auto pcrValues = tpm->GetPCRValues(pcrs, hashAlg);

    EXPECT_EQ(pcrValues.hashAlg, hashAlg);
    for (unsigned char i = 0; i < MOCK_MAX_PCR_COUNT; i++) {
        EXPECT_EQ(pcrValues.pcrs[i].index, i);
        EXPECT_TRUE(std::all_of(pcrValues.pcrs[i].digest.begin(), pcrValues.pcrs[i].digest.end(), [](unsigned char c) { return c == 0; }));
    }
}

TEST_F(TpmTest, GetPCRValues_negative)
{
    // TssPcrSelection calls GetCapability to get number of PCRs implemented
    auto caps = (TPMS_CAPABILITY_DATA*)calloc(1, sizeof(TPMS_CAPABILITY_DATA));
    caps->data.tpmProperties.count = 1;
    caps->data.tpmProperties.tpmProperty[0].property = TPM2_PT_PCR_COUNT;
    caps->data.tpmProperties.tpmProperty[0].value = MOCK_MAX_PCR_COUNT;

    EXPECT_CALL(*tpmLibMockObj, Esys_GetCapability(_,ESYS_TR_NONE,ESYS_TR_NONE,ESYS_TR_NONE,TPM2_CAP_TPM_PROPERTIES,TPM2_PT_PCR_COUNT,1,_,_))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<8>(caps), Return(0)));

    bool success = true;
    try {
        attest::PcrList pcrs = {0, 8, 16, 24};
        attest::HashAlg hashAlg = attest::HashAlg::Sha256;
        auto pcrValues = tpm->GetPCRValues(pcrs, hashAlg);
    } catch (std::exception& e) {
        success = false;
        EXPECT_STREQ(e.what(), "PCR index out of range");
    }
    EXPECT_FALSE(success);
}

/**
 * Test that GetTcgLog will throw an exception if no log is available.
 *
 * Note there is no positive unit test. This is because that would require
 * file IO. Positive testing will be done in integration testing.
 */
TEST_F(TpmTest, GetTcgLog_negative) {
    bool success = true;
    try {
#ifdef PLATFORM_UNIX
		Tss2Wrapper::GetTcgLogFromFile("");
#else
        throw FileNotFound();
#endif // PLATFORM_UNIX [todo: Add the appropriate scenario for Windows.]
    } catch (FileNotFound&) {
        success = false;
    }
    EXPECT_FALSE(success);
}

/**
 * Tests retrieving TPM version
 */
TEST_F(TpmTest, GetVersion_positive) {
    // GetCapability output
    auto cap_tpm1 = (TPMS_CAPABILITY_DATA*)calloc(1,sizeof(TPMS_CAPABILITY_DATA));
    cap_tpm1->data.tpmProperties.count = 1;
    cap_tpm1->data.tpmProperties.tpmProperty[0].property = TPM2_PT_FAMILY_INDICATOR;
    cap_tpm1->data.tpmProperties.tpmProperty[0].value = 0x312e3200;

    auto cap_tpm2 = (TPMS_CAPABILITY_DATA*)malloc(sizeof(TPMS_CAPABILITY_DATA));
    cap_tpm2->data.tpmProperties.count = 1;
    cap_tpm2->data.tpmProperties.tpmProperty[0].property = TPM2_PT_FAMILY_INDICATOR;
    cap_tpm2->data.tpmProperties.tpmProperty[0].value = 0x322e3000;

    EXPECT_CALL(*tpmLibMockObj, Esys_GetCapability(_,ESYS_TR_NONE,ESYS_TR_NONE,ESYS_TR_NONE,
                                                   TPM2_CAP_TPM_PROPERTIES,TPM2_PT_FAMILY_INDICATOR,1,_,_))
            .Times(2)
            .WillOnce(DoAll(SetArgPointee<7>(TPM2_NO), SetArgPointee<8>(cap_tpm1), Return(0)))
            .WillOnce(DoAll(SetArgPointee<7>(TPM2_NO), SetArgPointee<8>(cap_tpm2), Return(0)));

    auto version = tpm->GetVersion();
    EXPECT_EQ(version, attest::TpmVersion::V1_2);

    version = tpm->GetVersion();
    EXPECT_EQ(version, attest::TpmVersion::V2_0);
}

/**
 * Tests TPM version not being known
 */
TEST_F(TpmTest, GetVersion_unknownversion) {
    auto cap = (TPMS_CAPABILITY_DATA*)calloc(1,sizeof(TPMS_CAPABILITY_DATA));
    cap->data.tpmProperties.count = 1;
    cap->data.tpmProperties.tpmProperty[0].property = TPM2_PT_FAMILY_INDICATOR;
    cap->data.tpmProperties.tpmProperty[0].value = 0x0;

    EXPECT_CALL(*tpmLibMockObj, Esys_GetCapability(_,ESYS_TR_NONE,ESYS_TR_NONE,ESYS_TR_NONE,
                                                   TPM2_CAP_TPM_PROPERTIES,TPM2_PT_FAMILY_INDICATOR,1,_,_))
            .Times(1)
            .WillOnce(DoAll(SetArgPointee<7>(TPM2_NO), SetArgPointee<8>(cap), Return(0)));

    bool success = true;
    try {
        auto version = tpm->GetVersion();
    } catch (std::exception& e) {
        success = false;
        EXPECT_STREQ(e.what(), "Invalid TPM version string");
    }
    EXPECT_FALSE(success);
}

/**
 * Tests TPM version retrieval failing
 */
TEST_F(TpmTest, GetVersion_getcapfail) {
    EXPECT_CALL(*tpmLibMockObj, Esys_GetCapability(_,ESYS_TR_NONE,ESYS_TR_NONE,ESYS_TR_NONE,
                                                   TPM2_CAP_TPM_PROPERTIES,TPM2_PT_FAMILY_INDICATOR,1,_,_))
            .Times(1)
            .WillOnce(Return(1));

    bool success = true;
    try {
        auto version = tpm->GetVersion();
    } catch (Tss2Exception& e) {
        success = false;
        EXPECT_EQ(e.get_rc(), 1);
    }
    EXPECT_FALSE(success);
}

/**
 * Tests Unsealing data using the TPM
 */
TEST_F(TpmTest, Unseal_positive) {
    ESYS_TR ekHandle = 1;
    ESYS_TR loadedDataHandle = 2;

    auto outData = (TPM2B_SENSITIVE_DATA*)calloc(1,sizeof(TPM2B_SENSITIVE_DATA));
    outData->size = 1;
    outData->buffer[0] = 1;

    EXPECT_CALL(*tpmLibMockObj, Esys_TR_FromTPMPublic(_,_,ESYS_TR_NONE,ESYS_TR_NONE,ESYS_TR_NONE,_))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<5>(ekHandle), Return(0)));

    auto outPriv = (TPM2B_PRIVATE*)calloc(1,sizeof(TPM2B_PRIVATE));
    outPriv->size = 10;
    ESYS_IMPORT_PARAMS params;
    params.outPrivate = &outPriv;

    // Import is mocked using a struct for input parameters
    EXPECT_CALL(*tpmLibMockObj, Esys_Import(_))
        .WillOnce(DoAll(SetArgPointee<0>(params), Return(0)));

    EXPECT_CALL(*tpmLibMockObj, Esys_Load(_,ekHandle,_,ESYS_TR_NONE,ESYS_TR_NONE,outPriv,_,_))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<7>(loadedDataHandle), Return(0)));

    // TssPcrSelection calls GetCapability to get number of PCRs implemented
    auto caps = (TPMS_CAPABILITY_DATA*)calloc(1, sizeof(TPMS_CAPABILITY_DATA));
    caps->data.tpmProperties.count = 1;
    caps->data.tpmProperties.tpmProperty[0].property = TPM2_PT_PCR_COUNT;
    caps->data.tpmProperties.tpmProperty[0].value = MOCK_MAX_PCR_COUNT;

    EXPECT_CALL(*tpmLibMockObj, Esys_GetCapability(_,ESYS_TR_NONE,ESYS_TR_NONE,ESYS_TR_NONE,TPM2_CAP_TPM_PROPERTIES,TPM2_PT_PCR_COUNT,1,_,_))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<8>(caps), Return(0)));

    EXPECT_CALL(*tpmLibMockObj, Esys_Unseal(_,loadedDataHandle,_,_,_,_))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<5>(outData), Return(0)));

    std::vector<unsigned char> inPub(sizeof(TPM2B_PUBLIC));
    std::vector<unsigned char> inPriv(sizeof(TPM2B_PRIVATE));
    std::vector<unsigned char> data(20);
    attest::PcrSet pcrSet;
    pcrSet.hashAlg = attest::HashAlg::Sha256;
    attest::HashAlg hashAlg = attest::HashAlg::Sha256;
    auto decrypted = tpm->Unseal(inPub, inPriv, data, pcrSet, hashAlg);

    EXPECT_EQ(decrypted.size(), 1);
    EXPECT_EQ(decrypted[0], 1);
}

/**
 * Tests Unsealing data using the TPM failing at import step
 */
TEST_F(TpmTest, Unseal_importfail) {
    ESYS_TR ekHandle = 1;
    ESYS_TR loadedDataHandle = 2;

    EXPECT_CALL(*tpmLibMockObj, Esys_TR_FromTPMPublic(_,_,ESYS_TR_NONE,ESYS_TR_NONE,ESYS_TR_NONE,_))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<5>(ekHandle), Return(0)));

    EXPECT_CALL(*tpmLibMockObj, Esys_Import(_)).WillOnce(Return(1));

    EXPECT_CALL(*tpmLibMockObj, Esys_Load(_,_,_,_,_,_,_,_)).Times(0);

    EXPECT_CALL(*tpmLibMockObj, Esys_GetCapability(_,_,_,_,_,_,_,_,_)).Times(0);

    EXPECT_CALL(*tpmLibMockObj, Esys_Unseal(_,loadedDataHandle,_,_,_,_)).Times(0);

    bool success = true;
    try {
        std::vector<unsigned char> inPub(sizeof(TPM2B_PUBLIC));
        std::vector<unsigned char> inPriv(sizeof(TPM2B_PRIVATE));
        std::vector<unsigned char> data(20);
        attest::PcrSet pcrSet;
        attest::HashAlg hashAlg = attest::HashAlg::Sha256;
        auto decrypted = tpm->Unseal(inPub, inPriv, data, pcrSet, hashAlg);
    } catch (Tss2Exception& e) {
        success = false;
        EXPECT_EQ(e.get_rc(), 1);
    }
    EXPECT_FALSE(success);
}

/**
 * Tests Unsealing data using the TPM failing at load step
 */
TEST_F(TpmTest, Unseal_loadfail) {
    ESYS_TR ekHandle = 1;
    ESYS_TR loadedDataHandle = 2;

    EXPECT_CALL(*tpmLibMockObj, Esys_TR_FromTPMPublic(_,_,ESYS_TR_NONE,ESYS_TR_NONE,ESYS_TR_NONE,_))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<5>(ekHandle), Return(0)));

    auto outPriv = (TPM2B_PRIVATE*)calloc(1,sizeof(TPM2B_PRIVATE));
    outPriv->size = 10;
    ESYS_IMPORT_PARAMS params;
    params.outPrivate = &outPriv;

    EXPECT_CALL(*tpmLibMockObj, Esys_Import(_))
        .WillOnce(DoAll(SetArgPointee<0>(params), Return(0)));

    EXPECT_CALL(*tpmLibMockObj, Esys_Load(_,ekHandle,_,ESYS_TR_NONE,ESYS_TR_NONE,outPriv,_,_))
        .Times(1)
        .WillOnce(Return(2));

    EXPECT_CALL(*tpmLibMockObj, Esys_GetCapability(_,_,_,_,_,_,_,_,_)).Times(0);

    EXPECT_CALL(*tpmLibMockObj, Esys_Unseal(_,loadedDataHandle,_,_,_,_)).Times(0);

    bool success = true;
    try {
        std::vector<unsigned char> inPub(sizeof(TPM2B_PUBLIC));
        std::vector<unsigned char> inPriv(sizeof(TPM2B_PRIVATE));
        std::vector<unsigned char> data(20);
        attest::PcrSet pcrSet;
        attest::HashAlg hashAlg = attest::HashAlg::Sha256;
        auto decrypted = tpm->Unseal(inPub, inPriv, data, pcrSet, hashAlg);
    } catch (Tss2Exception& e) {
        success = false;
        EXPECT_EQ(e.get_rc(), 2);
    }
    EXPECT_FALSE(success);
}

/**
 * Tests Unsealing data using the TPM failing at unseal step
 */
TEST_F(TpmTest, Unseal_unsealfail) {
    ESYS_TR ekHandle = 1;
    ESYS_TR loadedDataHandle = 2;

    EXPECT_CALL(*tpmLibMockObj, Esys_TR_FromTPMPublic(_,_,ESYS_TR_NONE,ESYS_TR_NONE,ESYS_TR_NONE,_))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<5>(ekHandle), Return(0)));

    auto outPriv = (TPM2B_PRIVATE*)calloc(1,sizeof(TPM2B_PRIVATE));
    outPriv->size = MOCK_TPM_PUBLIC_SIZE;
    ESYS_IMPORT_PARAMS params;
    params.outPrivate = &outPriv;

    EXPECT_CALL(*tpmLibMockObj, Esys_Import(_))
        .WillOnce(DoAll(SetArgPointee<0>(params), Return(0)));

    EXPECT_CALL(*tpmLibMockObj, Esys_Load(_,ekHandle,_,ESYS_TR_NONE,ESYS_TR_NONE,outPriv,_,_))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<7>(loadedDataHandle), Return(0)));

    // TssPcrSelection calls GetCapability to get number of PCRs implemented
    auto caps = (TPMS_CAPABILITY_DATA*)calloc(1, sizeof(TPMS_CAPABILITY_DATA));
    caps->data.tpmProperties.count = 1;
    caps->data.tpmProperties.tpmProperty[0].property = TPM2_PT_PCR_COUNT;
    caps->data.tpmProperties.tpmProperty[0].value = MOCK_MAX_PCR_COUNT;

    EXPECT_CALL(*tpmLibMockObj, Esys_GetCapability(_,ESYS_TR_NONE,ESYS_TR_NONE,ESYS_TR_NONE,TPM2_CAP_TPM_PROPERTIES,TPM2_PT_PCR_COUNT,1,_,_))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<8>(caps), Return(0)));

    EXPECT_CALL(*tpmLibMockObj, Esys_Unseal(_,loadedDataHandle,_,_,_,_))
        .Times(1)
        .WillOnce(Return(3));

    bool success = true;
    try {
        std::vector<unsigned char> inPub(sizeof(TPM2B_PUBLIC));
        std::vector<unsigned char> inPriv(sizeof(TPM2B_PRIVATE));
        std::vector<unsigned char> data(20);
        attest::PcrSet pcrSet;
        pcrSet.hashAlg = attest::HashAlg::Sha256;
        attest::HashAlg hashAlg = attest::HashAlg::Sha256;
        auto decrypted = tpm->Unseal(inPub, inPriv, data, pcrSet, hashAlg);
    } catch (Tss2Exception& e) {
        success = false;
        EXPECT_EQ(e.get_rc(), 3);
    }
    EXPECT_FALSE(success);
}

/**
 * Tests WriteAikCert when undefine space fails
 */
TEST_F(TpmTest, WriteAikCert_UndefineSpaceFailure)
{
    EXPECT_CALL(*tpmLibMockObj, Esys_NV_UndefineSpace(_, _, _, _, _, _))
        .Times(1)
        .WillOnce(Return(1));

    bool success = true;
    int size = 2200;
    std::vector<unsigned char> data(2200);
    try {
        tpm->WriteAikCert(data);
    }
    catch (Tss2Exception& e) {
        success = false;
        EXPECT_EQ(e.get_rc(), 1);
    }
    EXPECT_FALSE(success);
}

/**
 * Tests WriteAikCert when define space fails
 */
TEST_F(TpmTest, WriteAikCert_DefineSpaceFailure)
{
    EXPECT_CALL(*tpmLibMockObj, Esys_NV_UndefineSpace(_, ESYS_TR_RH_OWNER, _, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*tpmLibMockObj, Esys_NV_DefineSpace(_, _, _, _, _, _, _, _))
        .Times(1)
        .WillOnce(Return(1));

    bool success = true;
    int size = 2200;
    std::vector<unsigned char> data(2200);
    try {
        tpm->WriteAikCert(data);
    }
    catch (Tss2Exception& e) {
        success = false;
        EXPECT_EQ(e.get_rc(), 1);
    }
    EXPECT_FALSE(success);
}

/**
 * Tests WriteAikCert when write operation fails
 */
TEST_F(TpmTest, WriteAikCert_NvWriteFailure)
{
    EXPECT_CALL(*tpmLibMockObj, Esys_NV_UndefineSpace(_, ESYS_TR_RH_OWNER, _, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*tpmLibMockObj, Esys_NV_DefineSpace(_, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, _, _, _))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*tpmLibMockObj, Esys_NV_Write(_, _, _, _, _, _, _, _))
        .Times(1)
        .WillOnce(Return(1));

    bool success = true;
    int size = 2200;
    std::vector<unsigned char> data(2200);
    try {
        tpm->WriteAikCert(data);
    }
    catch (Tss2Exception& e) {
        success = false;
        EXPECT_EQ(e.get_rc(), 1);
    }
    EXPECT_FALSE(success);
}

/**
 * Tests WriteAikCert success case
 */
TEST_F(TpmTest, WriteAikCert_Positive)
{
    EXPECT_CALL(*tpmLibMockObj, Esys_NV_UndefineSpace(_, ESYS_TR_RH_OWNER, _, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*tpmLibMockObj, Esys_NV_DefineSpace(_, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, _, _, _))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*tpmLibMockObj, Esys_NV_Write(_, ESYS_TR_RH_OWNER, _, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, _, _))
        .Times(5)
        .WillOnce(Return(0))
        .WillOnce(Return(0))
        .WillOnce(Return(0))
        .WillOnce(Return(0))
        .WillOnce(Return(0));

    bool success = true;
    int size = 2200;
    std::vector<unsigned char> data(2200);
    try {
        tpm->WriteAikCert(data);
    }
    catch (Tss2Exception& e) {
        success = false;
    }
    EXPECT_TRUE(success);
}

/**
 * Tests retrieving HCL report when one exists
 */
TEST_F(TpmTest, GetHCLReport_positive)
{
    auto hcl_report_packet_1 = (TPM2B_MAX_NV_BUFFER*)calloc(1, sizeof(TPM2B_MAX_NV_BUFFER));
    auto hcl_report_packet_2 = (TPM2B_MAX_NV_BUFFER*)calloc(1, sizeof(TPM2B_MAX_NV_BUFFER));
    auto hcl_report_packet_3 = (TPM2B_MAX_NV_BUFFER*)calloc(1, sizeof(TPM2B_MAX_NV_BUFFER));
    hcl_report_packet_1->size = MOCK_HCL_REPORT_PACKET_SIZE;
    hcl_report_packet_2->size = MOCK_HCL_REPORT_PACKET_SIZE;
    hcl_report_packet_3->size = MOCK_HCL_REPORT_PACKET_SIZE;

    hcl_report_packet_1->buffer[0] = 1; // Make sure these buffers are actually being used

    auto hcl_report_nv_pub = (TPM2B_NV_PUBLIC*)calloc(1, sizeof(TPM2B_NV_PUBLIC));
    hcl_report_nv_pub->size = sizeof(TPMS_NV_PUBLIC);
    hcl_report_nv_pub->nvPublic.dataSize = MOCK_HCL_REPORT_SIZE;

    EXPECT_CALL(*tpmLibMockObj, Esys_TR_FromTPMPublic(_, HCL_REPORT_INDEX, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, _))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<5>(MOCK_HANDLE), Return(0)));

    EXPECT_CALL(*tpmLibMockObj, Esys_NV_ReadPublic(_, MOCK_HANDLE, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, _, _))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<5>(hcl_report_nv_pub), Return(0)));

    EXPECT_CALL(*tpmLibMockObj, Esys_NV_Read(_, _, MOCK_HANDLE, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, _, _, _))
        .Times(MOCK_HCL_REPORT_SIZE / MOCK_HCL_REPORT_PACKET_SIZE)
        .WillOnce(DoAll(SetArgPointee<8>(hcl_report_packet_1), Return(0)))
        .WillOnce(DoAll(SetArgPointee<8>(hcl_report_packet_2), Return(0)))
        .WillOnce(DoAll(SetArgPointee<8>(hcl_report_packet_3), Return(0)));

    //
    // GetHCLReport
    //
    auto hclReport = tpm->GetHCLReport();
    EXPECT_EQ(hclReport.size(), MOCK_HCL_REPORT_SIZE);
    EXPECT_EQ(hclReport[0], 1);
    EXPECT_TRUE(std::all_of(hclReport.begin() + 1, hclReport.end(), [](unsigned char c) { return c == 0; }));
}

/**
 * Test trying to get the HCL report when one does not exist on the TPM
 */
TEST_F(TpmTest, GetHCLReport_negative)
{
    EXPECT_CALL(*tpmLibMockObj, Esys_TR_FromTPMPublic(_, _, _, _, _, _))
        .Times(1)
        .WillOnce(Return(TPM2_RC_REFERENCE_H0));

    bool success = true;
    try {
        auto hclReport = tpm->GetHCLReport();
    }
    catch (Tss2Exception& e) {
        success = false;
        EXPECT_EQ(e.get_rc(), TPM2_RC_REFERENCE_H0);
    }
    EXPECT_FALSE(success);
}

/**
 * Run tests
 */
int main(int argc, char** argv)
{
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
