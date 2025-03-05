#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "Tpm.h"
#include "Tss2Wrapper.h"
#include "TpmMocks.h"

using ::testing::_;
using ::testing::DoAll;
using ::testing::Mock;
using ::testing::Return;
using ::testing::SetArgPointee;

std::shared_ptr<TpmLibMock> tpmLibMockObj;

TEST(TestCaseName, TestName) {
  EXPECT_EQ(1, 1);
  EXPECT_TRUE(true);
}

class Tss2WrapperTest : public ::testing::Test {
protected:
    std::unique_ptr<Tss2Wrapper> tss2Wrapper;

    void SetUp() override {
        tss2Wrapper = std::make_unique<Tss2Wrapper>();
        tpmLibMockObj = std::make_shared<TpmLibMock>();
    }

    // Runs after each test case
    void TearDown() override
    {
        EXPECT_TRUE(Mock::VerifyAndClearExpectations(tpmLibMockObj.get()));
        tss2Wrapper.reset();
        tpmLibMockObj.reset();
    }
};

TEST_F(Tss2WrapperTest, ConstructorTest) {
    // Test that the constructor initializes the TssWrapper object
    ASSERT_NE(tss2Wrapper, nullptr);
}

TEST_F(Tss2WrapperTest, Tss2RsaDecryptTest) {
    EXPECT_CALL(*tpmLibMockObj, Esys_TR_SetAuth(_, _, _))
        .Times(2)
        .WillOnce(Return(TSS2_RC_SUCCESS))
        .WillOnce(Return(TSS2_RC_SUCCESS));
    EXPECT_CALL(*tpmLibMockObj, Esys_RSA_Decrypt(_, _, _, _, _, _, _, _, _))
        .Times(1)
        .WillOnce(Return(TSS2_RC_SUCCESS));
    EXPECT_CALL(*tpmLibMockObj, Esys_TR_FromTPMPublic(_, _, _, _, _, _))
        .Times(1)
        .WillOnce(Return(TSS2_RC_SUCCESS));
    // Test the Tss2RsaDecrypt method
    std::vector<unsigned char> encryptedData = { 0x01, 0x02, 0x03, 0x04 };
    std::vector<unsigned char> decryptedData = tss2Wrapper->Tss2RsaDecrypt(encryptedData);

}