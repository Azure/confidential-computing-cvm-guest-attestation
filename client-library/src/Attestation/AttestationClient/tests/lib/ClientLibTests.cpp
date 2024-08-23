//-------------------------------------------------------------------------------------------------
// <copyright file="ClientLibTests.cpp" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------
#include <stdio.h>
#include <gtest/gtest.h>
#include <cstring>
#include <iostream>
#include <fstream>
#include <streambuf>
#include <numeric>
#include <random>
#include <json/json.h>
#include <openssl/bio.h>

#include "AttestationHelper.h"
#include <Logging.h>
#include <AttestationClientImpl.h>
#include <AttestationLibConst.h>
#include <HclReportParser.h>
#include <AttestationLibUtils.h>

constexpr char test_os_release[] = "test-os-release";
constexpr char valid_version_entries[] = "NAME=\"Test-OS\"\nVERSION_ID=\"1.10\"";
constexpr char invalid_version_entries1[] = "NAME=\"Test-OS\"\nVERSION_ID=\"garbage\"";
constexpr char invalid_version_entries2[] = "NAME=\"Test-OS\"\nVERSION_ID=\"1.ad\"";
constexpr char invalid_version_entries3[] = "NAME=\"Test-OS\"";
constexpr char invalid_version_entries4[] = "VERSION_ID=\"1.00\"";

constexpr char arm_id_key[] = "ArmID";
constexpr char arm_id_value[] = "https://DummyID";
constexpr char nonce_key[] = "Nonce";
constexpr char nonce_value[] = "NonceValueAsString";

static void createFile(const char* file_name, const char* buffer) {
    std::ofstream out(file_name, std::ios::out | std::ios::binary);
    if(out.fail()) {
        EXPECT_TRUE(false);
    }
    out.write(buffer, strlen(buffer));
    out.close();
}

static void deleteFile(const char* file_name) {
    EXPECT_EQ(remove(file_name), 0);
}

class Logger : public attest::AttestationLogger {
public:

    void Log(const char* log_tag,
             LogLevel level,
             const char* function,
             const int line,
             const char* fmt,
             ...) override {

         printf("%s: Function:%s(line:%d):%s\n",
                log_tag,
                function,
                line,
                fmt);

    }
};
namespace AttestationClientLibTest {

    class ClientLibTests : public ::testing::Test {
    protected:
        std::shared_ptr<AttestationClientImpl> client;
        std::shared_ptr<HclReportParser> hcl_report_parser;

        ClientLibTests() {}

        virtual ~ClientLibTests() {}

        void SetUp() override {
            std::shared_ptr<Logger> logger = std::make_shared<Logger>();
            client = std::make_shared<AttestationClientImpl>(logger);
            hcl_report_parser = std::make_shared<HclReportParser>();
        }

        void TearDown() override {
            client.reset();
            hcl_report_parser.reset();
        }

        void getAttestationParameters(attest::AttestationParameters& params, attest::IsolationType isolation_type);
        attest::AttestationResult getTpmInfo(attest::TpmInfo& tpm_info);
        attest::AttestationResult getIsolationInfo(attest::IsolationInfo& isolation_info, attest::IsolationType isolation_type);
    };

    TEST_F(ClientLibTests, Attest_positive) {

        // TODO: Add tests here to validate the attest calls works.
        ASSERT_TRUE(true);
    }

    TEST_F(ClientLibTests, Attest_negative) {
        // TODO: Add tests here to validate negative scenarios and make sure the
        // results are as expected.
        ASSERT_TRUE(true);
    }

    //TODO: Uncomment this test once Tpm simulator is enabled.
    /*
    TEST_F(ClientLibTests, Decrypt_positive) {

        std::ifstream t("sealedResponse.json");
        std::string json((std::istreambuf_iterator<char>(t)),
                         std::istreambuf_iterator<char>());

        printf("Sealed Response:%s\n", json.c_str());

        attest::Buffer json_buffer(json.begin(), json.end());

        std::string json_encoded = attest::base64::binary_to_base64url(json_buffer);

        // Added "\""" to the start and end of the encoded json to simulate how the service will send the
        // json response.
        json_encoded = "\"" + json_encoded + "\"";

        std::string json_decrypted;
        attest::AttestationResult result = client->Decrypt(json_encoded, json_decrypted);
        EXPECT_EQ(result.code_, attest::AttestationResult::ErrorCode::SUCCESS);
        printf("Result Description:%s\n", result.description_.c_str());
        printf("Decrypted Data:%s\n", json_decrypted.c_str());
    }
    */

    // This is similar to the test above. Tpm simulator is needed for live enc/dec.
    // This is encrypted with use RSAES and Sha256 hash.
    /*
    TEST_F(ClientLibTests, Encrypt_Decrypt_RSAPKCS1_Sha256_positive) {

        // I obtained this token from a live CVM. It expires in 8 hours.
        const std::string jwt_token = "eyJhbGciOiJSUzI1NiIsImprdSI6Imh0dHBzOi8vc2hhcmVkd2V1LndldS5hdHRlc3QuYXp1cmUubmV0L2NlcnRzIiwia2lkIjoiZFJLaCtoQmNXVWZRaW1TbDNJdjZaaFN0VzNUU090MFRod2lUZ1VVcVpBbz0iLCJ0eXAiOiJKV1QifQ.eyJleHAiOjE2ODAyMDIxNzQsImlhdCI6MTY4MDE3MzM3NCwiaXNzIjoiaHR0cHM6Ly9zaGFyZWR3ZXUud2V1LmF0dGVzdC5henVyZS5uZXQiLCJqdGkiOiIzYmY0OGRiMTNlOWNiY2JmZDI4OTM3MGQ5MTQ2YWFlMzE4NTg4Mzk5Y2RjZGExNDk1YWQ3ZTc3MDA2YTUzZDcxIiwibmJmIjoxNjgwMTczMzc0LCJzZWN1cmVib290Ijp0cnVlLCJ4LW1zLWF0dGVzdGF0aW9uLXR5cGUiOiJhenVyZXZtIiwieC1tcy1henVyZXZtLWF0dGVzdGF0aW9uLXByb3RvY29sLXZlciI6IjIuMCIsIngtbXMtYXp1cmV2bS1hdHRlc3RlZC1wY3JzIjpbMCwxLDIsMyw0LDUsNiw3LDExLDEyLDEzXSwieC1tcy1henVyZXZtLWJvb3RkZWJ1Zy1lbmFibGVkIjpmYWxzZSwieC1tcy1henVyZXZtLWRidmFsaWRhdGVkIjp0cnVlLCJ4LW1zLWF6dXJldm0tZGJ4dmFsaWRhdGVkIjp0cnVlLCJ4LW1zLWF6dXJldm0tZGVidWdnZXJzZGlzYWJsZWQiOnRydWUsIngtbXMtYXp1cmV2bS1kZWZhdWx0LXNlY3VyZWJvb3RrZXlzdmFsaWRhdGVkIjp0cnVlLCJ4LW1zLWF6dXJldm0tZWxhbS1lbmFibGVkIjpmYWxzZSwieC1tcy1henVyZXZtLWZsaWdodHNpZ25pbmctZW5hYmxlZCI6ZmFsc2UsIngtbXMtYXp1cmV2bS1odmNpLXBvbGljeSI6MCwieC1tcy1henVyZXZtLWh5cGVydmlzb3JkZWJ1Zy1lbmFibGVkIjpmYWxzZSwieC1tcy1henVyZXZtLWlzLXdpbmRvd3MiOnRydWUsIngtbXMtYXp1cmV2bS1rZXJuZWxkZWJ1Zy1lbmFibGVkIjpmYWxzZSwieC1tcy1henVyZXZtLW9zYnVpbGQiOiJOb3RBcHBsaWNhYmxlIiwieC1tcy1henVyZXZtLW9zZGlzdHJvIjoiTWljcm9zb2Z0IiwieC1tcy1henVyZXZtLW9zdHlwZSI6IldpbmRvd3MiLCJ4LW1zLWF6dXJldm0tb3N2ZXJzaW9uLW1ham9yIjoxMCwieC1tcy1henVyZXZtLW9zdmVyc2lvbi1taW5vciI6MCwieC1tcy1henVyZXZtLXNpZ25pbmdkaXNhYmxlZCI6dHJ1ZSwieC1tcy1henVyZXZtLXRlc3RzaWduaW5nLWVuYWJsZWQiOmZhbHNlLCJ4LW1zLWF6dXJldm0tdm1pZCI6IjcwRjVDRTlBLTJCREMtNEI2Qi04NDAxLUU5Qjk2NEQzQUVCNyIsIngtbXMtaXNvbGF0aW9uLXRlZSI6eyJ4LW1zLWF0dGVzdGF0aW9uLXR5cGUiOiJzZXZzbnB2bSIsIngtbXMtY29tcGxpYW5jZS1zdGF0dXMiOiJhenVyZS1jb21wbGlhbnQtY3ZtIiwieC1tcy1ydW50aW1lIjp7ImtleXMiOlt7ImUiOiJBUUFCIiwia2V5X29wcyI6WyJlbmNyeXB0Il0sImtpZCI6IkhDTEFrUHViIiwia3R5IjoiUlNBIiwibiI6InNndXR1Z0FBRUdpN1k2bHAtMU9tWnpmTTBHbE0wUkg3cVdHMV9FX3pRWTNpajRQVGZ5Wmd3ZVlaNDZYSGVucW84QXNBME9Oc0c0ei05cXJ4MEVYWW9namRqRDQ0bzZOSXVaSmFGR29RLVg3bzdBV2RsYjRsYUdUZ29MRERIcWtNeEx6MHFSbkhxcEJEOGkyLWpwZDRoRFZLRTFLYnVVdGpvMnBHZy1PdUpfNGtXdEhDRjhwTDZKb2tGRzgzaTNaZUg4VnNWcmhQYzlhY2huVklSeUc5dHBGRVJxcWkwQ0RkdkJDN3lDU3Y3cGtrX1RkcE4xMU1xMG4xdjJXT2NWMUFKcnRhenVHVHdSdmg1U0ZpMkJRWlZOV1FsVkFfeGUzTjlZbk92WU54cnN2NEJONEhzc1hqdzUyelpWbEdnTG56MlBNLTNkZWVPZnJpN0VGdV9ndXZZUSJ9XSwidm0tY29uZmlndXJhdGlvbiI6eyJjb25zb2xlLWVuYWJsZWQiOnRydWUsImN1cnJlbnQtdGltZSI6MTY4MDEzMDQxOSwic2VjdXJlLWJvb3QiOnRydWUsInRwbS1lbmFibGVkIjp0cnVlLCJ2bVVuaXF1ZUlkIjoiNzBGNUNFOUEtMkJEQy00QjZCLTg0MDEtRTlCOTY0RDNBRUI3In19LCJ4LW1zLXNldnNucHZtLWF1dGhvcmtleWRpZ2VzdCI6IjAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMCIsIngtbXMtc2V2c25wdm0tYm9vdGxvYWRlci1zdm4iOjMsIngtbXMtc2V2c25wdm0tZmFtaWx5SWQiOiIwMTAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMCIsIngtbXMtc2V2c25wdm0tZ3Vlc3Rzdm4iOjQsIngtbXMtc2V2c25wdm0taG9zdGRhdGEiOiIwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwIiwieC1tcy1zZXZzbnB2bS1pZGtleWRpZ2VzdCI6IjAzNTYyMTU4ODJhODI1Mjc5YTg1YjMwMGIwYjc0MjkzMWQxMTNiZjdlMzJkZGUyZTUwZmZkZTdlYzc0M2NhNDkxZWNkZDdmMzM2ZGMyOGE2ZTBiMmJiNTdhZjdhNDRhMyIsIngtbXMtc2V2c25wdm0taW1hZ2VJZCI6IjAyMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwIiwieC1tcy1zZXZzbnB2bS1pcy1kZWJ1Z2dhYmxlIjpmYWxzZSwieC1tcy1zZXZzbnB2bS1sYXVuY2htZWFzdXJlbWVudCI6Ijg5NjI1MzU5MzNmNWM0YjQyOWVjNDFkNjU1MGMxODdjMTYzYWE3NmYzYmUxZjhkNzUwYTI3MmE5ZDg5OTUwMjNlODI4NmEyZTQzMWE5NmMzNjA4N2FjNDZkNDE4ODY3NiIsIngtbXMtc2V2c25wdm0tbWljcm9jb2RlLXN2biI6MTE1LCJ4LW1zLXNldnNucHZtLW1pZ3JhdGlvbi1hbGxvd2VkIjpmYWxzZSwieC1tcy1zZXZzbnB2bS1yZXBvcnRkYXRhIjoiOWI2ZDAyZTc2ODMyZjNiYmIyMWJhNDhjOGY4OWM4NzVlMDVkYWY1YzgzNjU4YzdiMjRlNjAzNGVhNWUwOGUyYTAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAiLCJ4LW1zLXNldnNucHZtLXJlcG9ydGlkIjoiYjk4NTRlMGIxOGZkZjk1NTEwOGYzNjI5MmNjM2U0YTc0NzBiMGNmNDY1YzNkZmZhNTVjOGRkYjMyOTAxNTJiOSIsIngtbXMtc2V2c25wdm0tc210LWFsbG93ZWQiOnRydWUsIngtbXMtc2V2c25wdm0tc25wZnctc3ZuIjo4LCJ4LW1zLXNldnNucHZtLXRlZS1zdm4iOjAsIngtbXMtc2V2c25wdm0tdm1wbCI6MH0sIngtbXMtcG9saWN5LWhhc2giOiJ3bTltSGx2VFU4MmU4VXFvT3kxWWoxRkJSU05rZmU5OS02OUlZRHE5ZVdzIiwieC1tcy1ydW50aW1lIjp7ImNsaWVudC1wYXlsb2FkIjp7Im5vbmNlIjoiUVVSRk1ERXdNUT09In0sImtleXMiOlt7ImUiOiJBUUFCIiwia2V5X29wcyI6WyJlbmNyeXB0Il0sImtpZCI6IlRwbUVwaGVtZXJhbEVuY3J5cHRpb25LZXkiLCJrdHkiOiJSU0EiLCJuIjoidkpwMU13QUJkYkY4V1NiMzRGdlNteEY4Y3FJTlJSREdzNFNIUXBiRi13dlVxYXEzTy1vWEpBaEJiLS1XVWhUVG9Sd2dUNzFnczB0RlZDT3J0MFpaUS1JWUEtX2lxdkd5NV9YR3pTTXJiR1ljV0F4b0YyckdCNDUwdEwyVGZNeTR3UWRpNl9xNUROX0hQSk9ZX2hlbHRpNnhfWUkwaEVyN1VZYkxpN3U1NjlXaTRzbHZIeURlT2JnN3I4S0RaRy1FMnJsMmVkNUNhZkhMdjJtLW9IWDdkQmphR1AzeW1QZ2pPMFpKbHVLVVRBcW9fNzRtVnY1V2pzaktsTWdLN2w3eWE1dmZqWFZIenFHeUNuWnF1b3FIbWcwbmYzQXBsMGpTNXpWSDcyRDA3OENJSFpFaWR0S1h3RVphMVJfTGFFam1GMG9sVWVyZktIRXhNcTRCb1A0bjd3In1dfSwieC1tcy12ZXIiOiIxLjAifQ.agr9yNC1oVV5tETN4NQs5vHD5pkXUEwjr4Cf8ChZq1fcJWIIPKHNmr9MPf9eTKApeEcO42lXYgP_ZZXf2nTSnDlc_SlqtXPNI7DXwdomGPNUpuer0AO8xXaX9R9zbUzx7DmVaYldc5cchA8XFjT-cKTvQvli7ANIKvIovRSkPdDNOavg9_Pb41z8mtBSDt2i9w-V09d14Lf1qvyt3kZNCEvAOP9yDB3TGayS4x42lyKKiWPsM6ldbxF1uE-lOR4eRBYa6y8n8vCnGvgXb8Lz3VyrfGYBNy58tPbpte46CAGzjmSr-SgeyKaVelfBWIWaVDBoT4KJxVG3HGsmznx2IA";

        // initialize payload (AES key) with random bytes.
        std::vector<unsigned char> aes_key(32);
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> distrib(0, 255);
        for (auto& i : aes_key) {
            i = distrib(gen);
        }

        unsigned char* encrypted_data = nullptr;
        uint32_t encrypted_data_size = 0;
        unsigned char* encryption_metadata = nullptr;
        uint32_t encryption_metadata_size = 0;
        unsigned char* jwt = (unsigned char*)malloc((sizeof(unsigned char) * jwt_token.size()) + 1);
        std::memcpy(jwt, jwt_token.data(), jwt_token.size());
        jwt[jwt_token.size()] = '\0';

        attest::AttestationResult result = client->Encrypt(attest::EncryptionType::NONE,
            jwt,
            &aes_key.front(),
            aes_key.size(),
            &encrypted_data,
            &encrypted_data_size,
            &encryption_metadata,
            &encryption_metadata_size,
            RsaScheme::RsaEs,
            RsaHashAlg::RsaSha256);

        EXPECT_EQ(result.code_, attest::AttestationResult::ErrorCode::SUCCESS);
        EXPECT_EQ(encrypted_data_size, 256);

        // Try decrypting now
        int RSASize = 2048;
        int ModulusSize = RSASize / 8;
        uint8_t* decryptedBytes = nullptr;
        uint32_t decryptedBytesSize = 0;
        result = client->Decrypt(attest::EncryptionType::NONE,
            encrypted_data,
            encrypted_data_size,
            NULL,
            0,
            &decryptedBytes,
            &decryptedBytesSize,
            attest::RsaScheme::RsaEs,
            attest::RsaHashAlg::RsaSha256);

        EXPECT_EQ(result.code_, attest::AttestationResult::ErrorCode::SUCCESS);
        EXPECT_EQ(decryptedBytesSize, 32);
        std::vector<unsigned char> decrypted_AES(decryptedBytes, decryptedBytes+decryptedBytesSize);
        EXPECT_EQ(decrypted_AES, aes_key);
        for (int i = 0; i < aes_key.size(); ++i) {
            EXPECT_EQ(aes_key[i], decrypted_AES[i]) << "Vectors aes_key and decrypted_AES differ at index " << i;
        }
    }
    */

    TEST_F(ClientLibTests, Decrypt_negative) {

        // TODO: Add tests here to validate negative scenarios and make sure the
        // results are as expected.
        ASSERT_TRUE(true);
    }

    TEST_F(ClientLibTests, GetOSInfo_positive) {

        createFile(test_os_release, valid_version_entries);

        attest::OsInfo os_info = attest::OsInfo();

        attest::AttestationResult result = client->GetOSInfo(os_info);
        EXPECT_EQ(result.code_, attest::AttestationResult::ErrorCode::SUCCESS);

#ifdef PLATFORM_UNIX
        EXPECT_EQ(os_info.type, attest::OsType::LINUX);
        EXPECT_EQ(os_info.distro_name, "Test-OS");
        EXPECT_EQ(os_info.distro_version_major, 1);
        EXPECT_EQ(os_info.distro_version_minor, 10);
#else
        EXPECT_EQ(os_info.type, attest::OsType::WINDOWS);
        EXPECT_EQ(os_info.distro_name, "Microsoft");
#endif
        deleteFile(test_os_release);
    }

    TEST_F(ClientLibTests, GetOSInfo_negative1) {

        createFile(test_os_release, invalid_version_entries1);

        attest::OsInfo os_info = attest::OsInfo();

        attest::AttestationResult result = client->GetOSInfo(os_info);

#ifdef PLATFORM_UNIX
        EXPECT_EQ(result.code_, attest::AttestationResult::ErrorCode::
            SUCCESS);
        EXPECT_EQ(os_info.type, attest::OsType::LINUX);
        EXPECT_EQ(os_info.distro_name, "Test-OS");
        EXPECT_EQ(os_info.distro_version_major, 1);
        EXPECT_EQ(os_info.distro_version_minor, 0);
#else
        EXPECT_EQ(result.code_, attest::AttestationResult::ErrorCode::SUCCESS);
        EXPECT_EQ(os_info.type, attest::OsType::WINDOWS);
        EXPECT_EQ(os_info.distro_name, "Microsoft");
#endif
        deleteFile(test_os_release);
    }

    TEST_F(ClientLibTests, GetOSInfo_negative2) {

        createFile(test_os_release, invalid_version_entries2);

        attest::OsInfo os_info = attest::OsInfo();

        attest::AttestationResult result = client->GetOSInfo(os_info);

#ifdef PLATFORM_UNIX
        EXPECT_EQ(result.code_, attest::AttestationResult::ErrorCode::
            SUCCESS);
        EXPECT_EQ(os_info.type, attest::OsType::LINUX);
        EXPECT_EQ(os_info.distro_name, "Test-OS");
        EXPECT_EQ(os_info.distro_version_major, 1);
        EXPECT_EQ(os_info.distro_version_minor, 0);
#else
        EXPECT_EQ(result.code_, attest::AttestationResult::ErrorCode::SUCCESS);
        EXPECT_EQ(os_info.type, attest::OsType::WINDOWS);
        EXPECT_EQ(os_info.distro_name, "Microsoft");
#endif
        deleteFile(test_os_release);
    }

    TEST_F(ClientLibTests, GetOSInfo_negative3) {

        createFile(test_os_release, invalid_version_entries3);

        attest::OsInfo os_info = attest::OsInfo();

        attest::AttestationResult result = client->GetOSInfo(os_info);

#ifdef PLATFORM_UNIX
        EXPECT_EQ(result.code_, attest::AttestationResult::ErrorCode::
            SUCCESS);
        EXPECT_EQ(os_info.type, attest::OsType::LINUX);
        EXPECT_EQ(os_info.distro_name, "Test-OS");
        EXPECT_EQ(os_info.distro_version_major, 1);
        EXPECT_EQ(os_info.distro_version_minor, 0);
#else
        EXPECT_EQ(result.code_, attest::AttestationResult::ErrorCode::SUCCESS);
        EXPECT_EQ(os_info.type, attest::OsType::WINDOWS);
        EXPECT_EQ(os_info.distro_name, "Microsoft");
#endif
        deleteFile(test_os_release);
    }

#ifdef PLATFORM_LINUX
    TEST_F(ClientLibTests, GetOSInfo_negative4) {
        createFile(test_os_release, invalid_version_entries4);
        attest::OSInfo os_info = attest::OsInfo();

        attest::AttestationResult result = client->GetOSInfo(os_info);

        EXPECT_EQ(result.code_, attest::AttestationResult::ErrorCode::
            ERROR_FAILED_TO_GET_OS_INFO);
        EXPECT_TRUE(os_info.distro_name.empty());
        EXPECT_EQ(os_info.distro_version_major, 0);
        EXPECT_EQ(os_info.distro_version_minor, 0);
    }
#endif
    /**
     * Function to provide dummy value of artifacts to be retrieved from Tpm.
     */
    attest::AttestationResult ClientLibTests::getTpmInfo(attest::TpmInfo& tpm_info) {
        AttestationResult result(AttestationResult::ErrorCode::SUCCESS);

        uint8_t dummy_value_size = 10;
        attest::Buffer dummy_values(dummy_value_size);

        attest::PcrSet dummy_pcr_values = {};
        dummy_pcr_values.hashAlg = attest::HashAlg::Sha256;

        attest::PcrQuote dummy_quote;
        dummy_quote.quote = dummy_values;
        dummy_quote.signature = dummy_values;

        attest::EphemeralKey dummy_eph_key;
        dummy_eph_key.certifyInfo = dummy_values;
        dummy_eph_key.certifyInfoSignature = dummy_values;
        dummy_eph_key.encryptionKey = dummy_values;

        tpm_info.aik_cert_ = dummy_values;
        tpm_info.aik_pub_ = dummy_values;
        tpm_info.pcr_quote_ = dummy_quote;
        tpm_info.encryption_key_ = dummy_eph_key;
        tpm_info.pcr_values_ = dummy_pcr_values;

        return result;
    }

    /**
     * Function to provide dummy value of the isolation info
     */
    attest::AttestationResult ClientLibTests::getIsolationInfo(attest::IsolationInfo& isolation_info,
        attest::IsolationType isolation_type) {
        AttestationResult result(AttestationResult::ErrorCode::SUCCESS);

        uint8_t dummy_value_size = 10;
        attest::Buffer dummy_snp_report(dummy_value_size);
        attest::Buffer dummy_runtime_data(dummy_value_size);

        std::string dummy_vcek_cert = "dGVzdGNlcnQ=";
        isolation_info.isolation_type_ = isolation_type;
        if (isolation_type == attest::IsolationType::SEV_SNP) {
            isolation_info.vcek_cert_ = dummy_vcek_cert;
            isolation_info.snp_report_ = dummy_snp_report;
            isolation_info.runtime_data_ = dummy_runtime_data;
        }

        return result;
    }

    TEST_F(ClientLibTests, GetTpmInfo) {

        attest::TpmInfo tpm_info;

        // Calling getTpmInfo() function to get dummy values for artifacts from the tpm.
        // TODO: Replace the call with client->GetTpmInfo() once TPM simulator is enabled.
        attest::AttestationResult result = getTpmInfo(tpm_info);

        EXPECT_EQ(result.code_, attest::AttestationResult::ErrorCode::SUCCESS);
        EXPECT_FALSE(tpm_info.aik_pub_.empty());
        EXPECT_FALSE(tpm_info.aik_cert_.empty());
        EXPECT_EQ(tpm_info.pcr_values_.hashAlg, attest::HashAlg::Sha256);
        EXPECT_FALSE(tpm_info.pcr_quote_.quote.empty());
        EXPECT_FALSE(tpm_info.pcr_quote_.signature.empty());
        EXPECT_FALSE(tpm_info.encryption_key_.encryptionKey.empty());
        EXPECT_FALSE(tpm_info.encryption_key_.certifyInfo.empty());
        EXPECT_FALSE(tpm_info.encryption_key_.certifyInfoSignature.empty());
    }

    TEST_F(ClientLibTests, GetMeasurements_positive) {

        AttestationClientImpl::MeasurementType measurement_type =
            AttestationClientImpl::MeasurementType::TCG;

        std::vector<unsigned char> logs;
        attest::AttestationResult result = client->GetMeasurements(measurement_type,
            logs);

        EXPECT_EQ(result.code_, attest::AttestationResult::ErrorCode::SUCCESS);

        // Note: We are not validating if the logs are empty since OS not having measurements
        // is a valid case as some OSes do not expose log measurements.
    }

    TEST_F(ClientLibTests, GetMeasurements_negative) {

        AttestationClientImpl::MeasurementType measurement_type =
            AttestationClientImpl::MeasurementType::IMA;

        std::vector<unsigned char> logs;
        attest::AttestationResult result = client->GetMeasurements(measurement_type,
            logs);

        EXPECT_EQ(result.code_, attest::AttestationResult::ErrorCode::ERROR_INVALID_INPUT_PARAMETER);
        EXPECT_TRUE(logs.empty());
    }

    void ClientLibTests::getAttestationParameters(attest::AttestationParameters& params,
        attest::IsolationType isolation_type) {

        createFile(test_os_release, valid_version_entries);

        attest::OsInfo os_info;
        attest::AttestationResult result = client->GetOSInfo(os_info);
        EXPECT_EQ(result.code_, attest::AttestationResult::ErrorCode::SUCCESS);

        deleteFile(test_os_release);

        attest::TpmInfo tpm_info;
        attest::Buffer tcg_logs;
        attest::IsolationInfo isolation_info;

        // Calling getTpmInfo() function to get dummy values for artifacts from the tpm.
        // TODO: Replace the call with client->GetTpmInfo() once TPM simulator is enabled.
        result = getTpmInfo(tpm_info);
        EXPECT_EQ(result.code_, attest::AttestationResult::ErrorCode::SUCCESS);

        AttestationClientImpl::MeasurementType type = AttestationClientImpl::MeasurementType::TCG;
        result = client->GetMeasurements(type, tcg_logs);
        EXPECT_EQ(result.code_, attest::AttestationResult::ErrorCode::SUCCESS);

        result = getIsolationInfo(isolation_info, isolation_type);
        EXPECT_EQ(result.code_, attest::AttestationResult::ErrorCode::SUCCESS);

        std::unordered_map<std::string,
            std::string> client_payload;
        client_payload[arm_id_key] = std::string(arm_id_value);
        client_payload[nonce_key] = std::string(nonce_value);

        params.os_info_ = os_info;
        params.tpm_info_ = tpm_info;
        params.tcg_logs_ = tcg_logs;
        params.client_payload_ = client_payload;
        params.isolation_info_ = isolation_info;
    }

    TEST_F(ClientLibTests, TestCreatePayloadTvm) {
        attest::AttestationParameters params;
        getAttestationParameters(params, attest::IsolationType::TRUSTED_LAUNCH);

        std::string json_decoded;
        attest::AttestationResult result = client->CreatePayload(params,
            json_decoded);
        ASSERT_EQ(result.code_, attest::AttestationResult::ErrorCode::SUCCESS);

        Json::Value root;
        Json::Reader reader;
        bool success = reader.parse(json_decoded.c_str(), root);
        ASSERT_TRUE(success);

        std::string attestation_info_encoded = root.get("AttestationInfo", "").asString();
        ASSERT_FALSE(attestation_info_encoded.empty());

        attest::Buffer attestation_info_binary = attest::base64::base64url_to_binary(attestation_info_encoded);
        ASSERT_FALSE(attestation_info_binary.empty());

        std::string attestation_info_decoded = std::string(attestation_info_binary.begin(),
            attestation_info_binary.end());
        ASSERT_FALSE(attestation_info_decoded.empty());

        std::ofstream out("AttestationRequestJson.txt", std::ios::binary);
        out.write(attestation_info_decoded.c_str(), attestation_info_decoded.length());

        success = reader.parse(attestation_info_decoded.c_str(), root);
        ASSERT_TRUE(success);

        // Validating some values that we have manually set here to see if they are
        // not empty.
        EXPECT_FALSE(root.get(JSON_OS_TYPE_KEY, "").asString().empty());
        EXPECT_FALSE(root.get(JSON_OS_DISTRO_KEY, "").asString().empty());
        EXPECT_FALSE(root.get(JSON_OS_BUILD_KEY, "").asString().empty());

        Json::Value client_payload = root.get(JSON_CLIENT_PAYLOAD_KEY, "");

        EXPECT_FALSE(client_payload.get(arm_id_key, "").asString().empty());
        EXPECT_FALSE(client_payload.get(nonce_key, "").asString().empty());
        Json::Value isolation_info = root.get(JSON_ISOLATION_INFO_KEY, "");
        EXPECT_EQ(isolation_info.get(JSON_ISOLATION_TYPE_KEY, "").asString(), JSON_ISOLATION_TYPE_TVM);
    }

    TEST_F(ClientLibTests, TestCreatePayloadCvm) {
        attest::AttestationParameters params;
        getAttestationParameters(params, attest::IsolationType::SEV_SNP);

        std::string json_decoded;
        attest::AttestationResult result = client->CreatePayload(params,
            json_decoded);
        ASSERT_EQ(result.code_, attest::AttestationResult::ErrorCode::SUCCESS);

        Json::Value root;
        Json::Reader reader;
        bool success = reader.parse(json_decoded.c_str(), root);
        ASSERT_TRUE(success);

        std::string attestation_info_encoded = root.get("AttestationInfo", "").asString();
        ASSERT_FALSE(attestation_info_encoded.empty());

        attest::Buffer attestation_info_binary = attest::base64::base64url_to_binary(attestation_info_encoded);
        ASSERT_FALSE(attestation_info_binary.empty());

        std::string attestation_info_decoded = std::string(attestation_info_binary.begin(),
            attestation_info_binary.end());
        ASSERT_FALSE(attestation_info_decoded.empty());

        std::ofstream out("AttestationRequestJson.txt", std::ios::binary);
        out.write(attestation_info_decoded.c_str(), attestation_info_decoded.length());

        success = reader.parse(attestation_info_decoded.c_str(), root);
        ASSERT_TRUE(success);

        // Validating some values that we have manually set here to see if they are
        // not empty.
        EXPECT_FALSE(root.get(JSON_OS_TYPE_KEY, "").asString().empty());
        EXPECT_FALSE(root.get(JSON_OS_DISTRO_KEY, "").asString().empty());
        EXPECT_FALSE(root.get(JSON_OS_BUILD_KEY, "").asString().empty());

        Json::Value client_payload = root.get(JSON_CLIENT_PAYLOAD_KEY, "");

        EXPECT_FALSE(client_payload.get(arm_id_key, "").asString().empty());
        EXPECT_FALSE(client_payload.get(nonce_key, "").asString().empty());
        Json::Value isolation_info = root.get(JSON_ISOLATION_INFO_KEY, "");
        EXPECT_EQ(isolation_info.get(JSON_ISOLATION_TYPE_KEY, "").asString(), JSON_ISOLATION_TYPE_SEVSNP);

        Json::Value evidence_info = isolation_info.get(JSON_ISOLATION_EVIDENCE_KEY, "");
        EXPECT_FALSE(evidence_info.get(JSON_ISOLATION_PROOF_KEY, "").asString().empty());
        EXPECT_FALSE(evidence_info.get(JSON_ISOLATION_RUNTIME_DATA_KEY, "").asString().empty());
    }

    void TestBase64String(const std::string& base64UrlEncoded, const std::string base64Encoded)
    {
        attest::Buffer buffer = attest::base64::base64url_to_binary(base64UrlEncoded);
        attest::Buffer buffer1 = attest::base64::base64_to_binary(base64Encoded);
        EXPECT_TRUE(buffer == buffer1);

        std::string base64EncodedResult = attest::base64::binary_to_base64url(buffer1);
        EXPECT_TRUE(base64UrlEncoded == base64EncodedResult);
    }

    void ValidateBase64Encode(const std::string& to_encode, const std::string& expected)
    {
        const auto encoded = attest::base64::base64_encode(to_encode);
        EXPECT_FALSE(encoded.empty());
        EXPECT_EQ(expected, encoded);
    }

    void ValidateBase64Decode(const std::string& to_decode, const std::string& expected)
    {
        const auto decoded = attest::base64::base64_decode(to_decode);
        EXPECT_FALSE(decoded.empty());
        EXPECT_EQ(expected, decoded);
    }

    TEST_F(ClientLibTests, TestBase64UrlEncodeDecode) {
        // Test with one padding character
        std::string base64urlEncoded = "dGV4dCB0ZXN0IDE"; // "text test 1"
        std::string base64Encoded = "dGV4dCB0ZXN0IDE="; // this is base 64 encoded string of same text : "text test 1"
        TestBase64String(base64urlEncoded, base64Encoded);

        // Test with two padding characters
        base64urlEncoded = "d2FzaGluZ3Rvbg"; // "washington"
        base64Encoded = "d2FzaGluZ3Rvbg=="; // "washington"
        TestBase64String(base64urlEncoded, base64Encoded);

        // Test with no padding character
        base64urlEncoded = "MTIzNDU2"; // "123456"
        base64Encoded = "MTIzNDU2"; // "123456"
        TestBase64String(base64urlEncoded, base64Encoded);

        // Test with special characters
        base64urlEncoded = "d2a-aGlu_3Rvbg"; // unicode string wiht special characters
        base64Encoded = "d2a+aGlu/3Rvbg=="; // base64 representation of above string
        TestBase64String(base64urlEncoded, base64Encoded);

        // Test with no padding character
        ValidateBase64Encode("foobar", "Zm9vYmFy");

        // Test with one padding
        ValidateBase64Encode("fooba", "Zm9vYmE=");

        // Test with two padding
        ValidateBase64Encode("foob", "Zm9vYg==");

        // Test with no padding character
        ValidateBase64Decode("Zm9vYmFy", "foobar");

        // Test with one padding
        ValidateBase64Decode("Zm9vYmE=", "fooba");

        // Test with two padding
        ValidateBase64Decode("Zm9vYg==", "foob");
    }

    TEST_F(ClientLibTests, TestBase64ToBinaryWithZeroByteAtEnd) {
        std::string base64String = "abcsAA==";
        std::vector<unsigned char> base64ToBinary = attest::base64::base64_to_binary(base64String);
        std::string binaryToBase64 = attest::base64::binary_to_base64(base64ToBinary);
        EXPECT_EQ(binaryToBase64, base64String);

        base64String = "abcsAAA=";
        base64ToBinary = attest::base64::base64_to_binary(base64String);
        binaryToBase64 = attest::base64::binary_to_base64(base64ToBinary);
        EXPECT_EQ(binaryToBase64, base64String);

        base64String = "abcsAAAA";
        base64ToBinary = attest::base64::base64_to_binary(base64String);
        binaryToBase64 = attest::base64::binary_to_base64(base64ToBinary);
        EXPECT_EQ(binaryToBase64, base64String);

        base64String = "abcsAAAAAAAA";
        base64ToBinary = attest::base64::base64_to_binary(base64String);
        binaryToBase64 = attest::base64::binary_to_base64(base64ToBinary);
        EXPECT_EQ(binaryToBase64, base64String);
    }

    TEST_F(ClientLibTests, TestEncryptDataWithRSAPubKey) {
        const char k[] =
            "-----BEGIN PUBLIC KEY-----\n"
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0/hZGQABJgcye7Np2Bxb\n"
            "+rDmcwDjkaiStP7Rbk9GWKyL+fgIjJtAbarmyaDJfyuT2SE66mlOfvt7mHpmqG6Q\n"
            "Upr5w0zqLtQjHu9cJP8T/i3BwURn5m32MtkaHGCGQr43y4DluDKF/8Bd8ecduv7J\n"
            "CcDgjd7oszKoGoXsKfknOEuOqtEF59dOyCsC6JgGjvP/TR+cfSkIaLs+6RYFQ5ES\n"
            "PczvY4ZOjdT8pn6heU1nxLPYGq7if7Kso8+gOpvAJ5hwu2J8Tji7ZnkFFMqgjtLk\n"
            "m1lq8/KibiZGrUlnmXE0kt4N2PBpSF3SE33LqxCsHawb4uhtywmW6ldjc1A3kVVw\n"
            "ywIDAQAB\n"
            "-----END PUBLIC KEY-----\n";

        BIO* bio = BIO_new_mem_buf(k, (int)sizeof(k));
        attest::Buffer input_data(32); // 256-bit symmetric key
        attest::Buffer encrypted_data;
        attest::AttestationResult res = attest::crypto::EncryptDataWithRSAPubKey(bio, RsaScheme::RsaEs, RsaHashAlg::RsaSha256, input_data, encrypted_data);
        EXPECT_EQ(encrypted_data.size(), 256);
    }

    TEST_F(ClientLibTests, TestExtractJwkInfoFromAttestationJwt_positive) {
        const std::string jwt_token = "eyJhbGciOiJSUzI1NiIsImprdSI6Imh0dHBzOi8vc2hhcmVkZXVzMi5ldXMyLmF0dGVzdC5henVyZS5uZXQvY2VydHMiLCJraWQiO"
            "iJyai9VdW9lZFVEZUMxV1RwbnhCbzJmQnorUkZuQXVDNWo0bHVIc1FBYVhJPSIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2NTAwMDg1O"
            "DAsImlhdCI6MTY0OTk3OTc4MCwiaXNzIjoiaHR0cHM6Ly9zaGFyZWRldXMyLmV1czIuYXR0ZXN0LmF6dXJlLm5ldCIsImp0aSI6Im"
            "I2ODcyODdjMDEwMDA5MjNkYTUzN2JjOTc3M2I0ZGI1MWZiMDNhNDc5ODRjZjgyMTFkYzYwMjgxYjdjNzI0MmEiLCJuYmYiOjE2NDk"
            "5Nzk3ODAsInNlY3VyZWJvb3QiOnRydWUsIngtbXMtYXR0ZXN0YXRpb24tdHlwZSI6ImF6dXJldm0iLCJ4LW1zLWF6dXJldm0tYXR0"
            "ZXN0YXRpb24tcHJvdG9jb2wtdmVyIjoiMS4wIiwieC1tcy1henVyZXZtLWF0dGVzdGVkLXBjcnMiOlswLDEsMiwzLDQsNSw2LDcsM"
            "TEsMTIsMTNdLCJ4LW1zLWF6dXJldm0tYm9vdGRlYnVnLWVuYWJsZWQiOmZhbHNlLCJ4LW1zLWF6dXJldm0tZGJ2YWxpZGF0ZWQiOn"
            "RydWUsIngtbXMtYXp1cmV2bS1kYnh2YWxpZGF0ZWQiOnRydWUsIngtbXMtYXp1cmV2bS1kZWJ1Z2dlcnNkaXNhYmxlZCI6dHJ1ZSw"
            "ieC1tcy1henVyZXZtLWRlZmF1bHQtc2VjdXJlYm9vdGtleXN2YWxpZGF0ZWQiOnRydWUsIngtbXMtYXp1cmV2bS1lbGFtLWVuYWJs"
            "ZWQiOmZhbHNlLCJ4LW1zLWF6dXJldm0tZmxpZ2h0c2lnbmluZy1lbmFibGVkIjpmYWxzZSwieC1tcy1henVyZXZtLWh2Y2ktcG9sa"
            "WN5IjowLCJ4LW1zLWF6dXJldm0taHlwZXJ2aXNvcmRlYnVnLWVuYWJsZWQiOmZhbHNlLCJ4LW1zLWF6dXJldm0taXMtd2luZG93cy"
            "I6dHJ1ZSwieC1tcy1henVyZXZtLWtlcm5lbGRlYnVnLWVuYWJsZWQiOmZhbHNlLCJ4LW1zLWF6dXJldm0tb3NidWlsZCI6Ik5vdEF"
            "wcGxpY2FibGUiLCJ4LW1zLWF6dXJldm0tb3NkaXN0cm8iOiJNaWNyb3NvZnQiLCJ4LW1zLWF6dXJldm0tb3N0eXBlIjoiV2luZG93"
            "cyIsIngtbXMtYXp1cmV2bS1vc3ZlcnNpb24tbWFqb3IiOjEwLCJ4LW1zLWF6dXJldm0tb3N2ZXJzaW9uLW1pbm9yIjowLCJ4LW1zL"
            "WF6dXJldm0tc2lnbmluZ2Rpc2FibGVkIjp0cnVlLCJ4LW1zLWF6dXJldm0tdGVzdHNpZ25pbmctZW5hYmxlZCI6ZmFsc2UsIngtbX"
            "MtYXp1cmV2bS12bWlkIjoiRjdDRUE4MTMtNEM0NC00MzZDLTg1MzctNTcwMTk5OUM0NTg5IiwieC1tcy1wb2xpY3ktaGFzaCI6Ind"
            "tOW1IbHZUVTgyZThVcW9PeTFZajFGQlJTTmtmZTk5LTY5SVlEcTllV3MiLCJ4LW1zLXJ1bnRpbWUiOnsia2V5cyI6W3siZSI6IkFR"
            "QUIiLCJrZXlfb3BzIjpbImVuY3J5cHQiXSwia2lkIjoiVHBtRXBoZW1lcmFsRW5jcnlwdGlvbktleSIsImt0eSI6IlJTQSIsIm4iO"
            "iJzbjl4U3dBQURZT3AwWDRIR0NXZnUyQjlHbnZDYzZqTmhBS21iZDdlcFA0QXdWN3BGdGNhZVFDZVV6Rl84Wm5tOThxMGhsTjlOaV"
            "BfYV8wdWQxWmJvZEREa3EzaDY5elNEWGhrNTlLMU51ZEhwblp1eGhOZDJSRUR5WkkxUWFDR0tkMTdFcWI3WnQxV09ybjhqRlFjaS0"
            "xMDZXNnVmS1VlQlpLYTJsRDhNdlhqTV92Snl4SnlyUGJvQ0FXWmttanZmV1pQRUZGZ2JzZ3pYVDlHdGN6RDRRRGlqcHluZ0F5bzA5"
            "Q0R3VHFQWVFNNi1SbXZmNjNKX0tHYk1GWHk0WHBEQTlIcUdrZ25UN2xIZXhNYkdyaTRZUG15TWFiTEhzWDNnOEcwZ3ZBREE5MXkyN"
            "DF6VXRnTFJ0SjAtT1hwQklRN2ZScHdjUFpEX2RmYm9PYWFGN1hhbncifV19LCJ4LW1zLXZlciI6IjEuMCJ9.D1schVs3pOwo7BwGl"
            "ZT0-XO5aAe2NmXchblZIWxD-m2dLUJ0Jp8_j3tHBoAh3L_AaIgyqf0rV0h51D-0ZDwgQx4P0kOwnKjomL9mAbv9KHpTR9FlkG2VYm"
            "MybUEPR-Vb3hpzH6AlABmHXd5GX5YjG7wj3k-lvP2vOdJcZQmH2xkHfrh1pYwGc6f8Ese5ZgbI0ncnNOuwgumcYB5srjSnVeSF7v7"
            "NDnlvUiKwJzSZIFoyPa3bGzh9cIhfn3qTXMw7OP2Ne84sfSQ_2wZrMLSnBWn-fynX4WuNy7LiO-RAygvu3SQnEwksIRMMT3crNhPo"
            "_DyV3Os9MfOmCk7J0K4-bw";

        const std::string expected_n = "sn9xSwAADYOp0X4HGCWfu2B9GnvCc6jNhAKmbd7epP4AwV7pFtcaeQCeUzF_8Znm98q0hlN9NiP_a_0ud1ZbodDDkq3h69zSDXhk5"
            "9K1NudHpnZuxhNd2REDyZI1QaCGKd17Eqb7Zt1WOrn8jFQci-106W6ufKUeBZKa2lD8MvXjM_vJyxJyrPboCAWZkmjvfWZPEFFgbsg"
            "zXT9GtczD4QDijpyngAyo09CDwTqPYQM6-Rmvf63J_KGbMFXy4XpDA9HqGkgnT7lHexMbGri4YPmyMabLHsX3g8G0gvADA91y241zU"
            "tgLRtJ0-OXpBIQ7fRpwcPZD_dfboOaaF7Xanw";
        const std::string expected_e = "AQAB";
        std::string n, e;
        bool res = attest::jwt::ExtractJwkInfoFromAttestationJwt(jwt_token, n, e);

        EXPECT_TRUE(res);
        EXPECT_EQ(n, expected_n);
        EXPECT_EQ(e, expected_e);
    }

    TEST_F(ClientLibTests, TestExtractSnpReportAndRuntimeDataFromHclReport) {
        const std::string hcl_report_base64 = "SENMQQEAAAAbBwAAAgAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAQAAAB8AAwAAAAAAAQAAAAAAAAAAAAAAAAAAAAIAAAAAAAAAAAA"
            "AAAAAAAAAAAAAAQAAAAIAAAAAAAI3AQAAAAAAAAAAAAAAAAAAADajzAKxyB7n5IokwQbnggrlhHbZwRRKJVWBsKg3xN-MAAAAAA"
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABTZm1lTo_Q19KvSK-SLc6hhRAnEngipby03P2snLt4k8sm9OYA4qRL-nR-j5a_M"
            "qUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC4eKMsf4IEeaEZLbQ7OxGlYIu1MbNDC-COVZRs1P8kQBUA-H_a3-bUJ"
            "PYFQiJCW3gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHRmt-Th6X4E-iIxMlCnnXrU4Xb"
            "SCiG-LEirgDsx7W1m__________________________________________8CAAAAAAACNwAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            "AAALC1KEY-NU9hAK235FQTmfDwhLYm4zXw86QI2eDiA5YzobsZz78ryrtR2hs_uX5Co1wYqy1Zf591EXvJBFauZE4AAAAAAAAAA"
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADkdzcid4-KEfIR_gaTvTcs9pWi3Sqi9GTSBspsjTu9KXMhz9KdkZ"
            "v_UQY0Fa5HOukAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACnNeNYo5fGFvcrTCWk0p6lnDe_T_Hk45-R1blLKC61-GmFzkzLQ6r-c"
            "2IXFJnucS8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFsCAAABAAAAAgAAAAEAAABHAgAAeyJrZXlzIjpbeyJraWQiOiJIQ0xBa1B1YiI"
            "sImtleV9vcHMiOlsiZW5jcnlwdCJdLCJrdHkiOiJSU0EiLCJlIjoiQVFBQiIsIm4iOiJ2dTFiQ2dBQTNTajRCcTMtVjZ0VWNYMm"
            "FLRjJqbFBYTURwRlc4TDZCeWJ4NnJPa2pRRnBnWjAtZFBGY3NJWWR0X19NZjNVeXlJdTdGdDlOQnBidW1FdHA3U0lSOUVjTUNrS"
            "FNPVC1jblNfNUtFMHdoN2Y0ZE1jeDhpVFFJNEFHRjRUY05nRFc4eXRPTlZKZWJqY1ZReVRGOG1ZY1owZ19uV1dHal9Tck1uUTZY"
            "Zmhnc1ctcW94WWdvZ3J6MlNsWHptWWpJYkdieUFmUkJ5aGszS0RoRkFzWnctWmFVbnp0SWhFNTBsVHBpM0tfOHBxNXdfSlhCODY"
            "yVTZTQk1ZZHV4YUlnV0dUQnhabHR1YnRHamlyMXF4T2NjYUp2LVlOcHg2ZFNUWGlsaFNETlhsYVJ4aERDRnN5RWVFbDgtVnIyMD"
            "I0TUl3X2tFTnlOZkZhN0VUYWNHbHcifV0sInZtLWNvbmZpZ3VyYXRpb24iOnsiY29uc29sZS1lbmFibGVkIjp0cnVlLCJjdXJyZ"
            "W50LXRpbWUiOjE2NDk3OTc5NTgsInNlY3VyZS1ib290Ijp0cnVlLCJ0cG0tZW5hYmxlZCI6dHJ1ZSwidm1VbmlxdWVJZCI6IkEy"
            "ODhGOTFFLTQ0MDQtNEE5RC04OTAxLTZGN0JDRjJCNUQ2MSJ9fQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

        const std::string variable_data_base64 = "eyJrZXlzIjpbeyJraWQiOiJIQ0xBa1B1YiIsImtleV9vcHMiOlsiZW5jcnlwdCJdLCJrdHkiOiJSU0EiLCJlIjoiQVFBQiIsIm4"
            "iOiJ2dTFiQ2dBQTNTajRCcTMtVjZ0VWNYMmFLRjJqbFBYTURwRlc4TDZCeWJ4NnJPa2pRRnBnWjAtZFBGY3NJWWR0X19NZjNVeX"
            "lJdTdGdDlOQnBidW1FdHA3U0lSOUVjTUNrSFNPVC1jblNfNUtFMHdoN2Y0ZE1jeDhpVFFJNEFHRjRUY05nRFc4eXRPTlZKZWJqY"
            "1ZReVRGOG1ZY1owZ19uV1dHal9Tck1uUTZYZmhnc1ctcW94WWdvZ3J6MlNsWHptWWpJYkdieUFmUkJ5aGszS0RoRkFzWnctWmFV"
            "bnp0SWhFNTBsVHBpM0tfOHBxNXdfSlhCODYyVTZTQk1ZZHV4YUlnV0dUQnhabHR1YnRHamlyMXF4T2NjYUp2LVlOcHg2ZFNUWGl"
            "saFNETlhsYVJ4aERDRnN5RWVFbDgtVnIyMDI0TUl3X2tFTnlOZkZhN0VUYWNHbHcifV0sInZtLWNvbmZpZ3VyYXRpb24iOnsiY2"
            "9uc29sZS1lbmFibGVkIjp0cnVlLCJjdXJyZW50LXRpbWUiOjE2NDk3OTc5NTgsInNlY3VyZS1ib290Ijp0cnVlLCJ0cG0tZW5hY"
            "mxlZCI6dHJ1ZSwidm1VbmlxdWVJZCI6IkEyODhGOTFFLTQ0MDQtNEE5RC04OTAxLTZGN0JDRjJCNUQ2MSJ9fQ";

        const std::string snp_report_base64 = "AQAAAAEAAAAfAAMAAAAAAAEAAAAAAAAAAAAAAAAAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAACAAAAAAACNwEAAAAAAAAAAAA"
            "AAAAAAAA2o8wCscge5-SKJMEG54IK5YR22cEUSiVVgbCoN8TfjAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAU2ZtZU"
            "6P0NfSr0ivki3OoYUQJxJ4IqW8tNz9rJy7eJPLJvTmAOKkS_p0fo-WvzKlAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            "AAuHijLH-CBHmhGS20OzsRpWCLtTGzQwvgjlWUbNT_JEAVAPh_2t_m1CT2BUIiQlt4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB0Zrfk4el-BPoiMTJQp5161OF20gohvixIq4A7Me1tZv_________________________"
            "_________________AgAAAAAAAjcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACwtShGPjVPYQCtt-RUE5nw8IS2JuM18POkCNng4g"
            "OWM6G7Gc-_K8q7UdobP7l-QqNcGKstWX-fdRF7yQRWrmROAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            "AAAAA5Hc3InePihHyEf4Gk703LPaVot0qovRk0gbKbI07vSlzIc_SnZGb_1EGNBWuRzrpAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            "AApzXjWKOXxhb3K0wlpNKepZw3v0_x5OOfkdW5Sygutfhphc5My0Oq_nNiFxSZ7nEvAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

        attest::Buffer snp_report;
        attest::Buffer runtime_data;
        AttestationResult res = hcl_report_parser->
            ExtractSnpReportAndRuntimeDataFromHclReport(attest::base64::base64url_to_binary(hcl_report_base64),
                snp_report,
                runtime_data);

        EXPECT_EQ(res.code_, AttestationResult::ErrorCode::SUCCESS);
        EXPECT_EQ(variable_data_base64, attest::base64::binary_to_base64url(runtime_data));
        EXPECT_EQ(snp_report_base64, attest::base64::binary_to_base64url(snp_report));
    }

    TEST_F(ClientLibTests, TestExtractJwkInfoFromAttestationJwt_negative) {
        const std::string jwt_token_invalid = "eyJhbGciOiJSUzI1NiIsImprdSI6Imh0dHBzOi8vc2hhcmVkZXVzMi5ldXMyLmF0dGVzdC5henVyZS5uZXQvY2VydHMiLCJraWQiO"
            "iJyai9VdW9lZFVEZUMxV1RwbnhCbzJmQnorUkZuQXVDNWo0bHVIc1FBYVhJPSIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2NTAwMDg1O"
            "DAsImlhdCI6MTY0OTk3OTc4MCwiaXNzIjoiaHR0cHM6Ly9zaGFyZWRldXMyLmV1czIuYXR0ZXN0LmF6dXJlLm5ldCIsImp0aSI6Im";

        std::string n, e;
        bool res = attest::jwt::ExtractJwkInfoFromAttestationJwt(jwt_token_invalid, n, e);
        EXPECT_FALSE(res);
    }

    TEST_F(ClientLibTests, ConvertJwkToRsaPubKey_positive) {
        const std::string n = "sn9xSwAADYOp0X4HGCWfu2B9GnvCc6jNhAKmbd7epP4AwV7pFtcaeQCeUzF_8Znm98q0hlN9NiP_a_0ud1ZbodDDkq3h69zSDXhk5"
            "9K1NudHpnZuxhNd2REDyZI1QaCGKd17Eqb7Zt1WOrn8jFQci-106W6ufKUeBZKa2lD8MvXjM_vJyxJyrPboCAWZkmjvfWZPEFFgbsg"
            "zXT9GtczD4QDijpyngAyo09CDwTqPYQM6-Rmvf63J_KGbMFXy4XpDA9HqGkgnT7lHexMbGri4YPmyMabLHsX3g8G0gvADA91y241zU"
            "tgLRtJ0-OXpBIQ7fRpwcPZD_dfboOaaF7Xanw";
        const std::string e = "AQAB";
        BIO* pkey_bio = BIO_new(BIO_s_mem());
        attest::AttestationResult result = attest::crypto::ConvertJwkToRsaPubKey(pkey_bio, n, e);
        EXPECT_EQ(result.code_, attest::AttestationResult::ErrorCode::SUCCESS);
    }

    TEST_F(ClientLibTests, ConvertJWkToRsaPubKeyTest) {
        const std::string n = "qoOpjgAAp0_c_hhBU63bUbLGuuIPq3dFkpZbpHEZXubkDzRL9XzL3GzOEdAX1v0wF0qNteJwcTRQ2Q2F9yozHqzD-anbjBXvONpMYVyQuw2oEwSFuSB7eyrN1Emlc7dI1E7ZKCR-5_K3m6j2p10-5Swbmb3Ri2wkLI1kKmzXF4uZZWN6LDW9m0vpDW_53krrAwCCGgW6pW7W7K6gerdFwGT2rkUCNuYW0E0ie0Q1Q2hJdbfF8qHbML23ufmgDnq23YGSEbuXPUv8mgdDCeKhPB2WrkBdX7x-chTxRU9uO8yRDsCb6lAeHbvhOW1CbbWZIVctTe3T5hiwsC4BdbVGKQ";
        const std::string e = "AQAB";
        const std::string expected_rsa_pubkey =
            "-----BEGIN PUBLIC KEY-----"
            "\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqoOpjgAAp0/c/hhBU63b"
            "\nUbLGuuIPq3dFkpZbpHEZXubkDzRL9XzL3GzOEdAX1v0wF0qNteJwcTRQ2Q2F9yoz"
            "\nHqzD+anbjBXvONpMYVyQuw2oEwSFuSB7eyrN1Emlc7dI1E7ZKCR+5/K3m6j2p10+"
            "\n5Swbmb3Ri2wkLI1kKmzXF4uZZWN6LDW9m0vpDW/53krrAwCCGgW6pW7W7K6gerdF"
            "\nwGT2rkUCNuYW0E0ie0Q1Q2hJdbfF8qHbML23ufmgDnq23YGSEbuXPUv8mgdDCeKh"
            "\nPB2WrkBdX7x+chTxRU9uO8yRDsCb6lAeHbvhOW1CbbWZIVctTe3T5hiwsC4BdbVG"
            "\nKQIDAQAB"
            "\n-----END PUBLIC KEY-----\n";
        BIO* pkey_bio = BIO_new(BIO_s_mem());
        attest::AttestationResult result = attest::crypto::ConvertJwkToRsaPubKey(pkey_bio, n, e);
        EXPECT_EQ(result.code_, attest::AttestationResult::ErrorCode::SUCCESS);
        char* bio_str;
        long size = BIO_get_mem_data(pkey_bio, &bio_str);
        EXPECT_NE(size, 0);
        char* rsa_pubkey = (char*)malloc(size + 1);
        memcpy(rsa_pubkey, bio_str, size);
        rsa_pubkey[size] = '\0';
        EXPECT_EQ(expected_rsa_pubkey, std::string(rsa_pubkey));
    }

    TEST_F(ClientLibTests, ConvertJwkToRsaPubKey_negative) {
        BIO* pkey_bio = NULL;
        attest::AttestationResult result = attest::crypto::ConvertJwkToRsaPubKey(pkey_bio, "", "");
        EXPECT_EQ(result.code_, attest::AttestationResult::ErrorCode::ERROR_INVALID_INPUT_PARAMETER);

        pkey_bio = BIO_new(BIO_s_mem());
        const std::string garbage_n = "sn9xSwAADYOp0X4HGCWfu2B9GnvCc6jNhAKmbd7epP4AwV7pFtcaeQCeUzF_8Znm98q0hlN9NiP_a_0ud1ZbodDDkq3h69zSDXhk5";
        const std::string e = "AQAB";
        result = attest::crypto::ConvertJwkToRsaPubKey(pkey_bio, garbage_n, e);
        EXPECT_EQ(result.code_, attest::AttestationResult::ErrorCode::ERROR_CONVERTING_JWK_TO_RSA_PUB);
    }

    TEST_F(ClientLibTests, Encrypt_NONE) {
        const std::string jwt_token = "eyJhbGciOiJSUzI1NiIsImprdSI6Imh0dHBzOi8vc2hhcmVkZXVzMi5ldXMyLmF0dGVzdC5henVyZS5uZXQvY2VydHMiLCJraWQiO"
            "iJyai9VdW9lZFVEZUMxV1RwbnhCbzJmQnorUkZuQXVDNWo0bHVIc1FBYVhJPSIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2NTAwMDg1O"
            "DAsImlhdCI6MTY0OTk3OTc4MCwiaXNzIjoiaHR0cHM6Ly9zaGFyZWRldXMyLmV1czIuYXR0ZXN0LmF6dXJlLm5ldCIsImp0aSI6Im"
            "I2ODcyODdjMDEwMDA5MjNkYTUzN2JjOTc3M2I0ZGI1MWZiMDNhNDc5ODRjZjgyMTFkYzYwMjgxYjdjNzI0MmEiLCJuYmYiOjE2NDk"
            "5Nzk3ODAsInNlY3VyZWJvb3QiOnRydWUsIngtbXMtYXR0ZXN0YXRpb24tdHlwZSI6ImF6dXJldm0iLCJ4LW1zLWF6dXJldm0tYXR0"
            "ZXN0YXRpb24tcHJvdG9jb2wtdmVyIjoiMS4wIiwieC1tcy1henVyZXZtLWF0dGVzdGVkLXBjcnMiOlswLDEsMiwzLDQsNSw2LDcsM"
            "TEsMTIsMTNdLCJ4LW1zLWF6dXJldm0tYm9vdGRlYnVnLWVuYWJsZWQiOmZhbHNlLCJ4LW1zLWF6dXJldm0tZGJ2YWxpZGF0ZWQiOn"
            "RydWUsIngtbXMtYXp1cmV2bS1kYnh2YWxpZGF0ZWQiOnRydWUsIngtbXMtYXp1cmV2bS1kZWJ1Z2dlcnNkaXNhYmxlZCI6dHJ1ZSw"
            "ieC1tcy1henVyZXZtLWRlZmF1bHQtc2VjdXJlYm9vdGtleXN2YWxpZGF0ZWQiOnRydWUsIngtbXMtYXp1cmV2bS1lbGFtLWVuYWJs"
            "ZWQiOmZhbHNlLCJ4LW1zLWF6dXJldm0tZmxpZ2h0c2lnbmluZy1lbmFibGVkIjpmYWxzZSwieC1tcy1henVyZXZtLWh2Y2ktcG9sa"
            "WN5IjowLCJ4LW1zLWF6dXJldm0taHlwZXJ2aXNvcmRlYnVnLWVuYWJsZWQiOmZhbHNlLCJ4LW1zLWF6dXJldm0taXMtd2luZG93cy"
            "I6dHJ1ZSwieC1tcy1henVyZXZtLWtlcm5lbGRlYnVnLWVuYWJsZWQiOmZhbHNlLCJ4LW1zLWF6dXJldm0tb3NidWlsZCI6Ik5vdEF"
            "wcGxpY2FibGUiLCJ4LW1zLWF6dXJldm0tb3NkaXN0cm8iOiJNaWNyb3NvZnQiLCJ4LW1zLWF6dXJldm0tb3N0eXBlIjoiV2luZG93"
            "cyIsIngtbXMtYXp1cmV2bS1vc3ZlcnNpb24tbWFqb3IiOjEwLCJ4LW1zLWF6dXJldm0tb3N2ZXJzaW9uLW1pbm9yIjowLCJ4LW1zL"
            "WF6dXJldm0tc2lnbmluZ2Rpc2FibGVkIjp0cnVlLCJ4LW1zLWF6dXJldm0tdGVzdHNpZ25pbmctZW5hYmxlZCI6ZmFsc2UsIngtbX"
            "MtYXp1cmV2bS12bWlkIjoiRjdDRUE4MTMtNEM0NC00MzZDLTg1MzctNTcwMTk5OUM0NTg5IiwieC1tcy1wb2xpY3ktaGFzaCI6Ind"
            "tOW1IbHZUVTgyZThVcW9PeTFZajFGQlJTTmtmZTk5LTY5SVlEcTllV3MiLCJ4LW1zLXJ1bnRpbWUiOnsia2V5cyI6W3siZSI6IkFR"
            "QUIiLCJrZXlfb3BzIjpbImVuY3J5cHQiXSwia2lkIjoiVHBtRXBoZW1lcmFsRW5jcnlwdGlvbktleSIsImt0eSI6IlJTQSIsIm4iO"
            "iJzbjl4U3dBQURZT3AwWDRIR0NXZnUyQjlHbnZDYzZqTmhBS21iZDdlcFA0QXdWN3BGdGNhZVFDZVV6Rl84Wm5tOThxMGhsTjlOaV"
            "BfYV8wdWQxWmJvZEREa3EzaDY5elNEWGhrNTlLMU51ZEhwblp1eGhOZDJSRUR5WkkxUWFDR0tkMTdFcWI3WnQxV09ybjhqRlFjaS0"
            "xMDZXNnVmS1VlQlpLYTJsRDhNdlhqTV92Snl4SnlyUGJvQ0FXWmttanZmV1pQRUZGZ2JzZ3pYVDlHdGN6RDRRRGlqcHluZ0F5bzA5"
            "Q0R3VHFQWVFNNi1SbXZmNjNKX0tHYk1GWHk0WHBEQTlIcUdrZ25UN2xIZXhNYkdyaTRZUG15TWFiTEhzWDNnOEcwZ3ZBREE5MXkyN"
            "DF6VXRnTFJ0SjAtT1hwQklRN2ZScHdjUFpEX2RmYm9PYWFGN1hhbncifV19LCJ4LW1zLXZlciI6IjEuMCJ9.D1schVs3pOwo7BwGl"
            "ZT0-XO5aAe2NmXchblZIWxD-m2dLUJ0Jp8_j3tHBoAh3L_AaIgyqf0rV0h51D-0ZDwgQx4P0kOwnKjomL9mAbv9KHpTR9FlkG2VYm"
            "MybUEPR-Vb3hpzH6AlABmHXd5GX5YjG7wj3k-lvP2vOdJcZQmH2xkHfrh1pYwGc6f8Ese5ZgbI0ncnNOuwgumcYB5srjSnVeSF7v7"
            "NDnlvUiKwJzSZIFoyPa3bGzh9cIhfn3qTXMw7OP2Ne84sfSQ_2wZrMLSnBWn-fynX4WuNy7LiO-RAygvu3SQnEwksIRMMT3crNhPo"
            "_DyV3Os9MfOmCk7J0K4-bw";

        std::vector<unsigned char> aes_key(32);
        unsigned char* encrypted_data = nullptr;
        uint32_t encrypted_data_size = 0;
        unsigned char* encryption_metadata = nullptr;
        uint32_t encryption_metadata_size = 0;
        unsigned char* jwt = (unsigned char*)malloc((sizeof(unsigned char) * jwt_token.size()) + 1);
        std::memcpy(jwt, jwt_token.data(), jwt_token.size());
        jwt[jwt_token.size()] = '\0';

        attest::AttestationResult result = client->Encrypt(attest::EncryptionType::NONE,
            jwt,
            &aes_key.front(),
            aes_key.size(),
            &encrypted_data,
            &encrypted_data_size,
            &encryption_metadata,
            &encryption_metadata_size);

        EXPECT_EQ(result.code_, attest::AttestationResult::ErrorCode::SUCCESS);
        EXPECT_EQ(encrypted_data_size, 256);
    }

    TEST_F(ClientLibTests, TestParseClientPayload_negative) {
        std::string json_str = "{\"key\":\"value\"]";
        unsigned char* buffer = (unsigned char*)malloc((sizeof(unsigned char) * json_str.size()) + 1);
        std::memcpy(buffer, json_str.data(), json_str.size());
        buffer[json_str.size()] = '\0';
        std::unordered_map<std::string, std::string> client_payload_map;
        attest::AttestationResult result = client->ParseClientPayload(buffer, client_payload_map);
        EXPECT_EQ(result.code_, attest::AttestationResult::ErrorCode::ERROR_INVALID_INPUT_PARAMETER);
        free(buffer);
    }

    TEST_F(ClientLibTests, TestParseClientPayload_positive) {
        std::string json_str = "{\"key1\":\"value1\",\"key2\":\"value2\"}";
        unsigned char* buffer = (unsigned char*)malloc((sizeof(unsigned char) * json_str.size()) + 1);
        std::memcpy(buffer, json_str.data(), json_str.size());
        buffer[json_str.size()] = '\0';
        std::unordered_map<std::string, std::string> client_payload_map;
        attest::AttestationResult result = client->ParseClientPayload(buffer, client_payload_map);
        EXPECT_EQ(result.code_, attest::AttestationResult::ErrorCode::SUCCESS);
        EXPECT_EQ(client_payload_map.size(), 2);
        EXPECT_EQ(client_payload_map["key1"], "value1");
        EXPECT_EQ(client_payload_map["key2"], "value2");
        free(buffer);
    }

    TEST_F(ClientLibTests, TestParseURL) {
        AttestationResult result;
        std::string dns;

        result = attest::url::ParseURL("http://", dns);
        EXPECT_EQ(dns, "");
        EXPECT_EQ(result.code_, attest::AttestationResult::ErrorCode::ERROR_PARSING_DNS_INFO);

        result = attest::url::ParseURL("https://sharedeus2.eus2.attest.azure.net/ReportHealth?api-version=2020-03-31-preview", dns);
        EXPECT_EQ(dns, "sharedeus2.eus2.attest.azure.net");
        EXPECT_EQ(result.code_, attest::AttestationResult::ErrorCode::SUCCESS);

        result = attest::url::ParseURL("     https://sharedeus2.eus2.attest.azure.net/ReportHealth?api-version=2020-03-31-preview   ", dns);
        EXPECT_EQ(dns, "sharedeus2.eus2.attest.azure.net");
        EXPECT_EQ(result.code_, attest::AttestationResult::ErrorCode::SUCCESS);

        result = attest::url::ParseURL("sharedeus2.eus2.attest.azure.net/ReportHealth?api-version=2020-03-31-preview", dns);
        EXPECT_EQ(dns, "sharedeus2.eus2.attest.azure.net");
        EXPECT_EQ(result.code_, attest::AttestationResult::ErrorCode::SUCCESS);

        result = attest::url::ParseURL("https://sharedeus2.eus2.attest.azure.net", dns);
        EXPECT_EQ(dns, "sharedeus2.eus2.attest.azure.net");
        EXPECT_EQ(result.code_, attest::AttestationResult::ErrorCode::SUCCESS);
    }

    TEST_F(ClientLibTests, TestParseMaaResponse_negative) {
        std::string json_str = "{\"key\":\"value\"]";
        std::string enc_token;
        attest::AttestationResult result = client->ParseMaaResponse(json_str, enc_token);
        EXPECT_EQ(result.code_, attest::AttestationResult::ErrorCode::ERROR_PARSING_ATTESTATION_RESPONSE);
    }

    TEST_F(ClientLibTests, TestParseMaaResponse_positive) {
        std::string json_str = "{\"token\":\"value1\"}";
        std::string enc_token;
        attest::AttestationResult result = client->ParseMaaResponse(json_str, enc_token);
        EXPECT_EQ(result.code_, attest::AttestationResult::ErrorCode::SUCCESS);
        EXPECT_EQ(enc_token, "value1");
    }
};

int main(int argc, char** argv)
{
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
