// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include <gtest/gtest.h>
#include "Version.h"
#include <string>
#include <cstring>

class VersionTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

TEST_F(VersionTest, SecretsLibraryVersionValidation) {
    const char* version = secrets_library_version();
    
    // Check version is not null
    ASSERT_NE(version, nullptr);
    
    // Check version is not empty
    ASSERT_GT(strlen(version), 0);
    
    // Check version matches defined constant
    EXPECT_STREQ(version, SECRETS_LIB_VERSION_STRING);
 
    // Check consistency across calls
    const char* version2 = secrets_library_version();
    EXPECT_STREQ(version, version2);
}
