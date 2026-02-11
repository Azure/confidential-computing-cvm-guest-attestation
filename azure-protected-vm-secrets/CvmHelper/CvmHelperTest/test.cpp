#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <gtest/gtest.h>
#include <map>
#include <cstring>

#include "../inc/CvmHelper.h"

// Mock CPUID storage
static std::map<int, int[4]> g_cpuidResponses;

// This is what the library calls when UNIT_TEST is defined
extern "C" void test_cpuid(int cpuInfo[4], int leaf) {
    if (g_cpuidResponses.count(leaf)) {
        memcpy(cpuInfo, g_cpuidResponses[leaf], sizeof(int) * 4);
    } else {
        memset(cpuInfo, 0, sizeof(int) * 4);
    }
}

class CvmHelperTest : public ::testing::Test {
protected:
    void SetUp() override {
        g_cpuidResponses.clear();
    }

    void SetupHypervisorPresent() {
        g_cpuidResponses[0x1][2] = (1u << 31);
    }

    void SetupMicrosoftVendor() {
        g_cpuidResponses[0x40000000][1] = 'rciM';
        g_cpuidResponses[0x40000000][2] = 'foso';
        g_cpuidResponses[0x40000000][3] = 'vH t';
    }

    void SetupMaxFunction(UINT32 maxFunction) {
        g_cpuidResponses[0x40000000][0] = maxFunction;
    }

    void SetupHypervisorInterface() {
        g_cpuidResponses[0x40000001][0] = 0x31237648;  // "Hv#1"
    }

    void SetupIsolationFeatures() {
        g_cpuidResponses[0x40000003][1] = (1 << 22);  // Bit 54 of 64-bit mask
    }

    void SetupIsolationType(int type) {
        g_cpuidResponses[0x4000000C][1] = type;
    }

    void SetupValidMicrosoftHypervisor() {
        SetupHypervisorPresent();
        SetupMicrosoftVendor();
        SetupMaxFunction(0x4000000C);
        SetupHypervisorInterface();
        SetupIsolationFeatures();
    }

    // Helper to check if result is an error (>= 0x10)
    bool IsError(IsolationModeResult result) {
        return static_cast<int>(result) >= 0x10;
    }
};

// =============================================================================
// GetIsolationMode() - Error cases
// =============================================================================

TEST_F(CvmHelperTest, GetIsolationMode_ReturnsNoHypervisor_WhenNotPresent) {
    EXPECT_EQ(IM_RESULT_NO_HYPERVISOR, GetIsolationMode());
    EXPECT_TRUE(IsError(GetIsolationMode()));
}

TEST_F(CvmHelperTest, GetIsolationMode_ReturnsNoHyperv_WhenVendorWrong) {
    SetupHypervisorPresent();
    g_cpuidResponses[0x40000000][1] = 'XXXX';

    EXPECT_EQ(IM_RESULT_NO_HYPERV, GetIsolationMode());
}

TEST_F(CvmHelperTest, GetIsolationMode_ReturnsNoHyperv_WhenFirstVendorPartWrong) {
    SetupHypervisorPresent();
    g_cpuidResponses[0x40000000][1] = 'XXXX';
    g_cpuidResponses[0x40000000][2] = 'foso';
    g_cpuidResponses[0x40000000][3] = 'vH t';

    EXPECT_EQ(IM_RESULT_NO_HYPERV, GetIsolationMode());
}

TEST_F(CvmHelperTest, GetIsolationMode_ReturnsNoHyperv_WhenSecondVendorPartWrong) {
    SetupHypervisorPresent();
    g_cpuidResponses[0x40000000][1] = 'rciM';
    g_cpuidResponses[0x40000000][2] = 'XXXX';
    g_cpuidResponses[0x40000000][3] = 'vH t';

    EXPECT_EQ(IM_RESULT_NO_HYPERV, GetIsolationMode());
}

TEST_F(CvmHelperTest, GetIsolationMode_ReturnsNoHyperv_WhenThirdVendorPartWrong) {
    SetupHypervisorPresent();
    g_cpuidResponses[0x40000000][1] = 'rciM';
    g_cpuidResponses[0x40000000][2] = 'foso';
    g_cpuidResponses[0x40000000][3] = 'XXXX';

    EXPECT_EQ(IM_RESULT_NO_HYPERV, GetIsolationMode());
}

TEST_F(CvmHelperTest, GetIsolationMode_ReturnsNoHyperv_WhenMaxFunctionTooLow) {
    SetupHypervisorPresent();
    SetupMicrosoftVendor();
    SetupMaxFunction(0x40000003);

    EXPECT_EQ(IM_RESULT_NO_HYPERV, GetIsolationMode());
}

TEST_F(CvmHelperTest, GetIsolationMode_ReturnsNoHyperv_WhenMaxFunctionJustBelowRequired) {
    SetupHypervisorPresent();
    SetupMicrosoftVendor();
    SetupMaxFunction(0x4000000B);

    EXPECT_EQ(IM_RESULT_NO_HYPERV, GetIsolationMode());
}

TEST_F(CvmHelperTest, GetIsolationMode_ReturnsNoHyperv_WhenInterfaceWrong) {
    SetupHypervisorPresent();
    SetupMicrosoftVendor();
    SetupMaxFunction(0x4000000C);
    g_cpuidResponses[0x40000001][0] = 0x12345678;

    EXPECT_EQ(IM_RESULT_NO_HYPERV, GetIsolationMode());
}

TEST_F(CvmHelperTest, GetIsolationMode_ReturnsNoHyperv_WhenInterfaceZero) {
    SetupHypervisorPresent();
    SetupMicrosoftVendor();
    SetupMaxFunction(0x4000000C);

    EXPECT_EQ(IM_RESULT_NO_HYPERV, GetIsolationMode());
}

TEST_F(CvmHelperTest, GetIsolationMode_ReturnsNoIsolation_WhenIsolationFeaturesNotPresent) {
    SetupHypervisorPresent();
    SetupMicrosoftVendor();
    SetupMaxFunction(0x4000000C);
    SetupHypervisorInterface();

    EXPECT_EQ(IM_RESULT_NO_ISOLATION, GetIsolationMode());
}

TEST_F(CvmHelperTest, GetIsolationMode_ReturnsNoIsolationConfig_WhenMaxFunctionTooLow) {
    SetupHypervisorPresent();
    SetupMicrosoftVendor();
    SetupMaxFunction(0x40000003);
    SetupHypervisorInterface();
    SetupIsolationFeatures();

    EXPECT_EQ(IM_RESULT_NO_ISOLATION_CONFIG, GetIsolationMode());
}

TEST_F(CvmHelperTest, GetIsolationMode_ReturnsNoIsolationConfig_WhenMaxFunctionJustBelowRequired) {
    SetupHypervisorPresent();
    SetupMicrosoftVendor();
    SetupMaxFunction(0x4000000B);
    SetupHypervisorInterface();
    SetupIsolationFeatures();

    EXPECT_EQ(IM_RESULT_NO_ISOLATION_CONFIG, GetIsolationMode());
}

// =============================================================================
// GetIsolationMode() - Isolation type results
// =============================================================================

TEST_F(CvmHelperTest, GetIsolationMode_ReturnsNoIsolation_ForNoIsolation) {
    SetupValidMicrosoftHypervisor();
    SetupIsolationType(HV_ISOLATION_TYPE_NONE);

    EXPECT_EQ(IM_RESULT_NO_ISOLATION, GetIsolationMode());
    EXPECT_FALSE(IsError(GetIsolationMode()));
}

TEST_F(CvmHelperTest, GetIsolationMode_ReturnsVbsIsolation_ForVbsIsolation) {
    SetupValidMicrosoftHypervisor();
    SetupIsolationType(HV_ISOLATION_TYPE_VBS);

    EXPECT_EQ(IM_RESULT_VBS_ISOLATION, GetIsolationMode());
}

TEST_F(CvmHelperTest, GetIsolationMode_ReturnsSnpIsolation_ForSnpIsolation) {
    SetupValidMicrosoftHypervisor();
    SetupIsolationType(HV_ISOLATION_TYPE_SNP);

    EXPECT_EQ(IM_RESULT_SNP_ISOLATION, GetIsolationMode());
}

TEST_F(CvmHelperTest, GetIsolationMode_ReturnsTdxIsolation_ForTdxIsolation) {
    SetupValidMicrosoftHypervisor();
    SetupIsolationType(HV_ISOLATION_TYPE_TDX);

    EXPECT_EQ(IM_RESULT_TDX_ISOLATION, GetIsolationMode());
}

TEST_F(CvmHelperTest, GetIsolationMode_ReturnsRawValue_ForFutureTypes) {
    SetupValidMicrosoftHypervisor();
    SetupIsolationType(0x4);  // Unknown future type

    EXPECT_EQ(static_cast<IsolationModeResult>(0x4), GetIsolationMode());
}

// =============================================================================
// GetIsolationMode() - Enum alignment verification
// =============================================================================

TEST_F(CvmHelperTest, EnumValuesMatchIsolationTypes) {
    EXPECT_EQ(HV_ISOLATION_TYPE_NONE, static_cast<int>(IM_RESULT_NO_ISOLATION));
    EXPECT_EQ(HV_ISOLATION_TYPE_VBS, static_cast<int>(IM_RESULT_VBS_ISOLATION));
    EXPECT_EQ(HV_ISOLATION_TYPE_SNP, static_cast<int>(IM_RESULT_SNP_ISOLATION));
    EXPECT_EQ(HV_ISOLATION_TYPE_TDX, static_cast<int>(IM_RESULT_TDX_ISOLATION));
}

// =============================================================================
// IsConfidentialVM() - Success cases
// =============================================================================

TEST_F(CvmHelperTest, IsConfidentialVM_ReturnsTrue_ForSnpIsolation) {
    SetupValidMicrosoftHypervisor();
    SetupIsolationType(HV_ISOLATION_TYPE_SNP);

    EXPECT_TRUE(IsConfidentialVM());
}

TEST_F(CvmHelperTest, IsConfidentialVM_ReturnsTrue_ForTdxIsolation) {
    SetupValidMicrosoftHypervisor();
    SetupIsolationType(HV_ISOLATION_TYPE_TDX);

    EXPECT_TRUE(IsConfidentialVM());
}

// =============================================================================
// IsConfidentialVM() - Failure cases (non-CVM isolation types)
// =============================================================================

TEST_F(CvmHelperTest, IsConfidentialVM_ReturnsFalse_ForNoIsolation) {
    SetupValidMicrosoftHypervisor();
    SetupIsolationType(HV_ISOLATION_TYPE_NONE);

    EXPECT_FALSE(IsConfidentialVM());
}

TEST_F(CvmHelperTest, IsConfidentialVM_ReturnsFalse_ForVbsIsolation) {
    SetupValidMicrosoftHypervisor();
    SetupIsolationType(HV_ISOLATION_TYPE_VBS);

    EXPECT_FALSE(IsConfidentialVM());
}

TEST_F(CvmHelperTest, IsConfidentialVM_ReturnsFalse_ForUnknownIsolationType) {
    SetupValidMicrosoftHypervisor();
    SetupIsolationType(0x4);

    EXPECT_FALSE(IsConfidentialVM());
}

TEST_F(CvmHelperTest, IsConfidentialVM_ReturnsFalse_ForHighUnknownIsolationType) {
    SetupValidMicrosoftHypervisor();
    SetupIsolationType(0xF);

    EXPECT_FALSE(IsConfidentialVM());
}

// =============================================================================
// IsConfidentialVM() - Failure cases (error conditions)
// =============================================================================

TEST_F(CvmHelperTest, IsConfidentialVM_ReturnsFalse_WhenNoHypervisor) {
    EXPECT_FALSE(IsConfidentialVM());
}

TEST_F(CvmHelperTest, IsConfidentialVM_ReturnsFalse_WhenNoHyperv) {
    SetupHypervisorPresent();
    g_cpuidResponses[0x40000000][1] = 'XXXX';

    EXPECT_FALSE(IsConfidentialVM());
}

TEST_F(CvmHelperTest, IsConfidentialVM_ReturnsFalse_WhenNoIsolationFeatures) {
    SetupHypervisorPresent();
    SetupMicrosoftVendor();
    SetupMaxFunction(0x4000000C);
    SetupHypervisorInterface();

    EXPECT_FALSE(IsConfidentialVM());
}

TEST_F(CvmHelperTest, IsConfidentialVM_ReturnsFalse_WhenNoIsolationConfig) {
    SetupHypervisorPresent();
    SetupMicrosoftVendor();
    SetupMaxFunction(0x40000003);
    SetupHypervisorInterface();
    SetupIsolationFeatures();

    EXPECT_FALSE(IsConfidentialVM());
}

// =============================================================================
// Error detection helper tests
// =============================================================================

TEST_F(CvmHelperTest, IsError_ReturnsFalse_ForIsolationTypes) {
    EXPECT_FALSE(IsError(IM_RESULT_NO_ISOLATION));
    EXPECT_FALSE(IsError(IM_RESULT_VBS_ISOLATION));
    EXPECT_FALSE(IsError(IM_RESULT_SNP_ISOLATION));
    EXPECT_FALSE(IsError(IM_RESULT_TDX_ISOLATION));
}

TEST_F(CvmHelperTest, IsError_ReturnsTrue_ForErrors) {
    EXPECT_TRUE(IsError(IM_RESULT_NO_HYPERVISOR));
    EXPECT_TRUE(IsError(IM_RESULT_NO_HYPERV));
    EXPECT_TRUE(IsError(IM_RESULT_NO_ISOLATION_CONFIG));
}