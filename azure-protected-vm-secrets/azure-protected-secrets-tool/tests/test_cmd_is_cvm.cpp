// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include <gtest/gtest.h>
#include <cstring>
#include "CvmHelper/inc/CvmHelper.h"
#include "cmd_is_cvm.h"
#include "cli_common.h"

// Mock CPUID data for unit tests.
// Each test sets up g_cpuid_results to control what GetIsolationMode() returns.

struct CpuidEntry {
    int leaf;
    int regs[4]; // EAX, EBX, ECX, EDX
};

static CpuidEntry g_cpuid_results[16];
static int g_cpuid_count = 0;

extern "C" void test_cpuid(int cpuInfo[4], int leaf)
{
    for (int i = 0; i < g_cpuid_count; ++i) {
        if (g_cpuid_results[i].leaf == leaf) {
            cpuInfo[0] = g_cpuid_results[i].regs[0];
            cpuInfo[1] = g_cpuid_results[i].regs[1];
            cpuInfo[2] = g_cpuid_results[i].regs[2];
            cpuInfo[3] = g_cpuid_results[i].regs[3];
            return;
        }
    }
    cpuInfo[0] = cpuInfo[1] = cpuInfo[2] = cpuInfo[3] = 0;
}

static void reset_cpuid()
{
    g_cpuid_count = 0;
    std::memset(g_cpuid_results, 0, sizeof(g_cpuid_results));
}

static void add_cpuid(int leaf, int eax, int ebx, int ecx, int edx)
{
    g_cpuid_results[g_cpuid_count].leaf = leaf;
    g_cpuid_results[g_cpuid_count].regs[0] = eax;
    g_cpuid_results[g_cpuid_count].regs[1] = ebx;
    g_cpuid_results[g_cpuid_count].regs[2] = ecx;
    g_cpuid_results[g_cpuid_count].regs[3] = edx;
    g_cpuid_count++;
}

// Helper: set up CPUID results so GetIsolationMode() sees a hypervisor.
// Leaf 0x1 ECX bit 31 = 1 (hypervisor present)
// Leaf 0x40000000: vendor "Microsoft Hv", MaxFunction >= 0x4000000C
// Leaf 0x40000001: interface "Hv#1"
// Leaf 0x40000003: IsolationFeatures bit set
static void setup_hyperv_base(uint32_t maxFunction = 0x4000000C)
{
    // Leaf 0x1: hypervisor bit is ECX bit 31
    add_cpuid(0x1, 0, 0, (int)(1u << 31), 0);

    // Leaf 0x40000000: MaxFunction in EAX, vendor in EBX/ECX/EDX
    // "Microsoft Hv" -> EBX='rciM', ECX='foso', EDX='vH t'
    add_cpuid(0x40000000, (int)maxFunction, (int)0x7263694D, (int)0x666F736F, (int)0x76482074);

    // Leaf 0x40000001: interface "Hv#1" = 0x31237648
    add_cpuid(0x40000001, (int)0x31237648, 0, 0, 0);

    // Leaf 0x40000003: IsolationFeatures bit set (bit 54 of EAX:EBX combined 64-bit)
    // IsolationFeatures is bit 54 of the 64-bit PartitionPrivilegeMask
    // That's bit 22 of the second 32-bit word (EBX)
    add_cpuid(0x40000003, 0, (int)(1u << 22), 0, 0);
}

class IsCvmTest : public ::testing::Test {
protected:
    void SetUp() override { reset_cpuid(); }
};

TEST_F(IsCvmTest, NoHypervisor) {
    // Leaf 0x1 ECX bit 31 = 0 -> no hypervisor
    add_cpuid(0x1, 0, 0, 0, 0);
    EXPECT_EQ(GetIsolationMode(), IM_RESULT_NO_HYPERVISOR);
}

TEST_F(IsCvmTest, NotHyperV) {
    // Hypervisor present but vendor is not Microsoft
    add_cpuid(0x1, 0, 0, (int)(1u << 31), 0);
    add_cpuid(0x40000000, 0x40000001, 0x4D566572, 0x65776172, 0x00000000); // "VMware"
    EXPECT_EQ(GetIsolationMode(), IM_RESULT_NO_HYPERV);
}

TEST_F(IsCvmTest, NoIsolationConfig) {
    // Hyper-V present but MaxFunction < 0x4000000C
    setup_hyperv_base(0x4000000B);
    EXPECT_EQ(GetIsolationMode(), IM_RESULT_NO_ISOLATION_CONFIG);
}

TEST_F(IsCvmTest, SnpIsolation) {
    setup_hyperv_base();
    // Leaf 0x4000000C: IsolationType = SNP (0x2) in bits [4:1] of EBX
    add_cpuid(0x4000000C, 0, HV_ISOLATION_TYPE_SNP, 0, 0);
    EXPECT_EQ(GetIsolationMode(), IM_RESULT_SNP_ISOLATION);
}

TEST_F(IsCvmTest, TdxIsolation) {
    setup_hyperv_base();
    add_cpuid(0x4000000C, 0, HV_ISOLATION_TYPE_TDX, 0, 0);
    EXPECT_EQ(GetIsolationMode(), IM_RESULT_TDX_ISOLATION);
}

TEST_F(IsCvmTest, VbsIsolation) {
    setup_hyperv_base();
    add_cpuid(0x4000000C, 0, HV_ISOLATION_TYPE_VBS, 0, 0);
    EXPECT_EQ(GetIsolationMode(), IM_RESULT_VBS_ISOLATION);
}

TEST_F(IsCvmTest, NoIsolation) {
    setup_hyperv_base();
    add_cpuid(0x4000000C, 0, HV_ISOLATION_TYPE_NONE, 0, 0);
    EXPECT_EQ(GetIsolationMode(), IM_RESULT_NO_ISOLATION);
}

TEST_F(IsCvmTest, IsConfidentialVM_Snp) {
    setup_hyperv_base();
    add_cpuid(0x4000000C, 0, HV_ISOLATION_TYPE_SNP, 0, 0);
    EXPECT_TRUE(IsConfidentialVM());
}

TEST_F(IsCvmTest, IsConfidentialVM_Tdx) {
    setup_hyperv_base();
    add_cpuid(0x4000000C, 0, HV_ISOLATION_TYPE_TDX, 0, 0);
    EXPECT_TRUE(IsConfidentialVM());
}

TEST_F(IsCvmTest, IsConfidentialVM_Vbs) {
    setup_hyperv_base();
    add_cpuid(0x4000000C, 0, HV_ISOLATION_TYPE_VBS, 0, 0);
    EXPECT_FALSE(IsConfidentialVM());
}

TEST_F(IsCvmTest, IsConfidentialVM_None) {
    add_cpuid(0x1, 0, 0, 0, 0);
    EXPECT_FALSE(IsConfidentialVM());
}
