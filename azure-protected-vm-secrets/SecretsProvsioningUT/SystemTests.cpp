#include "gtest/gtest.h"
#include <windows.h>
#include "System.h"

TEST(TestSystemWindows, TestGetSmbios) {
    GetVmid();
    std::string uuid = GetSystemUuid();
}