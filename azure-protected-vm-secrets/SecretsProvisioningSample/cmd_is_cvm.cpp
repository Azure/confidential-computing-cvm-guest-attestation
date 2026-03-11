// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "cmd_is_cvm.h"
#include "cli_common.h"
#include "CvmHelper/inc/CvmHelper.h"
#include <iostream>

static const char* isolation_type_string(IsolationModeResult mode)
{
    switch (mode) {
        case IM_RESULT_SNP_ISOLATION:       return "SNP";
        case IM_RESULT_TDX_ISOLATION:       return "TDX";
        case IM_RESULT_VBS_ISOLATION:       return "VBS";
        case IM_RESULT_NO_ISOLATION:        return "NONE";
        case IM_RESULT_NO_HYPERVISOR:       return "NONE";
        case IM_RESULT_NO_HYPERV:           return "NONE";
        case IM_RESULT_NO_ISOLATION_CONFIG: return "NONE";
        default:                            return "NONE";
    }
}

static const char* hypervisor_string(IsolationModeResult mode)
{
    switch (mode) {
        case IM_RESULT_NO_HYPERVISOR:       return "None";
        case IM_RESULT_NO_HYPERV:           return "None";
        default:                            return "Microsoft Hv";
    }
}

static const char* error_string(IsolationModeResult mode)
{
    switch (mode) {
        case IM_RESULT_NO_HYPERVISOR:       return "NO_HYPERVISOR";
        case IM_RESULT_NO_HYPERV:           return "NO_HYPERV";
        case IM_RESULT_NO_ISOLATION_CONFIG: return "NO_ISOLATION_CONFIG";
        default:                            return nullptr;
    }
}

int cmd_is_cvm(const CliArgs& args)
{
    IsolationModeResult mode = GetIsolationMode();
    const char* iso = isolation_type_string(mode);
    const char* hyp = hypervisor_string(mode);
    const char* err = error_string(mode);

    if (args.json_output) {
        std::cout << "{\"isolation_type\":\"" << iso
                  << "\",\"hypervisor\":\"" << hyp << "\"";
        if (err) {
            std::cout << ",\"error\":\"" << err << "\"";
        }
        std::cout << "}\n";
    } else {
        std::cout << "isolation_type=" << iso << "\n";
        std::cout << "hypervisor=" << hyp << "\n";
        if (err) {
            std::cout << "error=" << err << "\n";
        }
    }

    bool is_cvm = (mode == IM_RESULT_SNP_ISOLATION || mode == IM_RESULT_TDX_ISOLATION);
    return is_cvm ? 0 : 1;
}
