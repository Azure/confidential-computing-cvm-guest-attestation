// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "cmd_is_secrets_enabled.h"
#include "cli_common.h"
#include "SecretsProvisioningLibrary.h"
#include "Version.h"
#include <iostream>

int cmd_is_secrets_enabled(const CliArgs& args)
{
    int result = is_secrets_provisioning_enabled();
    if (result > 0) {
        if (args.json_output) {
            std::cout << "{\"enabled\":true,\"version\":\"" << secrets_library_version() << "\"}\n";
        } else {
            std::cout << "enabled=true\n";
            std::cout << "version=" << secrets_library_version() << "\n";
        }
        return 0;
    } else if (result == 0) {
        if (args.json_output) {
            std::cout << "{\"enabled\":false}\n";
        } else {
            std::cout << "enabled=false\n";
        }
        return 1;
    } else {
        // TPM access failed — report the error matching ReturnCodes.h TpmError_Context_tctiInitError
        if (args.json_output) {
            std::cerr << "{\"enabled\":false,\"error\":\"" << get_error_message(-0x1005) << "\"}\n";
        } else {
            std::cerr << "error=" << get_error_message(-0x1005) << "\n";
        }
        return 1;
    }
}


