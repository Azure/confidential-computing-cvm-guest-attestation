// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once
#include <string>

struct CliArgs;

// Function pointer type for unprotect_secret — injectable for unit tests.
// Signature mirrors the real C API in SecretsProvisioningLibrary.h exactly.
// See cmd_validate_imds_README.md for the full IMDS blob structure and protocol.
typedef long (*UnprotectSecretFn)(char*, unsigned int, unsigned int, char**, unsigned int*);

int cmd_validate_imds(const CliArgs& args);

// Testable entry point — accepts injected unprotect_secret implementation
int cmd_validate_imds_impl(const std::string& imds_json, UnprotectSecretFn unprotect_fn, unsigned int policy);

