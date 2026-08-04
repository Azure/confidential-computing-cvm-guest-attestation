// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once
#include <string>

struct CliArgs {
    std::string command;
    std::string token;      // optional inline token for unprotect-secret
    unsigned int policy;
    bool policy_valid;      // false if --policy was given a non-numeric or out-of-range (0-4) value
    bool help;
    bool version;
    bool json_output;

    CliArgs() : policy(0), policy_valid(true), help(false), version(false), json_output(false) {}
};

CliArgs parse_args(int argc, char* argv[]);
std::string read_all_stdin();
