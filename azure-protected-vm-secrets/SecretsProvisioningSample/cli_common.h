// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once
#include <string>

struct CliArgs {
    std::string command;
    std::string token;      // optional inline token for unprotect-secret
    unsigned int policy;
    bool help;
    bool version;
    bool json_output;

    CliArgs() : policy(0), help(false), version(false), json_output(false) {}
};

CliArgs parse_args(int argc, char* argv[]);
std::string read_all_stdin();
