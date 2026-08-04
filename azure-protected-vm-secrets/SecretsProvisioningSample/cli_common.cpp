// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "cli_common.h"
#include <iostream>
#include <sstream>
#include <cstdlib>
#include <cstring>

CliArgs parse_args(int argc, char* argv[])
{
    CliArgs args;

    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--help") == 0 || std::strcmp(argv[i], "-h") == 0) {
            args.help = true;
        } else if (std::strcmp(argv[i], "--json") == 0) {
            args.json_output = true;
        } else if (std::strcmp(argv[i], "--version") == 0) {
            args.version = true;
        } else if (std::strcmp(argv[i], "--policy") == 0 && i + 1 < argc) {
            const char* value = argv[++i];
            char* end = nullptr;
            unsigned long parsed = std::strtoul(value, &end, 10);
            // Reject empty/non-numeric input (end not advanced to the NUL
            // terminator) and any value outside the supported range 0-4.
            if (*value == '\0' || end == value || *end != '\0' || parsed > 4) {
                args.policy_valid = false;
            } else {
                args.policy = static_cast<unsigned int>(parsed);
            }
        } else if (argv[i][0] != '-') {
            if (args.command.empty()) {
                args.command = argv[i];
            } else if (args.token.empty()) {
                args.token = argv[i];
            }
        }
    }
    return args;
}

std::string read_all_stdin()
{
    std::ostringstream buf;
    buf << std::cin.rdbuf();
    return buf.str();
}
