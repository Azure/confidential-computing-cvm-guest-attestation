// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "cmd_unprotect_secret.h"
#include "cli_common.h"
#ifndef UNIT_TEST
#include "SecretsProvisioningLibrary.h"
#else
// Forward declarations for unit test stubs — avoids pulling in TPM/crypto headers
extern "C" {
    long unprotect_secret(char* jwt, unsigned int jwtlen, unsigned int policy,
                          char** output_secret, unsigned int* eval_policy);
    void free_secret(char* secret);
    const char* get_error_message(long error_code);
}
#endif
#include <iostream>
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#else
#include <unistd.h>
#endif

int cmd_unprotect_secret(const CliArgs& args)
{
    // Accept the JWT either as an inline argument or from stdin
    std::string input = args.token.empty() ? read_all_stdin() : args.token;

    if (input.empty()) {
        if (args.json_output) {
            std::cout << "{\"error\":\"no input provided\"}\n";
        } else {
            std::cerr << "No input provided. Pass the token as an argument or pipe it via stdin.\n";
        }
        return 1;
    }

    char* output = nullptr;
    unsigned int eval_policy = 0;
    long result = unprotect_secret(
        const_cast<char*>(input.data()),
        static_cast<unsigned int>(input.size()),
        args.policy,
        &output,
        &eval_policy);

    if (result > 0) {
        size_t write_len = static_cast<size_t>(result);
        // Trim trailing null byte if present — the library returns length
        // including the null terminator from the encrypted string.
        if (write_len > 0 && output[write_len - 1] == '\0')
            write_len--;

        if (args.json_output) {
            std::string secret(output, write_len);
            std::string escaped;
            escaped.reserve(secret.size());
            for (unsigned char c : secret) {
                if      (c == '\\') escaped += "\\\\";
                else if (c == '"')  escaped += "\\\"";
                else if (c == '\n') escaped += "\\n";
                else if (c == '\r') escaped += "\\r";
                else if (c == '\t') escaped += "\\t";
                else if (c < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", c);
                    escaped += buf;
                }
                else escaped += static_cast<char>(c);
            }
            std::cout << "{\"secret\":\"" << escaped << "\"}\n";
        } else {
            // Binary-safe write: no trailing newline, no std::cout buffering
#if defined(UNIT_TEST)
            std::cout.write(output, static_cast<std::streamsize>(write_len));
            int written = std::cout ? static_cast<int>(write_len) : -1;
#elif defined(_WIN32)
            int written = _write(_fileno(stdout), output, static_cast<unsigned int>(write_len));
#else
            ssize_t written = write(STDOUT_FILENO, output, write_len);
#endif
            free_secret(output);
            return (written < 0) ? 1 : 0;
        }
        free_secret(output);
        return 0;
    }

    free_secret(output);
    if (args.json_output) {
        std::cout << "{\"error\":\"" << get_error_message(result) << "\"}\n";
    } else {
        std::cerr << get_error_message(result) << "\n";
    }
    return 1;
}


