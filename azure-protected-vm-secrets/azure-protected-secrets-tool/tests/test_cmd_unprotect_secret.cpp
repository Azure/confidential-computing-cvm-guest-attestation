// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//
// Unit tests for cmd_unprotect_secret argument routing.
// These tests do NOT require a TPM — they verify that:
//   - An inline token argument is preferred over stdin
//   - Missing input (no token, empty stdin) returns exit code 1
//   - --json formats output as {"secret":"..."} / {"error":"..."}
//   - Raw (non-json) path writes bytes and returns 0
//
// The real unprotect_secret() library call is stubbed out below.

#include <gtest/gtest.h>
#include <sstream>
#include <cstring>

#include "cli_common.h"
#include "cmd_unprotect_secret.h"

// ---------------------------------------------------------------------------
// Stub the library symbols so we don't need the full shared library.
// ---------------------------------------------------------------------------
static std::string g_stub_input;       // last JWT seen by the stub
static std::string g_stub_plaintext;   // what the stub "decrypts" to
static long        g_stub_return = 0;  // return value (>0 = success, <0 = error)

extern "C" {

long unprotect_secret(char* jwt, unsigned int jwtlen,
                      unsigned int /*policy*/,
                      char** output_secret,
                      unsigned int* eval_policy)
{
    g_stub_input = std::string(jwt, jwtlen);
    *eval_policy = 2; // AllowUnsigned
    if (g_stub_return <= 0) {
        *output_secret = nullptr;
        return g_stub_return;
    }
    // Copy plaintext (including null terminator to mirror library behaviour)
    size_t len = g_stub_plaintext.size() + 1;
    char* buf = new char[len];
    std::memcpy(buf, g_stub_plaintext.c_str(), len);
    *output_secret = buf;
    return static_cast<long>(len);
}

void free_secret(char* p) { delete[] p; }

const char* get_error_message(long code)
{
    if (code == -100) return "PolicyMismatchError";
    return "UnknownError";
}

} // extern "C"

// ---------------------------------------------------------------------------
// Helper: redirect stdin from a string, run cmd_unprotect_secret, capture
// stdout and return exit code.
// ---------------------------------------------------------------------------
static int run_cmd(const CliArgs& args,
                   const std::string& stdin_data,
                   std::string& stdout_out)
{
    // Redirect std::cin
    std::istringstream in(stdin_data);
    std::streambuf* old_cin = std::cin.rdbuf(in.rdbuf());

    // Capture std::cout
    std::ostringstream out;
    std::streambuf* old_cout = std::cout.rdbuf(out.rdbuf());

    int rc = cmd_unprotect_secret(args);

    std::cout.rdbuf(old_cout);
    std::cin.rdbuf(old_cin);

    stdout_out = out.str();
    return rc;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

class CmdUnprotectSecretTest : public ::testing::Test {
protected:
    void SetUp() override {
        g_stub_input     = "";
        g_stub_plaintext = "";
        g_stub_return    = 0;
    }
};

// --- Input routing ---

TEST_F(CmdUnprotectSecretTest, InlineTokenUsedOverStdin) {
    g_stub_plaintext = "my-secret";
    g_stub_return    = static_cast<long>(g_stub_plaintext.size() + 1);

    CliArgs args;
    args.command     = "unprotect-secret";
    args.token       = "inline-jwt";
    args.policy      = 2;
    args.json_output = true;

    std::string out;
    int rc = run_cmd(args, "stdin-jwt", out);

    EXPECT_EQ(rc, 0);
    EXPECT_EQ(g_stub_input, "inline-jwt");  // stdin was NOT used
    EXPECT_EQ(out, "{\"secret\":\"my-secret\"}\n");
}

TEST_F(CmdUnprotectSecretTest, StdinUsedWhenNoToken) {
    g_stub_plaintext = "from-stdin";
    g_stub_return    = static_cast<long>(g_stub_plaintext.size() + 1);

    CliArgs args;
    args.command     = "unprotect-secret";
    args.token       = "";
    args.policy      = 2;
    args.json_output = true;

    std::string out;
    int rc = run_cmd(args, "stdin-jwt", out);

    EXPECT_EQ(rc, 0);
    EXPECT_EQ(g_stub_input, "stdin-jwt");
    EXPECT_EQ(out, "{\"secret\":\"from-stdin\"}\n");
}

TEST_F(CmdUnprotectSecretTest, EmptyInputReturnsError) {
    CliArgs args;
    args.command     = "unprotect-secret";
    args.token       = "";
    args.policy      = 2;
    args.json_output = false;

    std::string out;
    int rc = run_cmd(args, "", out);  // empty stdin, no token

    EXPECT_EQ(rc, 1);
}

TEST_F(CmdUnprotectSecretTest, EmptyInputJsonReturnsErrorJson) {
    CliArgs args;
    args.command     = "unprotect-secret";
    args.token       = "";
    args.policy      = 2;
    args.json_output = true;

    std::string out;
    int rc = run_cmd(args, "", out);

    EXPECT_EQ(rc, 1);
    EXPECT_EQ(out, "{\"error\":\"no input provided\"}\n");
}

// --- Success output ---

TEST_F(CmdUnprotectSecretTest, JsonOutputOnSuccess) {
    g_stub_plaintext = "hello-world";
    g_stub_return    = static_cast<long>(g_stub_plaintext.size() + 1);

    CliArgs args;
    args.command     = "unprotect-secret";
    args.token       = "some-jwt";
    args.policy      = 2;
    args.json_output = true;

    std::string out;
    int rc = run_cmd(args, "", out);

    EXPECT_EQ(rc, 0);
    EXPECT_EQ(out, "{\"secret\":\"hello-world\"}\n");
}

TEST_F(CmdUnprotectSecretTest, JsonEscapesSpecialCharacters) {
    g_stub_plaintext = "tab:\there\nnewline\\backslash\"quote";
    g_stub_return    = static_cast<long>(g_stub_plaintext.size() + 1);

    CliArgs args;
    args.command     = "unprotect-secret";
    args.token       = "some-jwt";
    args.policy      = 2;
    args.json_output = true;

    std::string out;
    int rc = run_cmd(args, "", out);

    EXPECT_EQ(rc, 0);
    EXPECT_EQ(out, "{\"secret\":\"tab:\\there\\nnewline\\\\backslash\\\"quote\"}\n");
}

TEST_F(CmdUnprotectSecretTest, TrailingNullByteStripped) {
    // Library returns length including null terminator — raw output must not include it.
    // In json mode the secret string should not contain a trailing null character.
    g_stub_plaintext = "clean";
    g_stub_return    = static_cast<long>(g_stub_plaintext.size() + 1); // includes '\0'

    CliArgs args;
    args.command     = "unprotect-secret";
    args.token       = "jwt";
    args.policy      = 2;
    args.json_output = true;

    std::string out;
    int rc = run_cmd(args, "", out);

    EXPECT_EQ(rc, 0);
    EXPECT_EQ(out, "{\"secret\":\"clean\"}\n");
    EXPECT_EQ(out.find('\0'), std::string::npos);
}

// --- Failure output ---

TEST_F(CmdUnprotectSecretTest, JsonOutputOnLibraryFailure) {
    g_stub_return = -100; // maps to "PolicyMismatchError"

    CliArgs args;
    args.command     = "unprotect-secret";
    args.token       = "bad-jwt";
    args.policy      = 2;
    args.json_output = true;

    std::string out;
    int rc = run_cmd(args, "", out);

    EXPECT_EQ(rc, 1);
    EXPECT_EQ(out, "{\"error\":\"PolicyMismatchError\"}\n");
}

TEST_F(CmdUnprotectSecretTest, NonJsonOutputOnLibraryFailureGoesToStderr) {
    g_stub_return = -100;

    CliArgs args;
    args.command     = "unprotect-secret";
    args.token       = "bad-jwt";
    args.policy      = 2;
    args.json_output = false;

    std::string out;
    int rc = run_cmd(args, "", out);

    EXPECT_EQ(rc, 1);
    EXPECT_TRUE(out.empty()); // error goes to stderr, stdout is clean
}
