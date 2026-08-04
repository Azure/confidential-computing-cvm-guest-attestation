// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include <gtest/gtest.h>
#include <cstring>
#include "cli_common.h"

TEST(ParseArgsTest, NoArgs) {
    char* argv[] = { (char*)"azure-protected-secrets-tool" };
    CliArgs args = parse_args(1, argv);
    EXPECT_TRUE(args.command.empty());
    EXPECT_EQ(args.policy, 0u);
    EXPECT_FALSE(args.help);
    EXPECT_FALSE(args.version);
    EXPECT_FALSE(args.json_output);
}

TEST(ParseArgsTest, SingleCommand) {
    char* argv[] = { (char*)"azure-protected-secrets-tool", (char*)"is-cvm" };
    CliArgs args = parse_args(2, argv);
    EXPECT_EQ(args.command, "is-cvm");
    EXPECT_EQ(args.policy, 0u);
    EXPECT_FALSE(args.help);
    EXPECT_FALSE(args.version);
}

TEST(ParseArgsTest, UnprotectSecretWithPolicy) {
    char* argv[] = { (char*)"azure-protected-secrets-tool", (char*)"unprotect-secret", (char*)"--policy", (char*)"2" };
    CliArgs args = parse_args(4, argv);
    EXPECT_EQ(args.command, "unprotect-secret");
    EXPECT_EQ(args.policy, 2u);
}

TEST(ParseArgsTest, PolicyWithoutValue) {
    char* argv[] = { (char*)"azure-protected-secrets-tool", (char*)"unprotect-secret", (char*)"--policy" };
    CliArgs args = parse_args(3, argv);
    EXPECT_EQ(args.command, "unprotect-secret");
    EXPECT_EQ(args.policy, 0u);
}

TEST(ParseArgsTest, PolicyZero) {
    char* argv[] = { (char*)"azure-protected-secrets-tool", (char*)"unprotect-secret", (char*)"--policy", (char*)"0" };
    CliArgs args = parse_args(4, argv);
    EXPECT_EQ(args.policy, 0u);
    EXPECT_TRUE(args.policy_valid);
}

TEST(ParseArgsTest, PolicyOne) {
    char* argv[] = { (char*)"azure-protected-secrets-tool", (char*)"unprotect-secret", (char*)"--policy", (char*)"1" };
    CliArgs args = parse_args(4, argv);
    EXPECT_EQ(args.policy, 1u);
    EXPECT_TRUE(args.policy_valid);
}

TEST(ParseArgsTest, PolicyThree) {
    char* argv[] = { (char*)"azure-protected-secrets-tool", (char*)"unprotect-secret", (char*)"--policy", (char*)"3" };
    CliArgs args = parse_args(4, argv);
    EXPECT_EQ(args.policy, 3u);
    EXPECT_TRUE(args.policy_valid);
}

TEST(ParseArgsTest, PolicyFourIsMaxValid) {
    char* argv[] = { (char*)"azure-protected-secrets-tool", (char*)"unprotect-secret", (char*)"--policy", (char*)"4" };
    CliArgs args = parse_args(4, argv);
    EXPECT_EQ(args.policy, 4u);
    EXPECT_TRUE(args.policy_valid);
}

TEST(ParseArgsTest, PolicyAboveMaxRejected) {
    // 5 is outside the supported 0-4 range and must be rejected.
    char* argv[] = { (char*)"azure-protected-secrets-tool", (char*)"unprotect-secret", (char*)"--policy", (char*)"5" };
    CliArgs args = parse_args(4, argv);
    EXPECT_FALSE(args.policy_valid);
}

TEST(ParseArgsTest, PolicyNonNumericRejected) {
    char* argv[] = { (char*)"azure-protected-secrets-tool", (char*)"unprotect-secret", (char*)"--policy", (char*)"abc" };
    CliArgs args = parse_args(4, argv);
    EXPECT_FALSE(args.policy_valid);
}

TEST(ParseArgsTest, UnknownCommand) {
    char* argv[] = { (char*)"azure-protected-secrets-tool", (char*)"do-something" };
    CliArgs args = parse_args(2, argv);
    EXPECT_EQ(args.command, "do-something");
    EXPECT_FALSE(args.help);
    EXPECT_FALSE(args.version);
}

TEST(ParseArgsTest, IsSecretsProvisioningEnabled) {
    char* argv[] = { (char*)"azure-protected-secrets-tool", (char*)"is-secrets-provisioning-enabled" };
    CliArgs args = parse_args(2, argv);
    EXPECT_EQ(args.command, "is-secrets-provisioning-enabled");
}

TEST(ParseArgsTest, ValidateImdsMetadata) {
    char* argv[] = { (char*)"azure-protected-secrets-tool", (char*)"validate-imds-metadata" };
    CliArgs args = parse_args(2, argv);
    EXPECT_EQ(args.command, "validate-imds-metadata");
}

TEST(ParseArgsTest, HelpLongFlag) {
    char* argv[] = { (char*)"azure-protected-secrets-tool", (char*)"--help" };
    CliArgs args = parse_args(2, argv);
    EXPECT_TRUE(args.help);
    EXPECT_TRUE(args.command.empty());
    EXPECT_FALSE(args.version);
}

TEST(ParseArgsTest, HelpShortFlag) {
    char* argv[] = { (char*)"azure-protected-secrets-tool", (char*)"-h" };
    CliArgs args = parse_args(2, argv);
    EXPECT_TRUE(args.help);
    EXPECT_TRUE(args.command.empty());
}

TEST(ParseArgsTest, VersionFlag) {
    char* argv[] = { (char*)"azure-protected-secrets-tool", (char*)"--version" };
    CliArgs args = parse_args(2, argv);
    EXPECT_TRUE(args.version);
    EXPECT_TRUE(args.command.empty());
    EXPECT_FALSE(args.help);
}

TEST(ParseArgsTest, JsonFlag) {
    char* argv[] = { (char*)"azure-protected-secrets-tool", (char*)"is-cvm", (char*)"--json" };
    CliArgs args = parse_args(3, argv);
    EXPECT_EQ(args.command, "is-cvm");
    EXPECT_TRUE(args.json_output);
    EXPECT_FALSE(args.help);
    EXPECT_FALSE(args.version);
}

TEST(ParseArgsTest, UnprotectSecretInlineToken) {
    char* argv[] = { (char*)"azure-protected-secrets-tool", (char*)"unprotect-secret", (char*)"eyJmb28iOiJiYXIifQ" };
    CliArgs args = parse_args(3, argv);
    EXPECT_EQ(args.command, "unprotect-secret");
    EXPECT_EQ(args.token, "eyJmb28iOiJiYXIifQ");
    EXPECT_EQ(args.policy, 0u);
}

TEST(ParseArgsTest, UnprotectSecretInlineTokenWithPolicy) {
    char* argv[] = { (char*)"azure-protected-secrets-tool", (char*)"unprotect-secret", (char*)"eyJmb28iOiJiYXIifQ", (char*)"--policy", (char*)"2" };
    CliArgs args = parse_args(5, argv);
    EXPECT_EQ(args.command, "unprotect-secret");
    EXPECT_EQ(args.token, "eyJmb28iOiJiYXIifQ");
    EXPECT_EQ(args.policy, 2u);
}

TEST(ParseArgsTest, UnprotectSecretInlineTokenWithJson) {
    char* argv[] = { (char*)"azure-protected-secrets-tool", (char*)"unprotect-secret", (char*)"eyJmb28iOiJiYXIifQ", (char*)"--json" };
    CliArgs args = parse_args(4, argv);
    EXPECT_EQ(args.command, "unprotect-secret");
    EXPECT_EQ(args.token, "eyJmb28iOiJiYXIifQ");
    EXPECT_TRUE(args.json_output);
}

TEST(ParseArgsTest, TokenNotSetWithoutPositionalArg) {
    char* argv[] = { (char*)"azure-protected-secrets-tool", (char*)"unprotect-secret", (char*)"--policy", (char*)"2" };
    CliArgs args = parse_args(4, argv);
    EXPECT_EQ(args.command, "unprotect-secret");
    EXPECT_TRUE(args.token.empty());
    EXPECT_EQ(args.policy, 2u);
}

TEST(ParseArgsTest, OnlyOneTokenCaptured) {
    // Second positional arg is token; a third positional would be ignored
    char* argv[] = { (char*)"azure-protected-secrets-tool", (char*)"unprotect-secret", (char*)"first-token", (char*)"extra" };
    CliArgs args = parse_args(4, argv);
    EXPECT_EQ(args.command, "unprotect-secret");
    EXPECT_EQ(args.token, "first-token");
}

