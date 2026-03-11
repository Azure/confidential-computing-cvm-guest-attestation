// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include <iostream>

#ifdef DYNAMIC_SAMPLE
// CLI mode: dynamic linking to SecretsProvisioningLibrary
#include "cli_common.h"
#include "cmd_is_cvm.h"
#include "cmd_is_secrets_enabled.h"
#include "cmd_unprotect_secret.h"
#include "cmd_validate_imds.h"
#include "SecretsProvisioningLibrary.h"
#include "Version.h"

static void print_usage(std::ostream& out)
{
    out << "Usage: azure-protected-secrets-tool <command> [options]\n"
        << "\n"
        << "Commands:\n"
        << "  is-cvm                             Check if VM is a Confidential VM\n"
        << "  is-secrets-provisioning-enabled    Check if secrets provisioning is enabled\n"
        << "  unprotect-secret [TOKEN]           Decrypt a protected secret.\n"
        << "                                     TOKEN may be passed as an inline argument\n"
        << "                                     or piped via stdin.\n"
        << "  validate-imds-metadata             Validate IMDS metadata signature\n"
        << "\n"
        << "Options:\n"
        << "  --policy N   Set policy for unprotect-secret (0=RequireAll, 2=AllowUnsigned, 4=AllowLegacy)\n"
        << "  --json       Output in JSON format\n"
        << "  --help, -h   Print this help message\n"
        << "  --version    Print tool and library version\n";
}

int main(int argc, char* argv[])
{
    if (argc < 2) {
        print_usage(std::cerr);
        return 1;
    }

    CliArgs args = parse_args(argc, argv);

    if (args.help) {
        print_usage(std::cout);
        return 0;
    }

    if (args.version) {
        std::cout << secrets_library_version() << "\n";
        return 0;
    }

    if (args.command == "is-cvm") {
        return cmd_is_cvm(args);
    } else if (args.command == "is-secrets-provisioning-enabled") {
        return cmd_is_secrets_enabled(args);
    } else if (args.command == "unprotect-secret") {
        return cmd_unprotect_secret(args);
    } else if (args.command == "validate-imds-metadata") {
        return cmd_validate_imds(args);
    } else if (!args.command.empty()) {
        std::cerr << "Unknown command: " << args.command << "\n";
        print_usage(std::cerr);
        return 1;
    } else {
        print_usage(std::cerr);
        return 1;
    }
}

#else
// Static sample mode: direct linking to library internals
#include "SecretsProvisioningSample.h"

/*
* Main function
* commands are:
* - Create a key
* - Check if a key is present
* - Remove a key
* - Get the vmid
* - Encrypt data - takes in a string and encrypts it and prints a jwt
* - Decrypt data - takes in a jwt and decrypts it and prints the secret
*/
int main(int argc, char* argv[])
{
	if (argc < 2) {
		std::cout << "Please provide a command." << std::endl;
		return 1;
	}

	std::string command = argv[1];
	if (command == "Decrypt") {
		if (argc < 3) {
			std::cout << "Please provide a string to decrypt." << std::endl;
			return 1;
		}
		Decrypt(argv[2]);
	}
	else if (command == "GenerateKey") {
		GenerateKey();
	}
	else if (command == "IsKeyPresent") {
		if (IsKeyPresent()) {
			std::cout << "Key is present" << std::endl;
		}
		else {
			std::cout << "Key is not present" << std::endl;
		}
	}
	else if (command == "RemoveKey") {
		RemoveKey();
	}
	else if (command == "GetVmid") {
		GetVmidFromSmbios();
	}
	else if (command == "IsCvm") {
		IsCvm();
	}
	else if (command == "Encrypt") {
		if (argc < 3) {
			std::cout << "Please provide a string to encrypt." << std::endl;
			return 1;
		}
		std::string token = Encrypt(argv[2]);
		std::cout << "Token: " << token << std::endl;
	}
	else {
		std::cout << "Unknown command." << std::endl;
		return 1;
	}

	return 0;
}
#endif
