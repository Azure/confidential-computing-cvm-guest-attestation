#include <iostream>
#include <stdarg.h>
#include <vector>
#include <AttestationClient.h>
#include <iostream>
#include <string>
#include <nlohmann/json.hpp>
#include "src/Utils.h"
#include "src/Logger.h"
#include "src/AttestClient.h"
#include "src/HttpClient.h"

using json = nlohmann::json;
using namespace std;

#ifndef PLATFORM_UNIX
static char *optarg = nullptr;
static int optind = 1;
static int getopt(int argc, char *const argv[], const char *optstring) {
  // Error and -1 returns are the same as for getopt(), plus '?'
  //  for an ambiguous match or an extraneous parameter.
  if (
      (argv == nullptr) ||
      (optind >= argc) ||
      (argv[optind][0] != '-') ||
      (argv[optind][0] == 0)) {
    return -1;
  }

  int opt = argv[optind][1];
  const char *p = strchr(optstring, opt);

  if (p == NULL) {
    return '?';
  }
  if (p[1] == ':') {
    optind++;
    if (optind >= argc) {
      return '?';
    }
    optarg = argv[optind];
    optind++;
  }
  return opt;
}
#endif //! PLATFORM_UNIX

void usage(char *programName) {
  printf("Usage: %s [arguments]\n", programName);
  printf("   Options:\n");
  printf("\t-c Config file\n");
  printf("\t-h Print this help menu\n\n");
  printf("   Examples:\n");
  printf("\t%s -c config.json\n", programName);
  printf("\t%s -h\n", programName);
}

int main(int argc, char *argv[]) {
  std::string config_filename;
  std::string claims_filename;

  int opt;
  while ((opt = getopt(argc, argv, "c:h")) != -1) {
    switch (opt) {
    case 'c':
      config_filename.assign(optarg);
      break;
    case 'h':
      usage(argv[0]);
      exit(0);
    case ':':
      fprintf(stderr, "Option needs a value\n");
      exit(1);
    default:
      usage(argv[0]);
      exit(1);
    }
  }

  try {
    // user must provide a config file
    if (config_filename.empty()) {
      fprintf(stderr, "Config file is missing\n");
      usage(argv[0]);
      exit(1);
    }

    // set attestation request based on config file
    std::ifstream config_file(config_filename);
    json config = json::parse(config_file);
    config_file.close();

    std::string attestation_url;
    if (!config.contains("attestation_url")) {
      fprintf(stderr, "attestation_url is missing\n\n");
      usage(argv[0]);
      exit(1);
    }
    attestation_url = config["attestation_url"];

    std::string api_key;
    if (config.contains("api_key")) {
      api_key = config["api_key"];
    }

    std::string attestation_type;
    if (!config.contains("attestation_type")) {
      fprintf(stderr, "attestation_type is missing\n\n");
      usage(argv[0]);
      exit(1);
    }
    attestation_type = config["attestation_type"];

    if (!Utils::case_insensitive_compare(attestation_type, "amber") &&
        !Utils::case_insensitive_compare(attestation_type, "maa")) {
      fprintf(stderr, "Attestation type was incorrect\n\n");
      usage(argv[0]);
      exit(1);
    }

    // check for user claims
    std::string client_payload;
    json user_claims = config["claims"];
    if (!user_claims.is_null()) {
      client_payload = user_claims.dump();
    }

    // if attesting with Amber, we need to make sure an API token was provided
    // or it was added as an environment variable
    if (api_key.empty() && Utils::case_insensitive_compare(attestation_type, "amber")) {
      const char *api_key_value = std::getenv(AMBER_API_KEY_NAME);
      if (api_key_value == nullptr) {
        fprintf(stderr, "Attestation endpoint \"api_key\" value missing\n\n");
        usage(argv[0]);
        exit(1);
      }
      api_key = std::string(api_key_value);
    }

    std::string output_filename;
    if (config.contains("output_filename")) {
      output_filename = config["output_filename"];
    }

    AttestationClient *attestation_client = nullptr;
    Logger *log_handle = new Logger();

    // Initialize attestation client
    if (!Initialize(log_handle, &attestation_client)) {
      fprintf(stderr, "Failed to create attestation client object\n\n");
      Uninitialize();
      exit(1);
    }
    attest::AttestationResult result;

    bool has_quote = true;
    std::string quote_data;

    // get verifiable quote
    result = attestation_client->GetHardwarePlatformEvidence(quote_data, client_payload, attestation_type);
    if (result.code_ != attest::AttestationResult::ErrorCode::SUCCESS) {
      has_quote = false;
    }

    if (has_quote) {
      // Parses the returned json response
      json json_response = json::parse(quote_data);

      std::string encoded_quote = json_response["quote"];
      if (encoded_quote.empty()) {
          result.code_ = attest::AttestationResult::ErrorCode::ERROR_EMPTY_TD_QUOTE;
          result.description_ = std::string("Empty Quote received from IMDS Quote Endpoint");
      }

      // decode the base64url encoded quote to raw bytes
      std::vector<unsigned char> quote_bytes = Utils::base64url_to_binary(encoded_quote);

      // check if user wants to save the td quote
      if (!output_filename.empty()) {
          std::ofstream output_file(output_filename, std::ios::out | std::ios::binary);
          output_file.write((char *)quote_bytes.data(), quote_bytes.size());
          output_file.close();

          std::stringstream stream;
          stream << "Quote output file generated: " << output_filename;

          cout << stream.str() << endl;;
      }

      std::string encoded_claims =
          Utils::binary_to_base64url(std::vector<unsigned char>(client_payload.begin(), client_payload.end()));

      HttpClient http_client;
      AttestClient::Config attestation_config = {
        attestation_url,
        attestation_type,
        encoded_quote,
        encoded_claims,
        api_key
      };

      std::string jwt_token = AttestClient::VerifyEvidence(attestation_config, http_client);

      if (jwt_token.empty()) {
        fprintf(stderr, "Empty token received\n");
        exit(1);
      }

      cout << "Hardware attestation passed successfully!!" << endl;
      cout << "TOKEN:\n" << endl;
      std::cout << jwt_token << std::endl << std::endl;
    }

    Uninitialize();
  }
  catch (std::exception &e) {
    cout << "Exception occured. Details - " << e.what() << endl;
    exit(1);
  }
}