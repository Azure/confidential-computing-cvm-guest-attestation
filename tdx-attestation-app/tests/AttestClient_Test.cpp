#include <gtest/gtest.h>
#include "../src/HttpClient_I.h"
#include "../src/AttestClient.h"

class MockHttpClient : public HttpClient_I {
public:
  MockHttpClient(HttpClientResult code, std::string data) : return_code(code), response_data(data) {}
  ~MockHttpClient() {}

  HttpClientResult InvokeHttpRequest(std::string &http_response,
                                     const std::string &url,
                                     const HttpClient_I::HttpVerb &http_verb,
                                     const std::vector<std::string> &headers,
                                     const std::string &request_body = std::string()) override
  {
    http_response = this->response_data;
    return this->return_code;
  }

private:
  HttpClientResult return_code;
  std::string response_data;
};

const AttestClient::Config maa_config = {
  "http://maa/somepath",
  "maa",
  "base64url encoded evidence",
  "base64url encoded claims",
  ""
};

const AttestClient::Config amber_config = {
  "http://amber/somepath",
  "amber",
  "base64 encoded evidence",
  "base64 encoded claims",
  "api key"
};


TEST(AttestClientTests, VerifyEvidenceSuccesfullyWithMAA) {
  std::string response_data = R"({"token": "fake token"})";
  MockHttpClient mock_client(HttpClientResult::SUCCESS, response_data);
  std::string token = AttestClient::VerifyEvidence(maa_config, mock_client);

  EXPECT_EQ(token, "fake token");
}

TEST(AttestClientTests, VerifyEvidenceSuccesfullyWithAmber) {
  std::string response_data = R"({"token": "fake token"})";
  MockHttpClient mock_client(HttpClientResult::SUCCESS, response_data);
  std::string token = AttestClient::VerifyEvidence(amber_config, mock_client);

  EXPECT_EQ(token, "fake token");
}

TEST(AttestClientTests, ThrowsExceptionOnInvalidAttestationType) {
  const AttestClient::Config config = {
    "http://someurl/somepath",
    "another_type",
    "some encoded evidence",
    "some encoded claims",
    "api key"
  };

  std::string response_data = R"({"token": "fake token"})";
  MockHttpClient mock_client(HttpClientResult::SUCCESS, response_data);
  EXPECT_THROW(AttestClient::VerifyEvidence(config, mock_client), std::exception);
}

TEST(AttestClientTests, ThrowsExceptionOnEmptyResponse) {
  std::string response_data = "";
  MockHttpClient mock_client(HttpClientResult::SUCCESS, response_data);
  EXPECT_THROW(AttestClient::VerifyEvidence(maa_config, mock_client), std::exception);
}

TEST(AttestClientTests, ThrowsExceptionOnInvalidResponseCode) {
  std::string response_data = "some error";
  MockHttpClient mock_client(HttpClientResult::FAILED, response_data);
  EXPECT_THROW(AttestClient::VerifyEvidence(maa_config, mock_client), std::exception);
}

TEST(AttestClientTests, ThrowsExceptionOnInvalidResponse) {
  std::string response_data = "some error";
  MockHttpClient mock_client(HttpClientResult::FAILED, response_data);
  EXPECT_THROW(AttestClient::VerifyEvidence(maa_config, mock_client), std::exception);
}