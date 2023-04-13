#include <gtest/gtest.h>
#include "../src/Utils.h"

TEST(UtilsTests, HandleEmptyVector) {
  std::vector<unsigned char> input;
  std::string output = Utils::binary_to_base64url(input);
  EXPECT_EQ(output, "");
}

TEST(UtilsTests, BeAbleToEncode) {
  std::vector<unsigned char> input = {0, 1, 2, 3, 4};
  std::string output = Utils::binary_to_base64url(input);
  EXPECT_EQ(output, "AAECAwQ");
}

TEST(UtilsTests, EncodeToTheCorrectString) {
  std::string str = "Hello World!";
  std::vector<unsigned char> input(str.begin(), str.end());
  std::string output = Utils::binary_to_base64url(input);
  EXPECT_EQ(output, "SGVsbG8gV29ybGQh");
}

TEST(UtilsTests, NullBytesShouldNotBeRemovedDurinEncoding) {
  // Encoder  not trim any null bytes
  std::vector<unsigned char> input{0x61, 0x00, 0x00, 0x62, 0x00, 0x00, 0x63};

  std::string output = Utils::binary_to_base64url(input);
  std::string expected = "YQAAYgAAYw";
  EXPECT_EQ(output, expected);
}

TEST(UtilsTests, DecodeEncodedString) {
  std::vector<unsigned char> output = Utils::base64url_to_binary("YQ");

  std::string actual(output.begin(), output.end());
  std::string expected = "a";

  EXPECT_EQ(actual, expected);
}

TEST(UtilsTests, DecodeLongerEncodedString) {
  std::vector<unsigned char> output =
      Utils::base64url_to_binary("VGhpcyBpcyBzb21lIGRhdGE");

  std::string actual = std::string(output.begin(), output.end());
  std::string expected = "This is some data";

  EXPECT_EQ(actual, expected);
}

TEST(UtilsTests, ThrowExceptionWhenDecodingUnencodedString) {
  const std::string input = "This is not encoded";

  EXPECT_THROW(Utils::base64url_to_binary(input), std::exception);
}

TEST(UtilsTests, ConvertBase64UrlToBase64) {
  const std::string input = "YQ";
  const std::string output = Utils::base64url_to_base64(input);

  EXPECT_EQ(output, "YQ==");
}

TEST(UtilsTests, ReturnEmptyString) {
  const std::string input = "";
  const std::string output = Utils::base64url_to_base64(input);

  EXPECT_EQ(output, "");
}

TEST(UtilsTests, CompareStringCaseInsensitive) {
  const std::string string1 = "test";
  const std::string string2 = "TEST";

  bool output = Utils::case_insensitive_compare(string1, string2);
  ASSERT_TRUE(output);
}

TEST(UtilsTests, CompareDifferentStrings) {
  const std::string string1 = "Hello";
  const std::string string2 = "Testing";

  bool output = Utils::case_insensitive_compare(string1, string2);
  ASSERT_FALSE(output);
}

TEST(UtilsTests, CompareDiffentStrings_2) {
  const std::string string1 = "Test";
  const std::string string2 = "Testing";

  bool output = Utils::case_insensitive_compare(string1, string2);
  ASSERT_FALSE(output);
}

TEST(UtilsTests, CompareDiffentStrings_3) {
  const std::string string1 = "";
  const std::string string2 = "NewTest";

  bool output = Utils::case_insensitive_compare(string1, string2);
  ASSERT_FALSE(output);
}