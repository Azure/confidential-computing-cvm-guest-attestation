// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//
// Pre-generated test certificate chains for multi-root trust verification tests.
// Two independent CA hierarchies (RootA → IntermediateA → LeafA, RootB → IntermediateB → LeafB)
// allow testing that VerifyCertChain accepts chains rooted at either trusted root
// and rejects chains from unknown roots.
//
// Leaf subjects use ".SecureCPSProvisioning.cloudapp-test.net" suffix to match
// the X509_SUBJECT_NAME_SUFFIX pattern used in verification.
#pragma once

// TestRootA: CN=TestRootA, self-signed, RSA-2048, SHA-256, CA:TRUE pathlen:1
constexpr const char* TEST_ROOT_A =
    "MIIC9zCCAd+gAwIBAgIQGkL9uBatjaFKfkX9AvmdqjANBgkqhkiG9w0BAQsFADAU"
    "MRIwEAYDVQQDDAlUZXN0Um9vdEEwHhcNMjYwNDAyMDExNjI3WhcNMzYwNDAyMDEy"
    "NjI0WjAUMRIwEAYDVQQDDAlUZXN0Um9vdEEwggEiMA0GCSqGSIb3DQEBAQUAA4IB"
    "DwAwggEKAoIBAQDESUHOeS9xVCESekp4TwntNVUpktiPfyMFqOk//XZhJBQsqtfE"
    "TOCe5My8ldv2TOsvtJQcf3bjCwQospJ2JNFmW1eFubGSPqxowmOR59lA+U3HSU0x"
    "5ranYW7Z6nfVaq6Ifoke+KOTXF8KmhvHUFCs8xtGHpPwYeLtAtJp9lkIrA+CvaJz"
    "4JP0+92pxcEEGXjwG8dQn52Cr2XqC9Q9iO0gpeHrLzpsFOnd/ybN084YP8OjuIVU"
    "nBfJ9FQStxbvDdk0JaHUBFE5AEoSIu3j+9EfbAUPMRoSQMKWQLcurjc0DzF5x+Ze"
    "zWByqEyPrtSfyr93YEUkbmDbmgauztGRQ3CNAgMBAAGjRTBDMA4GA1UdDwEB/wQE"
    "AwIBBjASBgNVHRMBAf8ECDAGAQH/AgEBMB0GA1UdDgQWBBS7t6wUZTPQdDWb8nbF"
    "rPk2ukSEPTANBgkqhkiG9w0BAQsFAAOCAQEAvy/xbrFfAPwlKoJn1lCIkxgXUEX+"
    "cQiLLxFIwAdfp5B/BY2BQszuBh2Obl+5DCyyFCHYPXwHqpzvArC16iPy4BHnViin"
    "Y0kpqa1fs9Vz9sELV4cJsyT+uiObP2z3MzzjUvY5Dvs/NYnJ7mB1RIW2k7t6/cY"
    "EXwHQUNmvVAhTfnhuRbmgxfF9Qw6Nfv/YcXBPu0ienOB84VVllvhsvUX6RNuWg3"
    "i1FrosWO/5NMO+D4ogxuOYjO2IT2RFbBkkLcfiNtJ62NBjI3BwofdVziaekBerET"
    "blq+ElFeYsw3nkjUGBgJiyxzzS0gT77cWMN6XNG+pLmxHvTpbQRf8rvFJegQ==";

// TestIntermediateA: CN=TestIntermediateA, signed by TestRootA, CA:TRUE pathlen:0
constexpr const char* TEST_INTERMEDIATE_A =
    "MIIDIDCCAgigAwIBAgIQUZ/aiPXHRq1PQ9NKGuJ1MDANBgkqhkiG9w0BAQsFADAU"
    "MRIwEAYDVQQDDAlUZXN0Um9vdEEwHhcNMjYwNDAyMDExNjMwWhcNMzEwNDAyMDEy"
    "NjI5WjAcMRowGAYDVQQDDBFUZXN0SW50ZXJtZWRpYXRlQTCCASIwDQYJKoZIhvcN"
    "AQEBBQADggEPADCCAQoCggEBAKSpz0FsP0uLxNBMyQFuZTwbclVI0mrpf9utLzd3"
    "WRasE8VR4vjeYtxLW5Iem1wGPiGmcgDcwKKUmv6xFn+vuhmqQU0m9XKR3Tn6mlIv"
    "bL2XwYGSScZUWZbgEX8HsdiQKyjkUdSoBICfY8nnfHTFsFk/9ahx6E0etfPzG0dH"
    "8QEx1RRcyLsvWVmcCyG8j9kw6JEN5YlQVuZqXxMW8STIfNkw/DgHdNvn+rRuWCuB"
    "Oy/PYD37qqxdlexXlJ4OHsExYi3M1bj7VfzYZGCSrD3r5qVCCWjrmxBPyc+R5QDf"
    "h1EZPdgm941YqLVvEBETrR0xmYd6x02hUKqMgiTbUc0rIJkCAwEAAaNmMGQwDgYD"
    "VR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAwHwYDVR0jBBgwFoAUu7es"
    "FGUz0HQ1m/J2xaz5NrpEhD0wHQYDVR0OBBYEFA5wGFjEjKufDIyehMtkSr8eIdy/"
    "MA0GCSqGSIb3DQEBCwUAA4IBAQAe6NjD+O+oPQc/medAGqaQyTZ0Tu8/V99IHG0C"
    "AIvXWhuvVcXzMnN+sb5wVoF2WTuwGnlGYhmvpRKC1HzYu8VjKW1s3wQUxYGY+JyC"
    "18LWr9pGcOo3336lo2ky2+dgGL0Xo0AlfRODBx0ssiX2GPuY00Jcz6Yg+Lzz/5OL"
    "BDeEX5HbL0G1eHlUAtMnmA+AYQPJE4DwZI/dRP8cYI2x3CmFaJ2RY7yIUMEC7Ot"
    "NlMbvUwMgoAc8U20iRAGYjQ/ehGaBQ254ypTcrpfd5k7rytRw+1DZiXDYZ2q+GO3j"
    "4lVy34Q1OQ7+e2MiS8l56Sai7yzpsDmfoZ+YMnox2fj5t9Zk";

// TestLeafA: CN=eastus.SecureCPSProvisioning.cloudapp-test.net, signed by IntermediateA
constexpr const char* TEST_LEAF_A =
    "MIIDMTCCAhmgAwIBAgIQNrLSqKEO551Isj5PhX+DQDANBgkqhkiG9w0BAQsFADAc"
    "MRowGAYDVQQDDBFUZXN0SW50ZXJtZWRpYXRlQTAeFw0yNjA0MDIwMTE2MzJaFw0y"
    "ODA0MDIwMTI2MzFaMDkxNzA1BgNVBAMMLmVhc3R1cy5TZWN1cmVDUFNQcm92aXNp"
    "b25pbmcuY2xvdWRhcHAtdGVzdC5uZXQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw"
    "ggEKAoIBAQC26xRZvfNEl94BArlNWScp/mA48lkdC61aPtDED1defwbfv7sazDzC"
    "XC/Q2SWInGcCsN/OqzV2o5tpAn6Y2J/7JlVHIZ8rsMhvlxqW42zaf2yVBTb0kXv"
    "SmFCrs/Kb53QXsqjLnMN61kNMx3nw6Hjwb7QKbarUS8dRiB8FJh1nDzggPPbRYOH"
    "jWZIRsDqVNBZD+NkX318FHhNMwaRruOSE2p2LWtACzFZ3qaMcyLjt5STbR1EFtyY"
    "J7yA0x/2U2Jq/wpqRpQGVDr++ycXiNplQQJ67O+JlmiG/Zmb93sQhdthmLBwXpvb"
    "hgiPUBMcQUPqLjyR2WFsK5oRGGCq/DGWZAgMBAAGjUjBQMA4GA1UdDwEB/wQEAwIH"
    "gDAfBgNVHSMEGDAWgBQOcBhYxIyrnwyMnoTLZEq/HiHcvzAdBgNVHQ4EFgQUESgq"
    "QGGdAb7ZYfpN8Ti4jLHN518wDQYJKoZIhvcNAQELBQADggEBAG4tjstFLmgwbSxh"
    "jol5/OnWQnVzPqZr+sI9UbzmfYYcVyJc+HqeUam0Tr3lVz3uzaon8e3uP6JkjHOF"
    "6iBvoKycpgIEyD6nPhmt9Lg9Tv0Ad0AnsPYK6sxuYePF1m+Enj3cx9kucVKI7K8l"
    "V48NyAMsxVStVzygvsxysyUblkHlgx62A9NF5Bqz24+m50P5YJZcQdUgjEP6GyN6"
    "P8mWxavW6le3c99dV9EUI2R5sBAMoS3IeXh41FpDtsIXTe5GxgZBYnM/4y29sD4L"
    "ckNQBnzbLjAvwhHokV1CZyFpQ79IvsQk9U/RNN47m2PY+0mfIycqv5N+kEo8dzKK"
    "6q9wBJM=";

// TestRootB: CN=TestRootB, self-signed, RSA-2048, SHA-256, CA:TRUE pathlen:1
constexpr const char* TEST_ROOT_B =
    "MIIC9zCCAd+gAwIBAgIQeYJa1L0iYrRP0a+zuBq6DTANBgkqhkiG9w0BAQsFADAU"
    "MRIwEAYDVQQDDAlUZXN0Um9vdEIwHhcNMjYwNDAyMDExNjM1WhcNMzYwNDAyMDEy"
    "NjM0WjAUMRIwEAYDVQQDDAlUZXN0Um9vdEIwggEiMA0GCSqGSIb3DQEBAQUAA4IB"
    "DwAwggEKAoIBAQC3R0o/SzYpgPsfGi77nuKjD5n5irQmPEf45nlrPkmQOlWNl91f"
    "2k9Ub0W/Jw5dmCQheCkjHM+m3aGcdMA2P48NEyFDysOFzjSk4ZJ0Br9j4sZwXBM"
    "DmISqv6Lr2kbN8YoWWIPTgpSs0uq1jlPkyPx5BK8YEA+nGfsTvelB77axpGIA8p"
    "J7itMn+BJeojEm2IkGyL7e690jLUDm+hgZBc3ewtRAw2v4LBu5IopjtRiAcl3R2c"
    "+3ZE0ybzG9CE+lVcKOrCCsvWJy78153gUMqVIIIQts/YiE04bQjMzUCDgFdn1rpq"
    "NqkcJYP7mWT5O47xyra/lb7s40O05v4Z0RMaWpAgMBAAGjRTBDMA4GA1UdDwEB/wQE"
    "AwIBBjASBgNVHRMBAf8ECDAGAQH/AgEBMB0GA1UdDgQWBBR9crDJchZNr39vGXoK"
    "kdq9sFsXRzANBgkqhkiG9w0BAQsFAAOCAQEAHlElPEHok6vXnqzNnWfp8RLg88Dv"
    "rxh0XxXb31uO0tstoQq0hR7AISpgLrjS5zHj/cCOqtvZcjuo63zan3tOxQ/zWi+f"
    "//0Chl9DnXCINfcRakbd1ddXv101/YnRTO6kjlYItLQrac+ojHOtezJYU6p5hVCY"
    "ZP+2WBHvro28gLjyEifaD8036EbWx3lgpe4U6P/jYznBQa4oKI1UEvpbBbqI+OgD"
    "zgvWlYClDG7+PYTMHPXumtIFBXI4wUSTxNWZCWZciHqBG7V5oyfr5xuSPwa2Ag/b"
    "W1XsLHtplZgeQxuXsG+KxaUgQoRdUl4Ay1HcmzAPN95zOWcdQ4afF2J1kA==";

// TestIntermediateB: CN=TestIntermediateB, signed by TestRootB, CA:TRUE pathlen:0
constexpr const char* TEST_INTERMEDIATE_B =
    "MIIDIDCCAgigAwIBAgIQVFTxwpTmfLJDlxAlmcg6rjANBgkqhkiG9w0BAQsFADAU"
    "MRIwEAYDVQQDDAlUZXN0Um9vdEIwHhcNMjYwNDAyMDExNjM4WhcNMzEwNDAyMDEy"
    "NjM3WjAcMRowGAYDVQQDDBFUZXN0SW50ZXJtZWRpYXRlQjCCASIwDQYJKoZIhvcN"
    "AQEBBQADggEPADCCAQoCggEBALCmOaA9rPGaelBe22ziKFOcj/Qp/ivQLdLGzh9M"
    "keaeJqHzS0QKCs369X8DBTWJT1EFLxF5w8NwfuqyEdVdtpPOjxZgwp+GKI9e/O6t"
    "bobAishA6pTKrMczGOOAk4n3HjK4YX120zPGUY2YI5KSxiNJHtpoETREn6Ovc+3R"
    "Vh1EY90EbpD+faI6I7XAW6KNw1JNPIbF7VjKWepTAEERygXrGLcTh0pqJsSS/CIm"
    "lZBoK61DMjVdUC+HLLkQh2PToJS+3aa8IRF8quFsockFB57y/Sm5Y9eSYnRyjqV+"
    "YBCu752sOC52BxKbhXHuWfKH1G/axLKZfGWp+Lt46sE+VCkCAwEAAaNmMGQwDgYD"
    "VR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAwHwYDVR0jBBgwFoAUfXKw"
    "yXIWTa9/bxl6CpHavbBbF0cwHQYDVR0OBBYEFNLY4S/PbCJmDZG/0jO57Bhbe8MU"
    "MA0GCSqGSIb3DQEBCwUAA4IBAQBa499xhz9fL7AlJ1igKP0vPlXp5QWarHdUhBke"
    "8130/1zSlZO7IR9LbJ/PqbUPkFmFaufyY0/QAhMaoixjOgnDcpPQ7fhyB8YizPEp"
    "TfS3MeDeAq07DxdX/mOlE5ohBOUxfiB05v++8knRKClChr4JmkaP14BiUVbh388o"
    "V7Xh4BISln1eYHH+Bpg/ywa2jMvYVhoa8aps8X/oY5p9nQvw7PRAcUluQyiYUrCZ"
    "K4AuNQAv/rohfxumOlE1maDPlUVUBvbA8CHovi03LpIVqvIptniE2T2ZQ5E4YmzM"
    "JR7RHytosH8SWgw1KxbamPTigZh5v2UqFwGPnunssHhxYbcC";

// TestLeafB: CN=westus.SecureCPSProvisioning.cloudapp-test.net, signed by IntermediateB
constexpr const char* TEST_LEAF_B =
    "MIIDMTCCAhmgAwIBAgIQOpA2E/rvJ5ZBFuNDLTn46jANBgkqhkiG9w0BAQsFADAc"
    "MRowGAYDVQQDDBFUZXN0SW50ZXJtZWRpYXRlQjAeFw0yNjA0MDIwMTE2NDBaFw0y"
    "ODA0MDIwMTI2MzlaMDkxNzA1BgNVBAMMLndlc3R1cy5TZWN1cmVDUFNQcm92aXNp"
    "b25pbmcuY2xvdWRhcHAtdGVzdC5uZXQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw"
    "ggEKAoIBAQC5m6cg+FcYFdj7tJpTwHkTA4+N+WhewNPRi9xOXwMqV/nJtyCo/9xT"
    "sEBQxvboEB3T22gvGpX2A2yO54SpSGYvRb+ohK0DMkA9WwJB6xBzxv61HBKiGeUG"
    "buyJ54DoXZ+WpjlIYpQJQXQEhA/K37fRaRwdSQ6T7iFnfiXolHHwdPXySJS75rfX"
    "jM0Vzm3cGClGQtTlcaDVSYVtkhQVxP6oYD/pgKU44P9zUWb81xTNQrR0+X9oV6uW"
    "xKipQFKcztHcOzjg94TxFK/McYpFDa/97cz14GamR+Jf7EqQytleTDsUT2b9X2o4"
    "eH6DusvkksZmEYO9PbUOnZHBCZxNd0DlAgMBAAGjUjBQMA4GA1UdDwEB/wQEAwIH"
    "gDAfBgNVHSMEGDAWgBTS2OEvz2wiZg2Rv9IzuewYW3vDFDAdBgNVHQ4EFgQUk6JN"
    "juvzuZyt7sj24ET1eklnMX0wDQYJKoZIhvcNAQELBQADggEBAHJknvzy+UMQyAT6"
    "cBlztgLQkTk4ma0qyXGOVyXShXFGOACbzYgMFJn7zyYZyfjtO7UeTuEjyN0XuMdV"
    "H4Zazcjkk1Rh9BfY5HQFRqHBybwATHcqhabINWK38srw+MkcKqWNHoDcqCSGOTHC"
    "a/M5wfvs+wTF+dJewaulf6pKdiG2msWmMEUuDf7nzp0BJJycxChNQKnxs5nM4xlW"
    "xaRp8EOdT2ujGEcBBbghU0HBOy1m7RUNgt0ZNO5nSzEcQSclTAb6yHgPorCjDSqf"
    "R4PI1A+5Mkll7wxi+awgHUI8ogJ7OdJ7GEn9od+FVdEaiDnVMhJJUBwLWI9diiLI"
    "0bKDbqw=";

// Subject suffix for test leaf certs — NOT the same as production X509_SUBJECT_NAME_SUFFIX
// to avoid accidentally matching production logic
constexpr const char* TEST_SUBJECT_SUFFIX = ".SecureCPSProvisioning.cloudapp-test.net";
