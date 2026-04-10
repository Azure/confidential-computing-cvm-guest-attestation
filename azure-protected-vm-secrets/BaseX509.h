// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once
#ifndef PLATFORM_UNIX
#include "Windows.h"
#include "wincrypt.h"
#else
#include <openssl/x509.h>
#endif
#include <vector>
#include <string>

constexpr const char* CCME_ROOTCERT_PEM = // CodeQL [SM05344] This is CCME, not AME root cert. We are working on alternative solutions (custom PKI-R) to deliver the cert.
"MIIFhDCCA2ygAwIBAgIQTCbDKjrVHLNOviLgKTAe8DANBgkqhkiG9w0BAQwFADBT"
"MQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSQw"
"IgYDVQQDExtDb21tZXJjaWFsIENsb3VkIFJvb3QgQ0EgUjEwHhcNMjQwMjAxMTk1"
"OTI1WhcNNDkwMjAxMjAwMzE2WjBTMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWlj"
"cm9zb2Z0IENvcnBvcmF0aW9uMSQwIgYDVQQDExtDb21tZXJjaWFsIENsb3VkIFJv"
"b3QgQ0EgUjEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDTwMFmax0Q"
"hSWxFgxn7YTeYgS9p/hyANNaEuEX389F6w4C3/ZPy4FsQcndVCoG9/auigXnXl6k"
"PJjN00ZBo6kdJsWuyMqahGw1NlK4Ls9W+yCGcpQ9Lma6xgVip3PCZqgylj6Flz2Q"
"BXb9MZkfHUKitbpNdDzc8HnDZtItuCOzHu0/G8iVUdwrHc9wrN6TleVjWz9ABtqe"
"uazmwNzkR+hXQTFL0A2QRlcTO2tNjROHQQoWOTuODxA/LsEKDOAG5WfRIrdYMxIg"
"+rb+xq5SBz8toxpYkbYbF0/kzqxOgxOPd2qZkCaL9XTW02X/dwW84eit+LKSoCId"
"X/rTka5/OJ4IUd2yeUSoqUeOCXyVUzcfDGQ3DJ78toPFicmrmJDex0Lk2IsMUXfS"
"knkjTSH9Tb8snQ4CrSNuvoa1oI8XeKaUhztbEoA8/iwSd52v94mCjKetJzBCKx7l"
"0GKdTvSJoQS84K87cmg/G9M2TvBSQCTELoU4291/fAUJnYw7IB5HXs2aPoAetanX"
"YlTJO+Q35tjbclteOQCb9bQEt9y2gBU13CZ8Jh2ziil5HecXl6REQGZx9wt4xWA/"
"OIIWUQj9VAgXz/f7j8egczMGU8lHhjTmbheEZvGj3iOflCc6Dp8hMuzcAP2AjwCI"
"Pq3ewmOB5qwr/p74pkig1cQzoEHNa2iGiwIDAQABo1QwUjAOBgNVHQ8BAf8EBAMC"
"AYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUY9kBqf8QzJCzvCBUPb1GOfkS"
"Ca0wEAYJKwYBBAGCNxUBBAMCAQAwDQYJKoZIhvcNAQEMBQADggIBALuU6qG+BqzG"
"O86hcICm8U/Dv9r3k/XCm88oR8oerTeuhBxxNfFqz2hUmYjcWwYLguLZqY+jgH3I"
"VR5YCufvF+FLl1DEoh+6PWLpMImF+ib5VNHD+Dyaj+3joJu1913BcEQ/SkDkuJQ9"
"hY7Gpq2SO3lwHSdpc94pH+OZqy73mIpMuymDpHvrS1CnnC6c/yxP+80+XsF9bBGQ"
"2L4xhLIU7U+Tpi0uBIstJit2dcoEY9MsXJlBcf+RUlNFgHYdfbdXppad84/aDqed"
"z1djNeXnGVwxVWO/iH2sKa/ARNLfU/jokPNReiRSdgAStRlk+vI9W2j+vezuHP+1"
"OyY7nUAqiJhSq9LT/DAS5rqpJxB+XPQFCOAIkQT1t+oHCweBQbOCx4r8VS+XSSGV"
"CnEKihpi4bxVa9VXnyhHd7ObestJ2cAo8B27cMZ62WBQhL78l7pfzebmaJobWvPL"
"i4NQXGMwOpcsGebX2FrrjpvGeybYY5x+9eGoQXmDfIQmWCeBBAegHZCKUjwYUw8e"
"GtvKeyjIgX+cxLm6aLGFZnrwOpDaAANfkl4Zc50S+EAl4Lm81Cmp9vZOfTKjqS3z"
"o/8fr9+A4SYRYNKS+JZvsrChuJLtBa9ICCaCMN7ljXQ0yCm+RTICc2ENP4truMD1"
"fhnj9p0gY/wn0HhBJB8oSdSu29f0nP/Y";


#define ROOTCERT CCME_ROOTCERT_PEM

constexpr const char* CPSROOT_CERT_PEM =
"MIIFWDCCA0CgAwIBAgIQHJOSmEiKe55AxeRq7d4cGjANBgkqhkiG9w0BAQ0FADA9"
"MTswOQYDVQQDEzJBenVyZSBDb25maWRlbnRpYWwgQ2xvdWQgUHJvdmlzaW9uaW5n"
"IFJvb3QgQ0EgMjAyNjAeFw0yNjAzMzExOTQ2NTJaFw00MTAzMzExOTQ3MzJaMD0x"
"OzA5BgNVBAMTMkF6dXJlIENvbmZpZGVudGlhbCBDbG91ZCBQcm92aXNpb25pbmcg"
"Um9vdCBDQSAyMDI2MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAo/L5"
"KXPIF5DV5aims+EAZrf/5EdhAou5eVqAd7x07plgW8UWY8ebfD8rY9OdH+4OPHUf"
"9PLqjQ9Wjt6yg5u300s8JAlz8ceBb5eSIcVoexdsq6PMh9w0Us1cjGSn1LZe/Rdl"
"+rTq8dhknBRXP8zbnkdXFGPnQZeLJTO9J0Cy6PpNRg/7ZD6O38WIc1yoVRIZ8yLm"
"CJSmVC5NI1ZvKylPJkzMV+jV28YB//eVHUohU0HpYDn+gsUcNOSPvanFg1mns+aE"
"hSZQ55g95Wp4v2//nwQAh0NYJcb/PS4r6P023vZXbXrz+2idNkVaw9kGYzxValeH"
"3T7YAJ3wuzflwatXuz1LAg4/bwfN1kN20YP7fPlVPqv15mWDS0iI5RwgdULGT3u7"
"7tbhZSiTtKkIbxO4nmMN3DPotXC+WYxQsK0JSMqOMh9BFEAqzBNBiDatCwhq1a2u"
"j9YFSR9TIluziMRdsNWS+8MtPxc1YWmoERuE4EBA8NSxnBG4tpXLNFUx5XjaqQtC"
"HLikQJjSRnb5hpdHoWLySM5VPvi/kBaVNjQhrKIqsMuwbKci/1Yjm/EA1I5nn1u0"
"lQok0h2Cac5XTvjmHxoU6NYFcW5es7ScfvE0B0hmD0XsZZ0XXZPrsl1lCFnyd/xk"
"neWuXmetPjk3Y/CLQJnmM3x6Qnum8qUQl12XWwkCAwEAAaNUMFIwDgYDVR0PAQH/"
"BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFABAeLVKaAhxnOCYVb8o"
"ilYVsvvYMBAGCSsGAQQBgjcVAQQDAgEAMA0GCSqGSIb3DQEBDQUAA4ICAQBiTnDJ"
"mFIKHw2MaSX23ugTBj5p99HxqyFNgFEEjzNByftefxQjfM7dsOj4WHFTBB1yIUJH"
"mvP2my7lfyUwO+S/PXR7OXOgkS+u0MQG/EsyIk+LNOtXm/FPcYzWvMQX72Da+U3"
"jOYXvH0Bpvxdwj/KaFkreh7TTK3GCmnR0IrRQWEdVZN6kI0SaFYXtae8X+KCeI3Z"
"9wemuqk/QEPZbo2LXVFFpwlbLJupu3bImYeMyPnNFTPkqDdiSRKUrhEMS6l46ztJ"
"WRz8WryPhkh5puxpfuv8jnno52Q6gKCewn4sPzSfql8QeoAAII35ZPxFpCTjWPDD"
"7Nq26t22gfmQmN1Sh0JzdX/DU0/BIPXNgMnrOKPSpka2SrYy+4nndoRFtWw8Hox/"
"M2v7gVYZX7NYQD02wD/WJIymJ6QPdyMK10I6XXvZwzbcIxgfMl+OjaLr//IMCEnH"
"4+0Kl5dsc61jKO+geDxZT6S/3zNWHVRUJpt8nBij0PIXGMeBFN/3W4C98lNHcsMC"
"YzEIzwNEd/lyT38UIFTrXc+Jl2zTexj+5L1gyeEY10x5zanqr1PNS3puE0kHxSfi"
"oPYka4T+9uNfHLY+KfWDxCHLnpoxRNCpEVJ6wF5GQU1PJ6dCKCxLTgiMy2Rp9h1s"
"d3B4rQT/DECkXDwOzJRQrdgUJo/8YZ2E9OhGK3A==";

inline const std::vector<const char*>& GetTrustedRoots() {
    static const std::vector<const char*> roots = { CCME_ROOTCERT_PEM, CPSROOT_CERT_PEM };
    return roots;
}

template <typename Certificate>
class BaseX509
{
public:
    virtual ~BaseX509() = default;
    virtual Certificate LoadCertificate(const std::vector<unsigned char>& cert_buffer) = 0;
    virtual void LoadLeafCertificate(const char* cert) = 0;
    virtual void LoadIntermediateCertificate(const char* cert) = 0;
    virtual bool VerifyCertChain(const std::string& expectedSubjectSuffix) = 0;
    virtual bool VerifySignature(std::vector<unsigned char> const&signedData, std::vector<unsigned char> const&signature) = 0;

protected:
    virtual std::string GetSubjectName() const = 0;
    virtual std::string GetCommonName() const = 0;
    virtual bool VerifySubjectSuffix(const std::string& expectedSuffix) const = 0;
};
