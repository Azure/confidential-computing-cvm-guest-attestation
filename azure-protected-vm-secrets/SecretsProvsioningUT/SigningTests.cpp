#include "gtest/gtest.h"
#ifdef PLATFORM_UNIX
#include "Linux/OsslX509.h"
#else
#include "Windows/WincryptX509.h"
#include "BcryptError.h"
#endif // !PLATFORM_UNIX
#include "JsonWebToken.h"

#define JWT \
"eyJhbGciOiJSUzI1NiIsImtpZCI6IkRDMjc3NTMxQzgyQTJDNTRCQUE2MURGRTk4" \
"RTMxRjVBN0UyOUFFN0MiLCJ4NXQiOiIzQ2QxTWNncUxGUzZwaDMtbU9NZlduNHBy" \
"bnciLCJ0eXAiOiJKV1QiLCJ4NWMiOiJNSUlIZ3pDQ0JtdWdBd0lCQWdJVEhnVFFK" \
"aVQvdmc1V2hBaGtVZ0FBQk5BbUpEQU5CZ2txaGtpRzl3MEJBUXNGQURCRU1STXdF" \
"UVlLQ1pJbWlaUHlMR1FCR1JZRFIwSk1NUk13RVFZS0NaSW1pWlB5TEdRQkdSWURR" \
"VTFGTVJnd0ZnWURWUVFERXc5QlRVVWdTVzVtY21FZ1EwRWdNRFl3SGhjTk1qUXdO" \
"akkyTVRnME9UVXlXaGNOTWpVd05qSXhNVGcwT1RVeVdqQThNVG93T0FZRFZRUURF" \
"ekZsWVhOMGRYTXVZM1p0Y0hKdmRtbHphVzl1YVc1bmMyVnlkbWxqWlM1amIzSmxM" \
"bUY2ZFhKbExYUmxjM1F1Ym1WME1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NB" \
"UThBTUlJQkNnS0NBUUVBNkI1YnErb0pjaFZtWFFwRWxkcEMwVWdVemVqb0FvODQ1" \
"Q0ZVTUZQQTUwTVg4K3BMRTBwZkQ3TVlhQ2ZZYkQ3SUV2dkh5UVRCdHVWN0x6TWpi" \
"cW9DTkczWkNidUNhSDQ3QTVCZ0FxQjNXdVB2Tkc2NE96OEFGTkRDZlYyNVQ3K2ht" \
"OWFFMjRQVjBiVXRuTWo1WHBmQXJZLzcrWDZxVjV0djNtYlFETytwT2d4OUxIMWFq" \
"UHZCMTFsL25UUDZDNzVyUVozQkl4R0tBczZrWUxYdGZINFpwcVR0REMwcUIzVzQ1" \
"NWZVVG1ReFE4cVJtcHBVY0drNnd0MFRwRnJHT0w2QXh6MjJMRms0YkRYbUZKQXZS" \
"RFkzU1BnaVErZThlU2FtTVl3YTJibkJZQ0VxY3BNblEzMnJhQWZnVE02UzBrWlZS" \
"ZGdlZGxnMXEvN3lhdDBESEN1YTVRSURBUUFCbzRJRWREQ0NCSEF3SndZSkt3WUJC" \
"QUdDTnhVS0JCb3dHREFLQmdnckJnRUZCUWNEQVRBS0JnZ3JCZ0VGQlFjREFqQTlC" \
"Z2tyQmdFRUFZSTNGUWNFTURBdUJpWXJCZ0VFQVlJM0ZRaUdrT01OaE5XMGVJVHhp" \
"ejZGbTkwV3pwMFNnV0NDOWZZcmcvTFJJQUlCWkFJQkNqQ0NBY3NHQ0NzR0FRVUZC" \
"d0VCQklJQnZUQ0NBYmt3WXdZSUt3WUJCUVVITUFLR1YyaDBkSEE2THk5amNtd3Vi" \
"V2xqY205emIyWjBMbU52YlM5d2EybHBibVp5WVM5RFpYSjBjeTlDVERKUVMwbEpU" \
"bFJEUVRBeUxrRk5SUzVIUWt4ZlFVMUZKVEl3U1c1bWNtRWxNakJEUVNVeU1EQTJM" \
"bU55ZERCVEJnZ3JCZ0VGQlFjd0FvWkhhSFIwY0RvdkwyTnliREV1WVcxbExtZGli" \
"QzloYVdFdlFrd3lVRXRKU1U1VVEwRXdNaTVCVFVVdVIwSk1YMEZOUlNVeU1FbHVa" \
"bkpoSlRJd1EwRWxNakF3Tmk1amNuUXdVd1lJS3dZQkJRVUhNQUtHUjJoMGRIQTZM" \
"eTlqY213eUxtRnRaUzVuWW13dllXbGhMMEpNTWxCTFNVbE9WRU5CTURJdVFVMUZM" \
"a2RDVEY5QlRVVWxNakJKYm1aeVlTVXlNRU5CSlRJd01EWXVZM0owTUZNR0NDc0dB" \
"UVVGQnpBQ2hrZG9kSFJ3T2k4dlkzSnNNeTVoYldVdVoySnNMMkZwWVM5Q1RESlFT" \
"MGxKVGxSRFFUQXlMa0ZOUlM1SFFreGZRVTFGSlRJd1NXNW1jbUVsTWpCRFFTVXlN" \
"REEyTG1OeWREQlRCZ2dyQmdFRkJRY3dBb1pIYUhSMGNEb3ZMMk55YkRRdVlXMWxM" \
"bWRpYkM5aGFXRXZRa3d5VUV0SlNVNVVRMEV3TWk1QlRVVXVSMEpNWDBGTlJTVXlN" \
"RWx1Wm5KaEpUSXdRMEVsTWpBd05pNWpjblF3SFFZRFZSME9CQllFRkYyV0FJYzR1" \
"c1RkR3QvcWorZytUc2UxaGVZdE1BNEdBMVVkRHdFQi93UUVBd0lGb0RDQ0FTWUdB" \
"MVVkSHdTQ0FSMHdnZ0VaTUlJQkZhQ0NBUkdnZ2dFTmhqOW9kSFJ3T2k4dlkzSnNM" \
"bTFwWTNKdmMyOW1kQzVqYjIwdmNHdHBhVzVtY21FdlExSk1MMEZOUlNVeU1FbHVa" \
"bkpoSlRJd1EwRWxNakF3Tmk1amNteUdNV2gwZEhBNkx5OWpjbXd4TG1GdFpTNW5Z" \
"bXd2WTNKc0wwRk5SU1V5TUVsdVpuSmhKVEl3UTBFbE1qQXdOaTVqY215R01XaDBk" \
"SEE2THk5amNtd3lMbUZ0WlM1blltd3ZZM0pzTDBGTlJTVXlNRWx1Wm5KaEpUSXdR" \
"MEVsTWpBd05pNWpjbXlHTVdoMGRIQTZMeTlqY213ekxtRnRaUzVuWW13dlkzSnNM" \
"MEZOUlNVeU1FbHVabkpoSlRJd1EwRWxNakF3Tmk1amNteUdNV2gwZEhBNkx5OWpj" \
"bXcwTG1GdFpTNW5ZbXd2WTNKc0wwRk5SU1V5TUVsdVpuSmhKVEl3UTBFbE1qQXdO" \
"aTVqY213d2daMEdBMVVkSUFTQmxUQ0JrakFNQmdvckJnRUVBWUkzZXdFQk1HWUdD" \
"aXNHQVFRQmdqZDdBZ013V0RCV0JnZ3JCZ0VGQlFjQ0FqQktIa2dBTndBeUFHWUFP" \
"UUE0QURnQVlnQm1BQzBBT0FBMkFHWUFNUUF0QURRQU1RQmhBR1lBTFFBNUFERUFZ" \
"UUJpQUMwQU1nQmtBRGNBWXdCa0FEQUFNUUF4QUdRQVlnQTBBRGN3REFZS0t3WUJC" \
"QUdDTjNzREFUQU1CZ29yQmdFRUFZSTNld1FCTUI4R0ExVWRJd1FZTUJhQUZQRkdh" \
"TWJ4dy9BckxYMkxhdUd5K2I0MS9ORkJNQjBHQTFVZEpRUVdNQlFHQ0NzR0FRVUZC" \
"d01CQmdnckJnRUZCUWNEQWpBTkJna3Foa2lHOXcwQkFRc0ZBQU9DQVFFQXhHWThY" \
"cmkrR0FQZGk1QVpBYVpvdGNlbEJqcnFzZ2VZSlhDb1RqRDVVWVdiaDRxY3hDVXI1" \
"ZCtRQk5pMkJNdWZpWHFHeldkdndlVWZSUWhQQko0TUFSL204T3pTdGR0LzhXQTdL" \
"YXUzbW4ySUZldGFraitJUGQvNmFyTW5ueWVOUXB1UmNSYThrT1BjOXVvRVEzTmk4" \
"ZUNnY2c2YXNvbEp2NFlRaE4yNGpyam9yTXBpRE5KUFZWTm4zQU1ITHFkUk9CMHBY" \
"NWpYd1RVR0V4eTdreTBEaU5IL2FBSUtsTTVoVGp1UmIwTGNSSXJUNXhJeWowRVhj" \
"d2VRSWhXbkdqcCtqazBXT3dZMmYyZjhEdUlaT1pLS0hkKytSNWRpU29EcXAzdnpZ" \
"VlhHU01XY2dVNzFuWDRCbTJPSTdOdjByZUNmVWc3aDFuTG5tbXcxSUFnalpTUzBL" \
"Zz09In0.eyJlbmNyeXB0ZWRTZWNyZXQiOiJnSnpFRVRQZEZoTHFWNzlHS3IycVVB" \
"bis3ajZHT0V2aWZHSmVpZjVjNW5zc1BHWWRLREZzYktaZDVRc1NaNjA9IiwiZXBo" \
"ZW1lcmFsRWNkaFB1YmxpY0tleSI6Ik1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpq" \
"MERBUWNEUWdBRVh2QzhRbEhiOEtETEJsWG84ZmJRR29Ra1lBcHdCeVhqbkRicita" \
"aVUzTjJudTZoMnJYOEl4MmZpVWVjbU05QXBObElwRzlxbHZobVE5aU5nVFlmMFpR" \
"PT0iLCJlbmNyeXB0ZWRHdWVzdEVjZGhQcml2YXRlS2V5IjoiWkFvVnIrb2JiazNZ" \
"a0RrQ1BTVFZoMjYwVEFnRjk4dDk0K1RyMHpJUkp0Tk1UczJ6SnZKMTZhVmN6RFB2" \
"Sy80N2lGWU9pM014ME9oaUJabzFZcEVpcmk4aER2cHVScVNIK2VaZXU5OUVUTXVB" \
"emlQeU55di9FM2hJcnFOR25kSnhOK1JIZStqeHdJcVNObTBqaUhETU9NeEVqeUpo" \
"amJaZVNJZ0c1VTBKWmdrWFpZQlFOWitCbjNiMTIwL2YwK2lGQ2tOWTlPbk1WS0ZY" \
"MGc9PSIsIndyYXBwZWRBZXNUcmFuc3BvcnRLZXkiOiJCQy9WRGxVRG5pZGpzLzdE" \
"dEt4UEdWNWNndDNjeHR5TlBvcTZvMVFtcTl5d01RS01lOHRSdnZYMWd0d1AzVEZP" \
"bm15VC80aXh1TTFEcEczN0lyODRiMlQ3Zmw0cCsyTFUreFp3WVp5ditDa3JKV1Zk" \
"OFNlVTdLT2h1cEdxVVRlV0Vtb3QxRERtcWhtczRJVktwbCtrbloyOUl2TlUzb2xm" \
"dVcvSnBqbVZsZlJUK3BNRTkySUNGNlJQS2JqMVRabGpQY3pVSEc5NDYweEltYnVM" \
"SkVkdkIrZ0t0YkpySk1iSzEyYUxZL0EvRzRrNC9KVTJBK1UvaUJkNzdsNWF0cHha" \
"ZUkxSFJLOXJZSFZlQXRVb1N6MTMxeGs0akdoZUxZL0dJQ3p4RDhYWVdKYmp0SkJt" \
"SlIydTZaelZtNk9KZ1hzNUxIQmViYnNQRERJaVV4dTlKUmJWWXc9PSIsImRhdGFO" \
"b25jZSI6IkJTb2w2NjQ3YVo0VGVkcXciLCJrZXlOb25jZSI6ImVrZUhObFg0Ylhv" \
"RGxOeW4iLCJzYWx0IjoiVG56ZzQxYTVOUURUYjRLMHM5dDlCMEw3VFJnM0daRERh" \
"QVhGS3EycnFYaz0iLCJuYmYiOjE3MjA3MzUwMDUsImV4cCI6MTcyMDczNjgwNSwi" \
"aWF0IjoxNzIwNzM1MDA1fQ.R3brmL-6AeDWG3FqYH7OckpMkplkucmuRFJOFT731" \
"NxSmD1g8Leldyy4tnwxoEHXF1ZEpupgDvVf3eg1uUYuWd3GzVAX7H_hl8pT7KQEF" \
"52L6iSAKrCkZvKiqXAI9dsSf6EKPPSvMao7w6Zjo9WdbS-3cl3gsxzb7v0BOX4PS" \
"Eb9BQVA7qeRqIhqXul1-7EY1WGH4dO4_TRZsc1Seb47qVg-wlkT118FN5eW5hVSE" \
"sJam_22bjLobc2vox-oBzVwp7KxVmfnShWltBqHvTZ9p4V4pzKaewdGgTv9IHKI-" \
"VwgMeGHQAOQG_EcG1A6Q24tNmdIz0pfCSWY-MIilqa-8Q"

TEST(X509Tests, LoadCertificate) {
    // Test that the LoadCertificate function loads the certificate correctly
    std::unique_ptr<JsonWebToken> jwt = std::make_unique<JsonWebToken>();
    jwt->ParseToken(JWT, true);

    std::string cert_str = jwt->getHeader()["x5c"];
    std::vector<unsigned char> cert = encoders::base64_decode(cert_str);
#ifdef PLATFORM_UNIX
    std::unique_ptr<OsslX509> x509 = std::make_unique<OsslX509>();
#else
	std::unique_ptr<WincryptX509> x509 = std::make_unique<WincryptX509>();
#endif // !PLATFORM_UNIX
    x509->LoadIntermediateCertificate(INTERCERT);
    x509->LoadLeafCertificate(cert_str.c_str());
    bool result = x509->VerifyCertChain();
    EXPECT_TRUE(result);
}

TEST(X509Tests, ValidateSignature) {
    // Test that the VerifySignature function correctly verifies a signature
    std::unique_ptr<JsonWebToken> jwt = std::make_unique<JsonWebToken>();
    jwt->ParseToken(JWT, true);

    std::string cert_str = jwt->getHeader()["x5c"];
    std::vector<unsigned char> cert = encoders::base64_decode(cert_str);

    std::string str_jwt = std::string(JWT);
    std::string signed_prtion = str_jwt.substr(0, str_jwt.find_last_of('.')); 

#ifdef PLATFORM_UNIX
    std::unique_ptr<OsslX509> x509 = std::make_unique<OsslX509>();
#else
	std::unique_ptr<WincryptX509> x509 = std::make_unique<WincryptX509>();
#endif // !PLATFORM_UNIX
    x509->LoadIntermediateCertificate(INTERCERT);
    x509->LoadLeafCertificate(cert_str.c_str());
    bool result = x509->VerifyCertChain();
    EXPECT_TRUE(result);

    std::vector<unsigned char> signed_data(signed_prtion.begin(), signed_prtion.end());
    result = x509->VerifySignature(signed_data, jwt->getSignature());
    EXPECT_TRUE(result);
}

TEST(X509Tests, FailValidateSignature) {
    // Test that the VerifySignature function handles an invalid signature properly
    std::unique_ptr<JsonWebToken> jwt = std::make_unique<JsonWebToken>();
    jwt->ParseToken(JWT, false);

    std::string cert_str = jwt->getHeader()["x5c"];
    std::vector<unsigned char> cert = encoders::base64_decode(cert_str);

    // Modify jwt
    jwt->addClaim("dataNonce", encoders::base64_encode(std::vector<unsigned char>(32, 0)));

    std::string str_jwt = jwt->CreateToken();
    std::string signed_prtion = str_jwt.substr(0, str_jwt.find_last_of('.'));

#ifdef PLATFORM_UNIX
    std::unique_ptr<OsslX509> x509 = std::make_unique<OsslX509>();
#else
	std::unique_ptr<WincryptX509> x509 = std::make_unique<WincryptX509>();
#endif // !PLATFORM_UNIX
    x509->LoadIntermediateCertificate(INTERCERT);
    x509->LoadLeafCertificate(cert_str.c_str());
    bool result = x509->VerifyCertChain();
    EXPECT_TRUE(result);

    std::vector<unsigned char> signed_data(signed_prtion.begin(), signed_prtion.end());
#ifndef PLATFORM_UNIX
    EXPECT_THROW({
            // We expect this to throw an error of invalid signature
            result = x509->VerifySignature(signed_data, jwt->getSignature());
        }, BcryptError
    );
#else
    // We expect this to return false for invalid signature
    result = x509->VerifySignature(signed_data, jwt->getSignature());
    ASSERT_FALSE(result);
#endif // !PLATFORM_UNIX
}

#ifdef PLATFORM_UNIX
TEST(X509Tests, CertGen) {
	// Test that the LoadCertificate function loads the certificate correctly
    std::unique_ptr<OsslX509> certChain;
    std::vector<unsigned char> testData = { 0x01, 0x02, 0x03, 0x04, 0x05 };
    std::vector<unsigned char> badData = { 0x05, 0x04, 0x03, 0x02, 0x01 };
    std::vector<unsigned char> signature;
    try {
        certChain = generateCertChain();
        signature = certChain->SignData(testData);
	}
	catch (std::exception& e) {
		std::cout << e.what() << std::endl;
	}
	EXPECT_TRUE(certChain->VerifyCertChain());
    EXPECT_TRUE(certChain->VerifySignature(testData, signature));
    EXPECT_FALSE(certChain->VerifySignature(badData, signature));
}
#endif // PLATFORM_UNIX