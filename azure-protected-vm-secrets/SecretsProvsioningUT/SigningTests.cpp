// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "gtest/gtest.h"
#ifdef PLATFORM_UNIX
#include "Linux/OsslX509.h"
#else
#include "Windows/WincryptX509.h"
#include "BcryptError.h"
#endif // !PLATFORM_UNIX
#include "JsonWebToken.h"

constexpr const char* JWT = \
"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Imh0dHBzOi8vY3ZtcHMt" \
"dGVzdGFtZS1kcHMtY2RtLnZhdWx0LmF6dXJlLm5ldC9rZXlzL2Nwc3NlY3JldHNw" \
"cm92aXNpb25pbmd0ZXN0LzhjN2IxOTlkYWU5NzQyNTI4YmFkN2MxY2IxMjg0ZDFm" \
"IiwieC1hei1jdm0tcHVycG9zZSI6InNlY3JldHMtcHJvdmlzaW9uaW5nIiwieDVj" \
"IjpbIk1JSUlOakNDQng2Z0F3SUJBZ0lRZG5Cd0w4ZmJmZURSTDRxMXBwY05JakFO" \
"QmdrcWhraUc5dzBCQVFzRkFEQTJNVFF3TWdZRFZRUURFeXREUTAxRklFY3hJRlJN" \
"VXlCU1UwRWdNakEwT0NCVFNFRXlOVFlnTWpBME9TQkZWVEpESUVOQklEQXhNQjRY" \
"RFRJMU1EY3lPREUzTVRneU0xb1hEVEkyTURFeU9ESXpNVGd5TTFvd1FERStNRHdH" \
"QTFVRUF4TTFZMlZ1ZEhKaGJIVnpaWFZoY0M1VFpXTjFjbVZEVUZOUWNtOTJhWE5w" \
"YjI1cGJtY3VZMnh2ZFdSaGNIQXRkR1Z6ZEM1dVpYUXdnZ0VpTUEwR0NTcUdTSWIz" \
"RFFFQkFRVUFBNElCRHdBd2dnRUtBb0lCQVFEZ1hiOFJlWEZvczVuT1ZQNjVUWlJD" \
"a0xhc2g3bmx0N0M2SDBKRFVoSkNEN05SQkUxUDMzUXU2OVZEMEdTUFZRV2xOZFAv" \
"Z2ZoRG8yb2h3NmExTGo5dm9FdkFLNlRrK3N0bE1TdlJUWjhnemlaTXB5MW1PUVJF" \
"bE5kUWk2dnRGc2d3U3dJd1R0RnhDNFlxbTBXNGljVDZUNFpNOHo1N0VoUGZaWFF2" \
"NUg3TituUW9rUzdsQldRd1pBNFA0YStWbmtFQVFENzA0S0VSNitNeXNXeEZJY0pU" \
"a1dxTnBJMkdPOEtUa0ZFdlJEYXlrWmlrb0o1TkVLaXNtYVFTSXdmUXdWUjhqVHAr" \
"S0ZKV3B5K2FhUWpISFV6eG43NFZKcGdFMG8vOUk1aVc1M20wT3RhVU4rQ0Y0TDRO" \
"QXk4dHJOZzZkTzkzMjFoRWZnQnArNjdIRUNQVUMxVTVBZ01CQUFHamdnVTBNSUlG" \
"TURDQm5RWURWUjBnQklHVk1JR1NNQXdHQ2lzR0FRUUJnamQ3QVFFd1pnWUtLd1lC" \
"QkFHQ04zc0NBakJZTUZZR0NDc0dBUVVGQndJQ01Fb2VTQUF6QURNQVpRQXdBREVB" \
"T1FBeUFERUFMUUEwQUdRQU5nQTBBQzBBTkFCbUFEZ0FZd0F0QUdFQU1BQTFBRFVB" \
"TFFBMUFHSUFaQUJoQUdZQVpnQmtBRFVBWlFBekFETUFaREFNQmdvckJnRUVBWUkz" \
"ZXdNQ01Bd0dDaXNHQVFRQmdqZDdCQUl3UUFZRFZSMFJCRGt3TjRJMVkyVnVkSEpo" \
"YkhWelpYVmhjQzVUWldOMWNtVkRVRk5RY205MmFYTnBiMjVwYm1jdVkyeHZkV1Jo" \
"Y0hBdGRHVnpkQzV1WlhRd0RBWURWUjBUQVFIL0JBSXdBREFkQmdOVkhTVUVGakFV" \
"QmdnckJnRUZCUWNEQVFZSUt3WUJCUVVIQXdJd0RnWURWUjBQQVFIL0JBUURBZ1dn" \
"TUIwR0ExVWREZ1FXQkJSaENFMzd0Z0w4YngydEtGVzJwWjI4allpL1JEQWZCZ05W" \
"SFNNRUdEQVdnQlRQVVFHcTZVTXNaSFliU3ZDcXdQS1MrRS9EdXpDQ0FlSUdBMVVk" \
"SHdTQ0Fka3dnZ0hWTUhXZ2M2QnhobTlvZEhSd09pOHZjSEpwYldGeWVTMWpaRzR1" \
"Y0d0cExtTnZjbVV1ZDJsdVpHOTNjeTV1WlhRdlpXRnpkSFZ6TW1WMVlYQXZZM0pz" \
"Y3k5alkyMWxaV0Z6ZEhWek1tVjFZWEJ3YTJrdlkyTnRaV1ZoYzNSMWN6SmxkV0Z3" \
"YVdOaE1ERXZNalF2WTNWeWNtVnVkQzVqY213d2Q2QjFvSE9HY1doMGRIQTZMeTl6" \
"WldOdmJtUmhjbmt0WTJSdUxuQnJhUzVqYjNKbExuZHBibVJ2ZDNNdWJtVjBMMlZo" \
"YzNSMWN6SmxkV0Z3TDJOeWJITXZZMk50WldWaGMzUjFjekpsZFdGd2NHdHBMMk5q" \
"YldWbFlYTjBkWE15WlhWaGNHbGpZVEF4THpJMEwyTjFjbkpsYm5RdVkzSnNNR2Fn" \
"WktCaWhtQm9kSFJ3T2k4dlkzSnNMbTFwWTNKdmMyOW1kQzVqYjIwdlpXRnpkSFZ6" \
"TW1WMVlYQXZZM0pzY3k5alkyMWxaV0Z6ZEhWek1tVjFZWEJ3YTJrdlkyTnRaV1Zo" \
"YzNSMWN6SmxkV0Z3YVdOaE1ERXZNalF2WTNWeWNtVnVkQzVqY213d2U2QjVvSGVH" \
"ZFdoMGRIQTZMeTlqWTIxbFpXRnpkSFZ6TW1WMVlYQndhMmt1WldGemRIVnpNbVYx" \
"WVhBdWNHdHBMbU52Y21VdWQybHVaRzkzY3k1dVpYUXZZMlZ5ZEdsbWFXTmhkR1ZC" \
"ZFhSb2IzSnBkR2xsY3k5alkyMWxaV0Z6ZEhWek1tVjFZWEJwWTJFd01TOHlOQzlq" \
"ZFhKeVpXNTBMbU55YkRDQ0FlY0dDQ3NHQVFVRkJ3RUJCSUlCMlRDQ0FkVXdlQVlJ" \
"S3dZQkJRVUhNQUtHYkdoMGRIQTZMeTl3Y21sdFlYSjVMV05rYmk1d2Eya3VZMjl5" \
"WlM1M2FXNWtiM2R6TG01bGRDOWxZWE4wZFhNeVpYVmhjQzlqWVdObGNuUnpMMk5q" \
"YldWbFlYTjBkWE15WlhWaGNIQnJhUzlqWTIxbFpXRnpkSFZ6TW1WMVlYQnBZMkV3" \
"TVM5alpYSjBMbU5sY2pCNkJnZ3JCZ0VGQlFjd0FvWnVhSFIwY0RvdkwzTmxZMjl1" \
"WkdGeWVTMWpaRzR1Y0d0cExtTnZjbVV1ZDJsdVpHOTNjeTV1WlhRdlpXRnpkSFZ6" \
"TW1WMVlYQXZZMkZqWlhKMGN5OWpZMjFsWldGemRIVnpNbVYxWVhCd2Eya3ZZMk50" \
"WldWaGMzUjFjekpsZFdGd2FXTmhNREV2WTJWeWRDNWpaWEl3YVFZSUt3WUJCUVVI" \
"TUFLR1hXaDBkSEE2THk5amNtd3ViV2xqY205emIyWjBMbU52YlM5bFlYTjBkWE15" \
"WlhWaGNDOWpZV05sY25SekwyTmpiV1ZsWVhOMGRYTXlaWFZoY0hCcmFTOWpZMjFs" \
"WldGemRIVnpNbVYxWVhCcFkyRXdNUzlqWlhKMExtTmxjakJ5QmdnckJnRUZCUWN3" \
"QW9abWFIUjBjRG92TDJOamJXVmxZWE4wZFhNeVpYVmhjSEJyYVM1bFlYTjBkWE15" \
"WlhWaGNDNXdhMmt1WTI5eVpTNTNhVzVrYjNkekxtNWxkQzlqWlhKMGFXWnBZMkYw" \
"WlVGMWRHaHZjbWwwYVdWekwyTmpiV1ZsWVhOMGRYTXlaWFZoY0dsallUQXhNQTBH" \
"Q1NxR1NJYjNEUUVCQ3dVQUE0SUJBUUNPYnFFcXYyQ2lKQlF2YTlhczZlNGdNR1VF" \
"dkdmM2tBTkdnU3NvKzFGSzRxUkNUZGNuUUhDZ3hUcGx2OWpNZ2pRSE5PaEwzK3ZR" \
"aUFpNkdjUi9KRCtMZHREUXlMK3JvSEVrcGkzeUl6WWRySm1UU3E2VnFXMHNiWm9v" \
"TWwwK3FuZER6U2tWaWZ4bWVBM3luVlNySEFPZmhJREZaeWhMNStYWVFDTEliZ3Nj" \
"d3BVM1VYR0pQMEc5NElOcmZUaVhISGdOVGc1WU8rdFdZSE1SdUNaNTRlNE02a0kz" \
"cE43M09ZM2RlUGt4QWxENUc1dXNqTFlkUFNyU0c4bHliRXRNQTZ0dXM4RDVUdkxo" \
"R0U0bUNjYjE4OE4wc3ZFWUlDZzdTcThxRWJHM3V4U0VTcUhBZEErRC9XNUhDakd0" \
"cmJNRkx1d0pkcVZIb0p6S1ZVS3lmWTVJK0M3bSIsIk1JSUZoekNDQTIrZ0F3SUJB" \
"Z0lUTXdBQUFBVThhL2I3NzYxWnh3QUFBQUFBQlRBTkJna3Foa2lHOXcwQkFRd0ZB" \
"REJUTVFzd0NRWURWUVFHRXdKVlV6RWVNQndHQTFVRUNoTVZUV2xqY205emIyWjBJ" \
"RU52Y25CdmNtRjBhVzl1TVNRd0lnWURWUVFERXh0RGIyMXRaWEpqYVdGc0lFTnNi" \
"M1ZrSUZKdmIzUWdRMEVnVWpFd0hoY05NalF4TVRFNU1qTTBOVEUxV2hjTk16QXhN" \
"VEU1TWpNME5URTFXakEyTVRRd01nWURWUVFERXl0RFEwMUZJRWN4SUZSTVV5QlNV" \
"MEVnTWpBME9DQlRTRUV5TlRZZ01qQTBPU0JGVlRKRElFTkJJREF4TUlJQklqQU5C" \
"Z2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF0TFpaKzMzNHZnRUxh" \
"R0NHdEpQQWU3OWlnTVRvVGRuSzdHcUFRQzA3Y3hkV1Bpc0dURlVFRmlvek9WeGs2" \
"ZkV3aWN4ODlrNG9NUkJ0dThwSS9YVS9YVCtCTEd5TERkK2o3UzhkT3ZOOWxBMnlv" \
"UWo1ZGFlQ2VWM05LQUtqS2tuUFFLOElFb3ZzSmF5SjljZktVckVUWUUxUk9ybVJw" \
"WkE0RUxqZjBSOG5HVGRmMXEyU3h4c245Wmd6NUNMNWI2dHZzS25UZ1YrMUl6dWhj" \
"V2xYY2JjWlhYSUgyOUpDRGIzdTl3ZTRFZkI3UHVVOG9rZ0FHZy9jWXV0QjJQa2tm" \
"N1lrQi9LWTFFcmJuM2xydzU0MVgzZ0h2T1JueDFEZkF5TzRRbW5pWDZXT25FMThO" \
"cHpld1huQVM3dFhQNXNlUWVzTmFpWklhdy91MGpHcjdRQWZqUnBUeXdJREFRQUJv" \
"NElCYnpDQ0FXc3dEZ1lEVlIwUEFRSC9CQVFEQWdHR01Ed0dBMVVkSlFRMU1ETUdD" \
"Q3NHQVFVRkJ3TUNCZ2dyQmdFRkJRY0RBUVlLS3dZQkJBR0NOeFFDQVFZS0t3WUJC" \
"QUdDTndvRERBWUZaNEVGQ0FNd0VnWURWUjBUQVFIL0JBZ3dCZ0VCL3dJQkFEQWRC" \
"Z05WSFE0RUZnUVV6MUVCcXVsRExHUjJHMHJ3cXNEeWt2aFB3N3N3SHdZRFZSMGpC" \
"Qmd3Rm9BVVk5a0JxZjhRekpDenZDQlVQYjFHT2ZrU0NhMHdYQVlEVlIwZkJGVXdV" \
"ekJSb0UrZ1RZWkxhSFIwY0RvdkwyTnliQzV0YVdOeWIzTnZablF1WTI5dEwzQnJh" \
"Vzl3Y3k5amNtd3ZRMjl0YldWeVkybGhiQ1V5TUVOc2IzVmtKVEl3VW05dmRDVXlN" \
"RU5CSlRJd1VqRXVZM0pzTUdrR0NDc0dBUVVGQndFQkJGMHdXekJaQmdnckJnRUZC" \
"UWN3QW9aTmFIUjBjRG92TDJOeWJDNXRhV055YjNOdlpuUXVZMjl0TDNCcmFXOXdj" \
"eTlqWlhKMGN5OURiMjF0WlhKamFXRnNKVEl3UTJ4dmRXUWxNakJTYjI5MEpUSXdR" \
"MEVsTWpCU01TNWpjblF3RFFZSktvWklodmNOQVFFTUJRQURnZ0lCQUlFRXBBUis0" \
"d2ZPaFM5VmEyblNqL0p1UHhqSFdSQVpoTFV1d1BRQ0tvZTNlbjA4RHloUFB6SmZR" \
"NDZRcEFEM1dqVGhqanpISWtxZHBrWnRDSVplQXhjU0ExNTVCU01QRnQ5VXlWbXJu" \
"bEk0ak5tbkxVT1R1dTNYL1RENFR0ZTcwSklmVmxuQXdtUEt3TEgyZW05Y05RMWVC" \
"aWJFUm54Q29meHNCV2RjMGtoTlFRVEFVRkdkbUZjVUVYalN5QzhSUXdjY050eURn" \
"L0tRQUlmUkROcUoya0tjM0phU0QrQnhhZEdDTGRIWkE3V2c5WDVuTzJPaTF0Qm1l" \
"OTZCRWpqa0MrZ0JOS3owQWs3UUhHZWpjVGkvUCtzMHVGanhHK0lKWHEralRrd0Nh" \
"MkJoR05jaDRsMzR6bWs0UXptVjZKaGYzcGV0d001MUdVM1p0NVZFRmJpaVk5aGFV" \
"WlpmNm0vYmNMNTRrdUNGa1J0eGpscmdWdEJQbzV1UDRnTSs5RU5iK1pDVkEydVZm" \
"Mjhnd0w5L01UVy96dnQ0YkppYTlBWndqbUowTEhYS09qL3plY3FVSThMNEE5NFIw" \
"aW1hS29JYVRxd21UdEc0QkZaMlA1Z21DTFRZMWFXazNEQVFFbkNpczVmZldQbEwv" \
"M3ZSRlpybTM1bEJGcDJONCthemRuTTBvZ2ZQdXozekxJaDN3UWpQUkw0L25UWUhG" \
"RUVXRkFnbWpxWk5VN2hKeUVQUVdpOFBkY2UrVkJjK0VNT0RNVWszeXJIRVNEVy95" \
"RmludnVNUXdmTFZJT2xBMVpFTGV0dDFqUGh3blY4eDVKaldwY0R0QnBmM0h2THVi" \
"dVhTSGYzdkJrK2lUUG1lMHUyZnlNZDh2VDJ3ZjJXdzRTNlhOYmRid1h2WFp0K0tX" \
"a0tyIl0sIng1dCI6ImI0R1NYOE9pYjRiOGRnUWVvemhKVE1KSk1SSSJ9.eyJlbmN" \
"yeXB0ZWRTZWNyZXQiOiIvbEFOU1lxQmFkTTY3cjhsb2NXai9IUzJWaGlvUjVDa2d" \
"4dExTT0gwVGgxYyIsImVwaGVtZXJhbEVjZGhQdWJsaWNLZXkiOiJNRmt3RXdZSEt" \
"vWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUU0YnF3STdlUmlSYkp1NTJ4OXhVWFF" \
"0RWVyZ3UyOHFsSnZPajJPQ0dWcENJRWs4NzhkUVl5MFltZ1R0U3luNk85QS9tRWx" \
"IQXJsWlNlbXYwSllzNHRjUT09IiwiZW5jcnlwdGVkR3Vlc3RFY2RoUHJpdmF0ZUt" \
"leSI6InVFS2pmbHJIMG1sN2dDd2hLNzZmZm9tMVJwcm90em1sY2RpNk5nU0lESUp" \
"2U2g4c01nRU1ENDFCR2tjMHVMTXM4cFQvVWZRbjlSOXNhcnhEdVN0WFhxaXhXNkx" \
"UYjloeUdZL2tMMitqK1hzUCs4QzRVZjdnc05oQmt4eUhBZ1BUTlA3Y2Q3ZFo3SWQ" \
"rcHBxS2Y2aWhOVnh3M2RPRHhUTEl0UThvZ0NwRmM2dzR0RExpazdWcTlQUTA4Y0t" \
"BQSt0VXppSFRkajQxWlFEdUZnPT0iLCJ3cmFwcGVkQWVzVHJhbnNwb3J0S2V5Ijo" \
"iSGRHelNwS0Z0bGduRUk4ZFlpVGwyLzVRTDV1eEIrRHhYOHRmZS9VT0NRNzF1bEt" \
"WbGZ1M2MwdHF6ZGF1Y21sbEpLYU9nREtlbms4akNSRFRyQ1RUaUh6YVJNU3NvNzd" \
"ZOWlXYVBxVk1KSnYyUTVOei9hT25IWFBNNU1nN1NOUThpTnRocFBlZDZ4OTdGVlp" \
"CclBTa0dnRnRJNGVyTDQyRFY4VDB6Rzg2UGxISUlVc1l3OXVBbzdaa1FVQXBpVFV" \
"6WUZmdGVGY2dqWDlEY2h4bElPRElQZk5qQVlaTDRPREtqSGJMbWZiVlZpRW1MbXR" \
"jUDVaRzdKTVBPcnI5SUlJaFZkS3I1QnZDZklOUFNhMEp0d3NIMUtEVFJmRzBucGw" \
"1U3RrZEppQm1LUU1TZUx6M0g0Z2lHcnNXcitBYnJqNXg3US9ycGljSVk2Y3U3ZXB" \
"rb2Znc09RPT0iLCJkYXRhTm9uY2UiOiJZcnBlOGc5QzVLTXVlS1JoIiwia2V5Tm9" \
"uY2UiOiJwSG1iSEw4Tm9Nd0FwWXZOIiwic2FsdCI6Imk3VWQ4dk5zM1FrT2F2Vm5" \
"mamVrOGtGbVhoRDFrNmVrekJIck9uVzhqVUE9IiwiZXhwIjoxNzUzODEwNDk0LCJ" \
"pYXQiOjE3NTM4MDg2OTR9.Ceo6Zvn2QEdILkXtWGI4KkYn0C3mf7Xg0gA7jw47YI" \
"jIoTtHn6xkkwVvxR4YuJiRHMEJkLfhrSGDh6YUdeyfCwjfQ9Q8cZdF7c_SshPild" \
"xCOpViNuLn4uHQks-EItdyqNjk2AbZEqk1FhdvwMjtzmlvHdyZTx-CmXGKskTLbD" \
"Dqp3CvQp946rPTm5o8F6CplFlVM1kTcOXeV-rDvafUtNZx4FGnDaADZxfl_tfRnh" \
"ugxAcc8HQbNdXHSRrxjqUCQoDiHx7Zv-uycprQyzRzgfUKCwIvjmp56gwSbuVXGg" \
"igwCJ0Q8RGB_ZjPAAXxoaT8lKmLrDt0m3T8CS3uyqTaA";


#define X509_TEST_SUBJECT_NAME_SUFFIX ".SecureCPSProvisioning.cloudapp-test.net"

TEST(X509Tests, DISABLED_LoadCertificate) {
    // Test that the LoadCertificate function loads the certificate correctly
    std::unique_ptr<JsonWebToken> jwt = std::make_unique<JsonWebToken>();
    jwt->ParseToken(JWT, true, X509_TEST_SUBJECT_NAME_SUFFIX);

    #ifdef PLATFORM_UNIX
    std::unique_ptr<OsslX509> x509 = std::make_unique<OsslX509>();
#else
	std::unique_ptr<WincryptX509> x509 = std::make_unique<WincryptX509>();
#endif // !PLATFORM_UNIX

	auto chain = jwt->getHeader()["x5c"];
    if (!chain.is_array() || chain.empty()) {
        throw std::runtime_error("x5c header missing or malformed.");
    }
    // Load intermediates
    for (size_t i = 1; i < chain.size(); ++i) {
        x509->LoadIntermediateCertificate(chain[i].get<std::string>().c_str());
    }
    x509->LoadLeafCertificate(chain[0].get<std::string>().c_str());

    bool result = x509->VerifyCertChain(X509_TEST_SUBJECT_NAME_SUFFIX);
    EXPECT_TRUE(result);
}

TEST(X509Tests, DISABLED_ValidateSignature) {
    // Test that the VerifySignature function correctly verifies a signature
    std::unique_ptr<JsonWebToken> jwt = std::make_unique<JsonWebToken>();
    jwt->ParseToken(JWT, true, X509_TEST_SUBJECT_NAME_SUFFIX);


    std::string str_jwt = std::string(JWT);
    std::string signed_prtion = str_jwt.substr(0, str_jwt.find_last_of('.')); 

#ifdef PLATFORM_UNIX
    std::unique_ptr<OsslX509> x509 = std::make_unique<OsslX509>();
#else
	std::unique_ptr<WincryptX509> x509 = std::make_unique<WincryptX509>();
#endif // !PLATFORM_UNIX
    auto chain = jwt->getHeader()["x5c"];
    if (!chain.is_array() || chain.empty()) {
        throw std::runtime_error("x5c header missing or malformed.");
    }
    // Load intermediates
    for (size_t i = 1; i < chain.size(); ++i) {
        x509->LoadIntermediateCertificate(chain[i].get<std::string>().c_str());
    }
    x509->LoadLeafCertificate(chain[0].get<std::string>().c_str());

    bool result = x509->VerifyCertChain(X509_TEST_SUBJECT_NAME_SUFFIX);
    EXPECT_TRUE(result);

    std::vector<unsigned char> signed_data(signed_prtion.begin(), signed_prtion.end());
    result = x509->VerifySignature(signed_data, jwt->getSignature());
    EXPECT_TRUE(result);
}

TEST(X509Tests, DISABLED_FailValidateSignature) {
    // Test that the VerifySignature function handles an invalid signature properly
    std::unique_ptr<JsonWebToken> jwt = std::make_unique<JsonWebToken>();
    jwt->ParseToken(JWT, false);

    // Modify jwt
    jwt->addClaim("dataNonce", encoders::base64_encode(std::vector<unsigned char>(32, 0)));

    std::string str_jwt = jwt->CreateToken();
    std::string signed_prtion = str_jwt.substr(0, str_jwt.find_last_of('.'));

#ifdef PLATFORM_UNIX
    std::unique_ptr<OsslX509> x509 = std::make_unique<OsslX509>();
#else
	std::unique_ptr<WincryptX509> x509 = std::make_unique<WincryptX509>();
#endif // !PLATFORM_UNIX
    auto chain = jwt->getHeader()["x5c"];
    if (!chain.is_array() || chain.empty()) {
        throw std::runtime_error("x5c header missing or malformed.");
    }
    // Load intermediates
    for (size_t i = 1; i < chain.size(); ++i) {
        x509->LoadIntermediateCertificate(chain[i].get<std::string>().c_str());
    }
    x509->LoadLeafCertificate(chain[0].get<std::string>().c_str());
    bool result = x509->VerifyCertChain(X509_TEST_SUBJECT_NAME_SUFFIX);
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
TEST(X509Tests, DISABLED_CertGen) {
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
	EXPECT_TRUE(certChain->VerifyCertChain(X509_SUBJECT_NAME_SUFFIX));
    EXPECT_TRUE(certChain->VerifySignature(testData, signature));
    EXPECT_FALSE(certChain->VerifySignature(badData, signature));
}
#endif // PLATFORM_UNIX
