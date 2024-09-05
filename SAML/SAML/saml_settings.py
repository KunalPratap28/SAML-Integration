SAML_SETTINGS = {
    'strict': True,
    'debug': False,
    "sp": {
        "entityId": "SAML",
        "assertionConsumerService": {
            "url": "http://127.0.0.1:8000/saml/acs/",
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        },
        "singleLogoutService": {
            "url": "http://127.0.0.1:8000/saml/logout",
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        },
        "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:khyati.a@consultadd.com",
        "x509cert": "",
        "privateKey": ""
    },
    "idp": {
        "entityId": "https://app.onelogin.com/saml/metadata/6856c8d6-2c03-4b2b-a8e4-05132d4ee603",
        "singleSignOnService": {
            "url": "https://user-details.onelogin.com/trust/saml2/http-post/sso/6856c8d6-2c03-4b2b-a8e4-05132d4ee603",
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        },
        "singleLogoutService": {
            "url": "https://user-details.onelogin.com/trust/saml2/http-redirect/slo/3482908",
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        },
        "x509cert": "MIID5TCCAs2gAwIBAgIUTWYt6eSUIcQYegqEqkD4KHxpnmUwDQYJKoZIhvcNAQEFBQAwSDETMBEGA1UECgwKQ29uc3VsdGFkZDEVMBMGA1UECwwMT25lTG9naW4gSWRQMRowGAYDVQQDDBFPbmVMb2dpbiBBY2NvdW50IDAeFw0yNDA5MDQxNDM1MThaFw0yOTA5MDQxNDM1MThaMEgxEzARBgNVBAoMCkNvbnN1bHRhZGQxFTATBgNVBAsMDE9uZUxvZ2luIElkUDEaMBgGA1UEAwwRT25lTG9naW4gQWNjb3VudCAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCl638bZqGl3f75hlu2AmfC/EKnG6aAq6hPzbdQM0MynbaiNn4Qg4gWb2d3UvEd/mGZM8pQa9uMEr8MmSc/8c6owogD+nfAqUfVXwbveARevi9d0mltmiOaQcHu93CjXcvI4KVz1DyF3P7y6Q4KyXBZTpl6KWtacDax+rDnYPoV2HADthaAyR4NVWqrDrq/BS4xvi1xSdWm67lOp9LHv2eBCDdm7czSsdjU5mV5zY9iFegcw0ePSKZDMpNS8hwg/W9VWJhZFyo8cTmQFD2yi66C/Sua1FFVigVyxhMZm7P5QYgD+V/G0gaKAH1/UXBUbtu++Oo5TBgYI+wL9ulnjg7PAgMBAAGjgcYwgcMwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQU04sTZ83dHI/wfbSG9YoOKy1kPMowgYMGA1UdIwR8MHqAFNOLE2fN3RyP8H20hvWKDistZDzKoUykSjBIMRMwEQYDVQQKDApDb25zdWx0YWRkMRUwEwYDVQQLDAxPbmVMb2dpbiBJZFAxGjAYBgNVBAMMEU9uZUxvZ2luIEFjY291bnQgghRNZi3p5JQhxBh6CoSqQPgofGmeZTAOBgNVHQ8BAf8EBAMCB4AwDQYJKoZIhvcNAQEFBQADggEBAHMxNfheJCUIbrNaEnHY6z1VAd3RCe8gm2mLyuC0oJDxj2I6oz8HfADNcxBGWS383hRp/z4NE0JfHiHVjt4Ao+6/a/p1W3sfwjXurdIN3DtYg/8TxxYULl5Dg4uvqf0XxI6zzi5j4ZgIrNBm/SL8hkzoEdeaXkfdZltZJwfWuLDZitIWjJc4bOPrsULe51NpZgmGLLqDUFoZdW79f1QojsYmK1sPfogO2+jajQ28/YsSSgcluD2pyrOSLyPg6pDX7bsby1Askn3sAnlEeL+wQb/n5WcyQB0LLcPDItijX7/7AJalQYeVqyPs3B7TVaWK90J+qWm0LvpJe9rEiQZTybY=",
    },
}