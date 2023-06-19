// This file contains ECDSA master key certificate and private key in PEM for testing purpose.
package keymanager

const (
	// The master key self-signed X509 certificate is hard coded into KeyManager
	// as Ethereum does for its public key.
	//
	// The key is used to verify the integrity of Accel's public proposing key which is
	// signed by the private master key.
	masterCert string = `
-----BEGIN CERTIFICATE-----
MIICfzCCAiagAwIBAgIJAK4zj0XFFkXXMAoGCCqGSM49BAMCMIGaMQswCQYDVQQG
EwJVUzELMAkGA1UECAwCQ0ExEjAQBgNVBAcMCVN1bm55dmFsZTEaMBgGA1UECgwR
VGh1bmRlclRva2VuIEluYy4xETAPBgNVBAsMCENvcmUtRW5nMRcwFQYDVQQDDA5U
ZXN0aW5nVGVzdG5ldDEiMCAGCSqGSIb3DQEJARYTcWFAdGh1bmRlcnRva2VuLmNv
bTAeFw0xODA2MTIyMjQxNTRaFw0yODA2MDkyMjQxNTRaMIGaMQswCQYDVQQGEwJV
UzELMAkGA1UECAwCQ0ExEjAQBgNVBAcMCVN1bm55dmFsZTEaMBgGA1UECgwRVGh1
bmRlclRva2VuIEluYy4xETAPBgNVBAsMCENvcmUtRW5nMRcwFQYDVQQDDA5UZXN0
aW5nVGVzdG5ldDEiMCAGCSqGSIb3DQEJARYTcWFAdGh1bmRlcnRva2VuLmNvbTBZ
MBMGByqGSM49AgEGCCqGSM49AwEHA0IABAeDpmg8iMt18fULOphpJF/33mwf5Tq0
QLZxxKAy+RLjPb/In7FI4H8AYMxmzTnpneJnBdK6/Ze9jhhocbsYQByjUzBRMB0G
A1UdDgQWBBQ6/5a6HeVtryA4HlJf7I2HndcJuDAfBgNVHSMEGDAWgBQ6/5a6HeVt
ryA4HlJf7I2HndcJuDAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0cAMEQC
IBof2Oe2/XlB7crmwMuj4Xi5B1qVDot95mCGwFcAvX8zAiBXTakw6xpOllQWnnCY
AFLxoE0Mps86OHdIlHaQNyxxhw==
-----END CERTIFICATE-----
`
	// Private master key in plaintext.
	//lint:ignore U1000 Not used, here for reference.
	masterKey string = `
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIJ9R14uCjYr3laAerOc/fvNOBZ8Znt4rtT8chtUXQAV4oAoGCCqGSM49
AwEHoUQDQgAEB4OmaDyIy3Xx9Qs6mGkkX/febB/lOrRAtnHEoDL5EuM9v8ifsUjg
fwBgzGbNOemd4mcF0rr9l72OGGhxuxhAHA==
-----END EC PRIVATE KEY-----
`

	// Private master key encrypted using passphrase "Thunder_t00l"
	encryptedMasterKey string = `
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIHsMFcGCSqGSIb3DQEFDTBKMCkGCSqGSIb3DQEFDDAcBAhSBzf4GjMQKgICCAAw
DAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEJVvwUlbn9dzCPhmndpu5HoEgZDu
LK6OpbtcVX+3onp59e4PNRASLLNdmKcGr6LKT+2u8zEffBoo8l3e8h+GooAsz345
n09NlpgvvXFuUbvFypzBUuuUuw5Vp83K3x2Uq4M6TBBaHtQGzQnOJyTVHZW19J8t
xgDzUERgFzNx1Dez5HbjCDH24bQsBVUix5fO6XQflHLLL+rTLrNEQNEbtOs7sE0=
-----END ENCRYPTED PRIVATE KEY-----
`

	MasterKeyPassword = "Thunder_t00l"
)
