# Generate Production Accel Master Key / Certificate

On a dedicated host generate Accel Master key and self-signed certificate

1. Generate ECDSA key pair
  openssl ecparam -name prime256v1 -genkey -noout -out accelmaster_priv.pem
2. Encrypt the private key with a password
  openssl pkcs8 -topk8 -v2 aes-256-cbc -in accelmaster_priv.pem -out encrypted_accelmaster_priv.pem
3. Generate a self-signed certificate for X years. Here X = 2
  a. openssl req -new -x509 -key accelmaster_priv.pem -out accelmaster_cert.pem -days 730
  b. Issuer:
    C = US, ST = CA, L = Sunnyvale, O = ThunderToken Inc., OU = Engineering, CN = Testnet, emailAddress = it@thundertoken.com
4. Check the the certificate
  openssl x509 -in accelmaster_cert.pem -text -noout
5. Backup the private key in a safe and secure place
