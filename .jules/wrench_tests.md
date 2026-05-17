# Wrench's Testing Journal

## Critical Learnings
- **GCP OAuth Token Refreshes**: The `refresh` method creates a JWT assertion using `rsa.SignPKCS1v15` which relies on `x509.ParsePKCS8PrivateKey`. This requires generating a valid RSA key and formatting it as a PKCS8 PEM block in tests to mock valid key decoding correctly. We need to define valid/invalid RSA PEM blocks explicitly for reliable table-driven testing.
