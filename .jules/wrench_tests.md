WRENCH'S JOURNAL
- When testing `crypto.Signer` paths (like those in `CloudReporter`), you can generate real ECDSA keys using `ecdsa.GenerateKey` for happy paths, and create simple struct mocks implementing the `crypto.Signer` interface to test deterministic error scenarios (like `io.EOF`) without needing external mocking libraries.
- The `collector/internal/reporter` package coverage successfully increased from 5.2% to 85.7%.
- When testing HTTP-dependent integrations like cloud credential providers (e.g., in `core/pkg/objstore`), use `httptest.NewServer` to mock external API endpoints and ensure deterministic testing without requiring external dependency libraries.

* When testing file system errors in LocalStore, rely on `os.CreateTemp` to create a file and use it as a directory path (`filepath.Join(fileName, "subdir")`) to cause a guaranteed error, rather than hardcoding paths like `/root/protected/dir`, which might succeed if the tests are running as the root user.
- Extracted global test setup cleanup to happen cleanly inside subtest blocks.
- Learned that replacing standard package logic that references hardcoded IP endpoint by moving the IP to a package-level variable to enable URL injection with an HTTP test server.
- To mock GCP credential token exchange (e.g., `google.FindDefaultCredentials`) without network calls, provide a dummy service account JSON file with a dynamically generated RSA private key and set its `token_uri` field to point to a local `httptest.NewServer`.

- **Testing Oracle Cloud Infrastructure (OCI) Signatures:** The OCI signing logic `SignOCICavage` correctly expects PEM-encoded private keys, and supports both `RSA PRIVATE KEY` and `PRIVATE KEY` headers. During testing, to avoid file dependencies, generate keys in memory with `rsa.GenerateKey` and marshal them into valid PKCS#1 and PKCS#8 PEM blocks for mocking the `OCI_PRIVATE_KEY` environment variable.
- **Testing OPA Evaluation Parsing:** When testing functions that parse `rego.ResultSet` output into `ComplianceVerdict` structs (e.g., in `assessor/internal/evaluation`), build mock map structures and encapsulate them deeply within `[]*rego.ExpressionValue` slices to verify correctly typed assertions of dynamic `evalMap` keys (like parsing numbers gracefully from `json.Number` or `float64`).
