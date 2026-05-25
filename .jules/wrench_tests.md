# Wrench's Journal

- Mocking the standard library `crypto.Signer` interface is required to hit error paths for signature generation (e.g., when the underlying hardware or KMS fails to sign).
- To predictably trigger `json.Marshal` error paths for structs containing `time.Time` fields in Go tests, assign a date with a year outside the `[0, 9999]` range (e.g., `time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)`) to force an RFC3339 compliance error.
