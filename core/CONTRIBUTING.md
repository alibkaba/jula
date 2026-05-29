# Contributing to Jula Controls

Thank you for your interest in contributing to Jula Controls! Whether you're fixing a bug, improving documentation, or proposing a new feature, your help is appreciated.

## The BSL License & Developer Certificate of Origin (DCO)

Jula Controls is licensed under the **Business Source License (BSL) 1.1**. To protect this licensing structure and ensure that the codebase remains unencumbered, we require all contributors to agree to the Developer Certificate of Origin (DCO).

By contributing to this repository, you certify that you wrote the patch or otherwise have the right to submit it under the project's license. 

**How to sign off:**
All commits must include a `Signed-off-by` line. You can add this automatically by using the `-s` flag when committing:
```bash
git commit -s -m "feat: adding new integration logic"
```

## How to Contribute

### 1. Issues & Bug Reports
- Check existing issues before opening a new one to avoid duplicates.
- Provide clear, reproducible steps for bug reports.
- Include your environment details (OS, Go version, Cloud Provider).

### 2. Pull Requests
- Fork the repository and create your branch from `main`.
- Ensure your code adheres to standard Go formatting (`gofmt`).
- Write clear, concise commit messages.
- If you've added code that should be tested, add tests.
- Ensure the test suite passes before submitting your PR.

### 3. Code Style
- We follow standard Go conventions. 
- Keep the design decoupled. Remember the architecture philosophy: *The Integration Layer stays messy, the Translator Layer stays agnostic.*

### 4. Expectations
Please be patient! Jula Controls is actively maintained, but pull request and issue reviews may take some time. We appreciate your contributions and will get to them as soon as possible.
