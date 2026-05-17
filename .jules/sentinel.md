## 2026-05-17 - [Insecure Local File Permissions]
**Vulnerability:** Evidence files and manifest files were written with world-readable 0644 permissions, and directories with 0755 permissions.
**Learning:** Sensitive audit information could be leaked on a multi-user system because it uses the local OS for the local target output. Even though it's typically for dev/testing, test data can sometimes be sensitive and security standards should apply consistently to prevent accidental leakage.
**Prevention:** Use os.FileMode 0600 for os.WriteFile and 0700 for os.MkdirAll whenever writing sensitive artifacts.
