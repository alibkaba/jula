Learnings about tests:
- Go project, using standard testing library.
- No tests currently implemented (0.0% coverage).
- Focus on easily testable functions (pure functions/logic).
- Functions like getEnvStr, getEnvInt, parseWorkspace, sanitizeFilename are good candidates.
- t.Setenv is preferred over os.Setenv + defer os.Unsetenv since Go 1.17.
