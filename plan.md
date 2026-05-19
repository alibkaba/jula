1. **Target Refactor**: `internal/providers/http_generic/engine.go` (Lines 305 and 312).
2. **Issue**: Bare errors are being returned up the stack (`return types.Finding{}, err`), missing context wrapping. This violates the `Missing error wrapping/context` maintainability coding standard.
3. **Change**: Refactor to wrap the `err` with context using `fmt.Errorf`.
    - Change line 305 to `return types.Finding{}, fmt.Errorf("paginated extraction failed: %w", err)`
    - Change line 312 to `return types.Finding{}, fmt.Errorf("single-page extraction failed: %w", err)`
4. **Pre-commit**: I will call `pre_commit_instructions` tool to get the required checks and complete pre commit steps to make sure proper testing, verifications, reviews and reflections are done.
5. **Submit**: I will submit the code with title `🔧 Wrench: add error wrapping context to http generic engine`.
