## Wrench Tests Journal

*   **Mocking OPA Compilation Errors:** To simulate `PrepareForEval` errors in `EvaluateControl`, after calling `Compile()`, manually mutate the `evaluator.policyModules` map to contain invalid Rego syntax for a package that is mapped in `evaluator.controlPackageMap`.
*   **Mocking OPA Evaluation Errors:** To simulate evaluation errors (e.g., during `Eval()`), pass a cancelled context or a context with a timeout that immediately expires to `EvaluateControl`.
