# Wrench's Testing Journal

## Critical Learnings

*   **Triggering OPA `PrepareForEval` Errors**: To simulate OPA compilation errors (`PrepareForEval` failure) within `EvaluateControl`, one can exploit the fact that `EvaluateControl` recompiles the policies using the current contents of `policyModules`. First, call `Compile()` with valid Rego code to populate the `controlPackageMap`. Then, mutate the entry in `policyModules` to contain invalid syntax before calling `EvaluateControl`. The evaluator will successfully look up the policy path from the map, but fail when attempting to compile the new, invalid Rego content.
