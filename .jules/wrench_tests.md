# Wrench's Journal - Critical Learnings

- In the evaluator module, OPA PrepareForEval compilation errors can be simulated in tests by mutating the OPAEvaluator.policyModules map with invalid Rego syntax after calling Compile().
- In the evaluator module, OPA Eval runtime/execution errors can be simulated in unit tests by passing a canceled context before calling Eval().
