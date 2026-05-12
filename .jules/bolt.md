## 2026-05-12 - [Framework Grouping Optimization]
Learning: Grouping logic using nested loops (O(F*E)) is a common bottleneck when processing large datasets with many categories. Using a map for single-pass grouping (O(E)) significantly improves performance.
Action: Always use maps to group data by a key before processing categories to avoid redundant iterations over the full dataset.
## 2026-05-12 - Hoisting repetitive operations outside loops
Learning: In `internal/reporter`, JSON marshalling (`json.MarshalIndent`) and cryptographic hashing (`crypto.HashFile`) were being unnecessarily repeated inside `for _, criterion := range criteria` loops. Because the data (`ev` and `data` respectively) does not change based on the criterion, these operations can be done once beforehand.
Action: Always inspect loops for variables and computations that depend only on outer loop scopes, and hoist them. When serializing or hashing the same data for multiple criteria/destinations, do it exactly once to save allocations and CPU time.
