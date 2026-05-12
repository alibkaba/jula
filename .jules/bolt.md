## 2026-05-12 - [Framework Grouping Optimization]
Learning: Grouping logic using nested loops (O(F*E)) is a common bottleneck when processing large datasets with many categories. Using a map for single-pass grouping (O(E)) significantly improves performance.
Action: Always use maps to group data by a key before processing categories to avoid redundant iterations over the full dataset.
## 2026-05-12 - GCS Reporter Framework Grouping Loop Optimization
Learning: Grouping evidence by framework iteratively via an O(N*M) nested loop scales poorly when evidence count is large.
Action: Pre-allocate a map indexed by the grouping property (e.g., `framework`), allowing evidence arrays to be grouped in O(N) complexity inside a single pass, massively improving delivery performance with manageable memory allocation tradeoff.
