## 2026-05-12 - [Framework Grouping Optimization]
Learning: Grouping logic using nested loops (O(F*E)) is a common bottleneck when processing large datasets with many categories. Using a map for single-pass grouping (O(E)) significantly improves performance.
Action: Always use maps to group data by a key before processing categories to avoid redundant iterations over the full dataset.
