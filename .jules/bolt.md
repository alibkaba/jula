## 2026-05-12 - [Framework Grouping Optimization]
Learning: Grouping logic using nested loops (O(F*E)) is a common bottleneck when processing large datasets with many categories. Using a map for single-pass grouping (O(E)) significantly improves performance.
Action: Always use maps to group data by a key before processing categories to avoid redundant iterations over the full dataset.

## 2024-05-13 - Optimize Nested Loop in `ApplyExceptions`
Learning: Filtering exceptions into a map before the O(N) array mapping brings up an O(N*M) time complexity loop down to O(N + M) complexity.
Action: Whenever a piece of code performs inner loop searching where uniqueness can be used via Map/Struct, extract it into a map representation first to guarantee O(1) loop checking.
