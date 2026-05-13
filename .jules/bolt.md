## 2026-05-12 - Prevent Repeated JSON Marshalling

Learning: Inside loops over criteria, repeatedly re-marshalling identical structs to JSON wastes allocations and CPU cycles. Moving the marshal step outside the inner loop significantly cuts down on overall memory allocations.
Action: Whenever serializing data for multiple output destinations, check if the data remains the same across iterations. If it does, serialize once outside the loop and reuse the payload.

## 2026-05-13 - Optimize framework grouping loops
Learning: When consolidating objects categorized by a specific attribute (like a framework or region), iterating over the entire slice repeatedly for each category creates an $O(N \times M)$ complexity.
Action: Build a map grouping items by their category (`map[string][]Item`) in a single $O(M)$ pass, and then iterate the keys of the map. This is much faster and more idiomatic.
