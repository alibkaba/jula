## 2024-05-10 - Slice Capacity Pre-Allocation
Learning: Go allocates an arbitrary amount of memory every time `append()` needs more capacity. In large responses from GCP (like when extracting object storage data or large IAM queries), not allocating slice capacity beforehand creates lots of allocations and causes garbage collection pauses.
Action: Whenever parsing unmarshalled maps and lists from an external API call, look for length fields and use `make([]T, 0, len(elements))` to initialize correctly.
