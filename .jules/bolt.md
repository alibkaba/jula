## 2026-05-12 - Prevent Repeated JSON Marshalling

Learning: Inside loops over criteria, repeatedly re-marshalling identical structs to JSON wastes allocations and CPU cycles. Moving the marshal step outside the inner loop significantly cuts down on overall memory allocations.
Action: Whenever serializing data for multiple output destinations, check if the data remains the same across iterations. If it does, serialize once outside the loop and reuse the payload.
