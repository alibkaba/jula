## 2026-05-12 - Prevent Repeated JSON Marshalling

Learning: Inside loops over criteria, repeatedly re-marshalling identical structs to JSON wastes allocations and CPU cycles. Moving the marshal step outside the inner loop significantly cuts down on overall memory allocations.
Action: Whenever serializing data for multiple output destinations, check if the data remains the same across iterations. If it does, serialize once outside the loop and reuse the payload.

## 2026-05-12 - Hoisting repeated invariant hashes and string manipulations
Learning: Cryptographic hashing and formatting operations can easily sneak into inner loops of file reporting mechanisms when generating redundant payloads for different destinations. Here, `crypto.HashFile` and string sanitization were correctly moved outside of an inner loop iterating through different frameworks, improving allocation/op and CPU overhead significantly.
Action: Always check loops iterating over combinations to see what is perfectly constant across items. Move hashes, marshals, and resource string sanitizations out of innermost logic structures whenever iterating combinations.
