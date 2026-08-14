<p align="center">
  <img src="../../assets/logo.svg" alt="Wiretap" width="420"/>
</p>

# Array records showcase

Count-prefixed fixed-width records (authorized synthetic captures).

| Offset | Field |
|--------|-------|
| 0–1 | magic `R1` |
| 2 | version |
| 3 | count `u8` |
| 4… | `count` × `u32be` records |

```bash
wiretap analyze examples/array_records/captures.hex
wiretap schema infer examples/array_records/captures.hex
wiretap generate go schemas/draft.yaml --package records
```
