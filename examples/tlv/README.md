<p align="center">
  <img src="../../assets/logo.svg" alt="Wiretap" width="420"/>
</p>

# TLV showcase

Repeating Type-Length-Value records after a `0xA5` header (authorized synthetic
captures).

- `u8` magic `0xA5`
- repeating TLV: `type u8`, `length u8`, `value[length]`
  - type 1: device name (ASCII)
  - type 2: 2-byte sensor reading
  - type 3: flags

```bash
wiretap analyze examples/tlv/captures.hex
wiretap explain --at 0 examples/tlv/captures.hex
wiretap schema infer examples/tlv/captures.hex
```
