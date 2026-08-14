<p align="center">
  <img src="../../assets/logo.svg" alt="Wiretap" width="420"/>
</p>

# Thermostat showcase

Synthetic HVAC thermostat frames (authorized lab data) with magic, zone
discriminator, scaled temperatures, flags, and a CRC32 trailer.

| Offset | Field | Notes |
|--------|-------|-------|
| 0 | magic `TH` | constant |
| 2 | version | `u8` |
| 3 | zone | type-like discriminator |
| 4 | temp×10 | `u16be` |
| 6 | setpoint×10 | `u16be` |
| 8 | flags | bitfield |
| 9 | crc32 | IEEE trailer |

```bash
wiretap analyze examples/thermostat/captures.hex
wiretap cluster examples/thermostat/captures.hex
wiretap checksum examples/thermostat/captures.hex
wiretap visualize examples/thermostat/captures.hex -o thermo.svg
```
