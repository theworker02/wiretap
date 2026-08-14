# Wireshark stubs

Wiretap can emit a **reviewable Lua dissector stub** from a schema:

```bash
wiretap schema infer examples/thermostat/captures.hex > /tmp/th.yaml
wiretap generate wireshark /tmp/th.yaml --package thermo -o thermo.lua
```

See [generators.md](generators.md) for the full generator surface (Go, Kaitai, Wireshark).

## Expectations

- Output is a **stub**, not a finished dissector — register ports and refine fields yourself.
- Use only with **authorized** captures you are permitted to study.
- Wiretap does not install Wireshark plugins or sniff interfaces; acquisition stays separate from analysis ([capture-ethics.md](capture-ethics.md)).
