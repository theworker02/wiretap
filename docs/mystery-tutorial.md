# Mystery protocol tutorial

The `examples/mystery` captures are a fictional **Orbital Beacon** framing protocol.
Ground truth is intentionally not shipped for end-user discovery exercises.

## Suggested workflow

```bash
# Inspect
wiretap inspect examples/mystery/captures.hex

# Entropy map
wiretap entropy examples/mystery/captures.hex

# Full analysis
wiretap analyze --budget normal examples/mystery/captures.hex

# Checksum-focused search
wiretap checksum examples/mystery/captures.hex

# Cluster by shape
wiretap cluster examples/mystery/

# Infer a draft schema
wiretap schema infer examples/mystery/captures.hex > /tmp/mystery.yaml
wiretap validate /tmp/mystery.yaml
wiretap generate /tmp/mystery.yaml --package beacon -o /tmp/beacon.go
```

## What you should be able to evidence

Without spoiling exact offsets: look for a constant multi-byte prefix (magic),
a small type discriminator, a length field that matches message size, a
monotonic sequence, a plausible timestamp range, a sparse flags byte, a short
payload, and a trailer CRC that covers the prefix.

Maintainer note: regenerator lives at `scripts/gen_mystery.go`.
