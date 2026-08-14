<p align="center">
  <img src="../../assets/logo.svg" alt="Wiretap" width="420"/>
</p>

# Mystery protocol

Deliberately undocumented fictional protocol ("Orbital Beacon") for offline
inference practice. No end-user ground-truth schema is shipped — discover
structure from evidence.

```bash
wiretap analyze examples/mystery/captures.hex
wiretap explain --at field:4 examples/mystery/captures.hex
wiretap visualize examples/mystery/captures.hex -o map.svg
wiretap tui examples/mystery/captures.hex
```

Walkthrough: [docs/mystery-tutorial.md](../../docs/mystery-tutorial.md)  
Demo scripts: `scripts/demo.sh`, `scripts/demo.ps1`
