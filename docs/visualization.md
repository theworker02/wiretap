# Visualization

```bash
wiretap visualize examples/mystery/captures.hex -o map.svg
wiretap visualize --schema schemas/draft.yaml -o map.html
wiretap visualize --mermaid -o schema.mmd examples/mystery/captures.hex
wiretap visualize --graphviz -o schema.dot --from-schema --schema draft.yaml
```

Produces:

- **SVG / HTML** — pure SVG byte lanes with confidence colors (HTML wraps SVG; no JS)
- **Mermaid (`.mmd`)** — left-to-right field flowchart from schema or High/Medium hypotheses
- **Graphviz (`.dot`)** — same structure as a digraph

Confidence colors are measured levels, not invented scores.
