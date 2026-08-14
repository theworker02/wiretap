<p align="center">
  <img src="assets/logo.svg" alt="Wiretap" width="420"/>
</p>

# Wiretap docs site

Static HTML/CSS site for GitHub Pages. No Ruby, no bundler — Windows-friendly.

## Local preview

```bash
cd docs-site
python -m http.server 8080
# or: npx --yes serve -p 8080
```

Open http://localhost:8080/

## Deploy

1. Push to `main`
2. Repo **Settings → Pages → Source: GitHub Actions**
3. Workflow: [`.github/workflows/pages.yml`](../.github/workflows/pages.yml)

Brand assets are synced from [`../assets`](../assets). See [docs/brand.md](../docs/brand.md).
