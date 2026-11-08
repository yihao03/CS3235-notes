# Building the study site

Requires the installed global MarkBind CLI, version 7.2.1.

```sh
markbind serve
markbind build
```

`serve` opens a local preview on port 8080. `build` writes the static site to `_site/`.

All study notes remain in their original Markdown locations. `site.json` selects published pages explicitly; skill files and generated output are excluded. Source-review ledgers are available by link but excluded from search. Mermaid diagrams use MarkBind's bundled plugin, which loads Mermaid from its configured CDN and requires network access. Diagrams use native `<mermaid>` tags. Exact copies of the earlier Markdown notes are preserved in `original-notes/`.

Deployment is configured for `yihao03/CS3235-notes`, with `baseUrl` set to `/CS3235-notes` and output pushed to `gh-pages` by `markbind deploy`.

The original sketches referenced three absent figures: `canaries.png`, `fast-sfi.png`, and `lock-and-key.png`. Their site pages show explicit missing-figure notices with links to the fuller explanations. No replacement source figures were invented.

Source coverage records and the writing guide are under `part2/webbook-7-12/`; they are excluded from search. Runtime browser checks could not run in the restricted environment: local sockets and Chromium startup were denied. Static generation and generated-link checks were used instead.

## First publication

Run from this directory in a terminal with working GitHub access and writable Git metadata:

```sh
gh auth status
git init -b main
git add .gitignore 404.md SITE_README.md index.md site.json _markbind/layouts _markbind/variables.md _markbind/variables.json assets memory_vulnerabilities original-notes part2 stylesheets
git commit -m "Add CS3235 study notes and MarkBind site"
gh auth setup-git
gh repo create yihao03/CS3235-notes --private --source=. --remote=origin --push
markbind deploy
gh api --method POST repos/yihao03/CS3235-notes/pages -f build_type=legacy -f 'source[branch]=gh-pages' -f 'source[path]=/'
gh api repos/yihao03/CS3235-notes/pages --jq .html_url
```

If the Pages resource already exists, use `--method PUT` for its configuration instead. Private-repository Pages requires an eligible GitHub plan. Repository privacy does not make the published Pages site private. [GitHub Pages requirements](https://docs.github.com/en/pages/getting-started-with-github-pages/creating-a-github-pages-site).

After later edits:

```sh
git add <changed-files>
git commit -m "Update notes"
git push
markbind deploy
```
