# Build and publish

Requires global MarkBind 7.2.1.

```sh
markbind serve
markbind build
markbind deploy
```

Source: `yihao03/CS3235-notes`, private, branch `main`.

Publishing uses `markbind deploy` to push `_site/` to `gh-pages`. Pushes to `main` also run `markbind deploy --ci` through `.github/workflows/deploy.yml`. The workflow verifies the output branch and requests a Pages build.

In GitHub Settings > Pages, select **Deploy from a branch**, **gh-pages**, **/ (root)**. Private-repository Pages requires an eligible plan; the published site is normally public. [GitHub requirements](https://docs.github.com/en/pages/getting-started-with-github-pages/creating-a-github-pages-site).

The configured project path is `/CS3235-notes`. Change `baseUrl` and `deploy.repo` together if the repository moves.

## Local Git synchronization

The connected GitHub tools uploaded the initial sources because this environment mounts `.git` read-only. The local branch has no commits. Run once in a terminal with Git metadata write access:

```sh
git fetch origin
git reset --mixed origin/main
git branch -m main
git branch --set-upstream-to=origin/main main
```

`reset --mixed` updates Git metadata without changing working files. Afterwards, commit and push edits normally, then use `markbind deploy` for manual publication.

## Source and checks

- Notes remain in their Markdown locations. Earlier originals are preserved in `original-notes/`.
- Mermaid uses native `<mermaid>` tags and loads its renderer from a CDN.
- Three original figures were absent: `canaries.png`, `fast-sfi.png`, `lock-and-key.png`. Their pages link to fuller explanations.
- Static generation and local-link checks passed. Browser testing was blocked by local socket/Chromium restrictions.
- Coverage records are under `part2/webbook-7-12/` and excluded from search.
