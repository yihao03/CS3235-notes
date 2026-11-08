# Memory safety webbook course notes

> Source: [course overview](https://compsec.kisp-lab.org/Memory-Safety-Webbook/course-home.dc.html). The linked chapter notes include technical examples and caveats. Figures, policies and assignment parameters may change; check the live course/Canvas.

| Order | Topic | Notes | Original |
|---|---|---|---|
| Quick reference | Consolidated facts, formulas and caveats | [Cheatsheet](cheatsheet.md) | Chapters below |
| Preparation | Systems background | [Prerequisites](prerequisites.md) | [Self-test](https://compsec.kisp-lab.org/Memory-Safety-Webbook/prerequisite-self-test.dc.html) |
| Review | 26 in-chapter checkpoints with answers and caveats | [Review checkpoints](review-checkpoints.md) | [Quiz data](https://compsec.kisp-lab.org/Memory-Safety-Webbook/inclass-quizzes.js) |
| 00 | Security reasoning, threat models, logistics | [Introduction](introduction-0.md) | [Introduction](https://compsec.kisp-lab.org/Memory-Safety-Webbook/00-introduction.dc.html) |
| 1A–1B | Spatial bugs: stack/heap overflow, format strings, integers, bad casts | [Spatial](spatial-1a1b.md) | [1A](https://compsec.kisp-lab.org/Memory-Safety-Webbook/01a-spatial-memory-errors.dc.html) · [1B](https://compsec.kisp-lab.org/Memory-Safety-Webbook/01b-spatial-memory-errors-advanced.dc.html) |
| 2 | Temporal bugs: use-after-free and double-free | [Temporal](temporal-2.md) | [Chapter 2](https://compsec.kisp-lab.org/Memory-Safety-Webbook/02-temporal-memory-errors.dc.html) |
| 3 | Code injection, code reuse, ROP, vtables, data attacks | [Exploits](exploits-3.md) | [Chapter 3](https://compsec.kisp-lab.org/Memory-Safety-Webbook/03-control-flow-hijacking.dc.html) |
| 4 | Partial safety: canaries, DEP, ASLR, SFI, CFI | [Partial safety](partial-safety-4.md) | [Chapter 4](https://compsec.kisp-lab.org/Memory-Safety-Webbook/05-partial-memory-safety.dc.html) |
| 5 | Full safety: bounds, fat pointers, lock/key, costs | [Full safety](full-safety-5.md) | [Chapter 5](https://compsec.kisp-lab.org/Memory-Safety-Webbook/06-full-memory-safety.dc.html) |
| 6 | Rust ownership, borrowing, lifetimes, aliasing | [Rust](rust-6.md) | [Chapter 6](https://compsec.kisp-lab.org/Memory-Safety-Webbook/07-memory-safety-in-rust.dc.html) |
| Assignment | libheif case study, rules, 11 scoring rungs | [Assignment overview](assignment-overview.md) | [Handout](https://compsec.kisp-lab.org/Memory-Safety-Webbook/assignment.html) |

<mermaid>
flowchart LR
  P[Prerequisites] --> I[Threat models]
  I --> V[Spatial + temporal vulnerabilities]
  V --> E[Exploitation]
  E --> D[Partial defenses]
  D --> F[Full memory safety]
  F --> R[Rust]
  E -.-> A[libheif assignment]
</mermaid>
Older local sketches [`spatial.md`](spatial.md), [`temporal.md`](temporal.md), and [`c_basics.md`](c_basics.md) remain untouched. The files above cover the webbook chapters.
