# Coverage: topic 8

Source: [Sandboxing policies](https://compsec.kisp-lab.org/Memory-Safety-Webbook/sandboxing-policies.dc.html).

| Source section | Notes destination | Review |
| --- | --- | --- |
| 01 | 8.1 | Defaults, operational cost, playground comparison; independent Linux and Saltzer sources |
| 02 | 8.2 | All four terms; multiple domains per application |
| 03 | 8.2 | Matrix lookup, sparse representation, ACL/capability comparison |
| 04 | 8.3, Unix DAC, 8.6 | File example retained; historical mobile decision mapped to timing comparison |
| 05 | 8.3, Origins and SELinux | Origin construction and mandatory enforcement; SELinux material from §06 included here |
| 06 | 8.4 | Both label policies; complete eight-case truth table; composition; independent original Biba report consulted |
| 07 | 8.3, Roles | Role membership and command grants; conceptual sudo example |
| 08 | 8.5 | Historical sample, five API mismatches with severity ratings, architecture, manifest authorities, heap isolation, exercise answer |
| 09 | 8.6 | Static/dynamic tradeoffs, study denominators and results, Android runtime change |
| 10 | 8.7 | Component-letter example, attack sequence, historical vulnerability count, boundary check and privilege-reduction defenses |
| 11 | 8.8 | Historical samples and SMS interpretation; two additional chart comparisons verified in paper |
| 12 | 8.9 | Confidentiality/integrity goals, authentication release, syscall observability, narrow trusted interface |
| End summary | 8.1 to 8.9 | Distinctions and failure modes retained in main sections |
| References | Throughout | Descriptive source links near claims |

## Deliberate compression and limits

- Full `sudoers` syntax replaced by the equivalent role-to-command mapping; commands are conceptual examples, not deployment instructions.
- Manifest identity/version/icon fields omitted; requested authorities retained. Current optional grants explained separately.
- Permission chart is summarized with supported distinguishing observations, not reproduced wholesale. No missing benign value is inferred to be zero.
- SSH child/monitor example is represented as restricted parser/trusted checker and cross-linked to topic 7.
- File descriptors are explained in topics 7 and 9; topic 8 keeps the matrix representation comparison.
- Hardy's original web page timed out twice. Deputy mechanism is independently supported by Felt's paper; no unread Hardy quotation or detailed compiler story added.
- The Biba original was unreadable at the UC Davis PDF endpoint; independently read the OCR of the original report hosted by SciSpace, especially pages 32 to 34 and 54 to 58.
- Static chapter HTML includes unresolved interactive template strings. Narrative explains the interactions; the eight label outcomes were derived from the verified inequalities. Hidden permission-chart data not claimed to have been extracted.
- Workbook-specific synopsis/examples stay brief. Detailed concepts are independently supported by primary documentation/reports, each within its web extraction budget. Repeated citations to the same document share one budget.

## Checks

- All source sections read, including exercise answer and conclusion.
- Historical observations labeled by paper year/platform version.
- Strict Biba distinguished from other policies in Biba's report.
- Equations and all eight outcomes checked manually.
- Supplemental facts are cited blockquotes; no direct prose quotations.
- Plain headings, short blocks, tables, two Mermaid diagrams; no em/en dashes in prose.
- Relative topic links checked during site integration.

## Final editing pass

Repeated recall answers and duplicate source lists removed; unique details remain in the mapped sections. Question headings replaced with topic names.
