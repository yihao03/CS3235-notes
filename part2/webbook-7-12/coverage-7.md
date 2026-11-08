# Topic 7 coverage ledger

| Workbook section | Notes |
|---|---|
| 01 Two lines of defense | 7.1 |
| 02 Reference monitors | 7.2; NEAT from existing `part2/2a.md` retained |
| 03 Syscall policies | 7.3 |
| 04 Playground | 7.3 policy table, strict-mode exit distinction, key-leak analysis |
| 05 seccomp | 7.3 mechanism table, limits, install rules, libseccomp pseudocode |
| 06 Design principles | 7.1 |
| 07 OpenSSH | 7.4 |
| 08 Browsers | 7.5, including historical classification counts and architecture |
| 09 Android | 7.6 |
| 10 Policy/mechanism | 7.8 |
| 11 Namespaces | 7.7 |
| Summary and references | 7.1 to 7.8; references inline |

## Source and verification record

- Read the complete chapter's extracted text, including playground explanation; reactive labels are unresolved template placeholders in the web reader. The explanatory verdicts remain readable.
- Independently read primary sources for Linux seccomp/LSM/libseccomp, namespaces, NIST reference monitors, Saltzer/Schroeder, OpenSSH, Chromium, the browser study, and Android.
- Source-specific paraphrase budgets constrain wording. Workbook-derived discussion centers on the syscall example and mechanism overview; other detail uses independently read references.
- Browser counts checked against paper Figure 2: total includes two unclassified records. Historical sample and original Chromium architecture are labeled.
- Manual/source review only: sandbox examples were not executed; pseudocode requires error handling and startup setup.
- Humanizer scan: no em/en dashes, decorative bold, generic closers or chat wrappers.

## Omissions and limits

- Omitted the boat metaphor and the brief historical iPhone exploit anecdote; mechanisms and Android comparison are retained.
- Interactive animations were not executed. Notes retain their stated policy outcomes without claiming local measurements.
- Exact lab VM error messages are not presented as new observations. Signal distinctions use Linux documentation.
- Original OpenSSH internals beyond the chapter's scope, such as compression-state export, are omitted.
- Final topic links checked during site integration.

## Index terms

Threat model; reference monitor; NEAT; complete mediation; TCB; least privilege; fail-safe defaults; block-list; allow-list; seccomp strict; seccomp-bpf; TOCTOU; no_new_privs; LSM; libseccomp; privilege separation; OpenSSH; IPC; Chromium; renderer; site isolation; Android UID; APK signatures; namespaces; PID; user namespace; container.

## Final editing pass

Repeated recall answers and duplicate source lists removed; unique details remain in the mapped sections. Question headings replaced with topic names.
