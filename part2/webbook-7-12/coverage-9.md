# Topic 9 coverage ledger

Source: [Access control and capabilities](https://compsec.kisp-lab.org/Memory-Safety-Webbook/access-control-and-capabilities.dc.html). Full extracted chapter read, including exercise answer and concluding recap. Detailed expansions use independently read primary references; workbook-derived examples and analysis are kept concise for its 200-word source budget.

| Workbook item | Exact note heading |
| --- | --- |
| Policy location; matrix | 9.1 Authority and identity |
| Ambient authority | 9.2 Ambient authority |
| Capability definition | 9.3 Capability references |
| File descriptors | 9.4 Unix descriptors |
| Removing ambient authority | 9.5 Sandboxing delegated authority |
| Delegation | 9.6 Delegation and revocation |
| Comparison; revocation | 9.6 Delegation and revocation; 9.1 Authority and identity |
| Memory exercise and answer | 9.7 Page tables and CHERI |
| Recap; sources | 9.1 to 9.7; references inline |

Primary-reference mechanisms checked independently: matrix representation; credentials and file modes; STAT/BILL attack; unforgeability; fd locality and access mode; strict seccomp allowlist and setup; inheritance; SCM_RIGHTS; forwarder revocation; NFS caveat; MMU/TLB/CR3; CHERI bounds, tags, permissions and derivation; pure/hybrid migration; Capstone.

## Additions and corrections

- Hardy's original account grants directory write authority to support STAT collection, which then exposes BILL; workbook's billing-purpose simplification is replaced with this verified detail.
- CHERI sealed state, capability atomicity, compressed bounds and out-of-bounds pointer formation are supplements from the programming guide; the workbook only sketches CHERI.
- Descriptors' shared offsets, close-on-exec, NFS behavior and Linux root capabilities are useful additions.
- Hardware/platform claims are qualified as research/prototype implementations; no claim that x86 CHERI is deployed.

## Limits and omissions

- Extracted chapter leaves `{% raw %}{{ catTrace }}{% endraw %}`, `{% raw %}{{ copySource }}{% endraw %}`, `{% raw %}{{ copyTrace }}{% endraw %}`, `{% raw %}{{ passTrace }}{% endraw %}`, `{% raw %}{{ revokeTrace }}{% endraw %}` and button-dependent text unresolved. Surrounding prose is covered; exact VM trace output, executable copy source and interactive branches were not available and were not invented.
- No lab program was executed. The syscall and descriptor claims were checked against man pages; the diagrams and snippets explain behavior, rather than reporting measurements from this workspace.
- The 1966 Dennis/Van Horn and Levy historical survey references are not expanded; the notes retain the mechanisms and use original Lampson/Saltzer/Hardy references. Full historical survey is outside this chapter's instructional mechanisms.
- Recap wording and decorative teaching UI are compressed; all substantive extracted mechanisms, examples and caveats are mapped above.

## Index keywords

Access matrix; ACL; protection domain; ambient authority; least privilege; complete mediation; confused deputy; Hardy compiler; capability; unforgeability; attenuation; file descriptor; open file description; EBADF; redirection; strict seccomp; exit_group; Capsicum; cap_enter; cap_rights_limit; delegation; SCM_RIGHTS; revocation; forwarder; chmod; NFS; MMU; CR3; page tables; TLB; CHERI; provenance; monotonicity; tags; bounds; sealing; Morello; Capstone; Linux capabilities.

## Final editing pass

Repeated recall answers and duplicate source lists removed; unique details remain in the mapped sections. Question headings replaced with topic names.
