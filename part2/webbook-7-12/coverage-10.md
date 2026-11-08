# Topic 10 coverage ledger

Read: complete workbook chapter, sections 01 through 11, including the review answer. Chapter HTML exposes interactive source/trace/table variables as unresolved placeholders. Claims behind them were checked against primary references where feasible; no lab output was invented.

| Workbook section | Notes section | Mechanisms and examples retained |
|---|---|---|
| 01 Malware with kernel privileges | 10.1 | Rootkit, scanner deception, HyperSafe monitor hardening, file-system/volume/disk/bus filtering, privilege relationship |
| 02 VMM definition | 10.1, 10.2 | Guest kernel attacker; hosted versus bare-metal dependency; isolation; TCB; historical/concurrent/legacy use |
| 03 Applications | 10.2 | Banking/everyday domains; disposable malware guest; Livewire VMI; Overshadow encrypted OS view; Qubes |
| 04 Requirements | 10.3 | Complete mediation, transparency, compatibility, efficiency, equivalence, resource control; sufficient-condition qualification |
| 05 Trap and emulate | 10.4, 10.6 | Rings; trap; virtual IF; double translation; shadow page-table write protection; CR3; DMA |
| 06 x86 problem | 10.4 | Pentium seventeen/~250 result; POPF silent IF suppression with IOPL condition; CLI #GP; critical-section restore; SIDT |
| 07 Three answers | 10.5, 10.6 | Translation cache; direct user execution; Xen source changes and hypercalls; VMX root/non-root; exits; EPT; IOMMU; early hardware performance qualification |
| 08 Lowest layer | 10.7 | SubVirt boot capture; Blue Pill live capture; nested hostile VMM; SMM; software-only trust limit |
| 09 Transparency | 10.8 | Red pills; CPUID/DMI/virtual-device identity; detect-virt; historical chipset; resource/timing effects; outside clock; malicious/legitimate detection |
| 10 Covert channels | 10.9 | Restricted banking guest; cooperating receiver; cache protocol; 0.2bits/s; 256/0.2; integrity/confidentiality/availability conditions; mitigation limits |
| Closing summary and review answer | 10.1 to 10.9 | Qualified guarantees retained in main sections |
| 11 References | Near claims | Original papers and official product/architecture documentation |

## Source accuracy corrections

- The workbook attaches approximately 0.2bits/s to a simplified cache description. The original EC2 paper §8.1 measures the improved differential cache-set channel, with averaging and migration handling. The notes separate these.
- The 256-bit key calculation is hypothetical transmission time once a cooperating sender knows the key. The EC2 paper explicitly says its reported side-channel attacks are coarser than key-extraction attacks.
- Seventeen instructions is the original Robin/Irvine Pentium finding. Avoid extending it to every modern x86 CPU.
- POPF and CLI table states protected-mode, IOPL and virtual-interrupt assumptions; a universal ring-only rule would be inaccurate.
- Blue Pill's announcement's undetectability claim is not adopted as fact.
- Fidelity and practical transparency are distinguished; timing exceptions in classical definitions matter.

## Omissions and limits

- CP-40/CP-67/VM370 chronology and HP Dynamo analogy omitted; they do not add a mechanism beyond the retained history, translation and trusted-monitor requirements. Existing substantive mechanisms are preserved.
- VT-x/AMD-V introduction dates omitted to keep attention on the architecture; the early-versus-later hardware distinction remains.
- Interactive five-instruction selector could not be exercised through text-only HTML. Notes reproduce the security-relevant CLI/POPF distinction, CR3 handling and I/O/DMA responsibility without fabricating button output.
- Lab POPF/CPUID trace variables were unresolved. No claim of executing those measurements locally.
- Shadow tables, EPT and IOMMU are conceptual mechanisms, not configuration guidance for a current platform.
- No attempt to survey current confidential-VM products; the next chapter covers hardware-rooted protection.

## Verification and index terms

- Verified original EC2 paper §§8 and 8.1, including numerical rates and differential encoding; arithmetic: 256/0.2 = 1280 seconds = 21.33 minutes.
- Read primary architecture/papers: Popek/Goldberg, Robin/Irvine, Adams/Agesen, Xen, Intel VMX, Livewire, Overshadow, SubVirt, Blue Pill announcement, Garfinkel transparency and EC2 study; official Qubes/Microsoft docs.
- Kept source-derived material distributed across primary sources; workbook-specific material is limited to threat example, SMM/root-trust framing and practical detection examples.
- Humanizer scan: no em/en dash prose, staged introductions or decorative bold labels. Markdown tables and text diagrams render without custom plugins.
- Index terms: hypervisor, VMM, TCB, kernel rootkit, filter driver, trap and emulate, sensitive instruction, privileged instruction, Popek-Goldberg, IF, IOPL, CLI, POPF, SIDT, binary translation, paravirtualization, hypercall, VMX, VM exit, shadow page table, CR3, EPT, nested paging, DMA, IOMMU, VT-d, VMI, Livewire, Overshadow, Qubes, SubVirt, Blue Pill, SMM, red pill, transparency, covert channel, side channel, cache timing, EC2, co-residence.

## Final editing pass

Repeated recall answers and duplicate source lists removed; unique details remain in the mapped sections. Question headings replaced with topic names.
