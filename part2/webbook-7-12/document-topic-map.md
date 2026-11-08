# Topics and sources

| Topic | Primary workbook chapter | Prerequisites / supporting notes | Practice |
|---|---|---|---|
| 7: Sandboxing and privilege separation | [Chapter 7](https://compsec.kisp-lab.org/Memory-Safety-Webbook/sandboxing-and-privilege-separation.dc.html) | [Partial memory safety](../../memory_vulnerabilities/partial-safety-4.md), [existing sandbox sketch](../2a.md) | Chapter sandbox playground: honest request, shell spawn, file theft, resident-key leak; namespace demo |
| 8: Policies | [Chapter 8](https://compsec.kisp-lab.org/Memory-Safety-Webbook/sandboxing-policies.dc.html) | Topic 7 reference monitors and protection domains | Access matrix; Bell-LaPadula/Biba combinations; extension principals; permission re-delegation |
| 9: Capabilities | [Chapter 9](https://compsec.kisp-lab.org/Memory-Safety-Webbook/access-control-and-capabilities.dc.html) | Topic 8 access matrix; Unix descriptors | ACL versus capabilities; descriptor delegation; ambient-authority removal |
| 10: Virtual machines | [Chapter 10](https://compsec.kisp-lab.org/Memory-Safety-Webbook/virtual-machines.dc.html) | Topic 9 MMU; rings, page tables, interrupts | Sensitive-instruction comparison; red-pill observations; cache channel |
| 11: Trusted execution environments | [Chapter 11](https://compsec.kisp-lab.org/Memory-Safety-Webbook/trusted-execution-environments.dc.html) | Topic 10 lowest-layer trust; topic 12 hash/MAC distinctions | PCR extension; quote verification; sealing after changed boot; late launch |
| 12: Cryptographic primitives | [Chapter 12](https://compsec.kisp-lab.org/Memory-Safety-Webbook/cryptographic-primitives.dc.html) | XOR, conditional probability; topic 11 protected memory | One-bit functions; OTP reuse and bit flips; MAC verification; Merkle rollback |

The workbook uses chapter numbers 7 to 12 and separate section numbers within each chapter. No separate tutorials or labs for these topics are present in this workspace. The chapter demonstrations above are the available practice sources; worked mechanisms and recall checks appear in the corresponding notes.

Existing chapters 0 to 6 remain in [memory_vulnerabilities](../../memory_vulnerabilities/README.md). The new files do not replace those notes or the sandbox sketch.
