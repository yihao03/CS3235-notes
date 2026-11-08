# Sandboxing, isolation and cryptography

| Topic | Notes |
|---|---|
| 7 | [Sandboxing and privilege separation](07-sandboxing.md) |
| 8 | [Sandboxing policies](08-policies.md) |
| 9 | [Access control and capabilities](09-capabilities.md) |
| 10 | [Virtual machines](10-virtual-machines.md) |
| 11 | [Trusted execution environments](11-tee.md) |
| 12 | [Basic cryptographic primitives](12-cryptography.md) |

[Revision index](INDEX.md) · [Topic and practice map](document-topic-map.md) · [Earlier memory-safety notes](../../memory_vulnerabilities/README.md)

Read topics 7 to 10 in order. Topic 12's hash, MAC and secrecy definitions support topic 11's attestation and protected-memory mechanisms.

<mermaid>
flowchart TD
    A["7: Restrict compromised components"] --> B["8: Specify allowed access"]
    B --> C["9: Carry authority explicitly"]
    C --> D["10: Isolate entire operating systems"]
    D --> E["11: Trust hardware beneath hostile software"]
    F["12: Encryption, MACs and authenticated trees"] --> E
</mermaid>



