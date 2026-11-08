# Revision index

## Comparisons and common confusions

| Find | Locator |
|---|---|
| Syscall policy versus information-flow policy | [T7 §7.3](07-sandboxing.md#7-3-syscall-policies) |
| Policy versus mechanism | [T7 §7.8](07-sandboxing.md#7-8-isolation-boundaries) |
| DAC versus MAC versus RBAC | [T8 §8.3](08-policies.md#8-3-policy-authority) |
| Bell-LaPadula versus strict Biba | [T8 §8.4](08-policies.md#8-4-confidentiality-and-integrity-labels) |
| ACLs versus capabilities; revocation | [T9 §9.6](09-capabilities.md#9-6-delegation-and-revocation) |
| Page tables versus CHERI | [T9 §9.7](09-capabilities.md#9-7-page-tables-and-cheri) |
| Binary translation versus paravirtualization versus hardware | [T10 §10.5](10-virtual-machines.md#10-5-x86-virtualization-methods) |
| Integrity versus confidentiality of VM isolation | [T10 §10.9](10-virtual-machines.md#10-9-covert-channels) |
| Measured boot versus trusted boot versus sealing | [T11 §11.4](11-tee.md#11-4-measured-boot-trusted-boot-and-sealing) |
| SRTM versus DRTM | [T11 §11.6](11-tee.md#11-6-late-launch-and-drtm) |
| TPM versus SGX versus phone TEEs | [T11 §11.1](11-tee.md#11-1-trust-boundaries) |
| Perfect secrecy versus correctness | [T12 §12.2](12-cryptography.md#12-2-correctness-and-perfect-secrecy) |
| Confidentiality versus integrity; pad reuse and bit flips | [T12 §12.4](12-cryptography.md#12-4-one-time-pad) |
| MAC authenticity versus replay protection | [T12 §12.5](12-cryptography.md#12-5-message-authentication-codes) |
| Merkle read versus authenticated write | [T12 §12.7](12-cryptography.md#12-7-merkle-trees-for-untrusted-memory) |

## Section lookup

### 7. Sandboxing and privilege separation

| Section | Topic |
|---|---|
| [T7 §7.1](07-sandboxing.md#7-1-containment) | Containment |
| [T7 §7.2](07-sandboxing.md#7-2-reference-monitors-and-neat) | Reference monitors and NEAT |
| [T7 §7.3](07-sandboxing.md#7-3-syscall-policies) | Syscall policies |
| [T7 §7.4](07-sandboxing.md#7-4-openssh) | OpenSSH |
| [T7 §7.5](07-sandboxing.md#7-5-browsers) | Browsers |
| [T7 §7.6](07-sandboxing.md#7-6-android) | Android |
| [T7 §7.7](07-sandboxing.md#7-7-namespaces) | Namespaces |
| [T7 §7.8](07-sandboxing.md#7-8-isolation-boundaries) | Isolation boundaries |

### 8. Sandboxing policies

| Section | Topic |
|---|---|
| [T8 §8.1](08-policies.md#8-1-choosing-the-default) | Choosing the default |
| [T8 §8.2](08-policies.md#8-2-access-matrix) | Access matrix |
| [T8 §8.3](08-policies.md#8-3-policy-authority) | Policy authority |
| [T8 §8.4](08-policies.md#8-4-confidentiality-and-integrity-labels) | Confidentiality and integrity labels |
| [T8 §8.5](08-policies.md#8-5-browser-extensions-2010) | Browser extensions (2010) |
| [T8 §8.6](08-policies.md#8-6-permission-prompts) | Permission prompts |
| [T8 §8.7](08-policies.md#8-7-confused-deputies) | Confused deputies |
| [T8 §8.8](08-policies.md#8-8-permission-lists-and-malware) | Permission lists and malware |
| [T8 §8.9](08-policies.md#8-9-information-flow) | Information flow |

### 9. Access control and capabilities

| Section | Topic |
|---|---|
| [T9 §9.1](09-capabilities.md#9-1-authority-and-identity) | Authority and identity |
| [T9 §9.2](09-capabilities.md#9-2-ambient-authority) | Ambient authority |
| [T9 §9.3](09-capabilities.md#9-3-capability-references) | Capability references |
| [T9 §9.4](09-capabilities.md#9-4-unix-descriptors) | Unix descriptors |
| [T9 §9.5](09-capabilities.md#9-5-sandboxing-delegated-authority) | Sandboxing delegated authority |
| [T9 §9.6](09-capabilities.md#9-6-delegation-and-revocation) | Delegation and revocation |
| [T9 §9.7](09-capabilities.md#9-7-page-tables-and-cheri) | Page tables and CHERI |

### 10. Virtual machines

| Section | Topic |
|---|---|
| [T10 §10.1](10-virtual-machines.md#10-1-trust-boundary) | Trust boundary |
| [T10 §10.2](10-virtual-machines.md#10-2-security-uses) | Security uses |
| [T10 §10.3](10-virtual-machines.md#10-3-virtualization-requirements) | Virtualization requirements |
| [T10 §10.4](10-virtual-machines.md#10-4-trap-and-emulate) | Trap and emulate |
| [T10 §10.5](10-virtual-machines.md#10-5-x86-virtualization-methods) | x86 virtualization methods |
| [T10 §10.6](10-virtual-machines.md#10-6-memory-and-dma) | Memory and DMA |
| [T10 §10.7](10-virtual-machines.md#10-7-attacker-controlled-lower-layers) | Attacker-controlled lower layers |
| [T10 §10.8](10-virtual-machines.md#10-8-vm-detection) | VM detection |
| [T10 §10.9](10-virtual-machines.md#10-9-covert-channels) | Covert channels |

### 11. Trusted execution environments

| Section | Topic |
|---|---|
| [T11 §11.1](11-tee.md#11-1-trust-boundaries) | Trust boundaries |
| [T11 §11.2](11-tee.md#11-2-pcrs-and-measured-boot) | PCRs and measured boot |
| [T11 §11.3](11-tee.md#11-3-remote-attestation) | Remote attestation |
| [T11 §11.4](11-tee.md#11-4-measured-boot-trusted-boot-and-sealing) | Measured boot, trusted boot and sealing |
| [T11 §11.5](11-tee.md#11-5-bitlocker) | BitLocker |
| [T11 §11.6](11-tee.md#11-6-late-launch-and-drtm) | Late launch and DRTM |
| [T11 §11.7](11-tee.md#11-7-sgx) | SGX |
| [T11 §11.8](11-tee.md#11-8-phone-tees) | Phone TEEs |
| [T11 §11.9](11-tee.md#11-9-failure-modes) | Failure modes |

### 12. Basic cryptographic primitives

| Section | Topic |
|---|---|
| [T12 §12.1](12-cryptography.md#12-1-threat-model-and-prior-knowledge) | Threat model and prior knowledge |
| [T12 §12.2](12-cryptography.md#12-2-correctness-and-perfect-secrecy) | Correctness and perfect secrecy |
| [T12 §12.3](12-cryptography.md#12-3-one-bit-ciphers) | One-bit ciphers |
| [T12 §12.4](12-cryptography.md#12-4-one-time-pad) | One-time pad |
| [T12 §12.5](12-cryptography.md#12-5-message-authentication-codes) | Message authentication codes |
| [T12 §12.6](12-cryptography.md#12-6-combining-encryption-and-authentication) | Combining encryption and authentication |
| [T12 §12.7](12-cryptography.md#12-7-merkle-trees-for-untrusted-memory) | Merkle trees for untrusted memory |

[Topic and practice map](document-topic-map.md) · [Course contents](README.md)
