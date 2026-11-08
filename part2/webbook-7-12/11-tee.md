# 11. Trusted execution environments

Prerequisites: [VMs](10-virtual-machines.md), hashes, signatures, boot. [Workbook chapter](https://compsec.kisp-lab.org/Memory-Safety-Webbook/trusted-execution-environments.dc.html).

## 11.1 Trust boundaries

- Trusted computing base (TCB): every component whose failure can defeat the security claim. Hardware isolation shrinks the software TCB; application correctness remains necessary.
- The OS can withhold CPU, memory or I/O. Confidentiality and integrity provide no availability guarantee. [SGX design](https://www.intel.com/content/dam/develop/external/us/en/documents/hasp-2013-innovative-instructions-and-software-model-for-isolated-execution.pdf).

| Design | Protected object or operation | Software still trusted | Main qualification |
|---|---|---|---|
| TPM | Keys, measurements and policy checks inside the TPM | Initial measurement code and subsequent accepted measurers | Does not execute or isolate the application |
| TXT / SKINIT | A measured launch and its protected execution environment | Launched code and any remaining privileged platform services | Launch-time isolation must continue after launch |
| TrustZone | Secure-world memory, devices and services | Secure monitor, trusted OS, trusted applications | Isolation between trusted applications depends on the secure OS |
| SGX | Enclave pages within a process | Enclave code, processor implementation and microcode | Host still controls scheduling, paging and external services |
| Apple Secure Enclave | Dedicated security processor and protected state | Boot ROM, sepOS and relevant hardware | Separate processor, with its own software TCB |

Sources: [TPM introduction](https://trustedcomputinggroup.org/wp-content/uploads/Trusted-Platform-Module-2.0-Library-Part-0-Version-184_pub.pdf), [bootstrapping trust](https://www.andrew.cmu.edu/user/bparno/papers/BootstrappingTrustBook.pdf), [Arm architecture](https://documentation-service.arm.com/static/5f212796500e883ab8e74531), [Apple Platform Security](https://help.apple.com/pdf/security/en_US/apple-platform-security-guide.pdf).

Malware can move below the defender: kernel, hypervisor, firmware/SMM. Hardware roots anchor checks; hardware implementation and manufacturing remain trusted.

| Tool | Property used here |
|---|---|
| Encryption | Hides plaintext without the key |
| MAC | Detects modification for parties sharing a secret |
| Digital signature | Lets a verifier authenticate data using a public key |
| Cryptographic hash | Commits to measured bytes; SHA-256 produces 32 bytes |

[Workbook](https://compsec.kisp-lab.org/Memory-Safety-Webbook/trusted-execution-environments.dc.html).

## 11.2 PCRs and measured boot

A platform configuration register (PCR) stores a fixed-size digest:

```text
measurement = H(component_bytes)
PCR_next = H(PCR_current || measurement)
```

- Order matters: A then B generally differs from B then A.
- Extending a clean measurement after a malicious one preserves the earlier history. Restoring a chosen digest by extension requires breaking preimage resistance.
- Reset permissions depend on the PCR/platform profile. Resettable application PCRs lack protected boot PCRs' history guarantee.

[TPM guide](https://sweet.ua.pt/andre.zuquete/Aulas/AES/extras/Arthur-Challener2015_Book_APracticalGuideToTPM20.pdf); [PCR reset command](https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_pcrreset.1/).

Measured boot: the initial root of trust measures the next stage; each accepted stage repeats this before transferring control.

- The TPM records supplied digests without inspecting executed bytes. A compromised first measurer can report clean digests for malicious code.
- Exploiting code after measurement leaves its original digest unchanged. [Flicker](https://www.cs.wm.edu/~smherwig/readings/papers/08-eurosys-flicker.pdf).

> Linux IMA measures loaded executable content beyond boot; it still trusts the measurement machinery. [Sailer et al., IMA](https://www.usenix.org/legacy/publications/library/proceedings/sec04/tech/sailer.html).

### Event logs

The event log supplies the sequence behind a PCR. Check it against signed PCR evidence:

```text
for each selected PCR:
    replay = platform-defined initial value
    for event in that PCR's ordered log:
        replay = H(replay || event.digest)
    require replay == authenticated_PCR_value
    appraise each event against the verifier's policy
```

`tpm2_eventlog` parses the binary log. Acceptance also requires correct event semantics, trusted measurement coverage and policy appraisal. [Event log tooling](https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_eventlog.1/).

## 11.3 Remote attestation

<mermaid>
sequenceDiagram
    participant V as Verifier
    participant P as Platform and TPM
    V->>P: Fresh nonce and PCR selection
    P-->>V: Signed quote, PCR values, event log
    V->>V: Verify key, signature and nonce
    V->>V: Replay log and appraise measurements
</mermaid>

A TPM quote signs the selected PCR digest and caller-supplied qualifying data, usually a fresh nonce. Measured-program safety still requires appraisal. [Quote](https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_quote.1/).

| Check | Failure it addresses |
|---|---|
| Trusted attestation-key provenance | Attacker supplies its own signing key |
| Signature and PCR digest | Altered quote or substituted PCR values |
| Fresh nonce bound to this request | Replay of an old acceptable report |
| Expected PCR selection and algorithm | Attacker omits relevant measurements |
| Log replay and component policy | Genuine report describes unacceptable software |

`tpm2_checkquote` verifies signatures, qualifying data and PCR data; policy must still reject unacceptable measurements. [Checkquote](https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_checkquote.1/).

### AK, EK and privacy

- EK (endorsement key) and credential establish TPM authenticity.
- AK (AIK in TPM 1.2) signs attestation evidence; restricted signing prevents general-purpose quote forgery.
- Credential activation binds an AK name to the TPM holding an EK private key. The verifier/attestation CA must trust that EK credential.
- Reusing an AK permits report correlation. Separate AKs reduce this link; other identifiers can still defeat anonymity.

[TCG](https://trustedcomputinggroup.org/wp-content/uploads/Trusted-Platform-Module-2.0-Library-Part-0-Version-184_pub.pdf); [Credential activation](https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_makecredential.1/).

> Cuckoo attack: malicious software relays requests to another machine's genuine TPM. Attestation must bind the physical platform, TPM and measured execution. [Parno's original cuckoo-attack analysis](https://www.usenix.org/event/hotsec08/tech/full_papers/parno/parno.pdf).

## 11.4 Measured boot, trusted boot and sealing

| Mechanism | Decision | Consequence |
|---|---|---|
| Measured boot | Record measurements | Execution history for later appraisal |
| Digest-based trusted boot | Match accepted digest | Refuse unexpected stage |
| UEFI Secure Boot | Apply trust/revocation policy | Refuse unauthorized image |
| PCR-based sealing | Satisfy object policy | Release secret on success |

Secure Boot checks image authorization at load time against authorized/forbidden databases of hashes and certificates. One signer can approve multiple updates; unsafe images/signers need revocation. [UEFI §32](https://uefi.org/specs/UEFI/2.10/32_Secure_Boot_and_Driver_Signing.html).

### Sealed objects

A sealed object can require specified PCR values. Its disk blob remains encrypted under the TPM object hierarchy. Workflow: construct PCR policy, create object, satisfy policy in an authorization session, unseal. [PCR policy](https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_policypcr.1/).

| Situation | Expected result under an exact PCR policy |
|---|---|
| Same TPM, accepted measured state | Unseal can succeed |
| Changed measured component | PCR policy fails |
| Extra extend after malicious measurement | Still fails to reconstruct the accepted digest |
| Blob copied to another TPM | Original protected object cannot simply be opened |
| Accepted system compromised after measurement | PCR policy may still succeed |
| Authorized software update | Policy/recovery planning needed |

[A Practical Guide to TPM 2.0](https://sweet.ua.pt/andre.zuquete/Aulas/AES/extras/Arthur-Challener2015_Book_APracticalGuideToTPM20.pdf).

The `swtpm` exercise uses stand-in boot files and application-resettable PCR 23. Reset models reboot; privileged malware could also reset it and replay accepted measurements. [Workbook experiment](https://compsec.kisp-lab.org/Memory-Safety-Webbook/trusted-execution-environments.dc.html).

## 11.5 BitLocker

```text
TPM-backed key protector
        |
        v
Volume Master Key (VMK)
        | protects
        v
Full Volume Encryption Key (FVEK)
        | encrypts/decrypts
        v
Volume sectors
```

- Recovery and TPM protectors can protect separate copies of the VMK. Sector encryption runs outside the TPM.
- Boot components must remain accessible before unlocking the OS volume.
- Legitimate firmware/configuration changes can alter measured boot state and trigger recovery.

[BitLocker planning guide](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/planning-guide); [BitLocker overview](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/).

### PCR 11 prevents late unsealing

1. Seal the protector to the boot manager's early PCR 11 state.
2. Change PCR 11 before handing control to any boot loader.
3. A replacement OS on the same hardware cannot unseal the stolen blob afterwards. Keys already in RAM remain exposed to memory attacks. [BitLocker countermeasures](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/countermeasures).

Compatible Secure Boot configurations can use PCR 7 (Secure Boot state) and PCR 11 (BitLocker access control); other configurations use different profiles. [BitLocker configuration](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/configure).

> TPM-only startup needs no user preboot secret; TPM plus PIN adds authorization and anti-hammering. Physical interception of discrete TPM communications remains a deployment concern. An unlocked machine also needs OS and memory protection. [Microsoft's physical-attack guidance](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/countermeasures).

## 11.6 Late launch and DRTM

> Wojtczuk and Tereshkin's 2009 BIOS attack used an unsigned splash BMP inside a signed-code update. Overflow in `width * height * sizeof(pixel)` caused undersized allocation and firmware code execution. Signed code still needs safe parsers for unsigned inputs. [BIOS attack, pp. 34 to 42](https://www.blackhat.com/presentations/bh-usa-09/WOJTCZUK/BHUSA09-Wojtczuk-AtkIntelBios-SLIDES.pdf).

| SRTM | DRTM |
|---|---|
| Measurement begins at reset | Measurement begins through a special launch operation |
| Trust includes the initial boot measurer and chain | Excludes much earlier execution from the new measured chain |
| Large firmware chain complicates assurance | Smaller launch boundary; platform-specific residual trust remains |

| Launch property | Mechanism |
|---|---|
| AMD `SKINIT` | Protect/measure Secure Loader Block, disable interrupts/debug access, enter measured code |
| Intel `GETSEC[SENTER]` | Authenticated code module precedes measured environment |
| Protected transition | Interrupts disabled; measured memory protected from DMA; no attacker-controlled gap between measurement and entry |
| Dynamic PCR reset | Special launch authority/locality; ordinary software cannot reproduce PCR 17 launch reset |
| Historical PC PCR 17 | All ones after reset; zero at dynamic launch. Details vary by TPM/platform generation |

[Bootstrapping trust](https://www.andrew.cmu.edu/user/bparno/papers/BootstrappingTrustBook.pdf).

- Flicker suspends the OS, runs a sensitive computation, then resumes it; as few as 250 additional trusted prototype lines.
- Protect cross-boundary inputs, outputs and saved state; repeated invocations need continuity and freshness.

[Flicker paper](https://www.cs.wm.edu/~smherwig/readings/papers/08-eurosys-flicker.pdf).

XMHF launches its hypervisor with `SKINIT`/`GETSEC[SENTER]`. Verification covers specified properties, including hypervisor memory integrity, under hardware/model assumptions. [XMHF paper](https://www.ieee-security.org/TC/SP2013/papers/4977a430.pdf).

> Historical TXT attacks used compromised SMM to attack the freshly launched environment. DRTM must constrain firmware that can execute after launch. [TXT attacks](https://invisiblethingslab.com/resources/bh09dc/Attacking%20Intel%20TXT%20-%20slides.pdf).

## 11.7 SGX

Hardware metadata protects enclave pages against ordinary loads from code outside the enclave, including the kernel and hypervisor, including page-table manipulation. Defined transitions control entry/exit; the OS manages resources. [SGX design](https://www.intel.com/content/dam/develop/external/us/en/documents/hasp-2013-innovative-instructions-and-software-model-for-isolated-execution.pdf).

### Measurement coverage

| Construction operation | Contribution |
|---|---|
| `ECREATE` | Starts enclave construction |
| `EADD` | Adds a page and records layout/attributes |
| `EEXTEND` | Measures selected page contents |
| `EINIT` | Finalizes initial identity and permits execution |

Measurement commits to recorded construction history. Unmeasured bytes and later-loaded code/data need enclave-side verification. A measured loader can check signed code; attestation then identifies the loader/policy, without automatically identifying every later byte. [SGX Explained](https://css.csail.mit.edu/6.858/2020/readings/costan-sgx.pdf).

Before provisioning secrets, the verifier appraises enclave identity, measured software and attestation trust chain. Application correctness remains a separate requirement. [SGX design](https://www.intel.com/content/dam/develop/external/us/en/documents/hasp-2013-innovative-instructions-and-software-model-for-isolated-execution.pdf).

### Sealing identities

| Identity | Typical consequence |
|---|---|
| `MRENCLAVE` | Bind access to the measured enclave identity |
| `MRSIGNER` | Permit appropriately authorized versions under the same signer identity |

Sealing policy also includes product identity, security versions and key-derivation parameters. Plan upgrade authorization and rollback/freshness protection separately. [Intel's sealing guide](https://www.intel.com/content/www/us/en/developer/articles/technical/introduction-to-intel-sgx-sealing.html).

### Memory protection by generation

| Implementation | Off-package protection |
|---|---|
| Original MEE-based SGX | Encryption plus integrity/replay checking using an integrity tree |
| 3rd-generation Xeon Scalable server design discussed by Intel | AES-XTS encryption without the original integrity tree, enabling much larger EPC sizes |

Page ownership checks do not establish physical DRAM integrity. Guarantees depend on the processor generation. [Linux SGX encryption engines](https://docs.kernel.org/arch/x86/sgx.html#encryption-engines), [Intel, 2025](https://www.intel.com/content/www/us/en/developer/articles/news/more-information-encrypted-memory-frameworks.html).

## 11.8 Phone TEEs

| Property | Arm TrustZone on application processors | Apple Secure Enclave |
|---|---|---|
| Execution | Secure and normal worlds on a processor | Dedicated security subsystem/processor |
| Switching | Secure monitor saves/restores world context | Communication with the application processor |
| Resource protection | Secure attributes propagate to memory/peripherals | Protected memory plus security-specific engines |
| Software trust | Monitor and secure-world OS | Boot ROM and sepOS |

- TrustZone: secure world can access normal-world resources; reverse access is restricted. The trusted OS must isolate trusted applications. World switches must preserve register/shared-buffer confidentiality. [Arm TrustZone architecture](https://documentation-service.arm.com/static/5f212796500e883ab8e74531).

- Secure Enclave: immutable Boot ROM verifies sepOS; memory protection engine protects dedicated RAM. Device-unique UID binds secrets to hardware without exposing the raw key to ordinary software. Used for biometrics/file protection. Later boot monitors strengthen OS-bound keys; protections vary by chip generation. [Apple Platform Security](https://help.apple.com/pdf/security/en_US/apple-platform-security-guide.pdf).

## 11.9 Failure modes

| Attack or limitation | Mechanism | Security implication |
|---|---|---|
| Controlled channel | Host removes mappings and observes induced page faults | Page access sequence reveals secret-dependent behavior |
| Foreshadow | Transient execution leaks SGX plaintext through microarchitectural state | Enclave memory and architectural enclave keys can leak |
| Trusted-code bug | Enclave accepts unsafe inputs or corrupts its own memory | Hardware boundary contains vulnerable code |
| Physical interception | Attacker probes exposed communication paths | Discrete TPM deployment assumptions matter |
| Denial of service | Host refuses resources | Protected execution cannot guarantee completion |

Controlled-channel attacks recovered text and JPEG outlines from Haven/InkTag applications through access patterns. [Controlled channels](https://www.microsoft.com/en-us/research/wp-content/uploads/2016/02/ctrlchannels-oakland-2015.pdf).

Foreshadow extracted attestation/sealing material, enabling forged reports and compromising sealed data. Attestation depends on implementation security and platform updates. [Foreshadow](https://foreshadowattack.eu/).

> Keep enclave interfaces small; validate pointer ranges, lengths and host-returned values. Avoid repeated reads of mutable untrusted buffers. TeeRex found memory-corruption bugs in real enclaves. [TeeRex](https://arxiv.org/abs/2007.07586).
