# 10. Virtual machines

## 10.1 Trust boundary

A virtual machine monitor (VMM/hypervisor) allocates resources to guest OSs, each with its own kernel and applications. Isolation must survive guest kernel compromise.

| Component | Trust requirement |
| --- | --- |
| Guest applications, drivers, kernel | Treat as hostile |
| VMM | Correct resource allocation, virtual hardware and isolation |
| Host OS of a hosted VMM | Included in trusted computing base |
| Hardware/firmware | Enforce underlying protection |

Bare-metal VMMs remove the host OS dependency. Other uses include concurrent OSs, legacy environments and resource-restricted testing. [Robin and Irvine](https://www.usenix.org/legacy/publications/library/proceedings/sec2000/full_papers/robin/robin_html/index.html)

> HyperSafe hardens hypervisors through code/static-data memory lockdown and restricted pointer indexing for indirect transfers. BitVisor and Xen prototypes demonstrate hardening, without proving all hypervisor behavior correct. [HyperSafe](https://www.cs.fsu.edu/~zwang/files/oakland10.pdf)

### Kernel-controlled observations

| Windows filter layer | Intercepted requests |
| --- | --- |
| File system | Files and directory queries |
| Volume | Mounted volume operations |
| Disk | Disk operations |
| Bus | Bus device operations |

Security software uses these filters legitimately. Rootkits can remove directory entries before a scanner receives them: correct scanning fails on fabricated kernel observations. [File-system filters](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/), [driver types](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/types-of-wdm-drivers), [workbook](https://compsec.kisp-lab.org/Memory-Safety-Webbook/virtual-machines.dc.html)

## 10.2 Security uses

| Use | Mechanism/assumption |
| --- | --- |
| Separate trust domains | Banking and everyday browsing in separate VMs; prevent unintended cross-domain access |
| Malware analysis | Disposable guest; prevent escape, account for analysis detection |
| VM introspection (VMI) | Inspect guest state externally; trust monitor and interpret raw state correctly |
| Protect applications from OS | Additional boundary and trusted components within VM |

- Livewire moved IDS outside the monitored OS while retaining machine-state visibility, combining host IDS visibility with network IDS resistance to direct compromise. It demonstrated policies against real attacks. [Livewire](https://suif.stanford.edu/papers/vmi-ndss03.pdf)
- Overshadow gave protected applications plaintext and the compromised guest OS an encrypted view. Its trusted base included application, shim, VMM and hardware. OS services remained necessary; malicious syscall results required checking. [Overshadow](https://xenon.stanford.edu/~talg/papers/ASPLOS08/abstract.html), [syscall risks](https://www.usenix.org/legacy/event/hotsec08/tech/full_papers/ports/ports_html/)

> Qubes separates desktop activities and services into Xen compartments. Colored borders identify trust domains; supported mechanisms explicitly transfer files/clipboard data. [Qubes](https://www.qubes-os.org/intro/), [architecture](https://www.qubes-os.org/doc/QubesArchitecture/)

## 10.3 Virtualization requirements

| Requirement | Meaning |
| --- | --- |
| Equivalence/fidelity | Match original-machine behavior, allowing timing/resource differences |
| Resource control | VMM controls allocation and can regain control |
| Efficiency | Dominant instruction subset runs directly on CPU |

Popek and Goldberg's sufficient condition for classical virtualization:

```text
sensitive instructions ⊆ privileged instructions
```

| Instruction class | Definition |
| --- | --- |
| Privileged | Traps outside supervisor mode |
| Control-sensitive | Changes resource configuration |
| Behavior-sensitive | Behavior depends on configuration/execution mode |

Unintercepted sensitive operations can expose wrong state or escape VMM tracking. The theorem's architectural condition is sufficient; failing it leaves binary translation or guest modification possible. [Popek and Goldberg](https://www.cse.iitb.ac.in/~puru/courses/spring2024-25/downloads/popekgoldberg.pdf)

Complete mediation includes mappings, I/O and DMA. Compatibility means existing software works; transparency means software cannot detect virtualization. [Intel VMX](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-3c-part-3-manual.pdf), [transparency](https://www.usenix.org/legacy/event/hotos07/tech/full_papers/garfinkel/garfinkel_html/)

## 10.4 Trap and emulate

| Code | Native ring | Classical VMM example |
| --- | --- | --- |
| Applications | 3 | 3 |
| Guest kernel | 0 | 1 |
| VMM | Absent | 0 |

Ordinary instructions execute directly; sensitive operations transfer control to update virtual state. Ring 1 is a historical guest placement. [Adams and Agesen](https://web.stanford.edu/class/archive/cs/cs240/cs240.1136/readings/asplos235_adams.pdf)

### x86 interrupt-state failure

Assume protected mode, `IOPL = 0`, no special virtual-interrupt extension:

| Instruction | Native CPL 0 | Guest CPL 1 |
| --- | --- | --- |
| `cli` | Clear IF | General-protection fault; VMM clears virtual IF |
| `popf` | Restore IF | IF update silently suppressed; no VMM interception |

IF controls maskable external interrupts; exceptions and non-maskable interrupts remain possible. `popf` changes IF only when CPL is sufficiently privileged relative to IOPL; behavior depends on execution mode. [CLI](https://www.intel.com/content/dam/support/us/en/documents/processors/pentium4/sb/25366621.pdf), [POPF](https://www.intel.com/content/dam/support/us/en/documents/processors/pentium4/sb/25366721.pdf)

```text
save flags → CLI → critical section → POPF
             trap                     no trap
             virtual IF := 0          virtual IF stays 0
```

The guest expects restored interrupts; VMM state stays stale. Sensitive reads also fail: historical `sidt` could reveal actual IDTR instead of virtual state. Robin/Irvine identified 17 problematic instructions among roughly 250 Pentium instructions; this count is architecture-specific. [Analysis](https://www.usenix.org/legacy/publications/library/proceedings/sec2000/full_papers/robin/robin_html/index.html)

## 10.5 x86 virtualization methods

| Method | Intervention | Guest requirement | Cost |
| --- | --- | --- | --- |
| Binary translation | Kernel machine code | Unmodified OS binary | Translation/cache and sensitive-operation handling |
| Paravirtualization | Kernel source/ABI | Modified cooperative kernel | Guest-interface porting/maintenance |
| Hardware assistance | Processor mode | Kernel retains expected ring | VM exits/resource virtualization |

### Binary translation

VMware cached short translated kernel blocks, preserving ordinary operations and rewriting problematic instructions to update virtual state or invoke VMM. User code could run directly; translation could optimize frequent interceptions. Early hardware assistance did not consistently beat mature translation because transition costs and MMU handling mattered. [Adams and Agesen](https://web.stanford.edu/class/archive/cs/cs240/cs240.1136/readings/asplos235_adams.pdf)

### Paravirtualization

Xen's modified interface uses hypercalls for controlled operations; the VMM validates requests, including page-table updates. Original Xen changed the OS but preserved applications' ABI. Its 2003 tests reported near-native performance for tested workloads. Hypercalls cross the guest-kernel/VMM boundary as syscalls cross the user/kernel boundary. [Xen](https://www.cl.cam.ac.uk/research/srg/netos/papers/2003-xensosp.pdf)

### Hardware assistance

Intel VT-x adds VMX root/non-root operation, each supporting ordinary privilege levels. Guest kernels run at CPL 0 non-root; VM entry starts/resumes execution, VM exit returns to VMM. Execution controls select interception. AMD-V provides corresponding hardware support. [Intel VMX](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-3c-part-3-manual.pdf)

> "Ring -1" is a mnemonic: VMX adds an execution dimension, without adding a numbered x86 ring. [Intel §23.3](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-3c-part-3-manual.pdf)

## 10.6 Memory and DMA

```text
Guest virtual address
  │ guest page tables: guest OS policy
  ▼
Guest physical address
  │ VMM mapping: allocation/isolation
  ▼
Host physical address
```

| Mechanism | Enforcement | Maintenance |
| --- | --- | --- |
| Shadow page tables | Composed guest-virtual to host-physical mapping | VMM tracks table writes/address-space switches |
| Nested/second-level paging | Hardware walks guest then VMM mapping | Guest owns first level; VMM owns second |
| IOMMU | Translates/restricts device DMA | VMM configures device/domain mappings |

[KVM MMU](https://cdn.kernel.org/doc/html/latest/virt/kvm/x86/mmu.html)

Shadow paging write-protects guest table pages: writes fault to VMM for guest/shadow updates; `CR3` loads also need handling. Hidden shadow-cache faults are resolved by VMM; genuine guest protection faults reach the guest. [Shadow paging](https://web.stanford.edu/class/archive/cs/cs240/cs240.1136/readings/asplos235_adams.pdf)

Intel EPT implements second-level CPU translation; VT-d supplies IOMMU support. CPU tables cannot constrain direct device RAM writes: use device emulation or controlled passthrough with DMA isolation. [EPT/VT-d](https://www.intel.com/content/www/us/en/support/articles/000058162/processors/intel-xeon-processors.html)

## 10.7 Attacker-controlled lower layers

| Prototype | Installation/result |
| --- | --- |
| SubVirt | Changes boot path; original OS becomes guest above malicious services. Demonstrated on Windows XP/Linux. |
| Blue Pill | Captures running Vista x64 using AMD virtualization, without reboot. Undetectability was its author's claim. |

[SubVirt](https://www.microsoft.com/en-us/research/wp-content/uploads/2016/02/subvirt.pdf), [Blue Pill](https://blog.invisiblethings.org/2006/06/22/introducing-blue-pill.html)

```text
Guest OS
Defender VMM/security monitor
Attacker VMM virtualizing defender
Firmware / System Management Mode
Hardware
```

An attacker below the defender can fabricate observations. SMM inspection shifts trust to firmware and SMM memory protection. Software alone cannot establish the absence of a hostile underlying layer. [Workbook](https://compsec.kisp-lab.org/Memory-Safety-Webbook/virtual-machines.dc.html)

## 10.8 VM detection

| Evidence | Example |
| --- | --- |
| Declared identity | Hypervisor CPUID bit/vendor leaves |
| Firmware/devices | DMI strings, virtual device IDs |
| Implausible combination | Historical VMware i440BX chipset emulation |
| Resource effects | VMM consumes cache/TLB capacity |
| Timing | Intercepted instructions have different latency |

`systemd-detect-virt` checks Linux environments. QEMU/TCG and KVM strings vary by configuration. Detection establishes virtualization, without identifying maliciousness. [Workbook](https://compsec.kisp-lab.org/Memory-Safety-Webbook/virtual-machines.dc.html)

Logical, resource and timing discrepancies undermine transparency. Guest-clock adjustment cannot hide relative-operation timing or external clocks; modeling every relationship is impractical. Malware may suppress behavior when detected; legitimate guests may select cooperative interfaces. [Transparency](https://www.usenix.org/legacy/event/hotos07/tech/full_papers/garfinkel/garfinkel_html/)

## 10.9 Covert channels

A compromised banking guest contacts only the bank; a cooperating everyday guest contacts the attacker. Shared contention bypasses intended network separation:

```text
Bank sender → shared cache activity → everyday receiver → attacker
```

1. Receiver primes its buffer into cache.
2. Sender evicts it through memory accesses for 1; idles for 0.
3. Receiver times accesses: slow suggests 1, fast 0.

Covert channels use cooperating endpoints and unintended paths. Side channels reveal non-cooperating victims. Ristenpart et al. studied both on EC2 in 2009. [EC2 study](https://cs-people.bu.edu/tromer/papers/cloudsec.pdf)

### Measured bandwidth

| Channel | Historical rate |
| --- | --- |
| Cache | Approximately 0.2 bits/s |
| Memory bus | 0.006 bits/s |
| Disk | 0.0005 bits/s |

The measured cache algorithm improved the elementary protocol: odd/even cache-set groups, probe-time comparisons, sample averaging and core-migration handling. These are experimental rates from that setting. [EC2 §8](https://cs-people.bu.edu/tromer/papers/cloudsec.pdf)

```text
256 bits / 0.2 bits per second = 1,280 seconds ≈ 21.3 minutes
```

This assumes an already-known key and sustained useful throughput, excluding synchronization/error correction. It calculates leakage time; the paper did not thereby demonstrate EC2 cryptographic-key extraction.

| Property | VM protection and limits |
| --- | --- |
| Integrity | Prevent cross-VM writes; requires correct VMM, device mediation and policy |
| Confidentiality | Prevent direct reads/forbidden explicit transfers; shared-resource observations remain |
| Availability | Allocate/schedule resources; contention/DoS need separate controls |

> EC2 attacks first needed co-residence, then shared-hardware observation. Avoiding hostile co-residence removes those local paths; evaluate noise/partitioning per channel. The experiments establish no general absence of other channels. [Project](https://cs-people.bu.edu/tromer/cloudsec/), [§8.5](https://cs-people.bu.edu/tromer/papers/cloudsec.pdf)
