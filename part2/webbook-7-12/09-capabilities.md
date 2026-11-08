# 9. Access control and capabilities

## 9.1 Authority and identity

An access matrix records `rights[domain, object]`; a protection domain is executing code's authority, which need not match one human user. See [topic 8](08-policies.md) for matrix representations. Sparse implementations store useful entries. A hybrid checks an ACL at `open`, then issues a capability. [Lampson](https://bwlampson.site/08-Protection/WebPage.html)

Identity-based access resembles a concert guest list; capabilities resemble transferable tickets. The former authenticates a principal; the latter authorizes its holder. Identity checks evaluate `IsAllowed(principal, operation, object)`. [Workbook](https://compsec.kisp-lab.org/Memory-Safety-Webbook/access-control-and-capabilities.dc.html)

See [access models](08-policies.md#8-2-access-matrix) and [delegation](#9-6-delegation-and-revocation).

Unix permissions encode owner/group/other read, write and execute rights; path lookup also needs directory search permission. Linux normally checks filesystem UID/GID (usually effective IDs) and supplementary groups. [chmod](https://man7.org/linux/man-pages/man2/chmod.2.html), [path lookup](https://man7.org/linux/man-pages/man7/path_resolution.7.html)

## 9.2 Ambient authority

Ambient authority comes from the execution environment without an explicitly delegated reference for the task. A browser processing hostile content commonly needs much less authority than its user possesses. [Capsicum](https://www.cl.cam.ac.uk/research/security/capsicum/papers/2010usenix-security-capsicum-website.pdf)

```sh
cp foo.txt bar.txt
```

- Alice intends two file accesses. Compromised, unsandboxed `cp` can also modify `.bashrc`, `authorized_keys` or her thesis using her permissions.
- Running as root broadens the damage. [Workbook](https://compsec.kisp-lab.org/Memory-Safety-Webbook/access-control-and-capabilities.dc.html)

[Least privilege](08-policies.md#8-1-choosing-the-default) limits task authority, accidental damage and privileged code requiring audit; [complete mediation](07-sandboxing.md#7-2-reference-monitors-and-neat) covers every access route.

### Confused deputy

| Hardy's compiler | Detail |
| --- | --- |
| Private work | Write usage statistics to `(SYSX)STAT` |
| Excess authority | A home-files license permits writes throughout `SYSX` |
| Caller-controlled input | Debugging output filename |
| Attack | Request `(SYSX)BILL`; compiler overwrites billing data using authority its caller lacks |
| Capability repair | Keep statistics authority private; accept a separate caller-provided output capability |

The compiler confuses its authority with the caller's. A filename blacklist fails when new sensitive files appear; legitimate callers may also have `SYSX` write permission. An output capability specifies both destination and authority. [Hardy](https://cs.nyu.edu/~mwalfish/classes/ut/s11-cs372h/ref/hardy-confused-deputy.html)

## 9.3 Capability references

```text
capability = (object reference, permitted operations)
```

- Possession authorizes specified operations on that object. Pure capability systems provide no ambient bypass.
- Programs cannot forge inaccessible capabilities; receiving, copying and delegation follow system rules.
- An object name identifies an object but grants no authority. A capability does both. [Workbook](https://compsec.kisp-lab.org/Memory-Safety-Webbook/access-control-and-capabilities.dc.html)

| Implementation | Protected authority | User representation |
| --- | --- | --- |
| Unix descriptor | Kernel descriptor/open-file tables | Process-local integer index |
| CHERI pointer | Hardware metadata and validity tag | Address with bounded authority |

Guessing descriptor `3` cannot create a missing table entry. CHERI enforces valid derivation without increasing bounds or permissions. [open](https://man7.org/linux/man-pages/man2/open.2.html), [CHERI rules](https://ctsrd-cheri.github.io/cheri-c-programming/background/architectural-rules.html)

## 9.4 Unix descriptors

<mermaid>
flowchart LR
    P[Path + credentials] --> O[open: permission check]
    O --> F[Process descriptor table]
    R[read/write: local fd] --> F
    F --> D[Open file description: mode, flags, offset]
    D --> I[File object]
</mermaid>

- `open()` returns a nonnegative integer indexing the process's table.
- `O_RDONLY`, `O_WRONLY`, `O_RDWR` select access mode; the open file description stores status flags and offset.
- Different processes' descriptor `3` can name different files or grant different access. [open](https://man7.org/linux/man-pages/man2/open.2.html)

```c
int fd = open("foo.txt", O_RDONLY);
ssize_t n = write(fd, "x", 1);  // -1, errno = EBADF
```

`write` requires write access; `read` requires read access. Later operations check descriptor rights without repeating ACL lookups. File ownership cannot upgrade a descriptor's mode. [write](https://man7.org/linux/man-pages/man2/write.2.html), [read](https://man7.org/linux/man-pages/man2/read.2.html)

## 9.5 Sandboxing delegated authority

```sh
cat < foo.txt > bar.txt
```

The shell delegates stdin `0`, stdout `1`, normally stderr `2`. Redirection leaves `cat` able to open other files; sandboxing must remove that route. [Workbook](https://compsec.kisp-lab.org/Memory-Safety-Webbook/access-control-and-capabilities.dc.html)

### Strict seccomp

[Strict seccomp](07-sandboxing.md#7-3-syscall-policies) preserves descriptor reads/writes but forbids `open`, `fstat` and `close`. Complete setup and dynamic linking first; library termination must use an allowed syscall.

- Close unwanted descriptors before launching the worker: leaked descriptors still grant authority.
- Ordinary `open` preserves descriptors across `execve`; `O_CLOEXEC` prevents unintended inheritance. [open](https://man7.org/linux/man-pages/man2/open.2.html)

> Sensitive input plus an attacker-observable output permits disclosure even under `read`/`write` restrictions. Restrict objects and [information flows](08-policies.md#8-9-information-flow).

### Capsicum

- FreeBSD `cap_enter()` disables direct global-namespace access. Descendants inherit the mode; it cannot be cleared.
- Existing descriptors grant delegated access. `cap_rights_limit()` narrows their rights; separate interfaces restrict `ioctl` and `fcntl`. [Capsicum](https://www.cl.cam.ac.uk/research/security/capsicum/papers/2010usenix-security-capsicum-website.pdf), [interface](https://cgit.freebsd.org/src/tree/sys/sys/capsicum.h?id=4695e3aa7c685c092cb4b2662bee16c31be790f8)

> FreeBSD's `dhclient` compartment permits selected routing/BPF reads and interface queries. Its lease descriptor permits overwriting without reading. [Application example](https://www.cl.cam.ac.uk/research/security/capsicum/freebsd.html)

## 9.6 Delegation and revocation

Unix-domain descriptor transfer uses ancillary `SCM_RIGHTS` data:

```text
sendmsg(fd) → kernel installs open-file reference → recvmsg(new local fd)
```

- Sender and receiver numbers may differ. Sending ordinary bytes `"3"` creates no descriptor.
- Like cross-process duplication, transfer shares the open file description, including offset/status flags.
- Receiving write authority leaves an existing read-only descriptor unchanged.
- Accidental inheritance also delegates authority; the kernel cannot identify the mistake. [unix](https://man7.org/linux/man-pages/man7/unix.7.html)

### Permission changes

```c
int fd = open("foo.txt", O_RDONLY);
chmod("foo.txt", 0);
int again = open("foo.txt", O_RDONLY); // denied for ordinary caller
read(fd, buf, sizeof buf);            // existing local-file fd remains usable
```

Mode changes do not revoke this existing local-file descriptor. NFS server checks can apply restrictions to already-open files; privileged callers may bypass ordinary mode checks. [Workbook](https://compsec.kisp-lab.org/Memory-Safety-Webbook/access-control-and-capabilities.dc.html), [NFS notes](https://man7.org/linux/man-pages/man2/chmod.2.html), [privileges](https://man7.org/linux/man-pages/man7/capabilities.7.html)

### Revocable indirection

```text
delegate → revocable forwarder → object
                  ↑
          owner disconnects it
```

Copying eases delegation but complicates auditing and withdrawal. The owner can destroy the forwarder, revoking all its users. Separate forwarders create separate revocation groups. Delegates must receive only the forwarder: a direct object reference bypasses revocation. Future access stops; copied information remains. [Indirect objects](https://web.mit.edu/Saltzer/www/publications/protection/Descriptors.html)

## 9.7 Page tables and CHERI

### Page-table limits

- The MMU translates addresses and checks mapping permissions; TLB hits avoid repeated page-table walks. [Page tables](https://docs.kernel.org/mm/page_tables.html)
- Ordinary pointers are computable addresses. The current process's table, rooted at x86-64 `CR3`, supplies authority.
- This identity-based policy protects mappings, without bounding each pointer to its intended allocation. A per-process table resembling a capability-list row does not change that. [Capstone](https://www.usenix.org/system/files/usenixsecurity23-yu-jason.pdf), [CR3](https://www.microsoft.com/en-us/security/blog/2020/07/08/introducing-kernel-data-protection-a-new-platform-security-technology-for-preventing-data-corruption/)

### CHERI enforcement

| Field/rule | Effect |
| --- | --- |
| Address | Requested virtual location |
| Bounds | Accessible range |
| Permissions | Allowed operations, including data/capability loads/stores |
| Protected validity tag | Reject forged/corrupted capability bytes |
| Sealed object type | Opaque reference; no direct modification or dereference |

- Tags lie outside addressable memory. Overlapping byte writes clear a stored capability's tag; matching address bits cannot restore it.
- Boot-supplied roots permit derivation; descendants cannot expand bounds/permissions. Software can narrow authority without a privileged round trip.
- Hardware protects references and their use; atomic updates prevent corrupted data retaining an old valid tag. [Capabilities](https://ctsrd-cheri.github.io/cheri-c-programming/background/cheri-capabilities.html), [rules](https://ctsrd-cheri.github.io/cheri-c-programming/background/architectural-rules.html)
- CHERI coexists with virtual memory. OS/compiler/runtime select policy and bounds; hardware enforces them. Pure capability software uses capability pointers throughout; hybrid migration mixes conventional and capability code. Arm Morello and CHERI-RISC-V implement this approach. [FAQ](https://www.cl.cam.ac.uk/research/security/ctsrd/cheri/cheri-faq.html)

> Out-of-bounds pointer computation can preserve a valid tag when the address remains representable; dereferencing outside bounds still fails. Compressed bounds impose alignment/precision limits, especially for large objects. [Bounds](https://ctsrd-cheri.github.io/cheri-c-programming/background/cheri-capabilities.html)

> CHERI's base bounds/tag checks provide spatial protection. Stale aliases after deallocation require additional allocation/revocation mechanisms for temporal safety. [Capstone](https://www.usenix.org/system/files/usenixsecurity23-yu-jason.pdf)

Capstone (NUS and collaborators, 2023) supports isolation without trusting privileged software, including the OS. It demonstrated six memory-model constructions, including enclave models, a scheduler, an allocator and Rust-style memory safety. These research results do not describe every capability system's trusted base. [Capstone presentation](https://www.usenix.org/conference/usenixsecurity23/presentation/yu-jason)

> Linux `CAP_NET_BIND_SERVICE` splits root privilege. It grants a process/thread privileged-port binding authority, without naming a specific socket as an object capability would. [Linux capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html)
