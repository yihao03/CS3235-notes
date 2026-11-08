# 7. Sandboxing and privilege separation

## 7.1 Containment

| Defense/design | Purpose |
|---|---|
| Prevention | Stop compromise using memory safety, canaries, DEP, ASLR or CFI |
| Containment | Limit a compromised component's resources, including after dependency or non-memory-safety bugs |
| Policy/enforcement separation | Specify allowed requests separately from their checks |
| Small trusted computing base (TCB) | Minimize components whose correctness protects the resource |
| Least privilege | Give each component only required permissions |

Prevention and containment coexist. A small trusted broker can authenticate users and create sessions for a larger untrusted parser. [Chromium](https://blog.chromium.org/2008/09/security-architecture.html?hl=sk), [Provos, Friedl and Honeyman: privilege separation](https://usenix.org/legacy/events/sec03/tech/full_papers/provos_et_al/provos_et_al_html/index.html)

> Fail-safe defaults require explicit grants; economy of mechanism favors simple protection code. See [policy defaults](08-policies.md#8-1-choosing-the-default). [Original design principles](https://web.mit.edu/Saltzer/www/publications/protection/Basic.html)

## 7.2 Reference monitors and NEAT

A reference monitor checks a principal's requested operation on an object. Examples: users/processes/origins accessing files/sockets/DOMs. See [access models](08-policies.md#8-2-access-matrix).

<mermaid>
flowchart LR
    P[Principal] --> R[Reference monitor]
    Policy[Access policy] --> R
    R -->|Allow operation| O[Protected object]
    R -->|Deny| D[Reject request]
</mermaid>

| NEAT | Standard requirement |
|---|---|
| Non-bypassable | Complete mediation: no unchecked access path |
| Evaluable | Small and simple enough to verify |
| Always invoked | Complete mediation: every protected access is checked |
| Tamper-proof | Tamper resistance: monitored code cannot alter checks or rules |

Non-bypassable and always invoked overlap: both require complete mediation. [NIST: reference monitor](https://csrc.nist.gov/glossary/term/reference_monitor)

> Complete mediation includes initialization, recovery and shutdown. Cached authorization decisions need invalidation when authority changes. [Saltzer and Schroeder](https://web.mit.edu/Saltzer/www/publications/protection/Basic.html)

## 7.3 Syscall policies

A 30-byte stack-buffer overflow redirects execution to shellcode. `/bin/sh` needs `execve`; file theft can use `openat`, `read`, then `write`.

| Policy | Consequence |
|---|---|
| Deny `execve`; allow everything else | Stops shell execution; permits file theft through other calls |
| Deny `execve` after the first `read` | Requires remembered execution history |
| Allow `read`, `write(fd=1)`, `exit_group` | Constrains operations and output destination; does not classify output bytes |

A parser holding a private key can leak it through an allowed `write`. Separate the key and [release decision](08-policies.md#8-9-information-flow) from parsing. [Workbook: syscall playground](https://compsec.kisp-lab.org/Memory-Safety-Webbook/sandboxing-and-privilege-separation.dc.html)

### Linux enforcement mechanisms

| Mechanism | Checks and behavior | Limit |
|---|---|---|
| seccomp strict | Only `read`, `write`, raw `_exit` and `sigreturn`; disallowed calls terminate the thread, with `SIGKILL` process termination for a single-threaded process | Fixed policy; `exit_group` is forbidden |
| seccomp-bpf | Filter over syscall metadata, including number, architecture and six argument slots | Cannot dereference argument pointers |
| Linux Security Modules (LSMs) | Hooks inside kernel operations, with security attributes on objects | LSM framework needs an actual module/policy to enforce access rules |

[seccomp manual](https://man7.org/linux/man-pages/man2/seccomp.2.html), [kernel filter documentation](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html), [LSM framework](https://www.kernel.org/doc/html/latest/security/lsm.html).

Strict mode permits raw `_exit`; a library calling `exit_group` kills even an honest program. [seccomp manual](https://man7.org/linux/man-pages/man2/seccomp.2.html)

### Filter limits and installation

- `openat(dirfd, pathname, flags, mode)`: BPF sees the pathname pointer, not the filename. Dereferencing mutable userspace memory would permit TOCTOU: another thread changes it before kernel use.
- Classic filters are stateless. Finish startup before tightening restrictions for input handling.
- Filters survive allowed `fork`/`clone` and `execve`; additional filters tighten restrictions.
- Installation needs `no_new_privs` or `CAP_SYS_ADMIN` in the caller's user namespace, preventing malicious filters on later-executed privileged programs. [Kernel seccomp documentation](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html), [seccomp manual](https://man7.org/linux/man-pages/man2/seccomp.2.html)

File policies can use kernel inode/file hooks or a broker that validates and performs requests. [LSM object hooks](https://www.kernel.org/doc/html/latest/security/lsm.html), [OpenSSH broker design](https://usenix.org/legacy/events/sec03/tech/full_papers/provos_et_al/provos_et_al_html/index.html)

> Check architecture: syscall numbers differ across ABIs. Actions include allow, error, trap, thread/process termination and notification. [Kernel seccomp documentation](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html)

### Expressing an allow-list with libseccomp

```text
ctx := seccomp_init(KILL_PROCESS)
require ctx != null
require rule_add(ctx, ALLOW, read) succeeds
require rule_add(ctx, ALLOW, write, argument[0] == 1) succeeds
require rule_add(ctx, ALLOW, exit_group) succeeds
require seccomp_load(ctx) succeeds
seccomp_release(ctx)
process_untrusted_input()
```

- Default `KILL_PROCESS`: unmatched calls terminate the process with `SIGSYS`.
- `SCMP_A0(SCMP_CMP_EQ, 1)`: first argument (output FD) must equal 1.
- `seccomp_load` activates the filter; releasing the library context leaves it installed.
- Abort on installation failure. Startup and platform-specific syscalls are omitted. [Initialization](https://man7.org/linux/man-pages/man3/seccomp_init.3.html), [argument comparisons](https://man7.org/linux/man-pages/man3/seccomp_rule_add.3.html), [loading](https://man7.org/linux/man-pages/man3/seccomp_load.3.html)

> Seccomp reduces kernel attack surface; information-flow rules and other sandbox boundaries need separate enforcement. Test every required path, including library syscalls. [Kernel scope statement](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html), [Chromium Linux sandbox](https://chromium.googlesource.com/chromium/src.git/+/master/sandbox/linux)

## 7.4 OpenSSH

Architecture adopted in 2002, documented in 2003:

<mermaid>
flowchart LR
    N[Untrusted network] --> C[Unprivileged parser child]
    C -->|Typed IPC requests| M[Privileged monitor]
    M -->|Validate and perform| A[Authentication and session resources]
    M -->|Result or descriptor| C
</mermaid>

| Component | Authority and responsibility |
|---|---|
| Pre-authentication child | Empty filesystem root via `chroot`; dedicated UID/GID; network processing |
| Monitor | Retains privileged operations; validates requests and authentication state |
| Post-authentication child | Runs with authenticated user's permissions; requests remaining privileged operations |

`socketpair` IPC returns information, transfers descriptors and supports identity changes. For pseudo-terminals, the monitor creates the terminal and passes its FD; the child needs no general root authority.

The monitor must independently validate requests, protocol state and authorization, even from a compromised child. [Original OpenSSH design](https://usenix.org/legacy/events/sec03/tech/full_papers/provos_et_al/provos_et_al_html/index.html)

## 7.5 Browsers

### Historical Firefox vulnerability study

| Category | Meaning | Count |
|---|---|---:|
| WEB-TO-COMP | Execute native code in a browser component, often through memory corruption | 277 |
| CROSS-ORIGIN | Obtain another origin's data or privileges | 38 |
| USER | Confuse or manipulate user decisions through browser interfaces | 20 |
| INTRA-ORIGIN | Execute with a site's authority, including XSS-style attacks | 14 |
| WEB-TO-SYS | Escalate through exposed browser or plugin APIs | 11 |
| Unclassified | Insufficient information | 2 |
| Total | Historical sample | 362 |

WEB-TO-COMP: 76.5%; JavaScript: 88 cases. Historical sample only. In a single process, component compromise exposes other resources in that protection domain. [Dong et al., Figure 2 and vulnerability study](https://www.comp.nus.edu.sg/~prateeks/papers/BrowserQuant.pdf)

### Original Chromium architecture (2008)

| Sandboxed rendering engine | Privileged browser kernel | Needed on both sides |
|---|---|---|
| HTML/CSS, images, JavaScript, regular expressions, layout, DOM, rendering, SVG, XML, XSLT | Cookies, history, passwords, windows, address bar, Safe Browsing, networking/TLS, cache, downloads, clipboard | URL and Unicode parsing |

- Renderer: unparsed content to bitmaps, with restricted permissions.
- Browser: validates IPC requests; shared URL/Unicode parsing remains trusted.
- Original boundary protects OS resources; a compromised renderer can still attack sites whose data it handles. [2008 Chromium architecture, Table 1 and threat model](https://seclab.stanford.edu/websec/chromium/chromium-security-architecture.pdf)

### Later layers

| Layer | Boundary it supplies |
|---|---|
| Linux namespaces | Restrict process/resource views |
| seccomp-bpf | Reduce reachable kernel operations |
| Site isolation | Separate sites' documents and sensitive data across renderer processes |

Site isolation includes cross-site iframes. Site = scheme + registrable domain; [origin](08-policies.md#origins-and-selinux) also distinguishes host/port. Android isolates a subset of sites to reduce overhead. [Chromium Linux sandbox](https://chromium.googlesource.com/chromium/src.git/+/master/sandbox/linux), [site isolation design and scope](https://www.chromium.org/Home/chromium-security/site-isolation/)

> Extra processes cost memory; frequent boundary crossings cost IPC. Tight JavaScript/DOM interaction was a potential bottleneck in the browser study. Partition by privileges and communication patterns. [Dong et al., partitioning tradeoffs](https://www.comp.nus.edu.sg/~prateeks/papers/BrowserQuant.pdf)

## 7.6 Android

| Property | Enforcement consequence |
|---|---|
| App normally receives its own Linux UID and process | Kernel DAC separates its private files from other apps |
| Sandbox enforced below the runtime | Native and interpreted app code share the sandbox boundary |
| Developer signs the APK | Package identity and update trust rely on signing keys |
| IPC provides controlled sharing | Access still depends on the receiving interface and permissions |

Android 8 added app seccomp-bpf; Android 9 required individual SELinux sandboxes for nonprivileged apps targeting API 28+. Browser compromise inherits the browser app's grants. [Android application sandbox](https://source.android.com/docs/security/app-sandbox)

Certificates may be self-signed; no CA is required. Same-key apps historically could request a shared UID; `sharedUserId` is deprecated since API 29 (Android 10). [Android app signing](https://source.android.com/docs/security/features/apksigning), [manifest shared UID rules](https://developer.android.com/guide/topics/manifest/manifest-element#uid)

> APK signing proves integrity/key possession, not harmlessness. `jarsigner` uses JAR/v1 signing; v2+ covers the whole APK, including ZIP metadata unprotected by v1. [APK signing schemes](https://source.android.com/docs/security/features/apksigning)

## 7.7 Namespaces

| Namespace | Resource view |
|---|---|
| PID | Process identifiers |
| Network | Interfaces, protocol stacks, routing, firewall rules and ports |
| Mount | Mount points |
| User | User/group IDs and capabilities |
| UTS | Hostname and NIS domain name |
| IPC | System V IPC and POSIX message queues |
| Cgroup | Cgroup root directory |
| Time | Boot and monotonic clocks |

Containers use namespace views. `clone` creates a process in new namespaces; `unshare` separates execution context; `setns` joins an existing namespace where permitted. [Linux namespace overview](https://man7.org/linux/man-pages/man7/namespaces.7.html)

- PID hierarchy: first child is PID 1; descendants cannot address ancestors by PID. Ancestors can see descendants, subject to permissions. [PID namespaces](https://man7.org/linux/man-pages/man7/pid_namespaces.7.html)
- User namespaces map external UIDs to local UID 0. Capabilities govern namespace-scoped resources; local root has no host-root grant. [User namespaces](https://man7.org/linux/man-pages/man7/user_namespaces.7.html)
- Network namespaces isolate routes/interfaces; virtual Ethernet pairs can add connectivity. [Network namespaces](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)

```bash
unshare --user --map-root-user --pid --fork --mount-proc --net bash
ps ax
ip link
exit
```

Shell: PID 1, no external connectivity. `--fork` creates the PID-namespace child; `--mount-proc` supplies its `/proc` view. Host policy may disable unprivileged user namespaces. [unshare options](https://man7.org/linux/man-pages/man1/unshare.1.html)

> Namespaces share the host kernel. Syscall filtering reduces reachable kernel paths; permitted paths remain trusted. A kernel compromise defeats these boundaries. [Chromium Linux sandbox layers](https://chromium.googlesource.com/chromium/src.git/+/master/sandbox/linux)

## 7.8 Isolation boundaries

| Mechanism | Protected boundary / checking location | Trust consideration |
|---|---|---|
| Process syscall sandbox | Kernel mediates OS operations | Kernel and filter policy |
| Namespaces | Kernel separates resource views | Shared host kernel |
| Inline monitor, such as SFI | Checks within program | Correct checks and protection against bypass |
| Virtualization | Hypervisor separates guest OSs | Hypervisor and exposed interfaces |
| Hardware isolation / TEE | Hardware protects selected execution and data | Hardware/platform security assumptions |

Guarantees depend on policy and enforcement correctness. [Workbook: policy versus enforcement](https://compsec.kisp-lab.org/Memory-Safety-Webbook/sandboxing-and-privilege-separation.dc.html)

[Topic 8: permissions and information flow](08-policies.md).

