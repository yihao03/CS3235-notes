# 8. Sandboxing policies

Prerequisite: [7. Sandboxing and privilege separation](07-sandboxing.md).

## 8.1 Choosing the default

| Policy | Default | Author must identify | Failure from an omitted rule |
| --- | --- | --- | --- |
| Allow-list | Deny | Required access | Legitimate action fails |
| Block-list | Allow | Every dangerous action | Dangerous action succeeds |

Allow-listing implements fail-safe defaults. [Saltzer and Schroeder, §I.A.3](https://www.cs.virginia.edu/~evans/cs551/saltzer/)

[Syscall policies](07-sandboxing.md#7-3-syscall-policies) illustrate both failures: blocking `execve` leaves file theft possible; seccomp strict rejects needed calls but preserves existing descriptors.

> Least privilege limits required authority. Psychological acceptability favors protection users can work with. [Saltzer and Schroeder](https://www.cs.virginia.edu/~evans/cs551/saltzer/)

## 8.2 Access matrix

| Term | Meaning | Examples |
| --- | --- | --- |
| Principal | Authority holder | User/app/origin |
| Object | Protected resource | File/socket/DOM/camera |
| Right | Allowed operation | Read/write/execute |
| Protection domain | Accessible objects/rights | Parser/authentication service |

Applications can span domains. [Saltzer and Schroeder, glossary and protected subsystems](https://www.cs.virginia.edu/~evans/cs551/saltzer/)

Lampson's sparse matrix: rows = domains; columns = objects; cells = rights. Access requires the requested right in the cell. Implementations store rows or columns. [Lampson, *Protection*, §§2 and 3](https://cseweb.ucsd.edu/classes/wi19/cse221-a/papers/lampson74.pdf)

| Domain | Report | Audit log | Executable |
| --- | --- | --- | --- |
| Alice | `r,w` | `r` | `x` |
| Auditor | `r` | `r` | None |
| Service | `r` | `w` | `x` |

| Representation | Rights organized by | Lookup | Limitation |
| --- | --- | --- | --- |
| ACL | Object: matrix column | Report readers | Listing Alice's authority requires multiple ACLs |
| Capability list | Holder/domain: matrix row | Domain authority | Revocation/delegated-copy tracking need extra design |

Capabilities are unforgeable authority-bearing references; object names alone grant no authority. [Lampson, implementation techniques](https://cseweb.ucsd.edu/classes/wi19/cse221-a/papers/lampson74.pdf)

[Delegation and revocation](09-capabilities.md).

## 8.3 Policy authority

| Model | Decision | Example | Consequence |
| --- | --- | --- | --- |
| Discretionary access control, DAC | Owner controls grants | Unix file mode | An owner's program can exercise the owner's authority |
| Mandatory access control, MAC | System policy constrains subjects | SELinux type enforcement | Owners cannot override the mandatory restrictions |
| Role-based access control, RBAC | Permissions assigned to roles; users assigned to roles | Operations role can restart a service | Job changes can be handled through role membership |

DAC/MAC govern policy control; RBAC organizes permissions. They can coexist. [SELinux MAC documentation](https://github.com/SELinuxProject/selinux-notebook/blob/main/src/mac.md), [NIST RBAC FAQ](https://csrc.nist.gov/Projects/role-based-access-control/faqs)

### Unix DAC

```text
-rwxrw----  alice students  thesis.tex
 owner rwx | group rw- | others ---
```

- `chmod o+r thesis.tex` grants others read access; requires ownership or appropriate privilege.
- Alice's malicious process can change her file modes or copy contents elsewhere. DAC alone cannot constrain it. [Linux `chmod(2)`](https://man7.org/linux/man-pages/man2/chmod.2.html), [process credentials](https://man7.org/linux/man-pages/man7/credentials.7.html)

### Origins and SELinux

HTTP(S) origin:

```text
https://www.nus.edu.sg:443/~prateeks/add.php?q=x
└ scheme └──── host ───┘ port
```

- Origin = scheme + host + effective port; any difference separates origins. Path/query are irrelevant.
- Cross-origin object access is restricted; controlled network exceptions still permit some cross-origin requests. [RFC 6454, §§3 to 5](https://datatracker.ietf.org/doc/html/rfc6454)

SELinux labels subjects/objects with types. Kernel object managers enforce permitted type interactions; Unix ownership cannot override a mandatory denial. [SELinux type enforcement](https://github.com/SELinuxProject/selinux-notebook/blob/main/src/type_enforcement.md)

### Roles

```text
Alice -> webops role -> restart/status nginx
Bob   -> auditor role -> read logs
```

Administrator-controlled `sudoers` rules can map Unix groups to command permissions. Moving Alice to auditing changes membership, not each resource entry. [Workbook, RBAC example](https://compsec.kisp-lab.org/Memory-Safety-Webbook/sandboxing-policies.dc.html)

> Static separation of duty forbids conflicting role assignments; dynamic separation restricts simultaneous session roles. Example: separate payment preparation and approval. [NIST RBAC FAQ](https://csrc.nist.gov/Projects/role-based-access-control/faqs)

## 8.4 Confidentiality and integrity labels

For `Low < High`, fixed labels per access, simplified Bell-LaPadula and strict Biba:

| Model | High means | Read allowed when | Write allowed when | Forbidden directions |
| --- | --- | --- | --- | --- |
| Bell-LaPadula | Secret | `object <= subject` | `subject <= object` | Read up; write down |
| Strict Biba | Trusted | `subject <= object` | `object <= subject` | Read down; write up |

Read: object to subject. Write: subject to object.

| Subject | Operation | Object | Bell-LaPadula | Strict Biba |
| --- | --- | --- | --- | --- |
| Low | Read | Low | Allow | Allow |
| Low | Read | High | Deny | Allow |
| High | Read | Low | Allow | Deny |
| High | Read | High | Allow | Allow |
| Low | Write | Low | Allow | Allow |
| Low | Write | High | Allow | Deny |
| High | Write | Low | Deny | Allow |
| High | Write | High | Allow | Allow |

- Confidentiality: upward flow. Integrity: downward flow.
- Both on one label: same-level access only. Separate labels express independent requirements. [Biba, §§III and IV, including combined security/integrity constraints](https://scispace.com/pdf/integrity-considerations-for-secure-computer-systems-1euz8w4arz.pdf)

Guarantees require correct checks and labels. [Biba, original report abstract](https://www.cerias.purdue.edu/apps/reports_and_papers/view/2834/)

## 8.5 Browser extensions (2010)

Barth et al. studied 25 popular Firefox extensions in 2010. Extensions could access arbitrary files and launch processes; page exploits could inherit that authority.

| Finding in that sample | Result |
| --- | --- |
| Needed fewer than full privileges | 88% |
| Used unnecessarily powerful APIs | 76% |

| Task needs | API used |
| --- | --- |
| User-selected file (N) | Arbitrary file access (C) |
| Own SQLite database (N) | Any SQLite database (H) |
| One domain (M) | Arbitrary network access (H) |
| Display a page (L) | Arbitrary DOM access (H) |
| Own preferences (N) | Browser/all-extension preferences (H) |

Severity: C critical, H high, M medium, L low, N none.

Chrome architecture in the paper:

<mermaid>
flowchart LR
    P[Untrusted page] <-->|Shared DOM| C[Content script]
    C <-->|Messages| E[Extension core]
    E <-->|Messages| N[Optional native binary]
</mermaid>

- Content script: DOM access, JavaScript heap separate from page scripts.
- Core: declared install-time privileges. Gmail Checker requested `tabs`, `http://*.google.com/`, `https://*.google.com/`.
- Optional native code: full user authority.
- Compromised scripts need the core to accept privileged messages. [Barth et al., 2010](https://www.ndss-symposium.org/wp-content/uploads/2017/09/barth.pdf)

Users choose grants; platforms enforce them against extensions. DAC/MAC classification depends on the authority considered. [Workbook, extension exercise answer](https://compsec.kisp-lab.org/Memory-Safety-Webbook/sandboxing-policies.dc.html)

> Chrome still uses isolated worlds and messages for other extension APIs. The shared DOM remains untrusted input. Modern manifests separate API/host permissions and allow optional runtime grants; the 2010 manifest is historical. [Chrome content scripts](https://developer.chrome.com/docs/extensions/develop/concepts/content-scripts), [declaring permissions](https://developer.chrome.com/docs/extensions/develop/concepts/declare-permissions)

## 8.6 Permission prompts

| When | Benefit | Cost |
| --- | --- | --- |
| Install time | Fixed authority is easier to inspect | User has little usage context; historical Android acceptance was all-or-nothing |
| Time of use | Request accompanies the relevant action | Repeated interruptions consume attention |

Felt et al. (2012): Internet survey of 308 Android users; laboratory study of 25.

- 17% paid attention to permissions during installation.
- Only 3% of survey respondents answered all three comprehension questions correctly.

Historical interface/sample only. [Felt et al., SOUPS 2012](https://research.google/pubs/android-permissions-user-attention-comprehension-and-behavior/)

Android 6.0 added runtime requests for dangerous permissions. Request in context; handle denial/revocation; check permission before access. [Android runtime permission guide](https://developer.android.com/training/permissions/requesting)

> After denial, preserve unrelated functionality. Prompts identify the resource; apps must explain its purpose. [Android runtime permission guide](https://developer.android.com/training/permissions/requesting)

## 8.7 Confused deputies

Editor holds `{L1,L3}`; camera A requires `L1`, B requires `L2`. Editor can call A but cannot call B directly. A forwarding to B must preserve that restriction. [Workbook, ICC example](https://compsec.kisp-lab.org/Memory-Safety-Webbook/sandboxing-policies.dc.html)

Permission re-delegation: a privileged app acts for an unauthorized app. The confused deputy uses its own authority without checking the requester's entitlement.

Historical Android 2.2 Settings attack:

<mermaid>
sequenceDiagram
    participant M as App with no permissions
    participant S as Settings receiver
    participant O as Protected Wi-Fi API
    M->>S: Intent resembling widget request
    S->>O: Change Wi-Fi state
    O-->>S: Allowed: Settings has permission
</mermaid>

- Settings accepted widget control messages from arbitrary apps; Wi-Fi checks saw Settings' authority.
- Felt et al. (2011): 15 vulnerabilities in 5 core system apps.
- Defenses: check requester authority at the deputy boundary; or reduce effective permissions after less-privileged IPC (IPC Inspection).
- Preventing re-delegation does not prevent sharing already-accessed data. [Felt et al., 2011, §§4 to 6](https://static.usenix.org/events/sec11/tech/full_papers/Felt.pdf)

## 8.8 Permission lists and malware

Zhou and Jiang (2012): 1,260 malware samples versus 1,260 top free Android Market apps, collected October 2011.

| Observation | Interpretation |
| --- | --- |
| Internet, phone-state, network-state and external-storage access common in both | Broad permissions alone poorly distinguish intent |
| `READ_SMS`: 790 malware samples, 62.7% | SMS access was much more common in this malware sample |
| Paper reports fewer than 33 benign apps with `READ_SMS` | Do not treat absence from the top-20 chart as zero |
| Boot-completed: 688 malware versus 137 benign | Fits malware seeking unattended execution |

SMS access enabled premium-rate fraud and confirmation-message interception. Permission patterns cannot prove individual malice; these historical samples give no current malware rate. [Zhou and Jiang, §III.D and Figure 5](https://oaklandsok.github.io/papers/zhou2012.pdf)

## 8.9 Information flow

| Goal | Forbidden influence |
| --- | --- |
| Confidentiality | Secret input affects public observations beyond authorized release |
| Integrity | Attacker-controlled input corrupts trusted output |

Strict noninterference: public observations are independent of secret inputs. Declassification permits specified release, such as a password checker revealing whether a guess matches. [Sabelfeld and Myers, *A model for delimited information release*](https://research.chalmers.se/en/publication/2026)

```text
Stored secret + supplied guess -> trusted checker -> success/failure
Stored secret                 -X-> public raw-secret response
```

[Syscall filters](07-sandboxing.md#7-3-syscall-policies) cannot distinguish authorized results from secret bytes. Keep secrets and release decisions behind a narrow trusted interface. [workbook, false positives](https://compsec.kisp-lab.org/Memory-Safety-Webbook/sandboxing-policies.dc.html)

> Specify the released value: login outcome, never stored credentials. Unrestricted declassification can leak arbitrary secrets; repeated guesses accumulate observations. [Sabelfeld and Myers](https://research.chalmers.se/en/publication/2026)

