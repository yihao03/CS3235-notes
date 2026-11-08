# 12. Basic cryptographic primitives

## 12.1 Threat model and prior knowledge

| Goal | Tool | What the receiver obtains |
|---|---|---|
| Confidentiality | Encryption | Protection against learning plaintext from ciphertext |
| Integrity and shared-key authentication | Message authentication code (MAC) | Evidence that a key holder authenticated these bytes |
| Publicly verifiable authentication | Digital signature | Verification with a public key; outside this chapter |

Alice/Bob share a secret key; an adversary observes, replaces, injects, reorders or discards traffic. Key establishment/authenticated public-key distribution are separate problems. Random choices stay private except through outputs. [Workbook](https://compsec.kisp-lab.org/Memory-Safety-Webbook/cryptographic-primitives.dc.html)

> Kerckhoffs's second requirement permits the system to fall into enemy hands: assume a public algorithm and protect replaceable keys. [Kerckhoffs, requirement 2](https://www.petitcolas.net/kerckhoffs/crypto_militaire_1.pdf)

For the sum of two fair dice:

| Sum | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Outcomes out of 36 | 1 | 2 | 3 | 4 | 5 | 6 | 5 | 4 | 3 | 2 | 1 |

Guessing 7 succeeds with probability `1/6` before seeing any ciphertext. Security must preserve this prior uncertainty. [Workbook](https://compsec.kisp-lab.org/Memory-Safety-Webbook/cryptographic-primitives.dc.html)

## 12.2 Correctness and perfect secrecy

Encryption scheme:

```text
k ← Gen()             sample independently of the message
c ← Enc(k, m)         encryption may also use private randomness
m ← Dec(k, c)
```

Correctness: `Dec(k,Enc(k,m))=m` for all permitted `k,m`, with probability 1 over encryption randomness. Identity encryption `Enc(k,m)=m` is correct but exposes plaintext. [Franklin §3.3](https://www.cs.ucdavis.edu/~franklin/ecs228/2013/crypto_review_notes.pdf)

Perfect secrecy:

$$
\Pr[M=m\mid C=c]=\Pr[M=m].
$$

- For every plaintext distribution and observable `c` with `Pr[C=c]>0`, ciphertext changes no plaintext probability. `M` and `C` are independent.
- `M` is the actual message random variable; a `Guess` variable needs a defined guessing experiment.
- Holds against unlimited computation. [Shannon](https://dkrizanc.web.wesleyan.edu/courses/351/papers/Communication_Theory_of_Secrecy_Systems_Shannon_1949.pdf)

Equivalent condition, over sampled keys:

$$
\forall m_0,m_1,c:\quad
\Pr[\operatorname{Enc}(K,m_0)=c]
=
\Pr[\operatorname{Enc}(K,m_1)=c].
$$

Proof: each plaintext gives the same likelihood `p(c)`. Bayes yields `p(c)Pr[M=m]/p(c)=Pr[M=m]`. Conversely, independence for every distribution includes any chosen pair of messages. [Boneh/Shoup §2.1.2](https://crypto.stanford.edu/~dabo/cryptobook/BonehShoup_0_6.pdf)

| Proposed definition | Failure |
|---|---|
| Cannot guess the plaintext | Ignores prior knowledge, including the dice distribution |
| Cannot recover the key | Sending plaintext while ignoring the key satisfies this weak condition |
| Cannot predict the ciphertext | The attacker receives the ciphertext |
| Output is independent random noise | May hide everything while making correct decryption impossible |

## 12.3 One-bit ciphers

One-bit plaintext/key/ciphertext; uniform key. Four input pairs, two outputs each: `2⁴=16` deterministic functions. Rows list outputs for `(m,k)=00,01,10,11`.

| Outputs | Correct | Secret | Familiar form |
|---|---|---|---|
| `0000` | No | Yes | Constant 0 |
| `0001` | No | No | AND |
| `0010` | No | No | `m AND NOT k` |
| `0011` | Yes | No | Copy message |
| `0100` | No | No | `NOT m AND k` |
| `0101` | No | Yes | Copy key |
| `0110` | Yes | Yes | XOR |
| `0111` | No | No | OR |
| `1000` | No | No | NOR |
| `1001` | Yes | Yes | XNOR |
| `1010` | No | Yes | Complement key |
| `1011` | No | No | `m OR NOT k` |
| `1100` | Yes | No | Complement message |
| `1101` | No | No | `NOT m OR k` |
| `1110` | No | No | NAND |
| `1111` | No | Yes | Constant 1 |

1. Correctness: distinct messages need distinct outputs under each fixed key. Four rows survive.
2. Secrecy: both messages need identical output frequencies over uniform keys. Copy/complement message fails.
3. XOR/XNOR satisfy both; XNOR decrypts with `m=NOT(c XOR k)`.

Fresh random output lies outside these deterministic functions: secret, but not decryptable. [Workbook](https://compsec.kisp-lab.org/Memory-Safety-Webbook/cryptographic-primitives.dc.html)

## 12.4 One-time pad

For fixed length `n`, sample uniform `K ∈ {0,1}ⁿ`:

$$C=M\oplus K,\qquad M=C\oplus K.$$

Correctness: associativity and `K XOR K=0`.

```text
m = 5041592024313030    ASCII: PAY $100
k = 8f3a1c5e927bd046    fixed demonstration key
c = df7b457eb64ae076    m XOR k
```

Public demonstration key; never use for real data. [Workbook](https://compsec.kisp-lab.org/Memory-Safety-Webbook/cryptographic-primitives.dc.html)

For fixed `m,c`, exactly one key works, `k=m XOR c`:

$$\Pr[C=c\mid M=m]=2^{-n}.$$

Independent of `m`: perfect secrecy. Every same-length plaintext remains possible; posterior equals prior. [Shannon](https://dkrizanc.web.wesleyan.edu/courses/351/papers/Communication_Theory_of_Secrecy_Systems_Shannon_1949.pdf)

| Requirement | Why it matters |
|---|---|
| Uniform key | Every `n`-bit pad has probability `2⁻ⁿ` |
| Key independent of plaintext | Correlation can reveal message information |
| Secret key | Knowing `k` immediately reveals `m=c XOR k` |
| Fresh pad for every message | Reuse reveals relationships between messages |
| Enough secret material | An `n`-bit message consumes `n` fresh pad bits |

Correct, perfectly secret finite ciphers require `|K| ≥ |M|`: fixed-length binary keys for all `n`-bit messages need at least `n` bits. Computational encryption has no such message-length-key requirement. [Boneh/Shoup theorem 2.5](https://crypto.stanford.edu/~dabo/cryptobook/BonehShoup_0_6.pdf)

> A pseudorandom generator expands a short seed for computational stream-cipher security; OTP requires independent random bits. Ciphertext length leaks message length unless padding hides it. [Boneh, stream ciphers](https://crypto.stanford.edu/~dabo/courses/OnlineCrypto/slides/02-stream-v2-annotated.pdf)

### 12.4.1 Pad reuse

$$C_1\oplus C_2=(M_1\oplus K)\oplus(M_2\oplus K)=M_1\oplus M_2.$$

Known `M₁` gives `K=C₁ XOR M₁`, then `M₂=C₂ XOR K`. Language redundancy helps test guesses; incorrect guesses can produce incorrect second messages. [Boneh, attack 1](https://crypto.stanford.edu/~dabo/courses/OnlineCrypto/slides/02-stream-v2-annotated.pdf)

Hex example:

```text
M1 = 41 ('A')   M2 = 42 ('B')   K = a6
C1 = e7         C2 = e4
C1 XOR C2 = 03 = 41 XOR 42
Known M1: e7 XOR 41 = a6; e4 XOR a6 = 42
```

### 12.4.2 Malleability

For attacker-chosen `Δ`:

$$\operatorname{Dec}(K,C\oplus\Delta)=M\oplus\Delta.$$

ASCII `1=0x31`, `9=0x39`: XOR difference `0x08`. With known format/offset, flip that amount bit to change encrypted `PAY $100` into `PAY $900` without the key. [Boneh, attack 2](https://crypto.stanford.edu/~dabo/courses/OnlineCrypto/slides/02-stream-v2-annotated.pdf)

## 12.5 Message authentication codes

```text
t ← Tag(k, m)
send (m, t)
accept only if Verify(k, m, t) = 1
```

Correctness: `Verify(k,m,Tag(k,m))=1`.

EUF-CMA (existential unforgeability under chosen-message attack):

1. Challenger generates secret key.
2. Adversary adaptively requests tags on chosen messages.
3. Adversary wins with accepted `(m*,t*)` for never-queried `m*`.

Efficient adversaries must have negligible success probability. Many legitimate messages are allowed; replay is excluded from forgery. [Franklin, §3.3](https://www.cs.ucdavis.edu/~franklin/ecs228/2013/crypto_review_notes.pdf)

| Check | Against accidental corruption | Against deliberate substitution |
|---|---|---|
| TCP checksum | Detects many transmission errors | Attacker recomputes it |
| Unkeyed hash sent beside message | Detects changes if the digest remains trusted | Attacker replaces message and digest |
| Secure MAC with protected key | Yes | New valid message requires a forgery |

Internet checksum: public one's-complement arithmetic on 16-bit words. Collision resistance cannot authenticate an attacker-supplied digest. [RFC 1071, §1](https://www.rfc-editor.org/rfc/rfc1071.txt)

### 12.5.1 Probability and limits

- Fixed message, one accepted `t`-bit tag, deterministic verification: uniform blind guess succeeds with probability `2⁻ᵗ`.
- `q` attempts contribute at most `q/2ᵗ`; full bounds also depend on construction/adversarial queries.
- Computational MACs assume bounded resources. Information-theoretic authentication requires restricted queries/key use and suitable fresh secrets; forgery probability remains nonzero. [Wegman/Carter](https://research.ibm.com/publications/new-classes-and-applications-of-hash-functions)
- Either key holder can tag: no transferable proof Alice authored a message.
- Authenticated bytes can still contain unauthorized instructions or false claims. [Bellare/Rogaway ch. 6](https://web.cs.ucdavis.edu/~rogaway/classes/227/spring05/book/main.pdf)

Replay protection needs authenticated context and receiver state:

| Context included in authenticated bytes | Receiver action |
|---|---|
| Monotonic counter | Reject previously accepted or out-of-window counters |
| Timestamp | Reject stale messages; track duplicates within the permitted interval |
| Session identifier | Reject messages from another session |

Old messages retain valid tags. [Bellare/Rogaway](https://web.cs.ucdavis.edu/~rogaway/classes/227/spring05/book/main.pdf)

### 12.5.2 HMAC

$$\operatorname{HMAC}_K(m)=H((K'\oplus\mathrm{opad})\Vert H((K'\oplus\mathrm{ipad})\Vert m)).$$

- `K'`: hash keys longer than the hash block size; zero-pad to block size.
- `ipad`: repeated byte `0x36`; `opad`: repeated byte `0x5c`.
- `||`: concatenation.
- HMAC-SHA-256: 256-bit tag before truncation. [RFC 4231, §4](https://www.rfc-editor.org/rfc/rfc4231.txt)
- Modified messages require new keyed tags; old tags fail except with forgery probability. [RFC 2104, §§2 to 5](https://www.rfc-editor.org/rfc/rfc2104.txt)

## 12.6 Combining encryption and authentication

Encrypt-then-MAC (EtM), separate encryption/authentication keys:

```text
Sender:
  c = Enc(kE, m)
  t = Tag(kA, encode(context, IV_or_nonce, c))

Receiver:
  if Verify(kA, encode(context, IV_or_nonce, c), t) != 1: reject
  otherwise: m = Dec(kE, c)
```

Authenticate all interpretation fields with unambiguous encoding. Verify before decryption/processing to prevent error/timing oracles. [RFC 7366, §3](https://www.rfc-editor.org/rfc/rfc7366.txt)

> AEAD takes key, nonce, plaintext and associated data (e.g. packet header). It encrypts plaintext, authenticates the unencrypted associated data, and decrypts to plaintext or failure. Follow algorithm-specific nonce requirements; reuse under one key can destroy security. [RFC 5116, §§2 and 3](https://www.rfc-editor.org/rfc/rfc5116.txt)

## 12.7 Merkle trees for untrusted memory

At the [TEE boundary](11-tee.md), small processor state is trusted; DRAM can be modified/replayed.

| Design | Problem |
|---|---|
| One tag over all memory | Reading one block requires checking everything |
| Independent tag beside each block | An old block and its genuine old tag still verify |
| Authentication tree with trusted current root | A small root commits to the complete memory state |

Merkle trees recursively authenticate children. A leaf proof uses one sibling per level and an authenticated root: `log₂ n` siblings for a balanced binary tree of `n` leaves. [Merkle §6](https://www.ralphmerkle.com/papers/Protocols.pdf)

Workbook keyed variant:

```text
leaf[i] = MAC(k, block[i])
parent  = MAC(k, left_tag || right_tag)
```

Protect key/current root; keep other tags in DRAM. [Workbook](https://compsec.kisp-lab.org/Memory-Safety-Webbook/cryptographic-primitives.dc.html)

<mermaid>
flowchart BT
  A[Block 0] --> T0[Leaf tag 0]
  B[Block 1] --> T1[Leaf tag 1]
  C[Block 2] --> T2[Leaf tag 2]
  D[Block 3] --> T3[Leaf tag 3]
  T0 --> L[Left subtree tag]
  T1 --> L
  T2 --> R[Right subtree tag]
  T3 --> R
  L --> ROOT[Trusted current root]
  R --> ROOT
</mermaid>

Bind proofs to the requested block position and known tree geometry. Concatenate left/right children in order; another address's proof cannot authorize this read.

Read block 0: recompute leaf tag, combine with sibling 1, combine with right subtree, compare with trusted root before accepting.

A rollback can preserve internal tag consistency but disagree with the trusted root. Checking only the stored leaf tag misses it. [Merkle](https://www.ralphmerkle.com/papers/Protocols.pdf)

### 12.7.1 Writes

1. Verify old block/path against current root.
2. Preserve verified siblings.
3. Recompute new block/ancestor tags.
4. Commit data, tags and protected root consistently.

An unverified old sibling tag would make the new root endorse rollback. Cache implementations must also authenticate incoming data before modification and coordinate data/hash updates. [Gassend et al., §5](https://www.princeton.edu/~rblee/ELE572Papers/Fall04Readings/HashTress_Gassend.pdf)

### 12.7.2 Cost and assumptions

For `n=2ʰ` blocks without cached tags:

$$\text{read MACs}=1+\log_2 n.$$

One leaf MAC plus `h` ancestor MACs.

```text
1 GiB = 2^30 bytes
64-byte block = 2^6 bytes
number of blocks = 2^(30-6) = 2^24
tree height = 24
read work = 1 + 24 = 25 MACs
write work ≈ verify old path + generate new path ≈ 50 MACs
```

Binary-model costs; wider branching, tag caches and version-counter trees change constants. Verified-node caching reduces repeated traffic. [Gassend et al., §§5 and 6](https://www.princeton.edu/~rblee/ELE572Papers/Fall04Readings/HashTress_Gassend.pdf)

> Merkle's original public-file tree uses unkeyed hashes with an authentic root. Protect root freshness too: restoring it from the attacker's snapshot permits whole-state rollback. [Merkle, §6](https://www.ralphmerkle.com/papers/Protocols.pdf)

### 12.7.3 SGX generations

Skylake MEE: 8-way version-counter tree, top state on chip. Block MAC covers ciphertext and location/time tweak; address/per-block version distinguish writes. Updates verify existing data/counters before modification. [Gueron §§3.1, 3.2](https://eprint.iacr.org/2016/204.pdf)

| Architecture | External-memory protection |
|---|---|
| SGX before Ice Lake | MEE encryption plus an integrity tree with its root in on-chip SRAM; protects against memory replay |
| TME-based SGX from Ice Lake | Replaces MEE; no equivalent integrity Merkle tree; the same physical integrity/replay guarantees do not follow |

Both block DMA into enclaves. Software access controls and physical DRAM-bus protection remain separate properties. [Linux SGX](https://docs.kernel.org/arch/x86/sgx.html)

> Intel's 2025 statement: AES-XTS provides no physical integrity/anti-replay protection. Optional later-platform integrity modes add some protection; SGX physical guarantees depend on platform/threat model. [Intel, 2025](https://www.intel.com/content/www/us/en/developer/articles/news/more-information-encrypted-memory-frameworks.html)
