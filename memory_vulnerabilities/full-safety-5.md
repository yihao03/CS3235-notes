# Full memory safety

> Source: [06 Full Memory Safety](https://compsec.kisp-lab.org/Memory-Safety-Webbook/06-full-memory-safety.dc.html), including interactive metadata, five-rule, lock-and-key, and cost panels. Notes grouped by mechanism.

[Source summary](https://compsec.kisp-lab.org/Memory-Safety-Webbook/06-full-memory-safety.dc.html#summary).

## 0. Property and enforcement ([§01](https://compsec.kisp-lab.org/Memory-Safety-Webbook/06-full-memory-safety.dc.html#definition), [§02](https://compsec.kisp-lab.org/Memory-Safety-Webbook/06-full-memory-safety.dc.html#enforcement))

* Memory safety prevents invalid accesses. Stack canaries detect some damage later and ASLR obscures addresses; neither establishes validity of every access.
* Three obligations: (1) create/derive pointers only by permitted operations (allocation, `&`, derivation preserving access rights; integer-to-address conversion grants no rights); (2) every access is within the pointer's designated object's range **and** during that allocation's lifetime; (3) distinct live allocations occupy disjoint storage. Members are subobjects within an allocation and may need narrower bounds.
* Compiler instrumentation (or binary rewriting without source) inserts pointer metadata and inline reference monitors (IRMs). Unlike CFI's allowed-edge check, the policy checks whether the entire accessed region is inside a live object. Soundness assumes complete instrumentation, correct metadata propagation, and metadata inaccessible to application writes, despite sharing its address space. Spatial protection is needed to keep temporal lock/key metadata unforgeable.
* Static checking proves the property for every execution in the model; it rejects unprovable programs, including some safe ones, and needs no runtime check for a proved property. Dynamic checking accepts a program but checks before operations, stopping invalid executions; it incurs runtime metadata/check cost, though redundant checks can be eliminated. The two approaches can be combined. Ordinary C pointers contain neither explicit bounds nor lifetime; casts, aliases and separately compiled code complicate a full static proof. Rust mixes compile-time ownership with runtime checks.

<mermaid>
flowchart LR
  P["Pointer creation / derivation"] --> M["Propagate trusted bounds + lifetime metadata"]
  M --> A["Before access: whole width in permitted range?"]
  A --> L["Allocation still alive?"]
  L -->|both yes| OK["Access"]
  A -->|no| STOP["Reject"]
  L -->|no| STOP
</mermaid>
## 1. Spatial metadata storage ([§03](https://compsec.kisp-lab.org/Memory-Safety-Webbook/06-full-memory-safety.dc.html#bounds))

Bounds convention: `[base, bound)`; `bound` is the exclusive first disallowed byte. Pointer arithmetic, casts, struct storage, and library calls must preserve appropriate bounds. Accessing `w` bytes starting at `p` requires `base ≤ p` and `p+w ≤ bound`, calculated without wraparound. Checking only the starting address is insufficient.

| Representation | Pointer / metadata | Compatibility and cost | Examples |
|---|---|---|---|
| Literal fat pointer | `address + base + bound` in pointer (illustrated as 3 words) | Direct comparison, no bounds lookup; larger pointers/copies, changed pointer-containing struct layout and incompatible ordinary-library ABI | CCured where needed; fat-pointer part of Cyclone |
| Object header | ordinary address; `base + bound` in object's header | Changes allocation layout; retrieving header from an interior pointer needs an extra mechanism; once found, no tree search | Object-header designs (lookup is implementation-dependent) |
| Disjoint side table | ordinary address; bounds stored elsewhere | Lookup/propagation/memory traffic; SoftBound preserves object and pointer layout but calls must convey metadata, ordinary libraries need wrappers; Baggy changes allocation sizes/alignment | Jones–Kelly: splay tree of live object ranges; Baggy: rounded power-of-two aligned allocations and address-indexed table (shift + table byte); SoftBound: **per-pointer** disjoint metadata, potentially resident in registers between accesses |

Under SoftBound, two pointers to one object can carry different allowed ranges; object-indexed and pointer-indexed tables therefore differ. Side metadata is still in the same process and must be isolated from invalid writes. Comparisons may be cheaper than obtaining and propagating bounds.

<details>
<summary>Object bounds, pointer bounds, and one-past accesses</summary>

- With a 64-byte allocation at `B`, the allocation interval is `[B,B+64)`. A pointer at `B+64` may serve as a one-past sentinel but a one-byte dereference there fails; a four-byte access at `B+62` fails because its end is `B+66`. Guard the arithmetic so `p+w` cannot overflow.
- Object-indexed metadata answers “which live allocation contains address `p`?” Pointer-indexed metadata answers “which range is **this pointer** authorized to access?” Two pointers with the same numeric `p` could carry distinct subobject bounds, so recovering bounds from just the numeric address can lose that distinction.
- Literal fat pointers keep `(address,base,bound)` together but alter ABI/layout; SoftBound keeps numeric pointers ordinary-sized and carries metadata separately, requiring instrumented propagation through copies, casts, memory and library calls. Metadata itself must be protected from an out-of-bounds write. [Bounds section](https://compsec.kisp-lab.org/Memory-Safety-Webbook/06-full-memory-safety.dc.html#bounds).

</details>

## 2. SoftBound: five rules ([§04](https://compsec.kisp-lab.org/Memory-Safety-Webbook/06-full-memory-safety.dc.html#fatptr))

SoftBound implements conceptual fat-pointer semantics with a one-word ordinary pointer and separate per-pointer base/bound metadata; program object layouts remain byte-for-byte unchanged.

1. **Create:** `char *p = malloc(64);` on success records `[p,p+64)`; taking a local/global object's address gets bounds from its size. Derived pointers inherit metadata, subject to subobject policy.
2. **Access:** before `*p = 65`, check `p >= base && p + sizeof(*p) <= bound` (pseudocode; guard against arithmetic overflow). Check entire width, including casts to wider types; compiler may remove checks it proves redundant. Metadata may already be in registers; a table lookup is not necessarily needed for each access.
3. **Arithmetic:** `end = p + 64` is a legitimate one-past pointer (given successful 64-byte allocation) and retains bounds, but `*end` is rejected. Access-time checking does **not** license arbitrary out-of-range pointer arithmetic: e.g. `p+1000` here is itself undefined under the applicable C/C++ pointer rules.
4. **Casts:** `void *raw = p; char *q = (char *)raw;` keeps the same bounds. A changed type cannot expand allocation rights. Wrong-type accesses **within** the original bounds can still pass: spatial safety is not general type safety.
5. **Subobjects (optional policy):** `struct Record { char name[8]; int count; } obj; char *s = obj.name;` can narrow `s` to `name`, never widening beyond original bounds. Without narrowing, overflow from `name` into `count` remains within allocation bounds. Narrowing must accommodate legitimate enclosing-object recovery; it is a separate decision from cast propagation.

### Cast illustration and policy ([§05](https://compsec.kisp-lab.org/Memory-Safety-Webbook/06-full-memory-safety.dc.html#casts))

```cpp
struct Base { int x; };
struct Derived : Base { int y; }; // illustrated: 4-byte Base, 8-byte Derived
void foo(Base *b) {
    Derived *d = static_cast<Derived*>(b); // invalid if b names plain Base
    d->y = 0; // attempted [B+4,B+8), original bounds [B,B+4)
}
int main() { Base *b = new Base(); foo(b); delete b; }
```

* The invalid downcast is C++ undefined behavior, so there is no guaranteed outcome in an ordinary build. An instrumented access beyond the original 4-byte allocation illustrates what the monitor can detect; bounds alone do not catch a wrong-type access inside the range.
* Conversely, with `Derived *d = new Derived(); Base *b = d;` (valid upcast), `b` may carry **subobject** `[B,B+4)` or **allocation** `[B,B+8)`. Former guards base fields but needs a sound legitimate downcast path; latter allows enclosing-object round trip but does not protect base-subobject boundary. Original SoftBound for C propagates bounds on casts; optional field-pointer narrowing, not a cast to a smaller type, changes bounds.
* Literal fat pointers change data layouts/ABIs; SoftBound avoids that representation change but still needs metadata-aware instrumented calls and library wrappers. Layout compatibility and spatial safety alone do not ensure lifetime safety: a stale pointer's numerical address can remain within its old range ([§06](https://compsec.kisp-lab.org/Memory-Safety-Webbook/06-full-memory-safety.dc.html#fatptr-cost)).

## 3. Temporal safety: aliasing defeats nullification ([§07](https://compsec.kisp-lab.org/Memory-Safety-Webbook/06-full-memory-safety.dc.html#nullify))

Assume `SIZE > 0` and allocation succeeds:

```c
char *p = malloc(SIZE);
if (abrt) { free(p); p = NULL; }
free(p); // if abrt: free(NULL) does nothing; else first free

// Instead, create an alias before the branch:
char *p = malloc(SIZE);
char *r = p;
if (abrt) { free(p); p = NULL; }
free(r); // if abrt: double-free through dangling r
```

* `free(NULL)` is a no-op; dereferencing NULL is still undefined C behavior (often faults if zero page is unmapped, not guaranteed). Nulling `p` prevents reuse through `p` only. Aliases may reside in structs, containers, or other functions, so nulling one pointer does not invalidate every reference to the object.
* Complete dangling-pointer nullification (DangNull) must maintain a runtime reverse map from each dying object to all referencing pointer locations and clear them. That scales poorly with millions of pointers/objects; lock/key instead shares one per-object invalidation point.

## 4. CETS lock/key ([§08](https://compsec.kisp-lab.org/Memory-Safety-Webbook/06-full-memory-safety.dc.html#lockkey))

* Each allocation receives fresh key `k` and separately managed lock cell `L` containing `k`. Each pointer's metadata stores `(k, &L)`. Access checks `*L == k` before touching object. Instrumented `free` validates key and invalidates lock. Lock cell remains readable after object storage is freed; aliases all check that cell, no reverse alias list needed.
* Six-step interactive example (hex keys illustrative):

| Step | Action | Pointer/lock state | Result |
|---|---|---|---|
| 1 | `p=malloc(64)` | `p:(0x2a,L)`, `*L=0x2a` | unique fresh key |
| 2 | `r=p` | `r:(0x2a,L)` too | metadata copied, both aliases consult same lock |
| 3 | `*r=65` | `*L == 0x2a` | permitted (also needs spatial check) |
| 4 | `free(p)` | `*L=INVALID_KEY` | both aliases revoked without rewriting them |
| 5 | `*r=66` | old `0x2a != *L` | abort UAF; second instrumented `free(r)` likewise rejected |
| 6 | **Alternative from step 4:** `q=malloc(64)` then `*r` | even if chunk **and lock cell** reused, `*L=0x2b`, `r` still holds `0x2a` | stale pointer still rejected: address reuse ≠ renewed permission |

<mermaid>
flowchart LR
  P["p: old key k, L"] --> L["lock L: k while live"]
  R["r: old key k, L"] --> L
  F["free(p)"] -->|invalidate one cell| L
  L -->|INVALID or new key ≠ k| X["All old aliases fail"]
</mermaid>
* Keys must never be reissued to an allocation while a stale pointer might still hold them; finite implementations must ensure this. Correct pointer-copy propagation and spatial safety prevent forged keys/lock addresses or corrupted lock metadata. The original CETS prototype is single-threaded: concurrent `check → another thread frees → access` is a time-of-check/time-of-use gap requiring synchronization (see [Rust concurrency](https://compsec.kisp-lab.org/Memory-Safety-Webbook/07-memory-safety-in-rust.dc.html#concurrency)).

<details>
<summary>Lock/key across free, reuse, and concurrent access</summary>

- Suppose `p` and copied alias `r` both carry `(key=42,lock=&L)` and `*L=42`. `free(p)` changes the lock to invalid; **both** old aliases fail `*L == key` without scanning pointer locations.
- Reallocation at the same address, even reusing lock cell `L`, must issue a *different* key, say 43. Fresh `q` carries `(43,&L)` and passes; old `r` still carries 42 and fails. Repeating a key while stale pointers survive would create an ABA-style false acceptance.
- A check must also validate full access width against spatial bounds. In the original single-threaded CETS model, another thread freeing an object between key check and actual load/store is outside the guarantee; synchronization or stronger concurrent semantics are required. [Lock/key section](https://compsec.kisp-lab.org/Memory-Safety-Webbook/06-full-memory-safety.dc.html#lockkey).

</details>

## 5. Cost and deployment ([§09](https://compsec.kisp-lab.org/Memory-Safety-Webbook/06-full-memory-safety.dc.html#cost))

| Study / workload | Configuration | Mean runtime overhead over baseline |
|---|---|---:|
| 2010 CETS study, 17 SPEC benchmarks | SoftBound spatial only | +83% |
| Same study | CETS temporal only, after optimizations | +48% |
| Same study | SoftBound + CETS | **+116%** = 2.16× baseline (not sum of individual percentages) |
| Original SoftBound paper, 2009, **different 23 benchmarks** | Full spatial | +67% (do not conflate with +83%) |
| 2024 revisit, LLVM 12 / SPEC CPU 2017 | Combined | +139.6% geometric / +195.9% arithmetic |
| Same 2024 study | Combined + subobject checks | +161.1% geometric / +232.4% arithmetic |

Geometric mean combines runtime ratios; arithmetic mean averages percentage overheads. Metadata propagation, memory traffic, allocation bookkeeping, and uneliminated access checks contribute. Figures depend on implementation and workload. The 2024 [artifact](https://github.com/Fraunhofer-AISEC/softboundcets) has reproduction instructions but says it is not maintained. Deployment trades off coverage, speed, compatibility, and compiler/library maintenance; Rust checks many lifetime properties statically, with dynamic checks when needed.

## 6. Readings ([source bibliography](https://compsec.kisp-lab.org/Memory-Safety-Webbook/06-full-memory-safety.dc.html#references))

* [Szekeres et al., *SoK: Eternal War in Memory*, S&P 2013](https://nebelwelt.net/publications/files/13Oakland.pdf): six-stage attack graph; partial defenses sever late exploit edges.
* [Nagarakatte et al., *SoftBound*, PLDI 2009](https://doi.org/10.1145/1543135.1542504): per-pointer disjoint metadata, propagation, access-time checking, +67% original result. [CCured, POPL 2002](https://doi.org/10.1145/503272.503286): widened pointers. [Jones–Kelly, AADEBUG 1997](https://ep.liu.se/en/conference-article.aspx?series=&issue=1&Article_No=2): live-object splay tree. [Baggy Bounds Checking, USENIX Security 2009](https://www.usenix.org/legacy/event/sec09/tech/full_papers/akritidis.pdf): rounded/aligned allocation, indexed lookup.
* [Nagarakatte et al., *CETS*, ISMM 2010](https://doi.org/10.1145/1806651.1806657): lock/key, spatial prerequisite, concurrency caveat, benchmarks. [Lee et al., *DangNull*, NDSS 2015](https://www.ndss-symposium.org/wp-content/uploads/2017/09/05_1_2.pdf): reverse-map alias invalidation.
* [Orthen et al., *SoftBound+CETS Revisited*, EuroSec 2024](https://doi.org/10.1145/3642974.3652285), [reproduction artifact](https://github.com/Fraunhofer-AISEC/softboundcets). [C++ pointer arithmetic rule](https://eel.is/c++draft/expr.add): array interior/one-past limitations.
