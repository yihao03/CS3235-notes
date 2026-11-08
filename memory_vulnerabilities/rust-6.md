# Memory safety in Rust

> Source: [07 Memory Safety in Rust](https://compsec.kisp-lab.org/Memory-Safety-Webbook/07-memory-safety-in-rust.dc.html), including all six ownership and six aliasing/reborrow interactive examples. Builds on [Full Memory Safety](full-safety-5.md); notes grouped by mechanism, following `spatial-1a1b.md`.

[Source summary](https://compsec.kisp-lab.org/Memory-Safety-Webbook/07-memory-safety-in-rust.dc.html#summary).

## 0. C++ smart pointers and non-owning aliases ([§01](https://compsec.kisp-lab.org/Memory-Safety-Webbook/07-memory-safety-in-rust.dc.html#smartptr))

* A smart pointer owns/manages a resource through a pointer and releases it automatically. C++11 `std::unique_ptr<T>`: exclusive owner, moves rather than copies, moved-from handle empty, no reference-counting cost (destruction itself still runtime). `std::shared_ptr<T>`: copying an owning handle increments runtime strong reference count; releasing decrements it and count zero destroys object. Cycles of owning handles can leak; raw pointer aliases do not count; counting ownership does not synchronize accesses to the object.
* Neither enforces safe lifetime of non-owning aliases. Example: `auto owner = std::make_unique<int>(7); int *alias = owner.get(); owner.reset(); /* *alias = 9; would be UAF */`. Rust checks borrows: non-owning references must cease use before destruction or invalidation.

| Question | Mechanism |
|---|---|
| Who destroys this value? | Exclusive owner / shared owner count |
| May this alias still access it? | Borrow and referent lifetimes, plus permitted access mode |
| Is this element index valid? | Proven or checked bounds |

## 1. Spatial safety ([§02](https://compsec.kisp-lab.org/Memory-Safety-Webbook/07-memory-safety-in-rust.dc.html#spatial))

* Safe indexing is either statically proved in range or dynamically checked before access. Known index/array length may permit compile-time proof; optimizers remove redundant checks and iterator loops often avoid individual indexing checks, depending on code/build settings.
* `[T; N]` is an array type with length `N` in the type; `&[T]` is a slice reference carrying address + runtime length (a fat pointer; length is metadata, not part of slice type). Unknown indices are compared with length. Unlike SoftBound's separate base/bound metadata for arbitrary C pointers, slice metadata travels directly with the reference; safe Rust APIs preserve its validity, while unsafe slice construction must establish invariants.
* Invalid indexing panics before invalid memory access; panic can unwind the current thread and be caught, or abort the process by configuration. Memory safety does not ensure every program succeeds.

## 2. Exclusive ownership and moves ([§03](https://compsec.kisp-lab.org/Memory-Safety-Webbook/07-memory-safety-in-rust.dc.html#ownership))

* C's `p=malloc(sizeof(int)); q=p; free(p); free(q);` duplicates an unchecked alias and double-frees. `String`, `Box<T>` etc. are non-`Copy`; assigning/passing one transfers ownership without duplicating it. The old binding cannot be used until reinitialized. `Copy` types such as ordinary integers instead copy independent values. Borrowed references do not acquire ownership of allocation.
* Interactive six-step progression (distinct alternatives, not a single executable program):

| Step | Rust fragment | Why |
|---|---|---|
| 1 Own | `let country = String::from("Singapore"); println!("{}", country);` | `country` owns heap buffer and remains usable |
| 2 Move | `let country_name = country;` | `country_name` now owns; unlike C++ moved-from `unique_ptr`, old Rust binding is unavailable until reinitialized |
| 3 Use after move | `println!("{}", country);` after step 2 | compile-time **E0382**, use/borrow of moved value |
| 4 Drop | `{ let country_name = country; }` | inner owner drops buffer once on scope exit; old binding does not drop twice; explicit `drop` also consumes owner |
| 5 Borrow | `fn char_count(s: &str)->usize { s.chars().count() } let n=char_count(&country); println!("{} {}",country,n);` | temporary access, ownership retained; function need not consume argument |
| 6 Outlive | `let r; { let s=String::from("Singapore"); r=&s; } println!("{}",r);` | compile-time **E0597**: `s` dropped before last use of `r` |

* The compiler knows local/static bindings and types, though not necessarily their runtime values. A heap allocation may be owned by a local, static, or another owned object; simple exclusive-ownership chains root in locals/statics. The compiler follows transfers and inserts drops along control-flow paths without discovering the entire heap alias graph at runtime. Ordinary moves/borrows do not require reference counts (allocation and drop still cost runtime). `Rc`/`Arc` introduce explicit runtime bookkeeping. Deliberate leaks are possible: memory safety does not imply all allocated memory is reclaimed.

<mermaid>
flowchart LR
  A["country owns String"] -->|move| B["country_name owns String"]
  A -->|old binding used| E["Compile-time error E0382"]
  B -->|scope exit or drop| D["Destroy once"]
  B -->|borrow| R["temporary reference; owner unchanged"]
</mermaid>
## 3. Borrowing, lifetime, reborrowing ([§04](https://compsec.kisp-lab.org/Memory-Safety-Webbook/07-memory-safety-in-rust.dc.html#borrow))

* A borrow gives temporary access without transferring destruction responsibility. An old moved-from non-`Copy` binding cannot be used or borrowed until reinitialized. A reference cannot remain in use after referent invalidation: `Lifetime(borrow) ≤ Lifetime(referent)`; the compiler infers the region actually needed, which can end at last use rather than the closing brace (non-lexical lifetimes). Keeping a reference live prevents conflicting operations that could invalidate its referent.
* Reborrowing derives another reference through an existing one; a mutable reborrow temporarily restricts conflicting uses of the original. After the reborrow's last use, the original reference becomes usable again even if the reborrow binding remains in scope. This prevents use-after-free/reallocation without runtime per-pointer lifetime checks for ordinary references.

## 4. Aliasing xor mutability (AXM) ([§05](https://compsec.kisp-lab.org/Memory-Safety-Webbook/07-memory-safety-in-rust.dc.html#axm))

* C++ example: `std::vector<int> v(300,10); int &first=v[0];` prints `10`; `v.resize(4000)` **may** exceed capacity, relocate buffer and release old one; later read of `first` is undefined **if reallocated** (no promised output). The reference reads only but is declared mutable `int&`. Container still lives; its element's old storage may not.
* For overlapping ordinary Rust references to the same data, multiple shared `&T` or one exclusive `&mut T` can be in use. Unsynchronized conflicting access is disallowed. The rules depend on overlapping live uses, not the number of reference variables lexically in scope. Interior-mutability types move checks to runtime or synchronization; they are controlled exceptions rather than blanket unsafety.
* Six interactive cases (each has independent setup):

```rust
// 1. OK: two shared references read.
let buf = vec![0, 0]; let a = &buf; let a1 = &buf;
println!("{} {}", a[0], a1[0]);

// 2. OK: one exclusive mutable borrow.
let mut buf = vec![0, 0]; let x = &mut buf; x.push(1);

// 3. REJECT E0502: shared reference used after attempted mutable borrow.
let mut buf = vec![0, 0]; let a = &buf;
let x = &mut buf; println!("{}", a[0]);

// 4. REJECT E0499: first mutable borrow still used after second is requested.
let mut buf = vec![0, 0]; let x = &mut buf;
let x0 = &mut buf; x.push(1);

// 5. OK: mutable reborrow ends at last use before push.
let mut buf = vec![0, 0]; let x = &mut buf;
let x0 = &mut x[0]; *x0 = 2; x.push(3);

// 6. REJECT E0499: push before last use of element reborrow.
let mut buf = vec![0, 0]; let x = &mut buf;
let x0 = &mut x[0]; x.push(3); *x0 = 2;
```

In case 6, `push` could reallocate and dangle `x0`; in case 5, `x0` is not used afterwards. A long-lived name alone does not mean an ongoing borrow.

## 5. Concurrency and explicit shared access ([§06](https://compsec.kisp-lab.org/Memory-Safety-Webbook/07-memory-safety-in-rust.dc.html#concurrency))

* C-like race: main allocates `p`, starts worker with alias, writes `p[10]=0`, then `free(p)`; worker later writes `p[10]=1`. With `SIZE>10` and successful allocation, worker can UAF. Even a lock/key monitor can check a live key, then main free, then worker access: **check-to-access race**. Original CETS is single-threaded; concurrent deallocation needs synchronization.
* Rust threads combine ownership/borrowing with `Send` (type can transfer between threads) and `Sync` (shared references can cross threads). Ordinary references rule out unsynchronized conflicting accesses; synchronized mutation remains possible. Programs without data races can still have logical races or deadlocks.

| Type | Owners / access rule | Threading / caveat |
|---|---|---|
| `Rc<T>` | Single-thread shared ownership; `clone` increments strong count, drop decrements; zero drops value; `Weak` does not keep it alive | Neither `Send` nor `Sync`; cycles of strong `Rc` leak |
| `RefCell<T>` | Runtime AXM: multiple `borrow()` shared guards or one `borrow_mut()` exclusive; conflict panics, `try_borrow[_mut]` returns error; guard lifetimes checked statically | Not `Sync`; checks borrow access, **not** owner count |
| `Arc<T>` | Atomic reference count, shared lifetime across threads | Counting alone does not synchronize mutation of `T` |
| `Arc<Mutex<T>>` | Counted ownership **and** exclusive locked access | Guard releases lock on drop; `RwLock`/atomics are other controlled patterns |

* Shared ownership is a design choice, not necessary for every graph: indices into one exclusively owned collection are an alternative. Runtime cost follows the explicit chosen primitives.

```rust
use std::sync::{Arc, Mutex};
use std::thread;

fn main() {
    let count = Arc::new(Mutex::new(0));
    let worker_count = Arc::clone(&count);
    let worker = thread::spawn(move || {
        let mut value = worker_count.lock().unwrap();
        *value += 1;
    }); // guard unlocks on closure exit
    worker.join().unwrap();
    assert_eq!(*count.lock().unwrap(), 1);
}
```

`Arc` keeps allocation alive across worker lifetime; mutex guard protects mutation; `join` waits for worker before assertion.

## 6. Scope of the guarantee ([§07](https://compsec.kisp-lab.org/Memory-Safety-Webbook/07-memory-safety-in-rust.dc.html#unsafe))

* `unsafe` permits specific operations the compiler cannot prove safe (e.g. raw pointer dereference); borrow checking still applies to ordinary references. Allocators, FFI, smart-pointer internals may implement unsafe operations behind safe interfaces; every permitted use of that interface must preserve invariants. Safe clients depend on sound unsafe implementations, including transitive dependencies/foreign code. Review the whole abstraction: surrounding safe code may undermine an assumption relied on later in unsafe code; no fixed number of adjacent lines contains every bug.
* RustBelt machine-checks a model of a realistic Rust subset and verified unsafe-library contracts, not the entire real compiler/ecosystem. Xu et al.'s 186-report dataset, including known Rust memory-safety CVEs by 31 Dec 2020, found every memory-safety bug in that dataset involved unsafe code; Evans et al.'s 2020 ecosystem study found transitive dependency use of unsafe even without local unsafe. These findings apply to those datasets and do not prove that future vulnerabilities must look identical.

## 7. Readings ([source bibliography](https://compsec.kisp-lab.org/Memory-Safety-Webbook/07-memory-safety-in-rust.dc.html#references))

* [C++ `unique_ptr` specification](https://eel.is/c++draft/unique.ptr), [C++ `shared_ptr` specification](https://eel.is/c++draft/util.smartptr.shared).
* Rust docs: [pointer/slice metadata](https://doc.rust-lang.org/std/ptr/trait.Pointee.html), [panic/unwind catching](https://doc.rust-lang.org/std/panic/fn.catch_unwind.html), [borrowing and last-use lifetimes](https://doc.rust-lang.org/book/ch04-02-references-and-borrowing.html), [`Send`/`Sync`](https://doc.rust-lang.org/book/ch16-04-extensible-concurrency-sync-and-send.html), [`Rc`](https://doc.rust-lang.org/std/rc/index.html), [`RefCell`](https://doc.rust-lang.org/std/cell/struct.RefCell.html), [`Arc`](https://doc.rust-lang.org/std/sync/struct.Arc.html), [Unsafe Rust](https://doc.rust-lang.org/book/ch20-01-unsafe-rust.html), [Rustonomicon: working with unsafe](https://doc.rust-lang.org/nomicon/working-with-unsafe.html).
* [CETS paper §3.4](https://acg.cis.upenn.edu/papers/ismm10_cets.pdf): concurrent-free limitation. [RustBelt, POPL 2018](https://doi.org/10.1145/3158154): model/verified-contract soundness. [Xu et al., TOSEM 2021](https://doi.org/10.1145/3466642): 186 reports and known CVEs. [Evans et al., ICSE 2020](https://doi.org/10.1145/3377811.3380413): direct/transitive unsafe ecosystem usage.
