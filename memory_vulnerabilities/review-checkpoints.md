# Review checkpoints

> Source: [course quiz data](https://compsec.kisp-lab.org/Memory-Safety-Webbook/inclass-quizzes.js). Condensed answers to the 14 in-class and 12 embedded author questions; try the interactive questions in their linked chapters first. For the separate 10-question prerequisite test, see [prerequisites](prerequisites.md).

## Spatial errors ([1A](https://compsec.kisp-lab.org/Memory-Safety-Webbook/01a-spatial-memory-errors.dc.html), [1B](https://compsec.kisp-lab.org/Memory-Safety-Webbook/01b-spatial-memory-errors-advanced.dc.html))

| Checkpoint | Answer / reason |
|---|---|
| 1A-SYS | x86 stack grows toward low addresses; x86 is little-endian, `call` pushes return address to stack, `EIP` is instruction pointer (`ESP` stack pointer). |
| 1A-DEF | Spatial bounds **and** object lifetime must hold for every access. A memory leak wastes storage but does not by itself violate either property. |
| 1A-FMT | Attacker-controlled `printf(buf1)` treats `%lx-%lx-...` as conversions and prints unpassed argument slots, possibly a stack secret; `AAAA` alone is literal. |
| Stack-frame question | `call g` pushes the address in `f` after that call; local-buffer overflow may reach it. |
| Format-string question | `%x`/`%d` read nonexistent argument slots; `%n` can instead write through a fetched pointer. |
| 1B-HEAP | Overflow from heap `buf1` can reach adjacent `buf2`/`buf3` data and chunk metadata; local variables and saved return address live on stack, not next to this heap buffer. |
| 1B-INT | On the stated x64 build, `unsigned short x1=32767; short y1=x1+1; unsigned short y2=x1+1; printf("%hi, %hu",y1,y2)` prints `-32768, 32768`: arithmetic promotes to `int`, then assignment narrows. **Portability caveat:** conversion of 32768 to signed 16-bit `short` is implementation-defined (or raises an implementation-defined signal); the quiz's “wrap” is build-specific. |
| 1B-CAST | An unchecked downcast can produce both out-of-bounds reads and writes by accessing a field absent from the actual smaller object. |
| 8-bit `char` question | Quiz says `127 + 1 → -128` for signed 8-bit `char`; same caveat: arithmetic promotes to `int`, narrowing 128 to signed `char` is implementation-defined, not a portable hardware guarantee. |
| `static_cast` question | `Base` lacks `Derived::y`; an unchecked `static_cast<Derived*>(b)` does not create the derived field and using it can cross the real object's boundary. |
| Heap-metadata question | Classic overflow may corrupt adjacent freed chunk's `fd/bk`; later unsafe unlink can use them in writes. Modern glibc adds checks/tcache: this is a historical mechanism, not a universal present-day primitive. |

## Temporal errors and ownership ([2](https://compsec.kisp-lab.org/Memory-Safety-Webbook/02-temporal-memory-errors.dc.html), [6](https://compsec.kisp-lab.org/Memory-Safety-Webbook/07-memory-safety-in-rust.dc.html))

| Checkpoint | Answer / reason |
|---|---|
| 1C-TEMPORAL | After `free(p); p=NULL`, `free(p)` is harmless, but an alias `p_name` still points to dead storage: printing it is UAF. Testing `p` before `p->age` avoids the separate NULL dereference; remove/check aliases to fix UAF. |
| 1C-LOCKKEY | Under single-threaded execution, protected metadata and correct propagation, lock/key can reject UAF and double-free through **any** stale alias. It has runtime cost; clearing only one pointer cannot cover aliases. Concurrent free between check and access needs synchronization. |
| 1F-SPTR | `unique_ptr` is move-only without a reference count (true). `shared_ptr` does **not** establish compile-time complete safety (false): it counts owners at runtime, does not protect dangling raw aliases, and strong cycles may leak. |
| Double-free question | Duplicate free-list entry can yield two allocations of the *same chunk*; one owner can then change data seen by the other, or modify a link while the chunk remains listed so a later allocation returns another address. A second `free` can overwrite old user data with allocator links; it is not itself an immediate arbitrary write. Current allocator duplicate checks often abort. |

## Exploitation ([3](https://compsec.kisp-lab.org/Memory-Safety-Webbook/03-control-flow-hijacking.dc.html))

| Checkpoint | Answer / reason |
|---|---|
| CF-NOPSLED | `0x90` sled tolerates an imprecise landing address within its finite range and runs into shellcode. |
| CF-INJ | Event order **CDBA**: overflow plants sled/payload/return address → `ret` transfers → land in sled → run shellcode. |
| CF-REUSE | False statement: “code reuse needs injected executable code.” ret2libc/ROP run existing executable code and bypass the particular property DEP enforces. |
| NCF-CFDEF | Data-only attacks change a flag/UID or leak data (Heartbleed) without an unauthorized control transfer; CFI does not detect that memory access. |
| NCF-DOP | Code-injection requirements 1–3 (write injected code, make it executable, divert control to it) are **all unnecessary** for a data-oriented attack. The attack still needs a relevant data-access primitive. |

## Partial and full safety ([4](https://compsec.kisp-lab.org/Memory-Safety-Webbook/05-partial-memory-safety.dc.html), [5](https://compsec.kisp-lab.org/Memory-Safety-Webbook/06-full-memory-safety.dc.html))

| Checkpoint | Answer / reason |
|---|---|
| 1D-CANARY | Loader supplies fresh process secret from TLS (`%fs:0x28` on shown x86-64 Linux). A constant compiled into the binary could be read offline. |
| 1D-DEP | NX/DEP denies code-injection requirement 2: payload bytes must be executable. Code reuse does not need injected executable pages. |
| 1D-ASLR | ASLR changes a mapped region's base; within-region offsets stay fixed, so a leaked pointer plus known offset can locate other symbols **in the same region**. |
| 1D-SFI | Jumping straight to `mov` bypasses a preceding mask unless every memory access uses a reserved register that only validated coercion writes. |
| 1D-TCB | A separately checked machine-code verifier, not the code-generating compiler, is the trusted component; its correctness and complete coverage matter. |
| 1D-CFI | One tag for multiple legitimate targets admits any target in that equivalence class; conservative CFG approximation can admit more edges than a particular call actually uses. |
