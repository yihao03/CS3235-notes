# Spatial Memory Errors

> Sources: [01a Spatial](https://compsec.kisp-lab.org/Memory-Safety-Webbook/01a-spatial-memory-errors.dc.html) · [01b Spatial (Advanced)](https://compsec.kisp-lab.org/Memory-Safety-Webbook/01b-spatial-memory-errors-advanced.dc.html) · `lectures/1a`, `lectures/1b` PDFs · Lab 1A/1B solution tutorials.
> Organized by topic, not lecture order. Code snippets preserved from sources.

Additional source sections: [1A threat model](https://compsec.kisp-lab.org/Memory-Safety-Webbook/01a-spatial-memory-errors.dc.html#threat-model) · [1A x86 primer](https://compsec.kisp-lab.org/Memory-Safety-Webbook/01a-spatial-memory-errors.dc.html#x86) · [1A definition](https://compsec.kisp-lab.org/Memory-Safety-Webbook/01a-spatial-memory-errors.dc.html#spatial-def) · [1A summary](https://compsec.kisp-lab.org/Memory-Safety-Webbook/01a-spatial-memory-errors.dc.html#summary) · [1B integer overflow](https://compsec.kisp-lab.org/Memory-Safety-Webbook/01b-spatial-memory-errors-advanced.dc.html#intoverflow) · [1B C++ subtyping](https://compsec.kisp-lab.org/Memory-Safety-Webbook/01b-spatial-memory-errors-advanced.dc.html#cpp) · [1B bad casts](https://compsec.kisp-lab.org/Memory-Safety-Webbook/01b-spatial-memory-errors-advanced.dc.html#badcast) · [1B summary](https://compsec.kisp-lab.org/Memory-Safety-Webbook/01b-spatial-memory-errors-advanced.dc.html#summary).

## 0. Model

**Threat model:** benign-but-buggy programmer. Gap between intended behavior and behavior on real hardware = vulnerability.

**Definition:** spatial = access outside object's bounds (wrong place). Temporal = outside lifetime (wrong time). Leak is **not** a safety violation.

<mermaid>
flowchart TD
  MV["Memory vulnerability"] --> S["Spatial: wrong place"]
  MV --> T["Temporal: wrong time"]
  S --> SO["Stack overflow"]
  S --> HO["Heap overflow"]
  S --> FS["Format string"]
  S --> IO["Integer size error to overflow"]
  S --> BC["Bad cast and type confusion"]
</mermaid>
Worst case for all below: read/write-anything-anywhere.

Much of the request path (browser, protocols, server, OS) uses memory-unsafe C/C++; Microsoft and Chromium each attribute about 70% of serious bugs to memory safety. [1A motivation](https://compsec.kisp-lab.org/Memory-Safety-Webbook/01a-spatial-memory-errors.dc.html#motivation) plots [NVD](https://nvd.nist.gov/) annual published-CVE counts (2005–2025; copied in [introduction](introduction-0.md)) and cumulative product CVEs by CPE match (July 2026 snapshot): Linux kernel 18,708; Debian 10,068; Android 9,259; macOS 6,519; Chrome 5,470; Fedora 5,368; Windows Server 2019 5,101; iOS 4,511; Ubuntu 4,190; Windows 10 4,057. Nine of this top ten are OSes; Chrome is the only application. CPE matching/count methods differ from CVE Details. Privilege escalation is a distinct outcome (e.g. user → root/kernel), not synonymous with memory corruption. Current counts: [NVD](https://nvd.nist.gov/vuln/search/statistics?form_type=Basic&results_type=statistics&search_type=all), [CVE Details](https://www.cvedetails.com/top-50-products.php).

## 1. Background: x86 stack frame

Registers: `EIP/RIP` next instr, `ESP/RSP` stack top (moves), `EBP/RBP` frame anchor (fixed). Operands are `[reg ± offset]`, e.g. `mov -0x4[ebp], ecx`.

Layout for `f()` calling `g(x,y)` (`g` has `char buf[50]`):

```
high addresses
[ebp+8]  first arg (caller's)
[ebp+4]  return address (pushed by call)
[ebp+0]  saved EBP (pushed by prologue, EBP points here)
[ebp-4]  first local ...
low addresses  <- ESP moves, EBP fixed
```

Key collision:

<mermaid>
flowchart TB
  HI["high addresses"] --> CTRL["return address and saved EBP"]
  CTRL --> BUF["buf[49] ... buf[0]"]
  BUF --> LO["low addresses"]
  ST["stack allocation grows toward lower addresses"] -.-> LO
  WR["overflow from buf[0] grows toward higher addresses"] -.-> CTRL
</mermaid>
With `-fomit-frame-pointer` (commonly enabled in optimized builds) there may be no saved-EBP/RBP slot; the unoptimized lab binary keeps a frame pointer. On x86-64, saved `RBP` and the return address are each 8 bytes. Details: [x86 calling convention](https://wiki.osdev.org/Calling_Conventions), [UVA x86 guide](https://www.cs.virginia.edu/~evans/cs216/guides/x86.html).

## 2. Stack buffer overflow — CWE-787

Original snippet (both sources):

```c
int g(int x, int y) {
  char buf[50];
  scanf("%s", buf);   // no length limit!
}
```

Lab version (`login.c`, built `gcc -fno-stack-protector -no-pie -g -w`):

```c
void login(void) {
    int   authenticated = 0;
    char  buf[16];
    // ...
    scanf("%s", buf);  // the bug
    if (authenticated) printf("*** ACCESS GRANTED ***\n");
}
```

Overflow writes toward higher addresses: `buf[50+] → saved EBP → return address`. `ret` pops that slot into `EIP/RIP` → control hijack (Lecture 3: code injection / return-to-libc / ROP). Classic ref: [Aleph One, Phrack 1996](http://phrack.org/issues/49/14.html).

### 2.1 Lab `login.c`: measured layout and attacks

For the tutorial's exact x86-64 binary (`-O0 -fno-stack-protector -no-pie`), disassembly/debugging gives this layout relative to `buf`:

```text
high addresses
offset 40..47   saved return address
offset 32..39   saved RBP
offset 24..31   another 8-byte local/pointer
offset 20..23   authenticated (int)
offset 16..19   alignment padding
offset  0..15   buf[16]
low addresses
```

These offsets are **properties of this compiled binary, not of the C language**. Variable order, padding, optimization, ABI, compiler version, frame-pointer use, and stack-protector settings can all change them. Determine offsets from the actual binary (e.g. disassembly/GDB), not just source declaration order.

<details>
<summary>Calculating offsets in the compiled stack frame</summary>

- Set the buffer's first byte as offset 0. In this build `authenticated` is at +20, saved `RBP` at +32 and return address at +40. Four padding bytes separate the 16-byte buffer from the flag; source declaration order alone cannot establish that.
- `scanf("%s")` copies *n* non-whitespace bytes then writes NUL at offset *n*: with 20 `A`s byte 20 is zero; with 21 it is `0x41`. Forty filler bytes reach the return-address slot; later bytes replace it.
- `ret` interprets eight bytes starting at +40 as a little-endian address: `f6 11 40 00 00 00 00 00` is `0x00000000004011f6`. The added NUL may corrupt a following byte, so inspect the complete write. Remeasure under different compiler flags, ABI and mitigations. [1A source](https://compsec.kisp-lab.org/Memory-Safety-Webbook/01a-spatial-memory-errors.dc.html#overflow).

</details>

* `20` payload bytes only reach `authenticated`; with `scanf("%s", ...)`, the following NUL still writes zero there. A 21st nonzero byte changes its low byte, making `if (authenticated)` true.
* The saved return address begins 40 bytes after `buf`. Forty filler bytes followed by an encoded code address replace it.
* Replacing `RIP` with arbitrary text such as `ABCD` normally crashes; useful control hijacking requires a valid code address, such as the lab's otherwise-unreachable `win()`.

#### Little-endian encoding

x86-64 stores the least-significant byte at the lowest address. Thus a value displayed as `0x00000000004011f6` is injected as bytes:

```text
f6 11 40 00 00 00 00 00
```

If input begins with ASCII `ABCD` (`41 42 43 44` in increasing addresses), a debugger interpreting those four bytes as an integer displays `0x44434241`. Non-printable address bytes cannot reliably be typed at a prompt, so lab payloads are generated as raw bytes and piped to the program.

#### PIE, ASLR, and why the lab uses `-no-pie`

`-no-pie` links a non-PIE executable, fixing its code addresses; therefore `win()` has the same address each run. With PIE plus ASLR, the executable's load base changes each run, although offsets within the executable remain fixed. An attacker then needs an address leak, a partial-overwrite technique, or another way to recover the randomized base. ASLR may still randomize the stack even when the executable is non-PIE.

Fix: bound the write, derive bound from buffer:

```c
scanf("%49s", buf);             // for char buf[50]
scanf("%15s", buf);             // for the lab's char buf[16]
fgets(buf, sizeof(buf), stdin);
```

### 2.2 Stack canaries and compiler layout

A stack canary is a process/runtime secret placed between vulnerable locals and saved control data. The function checks it before returning and aborts if it changed. On common 64-bit Linux implementations it is 8 bytes, with one byte fixed to NUL and the remaining 56 bits randomized. The NUL (the low-address byte on little-endian systems) frustrates leaking/copying the complete canary through NUL-terminated string operations.

Canaries are mitigation, not memory safety:

* They detect a contiguous overwrite that crosses the canary on its way to saved `RBP`/`RIP`.
* They do not stop an overwrite that never crosses it, a non-contiguous arbitrary write, or heap/type-confusion corruption.
* A leaked canary can be copied back unchanged; blind guessing is normally impractical with 56 random bits unless repeated attempts or side channels help.
* Enabling optimization or `-fstack-protector[-strong]` may also reorder locals. In the tutorial build, this incidentally moved `authenticated` below `buf`, so a forward overflow could no longer reach it—but this layout side effect is not the canary's security contract.

See Lecture 1d for full mitigations.

## 3. Format-string bugs — CWE-134

`printf/scanf` are vararg: format string interpreted at runtime to decide how many args to pull.

Vulnerable pattern (slides; lab `fmt.c` is same shape):

```c
#include <stdio.h>
int main() {
  srand(time(NULL));
  char localStr[100];
  int magicNumber = rand() % 100;
  int userCode = 0xBBBBBBBB;
  printf("Username? ");
  fgets(localStr, sizeof(localStr), stdin);
  printf("Hello ");
  printf(localStr);   // BUG: user input as format
  printf("What is the access code? ");
  scanf("%d", &userCode);
  if (userCode == magicNumber) printf("You win!\n");
}
```

```c
// fmt.c lab
fgets(buf, sizeof(buf), stdin);
printf(buf);  // the bug
```

<mermaid>
flowchart LR
  U["user types percent-x codes"] --> P["printf assumes missing args on stack or regs"]
  P --> L["prints stack words, leaks secret"]
  U2["user pads input, embeds addr, uses percent-n"] --> W["percent-n writes count via attacker pointer"]
</mermaid>
* Read: `%x/%d/%s` dump stack words, reach `magicNumber`, `secret`.
* Write: `%n` stores chars-printed-so-far to `int*` from arg list. Attacker controls pointer (address placed in buffer) + value (pad with `%200x`). Write-anything-anywhere, same payoff as heap unlink.
* Fix (one line):

```c
printf(localStr);       // user picks specifiers
printf("%s", localStr); // user is just data
```

Compiler helps: `-Wformat-security` (normally used with `-Wformat`). Ref: [scut/teso format-string paper](https://cs155.stanford.edu/papers/formatstring-1.2.pdf).

x86 vs x64 plumbing: 32-bit passes all args on stack so `%x` walks stack directly. Under the x86-64 System V ABI, integer/pointer arguments use `RDI, RSI, RDX, RCX, R8, R9`, then the stack. For `printf`, `RDI` contains the format pointer, so the first five conversion arguments are fetched from `RSI` through `R9`; later ones come from the stack. Bug identical, offsets differ. See conflict §8 on register count.

### 3.1 Lab `fmt.c`: locating and using argument slots

Useful syntax:

| Format | Meaning |
|---|---|
| `%016lx` | print an 8-byte value as 16 hex digits, zero-padded |
| `%8$lx` | print positional argument 8 as an unsigned long in hex |
| `%8$s` | treat positional argument 8 as `char *` and print the pointed-to string |
| `%9$n` | treat argument 9 as `int *`; store the output count there |
| `%4919u` | print a field at least 4919 characters wide, increasing the output count |

POSIX positional syntax is `%m$conversion`; positions are **one-based**. The format pointer in `RDI` is not position 1 of the conversion-argument list: `%1$...` accesses the first variadic argument (`RSI` on this ABI).

A recognizable marker at the start of input (for example, `MARK`) reveals where attacker-controlled buffer bytes appear while probing with repeated `%016lx`. Because the bytes `4d 41 52 4b` are interpreted little-endian as one integer, the numeric output appears as `4b52414d`. Once the slot is known, positional formats avoid walking through all preceding slots.

For the tutorial's compiled `fmt.c` layout:

* slot 8 contains a pointer to `secret`, so `%8$s` dereferences it and leaks the string;
* slot 9 contains `&target`, so `%9$n` writes to `target`;
* the raw value of `target` may also appear in an earlier slot—do not confuse a variable's value with its address. `%n` requires the latter.

To write `0x1337`, first produce 4919 (`0x1337`) output characters, then use the target-pointer slot: for example, `%1$4919u%9$n` uses argument 1 for the padded output and argument 9 as the destination (the exact count must include any characters already printed by that same `printf` call). `%n` itself prints nothing. Avoid mixing positional (`%9$...`) and non-positional argument conversions in one format string.

Write-width modifiers are exact:

| Conversion | Pointer type / bytes written |
|---|---|
| `%n` | `int *` / typically 4 bytes |
| `%hn` | `short *` / 2 bytes |
| `%hhn` | `signed char *` / 1 byte |
| `%ln` | `long *` / 8 bytes on x86-64 Linux |

`%hn` and `%hhn` store the low 16 or 8 bits of the characters-written count, respectively. Narrow writes are useful for building a larger value piece by piece without printing an enormous number of characters.

ASLR alone does not stop the tutorial's `%8$s` leak or `%9$n` write: addresses change, but the vulnerable call still fetches the already-present pointer from the same argument slot as long as the compiled frame layout is unchanged. ASLR does matter when a payload must embed an absolute address directly.

<details>
<summary>Format-string argument slots and write counts</summary>

- System V x86-64 passes `printf`'s format in `RDI`, conversion argument positions 1–5 in `RSI`, `RDX`, `RCX`, `R8`, `R9`, and subsequent positions on the stack. The vulnerable call supplied **no actual conversion arguments**: consuming residue is undefined behavior and measured slots are binary-specific.
- `%m$lx` prints slot *m*; `%m$s` dereferences its value as a pointer, which may fault. `%m$n` treats it as `int *` and stores the output count there. A slot containing `&target` is not the same as one containing `target`'s value.
- Padding and `%n` act within one `printf`; count all bytes that same call already emitted. `%hhn`, `%hn`, `%n` store low 8 bits, low 16 bits or an `int` respectively; pointer type must match. Positional indexes are one-based; avoid mixing them with non-positional conversions. [1A source](https://compsec.kisp-lab.org/Memory-Safety-Webbook/01a-spatial-memory-errors.dc.html#formatstr).

</details>

## 4. Integer overflow → spatial overflow

Same bits, two meanings. Top bit set → signed/unsigned diverge by 256 (8-bit):

| bits | hex | unsigned | signed |
|---|---|---|---|
| 0000 0000 | 0x00 | 0 | 0 |
| 0111 1111 | 0x7F | 127 | 127 |
| **1**000 0000 | 0x80 | 128 | −128 |
| **1**010 0000 | 0xA0 | 160 | −96 |
| **1**111 1111 | 0xFF | 255 | −1 |

Webbook demo: feed 160 chars to `bad_function`; rebuild with `-funsigned-char` and same input behaves differently — whether it wraps depends on compiler/arch, no source change.

C rules (since C89):
1. Narrow operands promote to **signed** `int` before arithmetic (`unsigned char + unsigned char : int`).
2. Mixed signed/unsigned of same rank → signed converts to **unsigned** (negative becomes huge positive).

Hardware raises no fault: ALU runs same bit ops for both; signedness is compiler claim. So a wrapped length passes a guard then drives `memcpy/malloc` overflow. Integer bug corrupts the *size*, not memory directly.

### 4.1 Lab `records.c`: a small allocation followed by a large write

The important shape is:

```c
#define REC_SIZE 16
unsigned short count;
unsigned short bytes;

scanf("%hu", &count);
bytes = count * REC_SIZE;
char *buf = malloc(bytes);

for (int i = 0; i < count; i++)
    memset(buf + i * REC_SIZE, 'A', REC_SIZE);
```

An `unsigned short` is 16 bits in the lab, so assignment to `bytes` keeps the result modulo `2^16 = 65536`. The multiplication itself occurs after integer promotion, typically as a 32-bit `int`; the truncation happens when that result is assigned back to `unsigned short`.

| `count` | Mathematical `count * 16` | Stored `bytes` | Loop writes |
|---:|---:|---:|---:|
| 4095 | 65,520 | 65,520 | 65,520 bytes |
| 4096 | 65,536 | 0 | 65,536 bytes |
| 4097 | 65,552 | 16 | 65,552 bytes |

`4096` is the first wrapping count. At `4097`, the mismatch is easier to see: only 16 bytes are requested, but the loop correctly follows `count` and writes 65,552 bytes. The loop is not the root cause; allocation and writing use inconsistent representations of the intended size.

Use a type suitable for object sizes and check before multiplying:

```c
if ((size_t)count > SIZE_MAX / REC_SIZE)
    /* reject */;

size_t bytes = (size_t)count * REC_SIZE;
char *buf = malloc(bytes);
if (buf == NULL && bytes != 0)
    /* handle allocation failure */;
```

`malloc(0)` is implementation-defined in practical effect: it may return `NULL` or a unique pointer that still must not be dereferenced. Rejecting a zero record count explicitly is usually clearer when zero is not meaningful.

Refs: [OWASP integer overflow](https://owasp.org/www-community/vulnerabilities/Integer_overflow), [TOCTOU/TOSEM'15 §§1-3](https://dl.acm.org/doi/10.1145/2724714), [C99 conversions](https://stackoverflow.com/questions/50605/signed-to-unsigned-conversion-in-c-is-it-always-safe), [`-funsigned-char`](https://gcc.gnu.org/onlinedocs/gcc/C-Dialect-Options.html), [Godbolt](https://godbolt.org/).

## 5. Heap allocation and heap overflow

`malloc(n)` asks for at least `n` usable bytes whose lifetime continues until `free`; it does **not** promise that the underlying chunk is exactly `n` bytes. An allocator rounds sizes for alignment/minimum-size rules and stores bookkeeping beside the user allocation. These details below describe the lab's 64-bit glibc allocator and are not part of the C standard.

### 5.1 Requests, chunks, and the pointer returned by `malloc`

Useful vocabulary:

* **Request size:** the `n` supplied to `malloc(n)`.
* **Chunk:** allocator-managed region containing metadata plus usable storage.
* **User pointer:** address returned by `malloc`, pointing into the chunk rather than its physical beginning.
* **Usable size:** bytes the allocator makes available; it can exceed the request.
* **Stride:** distance from one adjacent user pointer to the next, equal to the first chunk's rounded physical size in these examples.

The webbook's probe makes two 50-byte requests:

```c
char *a = malloc(50);
char *b = malloc(50);
strcpy(a, "hello");

printf("a                 = %p\n", a);
printf("b                 = %p\n", b);
printf("b - a             = %ld\n", (long)(b - a));
printf("size word at a-8  = %#zx\n", ((size_t *)a)[-1]);
free(a);
printf("first word after free = %#zx\n", ((size_t *)a)[0]);
```

One real run gives:

```text
b - a                 = 64
size word at a - 8    = 0x41
first word after free = allocator link/bookkeeping
```

The 50-byte request becomes a 64-byte chunk. The raw size word `0x41` encodes a chunk size of `0x40` (64) plus flag bit `0x1`. Because chunk sizes are 16-byte aligned, the low bits are available as flags:

| Bit | glibc name | Meaning |
|---:|---|---|
| `0x1` | `PREV_INUSE` | the physically preceding chunk is in use |
| `0x2` | `IS_MMAPPED` | this chunk came from a separate `mmap` allocation |
| `0x4` | `NON_MAIN_ARENA` | this chunk belongs to a non-main arena |

Conceptually:

```c
chunk_size = raw_size & ~(size_t)0x7;  // simplified for this ABI
flags      = raw_size &  (size_t)0x7;
```

Do not read `PREV_INUSE` as “this chunk is currently allocated”; it describes the **previous physical chunk** and helps glibc decide whether backward coalescing is safe.

<details>
<summary>glibc chunk words, rounding, and the apparent header size</summary>

- On this 64-bit glibc build, a physical chunk has `prev_size` and `size` words before its user pointer. Alignment frees low `size` bits for flags: `0x41 & ~0x7 = 0x40` (64-byte chunk) and low bit 1 means the preceding physical chunk is in use.
- While the preceding chunk is allocated, its usable area can overlap the following chunk's `prev_size`. Only the next `size` word therefore looks like an 8-byte intervening header in the lab, though a freed chunk may need both words to coalesce. For `malloc(50)` here, adjacent returned pointers are 64 bytes apart, not universally `50 + 16`.
- The **requested C object** remains 50 bytes: allocator rounding does not authorize extra object accesses. Inspecting metadata via `a[-8]` or reading after `free` is allocator-specific/undefined as C code, suitable only for the lab diagnostic. Heap state, arena, tcache and glibc version alter results. [1B source](https://compsec.kisp-lab.org/Memory-Safety-Webbook/01b-spatial-memory-errors-advanced.dc.html#heap-bg).

</details>

#### Why the lab often calls the header “8 bytes”

glibc's physical chunk prefix is normally described as two 8-byte words, `prev_size` and `size`. However, `prev_size` is meaningful only when the previous chunk is free. While that previous chunk is allocated, glibc lets its user allocation use those overlapping eight bytes. Consequently, from one allocated user pointer to the next, only the next chunk's 8-byte `size` word looks like an intervening header:

```text
high addresses
next user data
next chunk: size                 <- 8 visible intervening bytes
next chunk: prev_size            <- usable tail of previous allocation
previous user data
low addresses
```

This is why the course's simplified model says “8-byte header.” It is correct for computing the demonstrated user-pointer distances, but the full glibc chunk structure is subtler. Always use the addresses printed by the exercise rather than assuming a universal header size.

### 5.2 Lab `acct.c`: two adjacent allocations

```c
struct account {
    char name[32];
    int  balance;
    int  is_admin;
};                                      // sizeof = 40 in this build

struct account *acct = malloc(sizeof *acct);
char *note = malloc(64);
scanf("%s", acct->name);               // unbounded write
```

In the supplied run:

```text
sizeof *acct                  = 40 bytes
note - (char *)acct           = 48 bytes
acct chunk size               = 0x30 = 48 bytes
note chunk size               = 0x50 = 80 bytes
note raw size word initially  = 0x51 = 0x50 | PREV_INUSE
```

The allocator rounds the 40-byte account request to a 48-byte chunk. The 64-byte note request needs an 80-byte chunk in this layout after metadata/alignment. Hence the actual adjacent layout is:

```text
high addresses
offset 48...    note user data (64 requested bytes)
offset 40..47   note raw size word, initially 51 00 00 00 00 00 00 00
offset 36..39   acct.is_admin
offset 32..35   acct.balance
offset  0..31   acct.name
low addresses
```

The printed pointer difference, 48, already includes both the 40-byte struct and the 8-byte intervening size word.

#### `scanf("%s")` and the extra NUL write

`%s` skips leading whitespace, copies until whitespace/EOF, and then writes a terminating `\0`. For `name[32]`, the safe field width is therefore:

```c
scanf("%31s", acct->name);  // at most 31 input bytes + terminating NUL
```

Important lab boundaries:

| Input | What is written |
|---|---|
| 32 characters | fills `name`; terminator starts overwriting `balance` |
| 36 characters | fills through `balance`; terminator writes zero into first byte of `is_admin` |
| 37 `A`s | first byte of `is_admin` becomes `0x41`, so it is nonzero |
| 47 characters | terminator lands at offset 47, still in the size word; `note` remains textually unchanged |
| 48 characters | terminator lands at offset 48 (`note[0]`), so `note` prints as empty |
| 48 `A`s + `PWNED` | 40 `A`s cover the struct, 8 cover metadata, and `PWNED` begins at `note[0]` |

For the final case:

```text
offset  0..39   A × 40       account object
offset 40..47   A × 8        corrupted note size word
offset 48..52   P W N E D    note data
offset 53       00           scanf terminator
```

The note changes successfully, but `free(note)` later detects the corrupted metadata and aborts. Heap corruption often becomes visible only when the allocator next examines the damaged chunk.

#### Why 41 `A`s can be accepted by `free` in this run

The first 40 `A`s fill the struct. The 41st (`'A' = 0x41`) replaces the low byte of the note's size word, and `scanf` writes NUL into the following byte:

```text
raw bytes:       41 00 00 00 00 00 00 00
raw size:        0x41
interpreted size 0x40 = 64, with PREV_INUSE set
```

That forged value happens to pass the checks exercised by this exact run. Other lengths produce:

| Repeated-`A` length | Raw size bytes from offset 40 | Size after flag masking | Typical result here |
|---:|---|---:|---|
| 40 | `00 00 ...` | 0 | invalid pointer/size |
| 41 | `41 00 ...` | `0x40` = 64 | accepted in the lab run |
| 42 | `41 41 00 ...` | `0x4140` = 16,704 | corruption check |
| 43 | `41 41 41 00 ...` | `0x414140` = 4,276,544 | out-of-range corruption |

This experiment assumes repeated uppercase `A`; input length alone is insufficient because different character bytes create different flags and sizes. For example, `'B' = 0x42` sets `IS_MMAPPED`, so it does **not** mean merely “size 0x40.” Allocator validation is also much more involved than checking “multiple of 16 plus a flag,” and behavior varies by glibc version and heap state.

An attacker can cross the metadata while preserving its original bytes, conceptually:

```text
A × 40 | 51 00 00 00 00 00 00 00 | PWNED
          original note size word
```

Then the note changes while the size word remains plausible. Raw-byte generation is needed for the embedded NULs. This is still an out-of-bounds write even if both calls to `free` finish quietly.

### 5.3 Allocated versus free chunks

The allocator stores bookkeeping *inside the heap*, interleaved with user data. Two layouts must be kept separate:

1. **Physical order:** all chunks, allocated or free, are packed next to physical neighbors.
2. **Logical free structures:** only free chunks are linked/cached for reuse; their logical order need not match physical order.

An allocated chunk needs its size metadata, but there is no master linked list of every allocated chunk. Once a chunk is freed, the allocator may overwrite its former user bytes with free-list/cache links. In the classic simplified model:

```c
struct chunk {
    size_t         size;  /* always present */
    struct chunk  *fd;    /* overlaps former user data while free */
    struct chunk  *bk;
};

void list_unlink(struct chunk *p) {
    p->fd->bk = p->bk;
    p->bk->fd = p->fd;
}
```

If an overflow controls a free neighbor's `fd` and `bk`, old unsafe-unlink attacks turn those assignments into attacker-influenced writes. Modern glibc validates links and places many small chunks in a per-thread **tcache**, which uses a single safe-linked pointer instead; the classic code is an attack model, not a faithful description of every modern `malloc`/`free` operation.

<mermaid>
flowchart LR
  A["allocated chunk A: overflowing data"] -->|physical neighbor| BH["chunk B metadata"]
  BH --> BD["chunk B user area / free-list links"]
  O["corrupted size or links"] --> USE["allocator later consumes corrupted bookkeeping"]
</mermaid>
No return address is required, so stack canaries are irrelevant. Heap metadata corruption can yield crashes, overlapping allocations, information leaks, or—under exploitable allocator behavior—an arbitrary-write primitive. Orig: [Phrack 2001 heap](http://phrack.org/issues/57/9.html). References: [webbook §01b](https://compsec.kisp-lab.org/Memory-Safety-Webbook/01b-spatial-memory-errors-advanced.dc.html), [ptmalloc overview](https://sourceware.org/glibc/wiki/MallocInternals), [tcache/safe-linking background](https://sourceware.org/glibc/wiki/MallocInternals#Tcache). See errata §8.

<details>
<summary>Physical neighbors and free-list links</summary>

- Physical adjacency determines which chunk an overflow reaches: A's write may hit B's size word before B's data. Free-list adjacency is different: B's logical `fd`/`bk` neighbors need not be its physical neighbors.
- Historical doubly linked unlink writes `fd->bk = bk` and `bk->fd = fd`; forged links can influence destination/value only if the allocator accepts them. This is **not** a claim that arbitrary forged links pass modern consistency checks.
- Modern small-allocation paths often use per-thread tcache, placing a protected singly linked next pointer in formerly user-controlled bytes. Coalescing, size checks, safe-linking and reuse depend on chunk size, heap state and glibc version; detection may occur at a later `free()` rather than the bad write. [1B source](https://compsec.kisp-lab.org/Memory-Safety-Webbook/01b-spatial-memory-errors-advanced.dc.html#heap-overflow).

</details>

## 6. C++ bad casting / type confusion

`Derived : Base` object = `Base` sub-object followed by `Derived` members. Multiple inheritance = `B1` sub-object, then `B2` sub-object, then `Derived` members — so `B2*` ≠ object start.

Upcast (derived → base): always safe, compiler *adds* sub-object offset.

```c
class Base { int x; };
class Derived : public Base { int y; };
Derived* d = new Derived();
Base* b = static_cast<Base*>(d); // safe, same address (single inheritance)
```

```c
class B1 { int x; }; class B2 { int y; };
class Derived : public B1, public B2 {};
Derived* d = new Derived();
B2* h = static_cast<B2*>(d); // safe, h = d + sizeof(B1)
```

Downcast (base → derived): safe only if object really is `Derived`; compiler *subtracts* offset blindly. `static_cast` does **no runtime check**; `dynamic_cast` checks runtime type (needs polymorphic class) and returns `nullptr` on failure.

Bad cast (slides, preserved):

```c
class Base { int x; };
class Derived : public Base { int y; }
int foo(Base* b) {
  Derived* d = static_cast<Derived*>(b); // bad if b = new Base()
  d->y = 0; // writes past object — field never allocated
}
```

Multiple-inheritance version: downcasting a `B1*` that is really just a `B1` shifts pointer back by `sizeof(B1)` and `b2->y` lands out of bounds.

<mermaid>
flowchart TD
  D["static cast Derived from B2"] --> SUB["subtract B2 offset"]
  SUB --> OK{"really Derived?"}
  OK -->|yes| GOOD["points at object start, safe"]
  OK -->|no| BAD["points before object, OOB"]
</mermaid>
### 6.1 Lab `badcast`: allocation size is not object size

The lab uses the single-inheritance equivalent of:

```cpp
class Base {
public:
    int x;
};

class Derived : public Base {
public:
    int  y;
    char tag[64];
};

Base *b = new Base;
char *other = new char[32];
Derived *d = static_cast<Derived *>(b);  // compiles, but b is not a Derived
scanf("%s", d->tag);                    // writes to a field that does not exist
```

The cast performs no allocation and creates no `Derived` object. It merely tells subsequent generated code to use the `Derived` offsets:

```text
Base::x       offset 0
Derived::y    offset 4
Derived::tag  offset 8, length 64
sizeof(Base)     = 4
sizeof(Derived)  = 72             (lab ABI/build)
```

For this run, glibc gives the 4-byte `Base` request a minimum 32-byte chunk with 24 usable bytes. Minimum chunk size must be large enough to hold allocator metadata when the chunk is later free; the extra capacity belongs to the allocation but does **not** make it part of the C++ object. Access beyond `sizeof(Base)` is still undefined behavior.

If `other` is the adjacent allocation, its user pointer is 32 bytes after `b`, while the invalid `tag` begins 8 bytes after `b`:

```text
high addresses
b + 32       other[0]
b + 24..31   next chunk's size word
b + 8..23    nonexistent tag bytes / spare usable allocation bytes
b + 4..7     nonexistent Derived::y plus padding area
b + 0..3     real Base::x object
low addresses
```

The distance from `d->tag` to `other` is `32 - 8 = 24` bytes. Twenty-four visible input bytes reach up to `other`; the automatic NUL then lands in `other[0]`, while a 25th nonzero byte makes the corruption visibly nonempty. As always, these distances rely on the two allocations actually being adjacent in this lab run.

A checked downcast requires a polymorphic base class and a null check:

```cpp
class Base {
public:
    virtual ~Base() = default;  // makes Base polymorphic
    int x;
};

if (Derived *d = dynamic_cast<Derived *>(b)) {
    // safe to use d as Derived
} else {
    // b does not point to a Derived object
}
```

For pointer casts, failed `dynamic_cast` returns `nullptr`; dereferencing that result without checking still crashes. A virtual function normally adds a hidden vptr and changes object size/layout (the tutorial observed `sizeof(Base) == 16`), but that exact size is ABI-dependent.

Runtime cost is one reason `static_cast` persists in performance-sensitive code despite the risk. Ref: [C++ casts](https://en.cppreference.com/w/cpp/language/static_cast.html), [dynamic_cast](https://en.cppreference.com/w/cpp/language/dynamic_cast.html).

## 7. Exploit outcomes and data-oriented attacks

Stack/heap/format all converge on read/write-anywhere. Slides preview Lecture 3: code injection (return into attacker payload, NOP sled `0x90` if address imprecise) and code reuse / return-to-libc (return into existing code, set up args on stack). Data-oriented attacks need neither: corrupt security-critical non-control data (e.g. `safemode` flag, `seteuid` uid, Heartbleed over-read). Refs: [Non-control-data attacks (Chen et al., USENIX 2005)](https://www.usenix.org/legacy/event/sec05/tech/full_papers/chen/chen.pdf), [Heartbleed](https://heartbleed.com/), [SEED labs](https://seedsecuritylabs.org/Labs_20.04/Software/).

## 8. ⚠️ Conflicts / errata in the course material

1. **Allocated chunks in a list?** Slides (1b): "stores each allocated chunk in a linked list." Webbook (01b): "There is no list of allocated chunks anywhere." **Webbook is correct** for glibc ptmalloc — allocated chunks carry only `size`; only free chunks are linked. Trust webbook.
2. **Unlink = current glibc?** Slides present `fd/bk` unlink as *the* mechanism. Webbook agrees it is the classic [Phrack 2001](http://phrack.org/issues/57/9.html) shape but notes modern glibc parks small chunks in per-size **tcache** with a single (safe-linked/scrambled) pointer, not `fd+bk`. Slides outdated; attack idea (overflow into neighbor metadata → controlled write on alloc/free) still holds.
3. **x64 register args.** Slides diagram: "first 5 args in registers"; webbook: "first five in registers". Reality (System V AMD64): **6** registers `rdi,rsi,rdx,rcx,r8,r9` (format + 5 varargs in regs for `printf`). Both sources mean "5 varargs after format" but phrase it as "5 args" — off-by-one if read literally. Effect unchanged: `%x` reads regs first, then stack.
4. **Slide code typo (1b, multiple-inheritance bad cast):** `Derived* d = (Derived*)b1; B2* b2 = (B2*)&d;` — `&d` takes address *of the pointer variable*, should be `(B2*)d`. Webbook's offset-subtraction description is the correct mental model.
5. **Integer promotion ranking.** Slides list `bool -> char -> short -> int -> unsigned int -> long ...` as one chain. C rules are two-step (§4 above): promote narrow → signed `int`, then signed→unsigned at same rank. Slide chain over-merges them; follow webbook + C standard.
6. **Missing `bad_function` source.** Webbook exercise references `bad_function` + `-funsigned-char` comparison but static fetch omits the listing; slides give only OWASP/TOSEM pointers. Pattern (§4) is the intended takeaway, not the exact listing.
7. **Tutorial positional-slot counting.** The spoken Q&A alternates between zero-based register counting and `printf` slot numbers. Actual `%m$...` syntax is one-based, and `RDI` holds the format rather than a conversion argument. Use §3.1's model and confirm against the specific binary.
8. **“Locals will always be on the stack.”** Not guaranteed. The compiler may keep a local in a register, optimize it away, merge storage, or reorder stack slots as permitted by observable C behavior. Debug/unoptimized builds merely make source-like stack layouts more likely.
9. **Why little-endian?** The tutorial's truncation/casting example describes one convenience of little-endian representation, not a definitive historical reason that modern CPUs use it. Endianness does not change byte order within the input stream; it changes how a multi-byte integer interprets those bytes.
10. **Canary and protection defaults.** A NUL-leading canary and default stack-protector/PIE settings are toolchain/platform conventions, not universal C or x86 requirements. Inspect the actual build flags and binary hardening.
11. **Bits versus bytes in the Lab 1B explanation.** `struct account` requests **40 bytes**, its chunk is 48 bytes, and the note's chunk is 80 bytes. The tutorial repeatedly says “bits” at this point; those occurrences should be “bytes.”
12. **“`0x41` in decimal is 64.”** Raw `0x41` is decimal 65. glibc interprets it as a 64-byte (`0x40`) chunk because bit `0x1` is the `PREV_INUSE` flag and is masked out of the size. Likewise, the original `0x51` means size `0x50` (80) plus that flag.
13. **The heap header is not universally 8 bytes.** The lab's user pointers are separated by a visible 8-byte `size` word, but a glibc chunk is commonly described with both `prev_size` and `size`. The former overlaps storage usable by the preceding allocated chunk. See §5.1.
14. **Allocator checks are not just alignment.** `free` does not merely accept “a multiple of 16 plus 1, 3, or 7.” The low bits have specific meanings, and glibc performs several consistency, range, arena, mapping, and list checks depending on the path/version. A value accepted in this lab is not generally valid.
15. **`dynamic_cast` failure.** A failed pointer `dynamic_cast` returns `nullptr`; this is not itself a “null-pointer error.” An error occurs only if code fails to test the result and dereferences it. The source class must be polymorphic, but the virtual member need not specifically be a destructor.

## 9. Lab workflow

### All lab checkpoints ([1A nine levels](https://compsec.kisp-lab.org/Memory-Safety-Webbook/01a-spatial-memory-errors.dc.html#labs), [1B ten levels](https://compsec.kisp-lab.org/Memory-Safety-Webbook/01b-spatial-memory-errors-advanced.dc.html#labs))

| Chapter / program | Levels and observed outcomes on the course build |
|---|---|
| 1A `login` 1–5 | (1) map flag +20, saved RIP +40 from `buf`; (2) 21 input characters flip flag to `0x41`; (3) overwrite RIP (e.g. `ABCD` yields `0x44434241`); (4) raw little-endian `win()` address reaches otherwise uncalled function; (5) restoring stack protector aborts RIP overwrite, and changed local layout also blocks earlier flag trick. |
| 1A `fmt` 6–9 | (6) find `MARK` in argument words, typically tenth conversion (`4b52414d` little-endian; counting conversions differs from positional indexes); (7) pointer slot leaks `swordfish`; (8) `%n` writes `0x1337` to `target`; (9) `%hn` writes low 16 bits `0xdead` of original `0x11220000`, producing `0x1122dead` without printing billions of characters. |
| 1B `acct` 1–4 | (1) offsets name +0, balance +32, admin +36, note +48 (8-byte intervening size word); (2) 37 `A`s set admin to 65; (3) 48 letters plus chosen word change separate note allocation; (4) four successive input lengths can give invalid pointer, quiet success, `corrupted (!prev)`, `corrupted (out)`—allocator wording/version dependent, quiet completion not proof of safety. |
| 1B `records` 5–7 | (5) first overflow at count 4096: need 65,536, allocate 0; (6) 4097 requests 16 while writing 65,552; (7) loop follows intended count, **multiplication result narrowed into `unsigned short bytes`** is the defective step. |
| 1B `badcast` 8–10 | (8) `Base` is 4 bytes, `Derived` 72; even nonexistent `y` at +4 is outside object; (9) 24 input characters put NUL at neighbor's first byte, 25 place a nonzero byte there; (10) `static_cast` returns unchecked pointer, `dynamic_cast` returns null for a plain `Base` (polymorphic base required). |

The 1A lab has eight browser-input levels and one shell/raw-byte level; all ten 1B levels run in browser (C for `acct`/`records`, C++ for `badcast`). Lab builds print addresses to teach offsets; they intentionally simplify discovery. Exact program source, hints and walkthroughs: chapter links above.

The course provides a Vagrant VM containing the expected compiler, GDB, Makefile, and lab files. Typical use is `vagrant up`, `vagrant ssh`, then `make` inside the lab directory; initial provisioning may take several minutes. OnlineGDB is a fallback for many exercises, but its compiler, hardening, and memory layout can differ, so use the supplied VM when exact offsets or mitigations matter.

Useful verification steps:

1. Record the exact compile flags (`-O` level, PIE, stack protector).
2. Inspect variable addresses and the frame in GDB rather than assuming source order.
3. Use a marker/pattern to measure offsets and format-string slots.
4. Generate binary payloads programmatically so NUL/non-printable bytes and little-endian addresses are exact.
5. Re-run after any compiler or flag change; exploit constants may no longer be valid.

## 10. Further reading

* [CWE-787 out-of-bounds write](https://cwe.mitre.org/data/definitions/787.html), [CWE-134 format string](https://cwe.mitre.org/data/definitions/134.html)
* [CVE Details by date / top products](https://www.cvedetails.com/browse-by-date.php)
* [Compiler Explorer](https://godbolt.org/), [OnlineGDB](https://www.onlinegdb.com/)
* [glibc MallocInternals](https://sourceware.org/glibc/wiki/MallocInternals)
