# Spatial Memory Errors

[textbook spatial memory vulnerabilities](https://compsec.kisp-lab.org/Memory-Safety-Webbook/01a-spatial-memory-errors.dc.html#bg-group)
Reading/writing memory outside the intended bounds of a memory segment.  
Memory leak is **not** a memory-safety issue

## Identifying memory segments from process memory dump

look at `proc/<pid>/maps` to identify memory segments of a process

decide the memory segment based on the permissions:

- stack: rw-p
- heap: rw-p
- data: r--p
- text: r-xp

## Types

### Buffer overflow

- **scanf()/strcpy()**: the input buffer is not checked for size, so if the input is larger than the buffer, it will overflow into adjacent memory.
  - some 'checks' may fail due to integer overflow which could be due to type narrowing or signedness issues.
  - overwriting the return address on the stack can lead to arbitrary code execution.

- **printf()**: if the format string is user controlled, it can be used to read/write arbitrary memory locations.
  - read: supplying extra format specifiers (e.g. `%x`) will read from the stack and print the values.
  - fix: use a fixed format string (e.g. `printf("%s", user_input)`) to prevent reading from the stack.

      ```C
      printf(localStr);          // the user picks the specifiers
      printf("%s", localStr);    // the user is now just data
      ```

  - write: supplying `%n` format specifier will write the number of bytes written so far

### Return oriented programming (ROP)

Unable to inject shellcode into the stack due to NX/DEP hence we reuse existing code to perform arbitary operations.

Gadgets: existing, small snippets of assembly instructions that end with a return instruction. These gadgets can be chained together to perform arbitrary operations.

- manipulate stack to modify the return address to point to the desired gadget
- place the arguments for the gadget on the stack in the correct order to set up parameters in the registers as per calling convention
- Turing complete: by chaining together enough gadgets, we can perform arbitrary computation
- often impractical to write ROP chains by hand, so tools like [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) and Ropper can be used to automate the process of finding gadgets and generating ROP chains.

### Heap Overflow

- Allocated memory consists of the metadata (size + flag = 8 byte)
- Total size of the allocated block is multiple of 16 bytes on glibc 64-bit systems
- After freeing the block, the metadata is used to link the free blocks together in a linked list

overwriting the pointer to free/occupied memory

### Data oriented attacks

non-control flow attacks that manipulate data in memory to achieve a desired effect without changing the control flow of the program.

e.g. Heartbleed

### C++ Type casting

Downcasting a pointer to a derived class that inherits multiple base classes can lead to undefined behavior if the pointer is not actually pointing to an object of the derived class. This can result in accessing memory outside the bounds of the intended object.

- write to memory outside the bounds of the intended object, which can lead to memory corruption and undefined behavior.
- downcast the second base class (class B) pointer to the derived class pointer, which will lead to accessing memory outside the bounds of the intended object. (before the class B)

## Mitigations

### Position Independent Executable (PIE)

Add a random offset to the base address of the executable at load time. This makes it harder for an attacker to predict the location of code in memory, making it more difficult to exploit memory corruption vulnerabilities.

### Stack canary

Known value between locals and saved return address on the stack. The value is checked before returning. Usually placed right after the frame pointer (ebp) and before the saved return address. If the value is changed, the program will terminate with a stack smashing detected error.

Enabled by default: objdump a simple program to inspect  
![stack canary](../../assets/canaries.png)  
disable using flag `-fno-stack-protector` when compiling

- stack first byte is 0x00 to prevent string overflows from overwriting the canary value
- enabling canaries can move locals around, e.g. placing buffers after the canary to prevent overflows from overwriting the canary value.

### Libsafe

intercepts calls to unsafe functions (e.g. strcpy, strcat, sprintf) and check:

`|frame-pointer – dest| > strlen(src)`

otherwise abort

### Guard Pages

Pages with No permissions (NR,NW,NX) are placed between memory segments to prevent overflows from one segment to another.

- Attacker can only write linearly
- All written values are not used in dereferences

### Non-executable Data DEP

DEP/W$\oplus$X: use NX bit  
prevents code injection  

### Address Space Layout Randomization (ASLR)

- Assumption:
  - Attacker can write arbitrary places
- Defense Goal:
  - Attacker can’t predict location accessed in attack
- Mechanism:
  - At load time, randomize stack, code, bss, etc.
  - Randomize heap location at runtime
  - Attacker can't predict location accessed

### Inline reference monitor (IRM)

**Reference monitor:** code that checks all references to an object
**Syscall sandbox:** restricts the set of syscalls that can be made by a process

helps w Fault isolation, but not memory safety

#### Software Fault Isolation (SFI)

![fast sfi](../../assets/fast-sfi.png)

the coeercion can be bypassed if we jump after the check  
Fix: use dedicaged registers to hold instead of ebp

Can disassemble the code to check for the following patterns:

1. Check if these IRM instructions exist before memory access

    ```
    and reg1, 0x00ff
    or reg1, 0xbe00
    mov (reg1), eax
    ```

2. All memory accesses use the dedicated register
3. The dedicated registers are used only in IRM instructions

##### Security Principle: Minimize Trusted Code Base (TCB)

- Reduce what one needs to trust (in this case, do not have to trust the compiler)
- Separate verifier from the enforcement
- Smaller the TCB, the better the design

Do not have to trust the compiler to perform fast SFI, we can just look at the disassembly to check for the IRM instructions and dedicated register usage.

#### Control Flow Inspection (CFI)

Mitigates control flow attacks

**Challenges:** Diffidult to implement in practice due to inability to determine all possible targets of indirect jumps/calls, compiler optimizatins, runtime compiler generated code, etc.

##### Abadi et al. - inline CFI

```x86
cmp ecx, 0x80480aa   ; is the computed target the one allowed destination?
jne error_label      ; not allowed -> abort / halt
jmp ecx              ; allowed -> do the original jump
```

##### Randomized tag

1. Each code block must start with a tag
2. The tag should be a random, secret value
3. If f can jump to block g,h,…
4. Then blocks g,h,… should have the same tag

### Fat pointer: pointer + metadata (e.g. bounds)

used by rust

Store the bounds of the memory segment in the pointer itself, so that any dereference can be checked against the bounds.

- pointer arithmetic is allowed beyond the bounds, as long as pointer is not dereferenced
- pointers of different size-types of diff bounds
- trade offs:
  - extra memory overhead for storing the metadata
  
safe typecasts require update to pointer bounds
