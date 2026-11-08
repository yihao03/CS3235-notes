# C Basics

## Common registers

### 32-bit registers

- esp: stack pointer
- ebp: stack base pointer (frame pointer)
- eip: instruction pointer (program counter)
  - points to the next instruction to be executed

### 64-bit registers

- rsp: stack pointer
- rbp: stack base pointer
- rip: instruction pointer

On 64 bit systems, arguments are passed in registers:

| Platform | Return Value | Parameter Registers | Additional Parameters | Stack Alignment | Scratch Registers | Preserved Registers | Call List |
| --- | --- | --- | --- | --- | --- | --- | --- |
| System V i386 | eax, edx | none | stack (right to left) | | eax, ecx, edx | ebx, esi, edi, ebp, esp | ebp |
| System V X86_64 | rax, rdx | rdi, rsi, rdx, rcx, r8, r9 | stack (right to left) | 16-byte at call | rax, rdi, rsi, rdx, rcx, r8, r9, r10, r11 | rbx, rsp, rbp, r12, r13, r14, r15 | rbp |
| Microsoft x64, UEFI X64 | rax | rcx, rdx, r8, r9 | stack (right to left) | 16-byte at call | rax, rcx, rdx, r8, r9, r10, r11 | rbx, rdi, rsi, rsp, rbp, r12, r13, r14, r15 | rbp |
| ARM (32-bit) | r0, r1 | r0, r1, r2, r3 | stack | 8 byte | r0, r1, r2, r3, r12 | r4, r5, r6, r7, r8, r9, r10, r11, r13, r14 | |

System V includes UNIX systems such as Linux, FreeBSD, and macOS, i386 is 32bit, X86_64 is 64bit

## Compiling a program

Source code -> **Compiler** -> Assembly Code -> **Assembler** -> Object Code -> **Linker** -> Executable Code -> **Loader** -> Run the code

## Function calling convention

[x86 Calling Convention](https://wiki.osdev.org/Calling_Conventions)

Parameters passed onto stack in reversed order as 32-bit values.

### Calling a function

1. Push all function operands into registers or onto the stack
2. Push the value of the program counter onto the stack (ret address)
3. Jump to the location of the desired subroutine code
4. Push the stack base pointer onto the stack (ebp)
5. Copy the value of the stack pointer to the stack base register (esp -> ebp)

[reference: quiz q6](https://compsec.kisp-lab.org/Memory-Safety-Webbook/prerequisite-self-test.dc.html)

### Returning from a function

1. Save the return value to either a register or onto the stack as per calling convention
2. Copy stack base register to stack pointer
3. Pop stack base register from the stack
4. Pop the program counter from the stack (i.e. the RET instruction)

[reference: quiz q7](https://compsec.kisp-lab.org/Memory-Safety-Webbook/prerequisite-self-test.dc.html)

/prac/chrome_pid/smaps
