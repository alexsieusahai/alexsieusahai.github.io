---
layout: post
title:  Pwndocker Usage with Alternative Dynamic Linkers and Libc
categories: [pwnable.kr]
excerpt: 
---
# Pwndocker Usage with Alternative Dynamic Linkers and Libc

A lot of the time, CTFs will give you the binary, linker used, and libc version used.

This is particularly important for, say, heap challenges, where certain techniques only exist on certain versions of libc.

## How to check what a binary is currently using?

Something that's perhaps very useful for debugging is seeing what the binary currently uses, based on the current environment configuration and the information within the ELF itself.

We can use `ldd` to see exactly what shared libarries are loaded for a given binary.

For example, on my system, `ldd` spits out the following for `/bin/ls`, on Ubuntu 22.04:

```
aa@aa:~$ ldd /bin/ls
        linux-vdso.so.1 (0x00007ffe801e2000)
        libselinux.so.1 => /lib/x86_64-linux-gnu/libselinux.so.1 (0x00007fdd9d6e0000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fdd9d4b8000)
        libpcre2-8.so.0 => /lib/x86_64-linux-gnu/libpcre2-8.so.0 (0x00007fdd9d421000)
        /lib64/ld-linux-x86-64.so.2 (0x00007fdd9d745000)
```

This describes the dynamic linker's understanding of all of the loaded shared objects, along with where they are in that particular process running `ldd` (those are virtual memory addresses, so they will change each invocation of `ldd` due to ASLR).

Note that these are the symbols that exist within the dynamic linker's symbol table (to the best of my knowledge, anyways); these merely describe the symbol name to offset mapping for that particular invocation of `ldd`, hence why the virtual addresses are shown, and not the physical addresses (in which case we'd expect persistence of those addresses, and we wouldn't expect all of them to be near the stack).

Importantly, for us, it shows us where each shared object was loaded from.

After we patch the ELF and setup the environment properly, ldd should show us that something that we wanted to change, such as `ld`, will be something like the following:

```
root@d396e79237b2:/ctf/work/habybeap# ldd habybeap
        linux-vdso.so.1 (0x00007ffcf0fe2000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f8881e95000)
        /ctf/work/habybeap/ld.so => /lib64/ld-linux-x86-64.so.2 (0x00007f888209f000)
```
(This particular binary is from Volga's 2022 ctf quals, `habybeap`).

## Setting up pwndocker

[First, install pwndocker and its dependencies.](https://github.com/skysider/pwndocker)

Importantly, we want to run `gdb` on the container itself; we want to allow `SYS_PTRACE` and an `unconfined` seccomp to allow `PTRACE` to be used; we run the following instead of what's in the docs:

```
docker run --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -it skysider/pwndocker /bin/bash
```

### Spacemacs setup

My main goal here is to make exploit dev for ctf style problems as painless as possible for my particular setup.
Mine is barebones; I tend to just prefer using `pwndbg` instead of `gud` or `realgud`.

I use `spacemacs` as my IDE; three particular packages (available on MELPA) that are extremely helpful here are:
```
dotspacemacs-additional-packages '(
                                  ...
                                  docker
                                  docker-tramp
                                  vterm
                                  ...
                                  )
```

This will allow us to just tramp into our container, spawn a virtual shell, and this gets me far enough to be happy for most things.

### Moving The Binary and Dependencies Over

By convention, we carry all of our binaries in `/ctf/work`.
Other than that, the following is fairly straightforward:

```
aa@aa:~$ docker ps
CONTAINER ID   IMAGE       COMMAND       CREATED          STATUS          PORTS       NAMES
28ab7631a919   pwndocker   "/bin/bash"   25 seconds ago   Up 25 seconds   23946/tcp   vigilant_dewdney
aa@aa:~$ docker cp volga/habybeap vigilant_dewdney:/ctf/work/
```

### Patching the ELF to use your desired `ld.so`

We'll use the bundled up `patchelf` in `pwndocker` to patch the binary:

I'm assuming that your current directory contains your desired `ld.so`, otherwise adjust accordingly:

```
patchelf --set-interpreter $PWD/ld.so <your_binary>
```

### Setting up your desired `libc` using LD_PRELOAD

This is very simple; note that we want `libc` to work for only our binary, so we just have to set the `LD_PRELOAD` variable accordingly in the same process:

```
LD_PRELOAD=$PWD/libc.so.6 <your_binary>
```

Importantly, we can't run `gdb` in the above command, as `gdb` is using a different dynamic loader than our binary; we instead want to run `gdb` like so:

```
ps aux | grep <your_binary>   # find the pid associated with your binary
gdb -p pid 
```

Happy pwning!
