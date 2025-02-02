---
title: "bi0sCTF22 - n0tes"
description: 
date: 2023-01-24 05:01:57
image: 
math: 
license: 
hidden: false
comments: false
draft: false
categories:
  - CTF Writeup
tags:
  - bi0sCTF2022
  - Double Fetch Race Condition
  - SROP

---


**tl;dr**

+ Double fetch race Condition in store_note function.
+ overwrite size during race window to get buffer overflow.
+ Do SROP for execve("/bin/sh\x00")

<!--more-->

**Challenge Points**: 856
**No. of solves**: 18
**Author**: [spektre](https://twitter.com/0xspektre)

## Challenge description

***Heard of heap notes? this ain't one.***

## Initial analysis

The binary is standard *x86 64-bit Dynamic stripped* executable.

The mitigations enabled on the binary are as follows:

```sh
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
On reversing the binary, we can see there are 6 options avaiable:
1. Store Note - stores note in the shared memory.
2. Delete Note - memset note to 0.
3. Print Note - prints the note.
4. Upgrade Note - Upgrade size of the note.
5. Encrypt/Decrypt - Encrypt note and store note in shared memory.
6. Exit

The binary operates with two threads, one thread does all the store, delete, print, upgrade and encrypt functionality and the other thread checks size of the note and memcpy into buf[64] if size is less than 64 once store_note is done.

## Vulnerability

store_note in thread 1 :
```c
void store_note(sh_mem *ptr) {
  syscall(SYS_write, 1, "Enter Note ID: ", 15);
  read_input(ptr->id, 8);
  syscall(SYS_write, 1, "Enter Note Name: ", 17);
  read_input(ptr->name, 16);
  syscall(SYS_write, 1, "Enter Note Size: ", 17);
  scanf("%d", &ptr->size);
  syscall(SYS_write, 1, "Enter Note Content: ", 20);
  read_input(ptr->buffer, ptr->size);
  ptr->size_input = true;
}
```
Functions running on thread 2 :
```c
void process(sh_mem *ptr){
  sleep(2);
    if (ptr->size > 64 || ptr->size < 0) {
    syscall(SYS_write, 1, "Size Limit Exceeded\n", 20);
    exit(0);
  }  
  encrypt_text(ptr);
  char msg[64];
  sleep(1);
  syscall(SYS_write, 1, "Sent!\n", 6);
  memcpy(msg, ptr->buffer, ptr->size);  
}

void *thread2(sh_mem *ptr) {
  while(true){
    ptr->size_input = false;
  while (ptr->size_input == false) {
  }
  process(ptr);
  ptr->thread2_done = true;
  }
}

```
thread2() starts once store_input is done. If you look closely, we can see there is a Race Condition in process() function which Double fetches size for size check and memcpy, with a sleep() in between. Which gives us enough time to overwrite the size in the race window using Upgrade().

Upgrade() :
```c
void upgrade_note(sh_mem *ptr) {
    if(ptr->thread2_done == false){
        syscall(SYS_write, 1, "Error\n", 6);
        return;
    }
  syscall(SYS_write, 1, "Enter Note Size: ", 17);
  scanf("%d", &ptr->size);
  syscall(SYS_write, 1, "Enter Name: ", 12);
  read_input(ptr->name, 0x10);
}
```
we can only use upgrade if thread2() completes executing as it checks if `ptr->thread2_done` is false.
in thread2(), ptr->size_input is set to `false` every time loop, but `ptr->thread2_done` is not reset, so we can use upgrade_note() during store_note() anytime after the first loop is done. This allows us to overwrite size during the race window to get buffer overflow.

## Exploitation

The plan for the exploit is as follows:

+ Use encrypt_decrypt() function to dump the encrypted payload into the shared memory.
+ store_note() once to get `ptr->thread2_done == true`
+ store_note again and overwrite size using upgrade() during the race window to get buffer overflow
+ Now in the rop chain read "/bin/sh\x00" into bss using read_input
+ Now set rax to 0x3b using alarm() (prep for SROP to trigger execve("/bin/sh\x00"))
+ Using alarm() twice returns the number of seconds remaining. so first call alarm(0x3b) and then alarm(0).
+ Now setup SigreturnFrame.

You can find the full exploit [here](https://gist.github.com/SanjayVardhan/d2d6e3a249acf6f023e4f9293f157867)

You can also solve this using ret2libc instead of SROP. The shared memory allocated is right before ld.so page, which has a pointer to an mmaped region. That mmaped region is located right below libc mapping. which gives us enough info to get libc base address, calculate execve address and then do execve("/bin/sh\x00").

## Conclusion

This is my first time making challenge for a ctf. I had a lot of fun and learnt a lot while making this challenge. Hope you had fun while solving as well.

Flag: `bi0sCTF{D3j4_vu!_1v3_ju5t_b33n_1n_th15_pl4c3_b3f0r3_0b91342067c4}`