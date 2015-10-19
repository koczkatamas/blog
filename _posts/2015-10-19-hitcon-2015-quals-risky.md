---
layout: post
title: "HITCON 2015 Quals: Risky"
modified: 2015-10-19
tags: hitcon hitcon2015quals
---
*This challenge was solved by and the write up was written by two of my teammates, gym and balidani.*

In this challange we were provided with a risc-v (<http://riscv.org/>) ELF executable. Unfortunately most of our common tools did not support the archticeture, but some googling quickly revealed that the riscv gnu xcompiler toolchain contains objdump for the riscv.
 
With objdump we could analyse the different regions of the ELF file and dump the asm code from the .text section. Although, the riscv developers provide a qemu fork <https://github.com/riscv/riscv-qemu> for riscv and a precompiled linux image, we could not run the provided binary in the vm so we stuck with the static analysis of the dumped code.
 
After, looking through the asm it became obvious that the binary reads a serial fom the input and if the serial is correct prints the flag.
 
First it verifies that the serial is in the form of 

{% highlight text %}
XXXX-XXXX-XXXX-XXXX-XXXX\n
{% endhighlight %}

{% highlight text %}
8005cc:       02d00693                li      a3,45

800610:       0097c683                lbu     a3,9(a5)
800614:       fce692e3                bne     a3,a4,8005d8 <.exit>
800618:       00e7c703                lbu     a4,14(a5)
80061c:       fad71ee3                bne     a4,a3,8005d8 <.exit>
800620:       0137c603                lbu     a2,19(a5)
800624:       fae61ae3                bne     a2,a4,8005d8 <.exit>
800628:       0187c683                lbu     a3,24(a5)
80062c:       00a00713                li      a4,10
800630:       fae694e3                bne     a3,a4,8005d8 <.exit>
{% endhighlight %}  
 
Than it checks if the serial only contains the '-' sign, uppercase characters and numbers. This is done by checking if the byte value is between 45 and 90 and than shifting a magic constant with the byte value and checking if the lst bit is zero.
 
{% highlight text %}
800648:       0006c703                lbu     a4,0(a3)
80064c:       00168693                addi    a3,a3,1
800650:       fd37071b                addiw   a4,a4,-45
800654:       0ff77713                andi    a4,a4,255
800658:       00e855b3                srl     a1,a6,a4
80065c:       0015f593                andi    a1,a1,1
800660:       f6e66ce3                bltu    a2,a4,8005d8 <.exit>
800664:       fc059ee3                bnez    a1,800640 <.next_check>
800668:       f71ff06f                j       8005d8 <.exit>
{% endhighlight %}
 
After this, all of the 4 byte segments of the serial are loaded as 32bit integers and check is made if they satisfy a series of equations. Such equation in the asm:
 
{% highlight text %}
800694:       03548b3b                mulw    s6,s1,s5
800698:       181aa737                lui     a4,0x181aa
80069c:       c5f7071b                addiw   a4,a4,-929
8006a0:       032987bb                mulw    a5,s3,s2
8006a4:       016787bb                addw    a5,a5,s6
8006a8:       008787bb                addw    a5,a5,s0
8006ac:       f2e796e3                bne     a5,a4,8005d8 <.exit>
{% endhighlight %}
 
These equations are the following:
 
{% highlight text %}
w0 * w1 + w2 * w3 + w4 == (0x181aa << 12) - 929
w0 * w2 + w1 + w4 == (0x2dead << 12) - 821
w0 + w1 + w2 + w3 + w4 == (0x8e2f6 << 12) + 1920
(w1 + w2 + w4) * (w0 + w3) == (0xb3da8 << 12) - 1185
w1 + w2 + w4 == (0xe3b0d << 12) - 529
w0 * w4 == (0x4978e << 12) - 1980
w1 * w2 == (0x9bcd3 << 12) + 222
w1 * w2 * w2 * w3 * w4 == (0x41c7a << 12) + 928
w2 * w3 == (0x313ac << 12) + 1924
{% endhighlight %}
 
If all these constraints are satisfied theses words are xored with some additional constants and concatenated into a string and the result is printed as the flag.

We used pythons z3 to find the serial the fullfills all these conditions such serial is 
{% highlight text %}
KTIY-ML5M-VK7R-FE5Q-L6DD
{% endhighlight %}

The xor constants can be read from the ASM code:

{% highlight text %}
80080c:       2c2817b7                lui     a5,0x2c281
800810:       d2f7879b                addiw   a5,a5,-721
800814:       02f12023                sw      a5,32(sp)
800818:       380537b7                lui     a5,0x38053
80081c:       5257879b                addiw   a5,a5,1317
800820:       02f12223                sw      a5,36(sp)
800824:       6b5c37b7                lui     a5,0x6b5c3
800828:       a247879b                addiw   a5,a5,-1500
80082c:       02f12423                sw      a5,40(sp)
800830:       275427b7                lui     a5,0x27542
800834:       7287879b                addiw   a5,a5,1832
800838:       02f12623                sw      a5,44(sp)
80083c:       297557b7                lui     a5,0x29755
800840:       72f7879b                addiw   a5,a5,1839
800844:       02f12823                sw      a5,48(sp)
{% endhighlight %}  
  
Note: the lui instruction loads immediate value into a register and performs a 12 bit left shift on it.
 
After rearranging the bytes we managed to get the correct flag: 
{% highlight text %}
hitcon{dYauhy0urak9nbavca1m}
{% endhighlight %}

The solver script:

{% highlight python %}
{% raw %}
from z3 import *

s = Solver()

serial = []
serial.append(BitVec('serial_0', 32))  # X
serial.append(BitVec('serial_1', 32))  # X
serial.append(BitVec('serial_2', 32))  # X
serial.append(BitVec('serial_3', 32))  # X
serial.append(BitVec('serial_4', 32))  # -
serial.append(BitVec('serial_5', 32))  # X
serial.append(BitVec('serial_6', 32))  # X
serial.append(BitVec('serial_7', 32))  # X
serial.append(BitVec('serial_8', 32))  # X
serial.append(BitVec('serial_9', 32))  # -
serial.append(BitVec('serial_10', 32)) # X
serial.append(BitVec('serial_11', 32)) # X
serial.append(BitVec('serial_12', 32)) # X
serial.append(BitVec('serial_13', 32)) # X
serial.append(BitVec('serial_14', 32)) # -
serial.append(BitVec('serial_15', 32)) # X
serial.append(BitVec('serial_16', 32)) # X
serial.append(BitVec('serial_17', 32)) # X
serial.append(BitVec('serial_18', 32)) # X
serial.append(BitVec('serial_19', 32)) # -
serial.append(BitVec('serial_20', 32)) # X
serial.append(BitVec('serial_21', 32)) # X
serial.append(BitVec('serial_22', 32)) # X
serial.append(BitVec('serial_23', 32)) # X
serial.append(BitVec('serial_24', 32)) # \n

# a6 = BitVec('a6', 64)
# s.add(a6 == 0x0000ff3ff0fff91f)

# Check serial format
# Check for colons
s.add(serial[4] == 0x2d)
s.add(serial[9] == 0x2d)
s.add(serial[14] == 0x2d)
s.add(serial[19] == 0x2d)
s.add(serial[24] == 0x10)

# Check for charset
for i in range(24):
    s.add(serial[i] >= 0x2d)
    s.add(serial[i] <= 0x5a)

    charset = [45, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90]
    expr = (serial[i] == charset[0])
    for char in charset[1:]:
        expr = Or(expr, serial[i] == char)

    s.add(expr == True)

words = []
w0 = (serial[0] + 
    serial[1] * 0x100 + 
    serial[2] * 0x10000 + 
    serial[3] * 0x1000000)
w1 = (serial[5] + 
    serial[6] * 0x100 + 
    serial[7] * 0x10000 + 
    serial[8] * 0x1000000)
w2 = (serial[10] + 
    serial[11] * 0x100 + 
    serial[12] * 0x10000 + 
    serial[13] * 0x1000000)
w3 = (serial[15] + 
    serial[16] * 0x100 + 
    serial[17] * 0x10000 + 
    serial[18] * 0x1000000)
w4 = (serial[20] + 
    serial[21] * 0x100 + 
    serial[22] * 0x10000 + 
    serial[23] * 0x1000000)

# Check products
s.add(w0 * w1 + w2 * w3 + w4 == (0x181aa << 12) - 929)
s.add(w0 * w2 + w1 + w4 == (0x2dead << 12) - 821)
s.add(w0 + w1 + w2 + w3 + w4 == (0x8e2f6 << 12) + 1920)
s.add((w1 + w2 + w4) * (w0 + w3) == (0xb3da8 << 12) - 1185)
s.add(w1 + w2 + w4 == (0xe3b0d << 12) - 529)
s.add(w0 * w4 == (0x4978e << 12) - 1980)
s.add(w1 * w2 == (0x9bcd3 << 12) + 222)
s.add(w1 * w2 * w2 * w3 * w4 == (0x41c7a << 12) + 928)
s.add(w2 * w3 == (0x313ac << 12) + 1924)

if s.check() == sat:
    print "sat :)"
    m = s.model()

    res = ""
    serial_num = []

    for i in range(24):
        res += chr(int(str(m[serial[i]])))
        serial_num.append(int(str(m[serial[i]])))

    print res

    w0 = (serial_num[0] + 
        serial_num[1] * 0x100 + 
        serial_num[2] * 0x10000 + 
        serial_num[3] * 0x1000000)
    w1 = (serial_num[5] + 
        serial_num[6] * 0x100 + 
        serial_num[7] * 0x10000 + 
        serial_num[8] * 0x1000000)
    w2 = (serial_num[10] + 
        serial_num[11] * 0x100 + 
        serial_num[12] * 0x10000 + 
        serial_num[13] * 0x1000000)
    w3 = (serial_num[15] + 
        serial_num[16] * 0x100 + 
        serial_num[17] * 0x10000 + 
        serial_num[18] * 0x1000000)
    w4 = (serial_num[20] + 
        serial_num[21] * 0x100 + 
        serial_num[22] * 0x10000 + 
        serial_num[23] * 0x1000000)

    x0 = (0x2c281 << 12) - 721
    x1 = (0x38053 << 12) + 1317
    x2 = (0x6b5c3 << 12) - 1500
    x3 = (0x27542 << 12) + 1832
    x4 = (0x29755 << 12) + 1839

    s0 = ("%08x" % (w0 ^ x0)).decode('hex')[::-1]
    s1 = ("%08x" % (w1 ^ x1)).decode('hex')[::-1]
    s2 = ("%08x" % (w2 ^ x2)).decode('hex')[::-1]
    s3 = ("%08x" % (w3 ^ x3)).decode('hex')[::-1]
    s4 = ("%08x" % (w4 ^ x4)).decode('hex')[::-1]

    print "hitcon{%s%s%s%s%s}" % (s0, s1, s2, s3, s4)

else:
    print "unsat :("
{% endraw %}    
{% endhighlight %}

The flag was:
{% highlight text %}
hitcon{dYauhy0urak9nbavca1m}
{% endhighlight %}
