---
layout: post
title: "TokyoWesterns CTF 5th 2019: Reverse - Holy Grail War"
modified: 2019-09-03
tags: twctf, twctf2019quals, reverse
---

So we got a pretty big binary (4.5MB) and an `output.txt` which contained the following hex value:

```
d4f5f0aa8aeee7c83cd8c039fabdee6247d0f5f36edeb24ff9d5bc10a1bd16c12699d29f54659267
```

I put the binary into IDA and while I waited for the analysis the finish, I dynamically run the binary on a few input cases.

My initial observations were the followings:
* It probably encrypts the input data and the `output.txt` contains the encrypted flag
* It used 8-byte blocks
* Seemingly the block's position mattered, so it was not a simple `ECB` mode.
  * `01234567` was encrypted to `4e6fa474bbf4eb00` if it was the first input block, but it was encrypted to `a1eb35de298e9ecd` if it was the second input block
* If I changed a byte in the block it did not change any other block, so the previous input / output block did not influence the current one. So it was not `CBC`, `OFB` or `CFB` block cipher mode, but probably `CTR` or similar
* There was padding in place, if I used a 7-byte input then I got a 8-byte output, but if I used a 8-byte input then I got a 16-byte output.

Here is an example which illustrates the situation (the `|` sign was not part of the input / output, I just put there to make it easier to see the block boundaries):

```
01234567|01234567|01234567 -> 4e6fa474bbf4eb00|a1eb35de298e9ecd|48811beafc8ed0dc|d2e084d9b6fc0ee0
01234567|_1234567|01234567 -> 4e6fa474bbf4eb00|ef83b139c03ae40d|48811beafc8ed0dc|d2e084d9b6fc0ee0
```

Meanwhile IDA analyzed the binary and I saw there are a lot of functions with symbol names like `graal_attach_thread`. Google for this directed me to this page: https://github.com/oracle/graal/blob/master/substratevm/C-API.md. Looks like the binary was created with [GraalVM](https://www.graalvm.org/) which is yet again some craziness (like the NekoVM) I heard about before, but I never really tried out.

So my teammates tried to play with the GraalVM toolchain, compile an empty app, BinDiff it with the challenge binary and try to figure out which parts of the binary contained framework code and where is the encryption.

Meanwhile I basically **binary searched** the binary with GDB (+pwndbg), searching for my test input strings / encrypted output in the memory and putting memory read/write watchpoints the these addresses. Without ASLR, the binary run the same way every execution, every memory address was the same, etc, so this technique worked quite well.

It turned out fast that this part of the binary is the interesting one:
```c
    v167 = a2[408627];
    v62 = a2[408603] + *(_DWORD *)(v61 + 8);
    v63 = a2[408604];
    v64 = a2[408605];
    v65 = a2[408606];
    v66 = a2[408607];
    v67 = a2[408608];
    v68 = a2[408609];
    v69 = a2[408610];
    v70 = a2[408611];
    v71 = a2[408612];
    v72 = a2[408613];
    v166 = a2[408614];
    v165 = a2[408615];
    v164 = a2[408616];
    v163 = a2[408617];
    v162 = a2[408618];
    v161 = a2[408619];
    v160 = a2[408620];
    v159 = a2[408621];
    v158 = a2[408622];
    v157 = a2[408623];
    v156 = a2[408624];
    v155 = a2[408625];
    v154 = v72;
    v73 = v63 + __ROL4__(v62 ^ v170, v62 & 0x1F);
    v74 = v64 + __ROL4__(v73 ^ v62, v73 & 0x1F);
    v75 = v65 + __ROL4__(v74 ^ v73, v74 & 0x1F);
    v76 = v66 + __ROL4__(v75 ^ v74, v75 & 0x1F);
    v77 = v67 + __ROL4__(v76 ^ v75, v76 & 0x1F);
    v78 = v68 + __ROL4__(v77 ^ v76, v77 & 0x1F);
    v79 = v69 + __ROL4__(v78 ^ v77, v78 & 0x1F);
    v80 = v70 + __ROL4__(v79 ^ v78, v79 & 0x1F);
    v81 = v71 + __ROL4__(v80 ^ v79, v80 & 0x1F);
    v82 = v72 + __ROL4__(v81 ^ v80, v81 & 0x1F);
    v83 = v166 + __ROL4__(v82 ^ v81, v82 & 0x1F);
    v84 = v165 + __ROL4__(v83 ^ v82, v83 & 0x1F);
    v85 = v164 + __ROL4__(v84 ^ v83, v84 & 0x1F);
    v86 = v163 + __ROL4__(v85 ^ v84, v85 & 0x1F);
    v87 = v162 + __ROL4__(v86 ^ v85, v86 & 0x1F);
    v88 = v161 + __ROL4__(v87 ^ v86, v87 & 0x1F);
    v89 = v160 + __ROL4__(v88 ^ v87, v88 & 0x1F);
    v90 = v159 + __ROL4__(v89 ^ v88, v89 & 0x1F);
    v91 = v158 + __ROL4__(v90 ^ v89, v90 & 0x1F);
    v92 = v157 + __ROL4__(v91 ^ v90, v91 & 0x1F);
    v93 = v156 + __ROL4__(v92 ^ v91, v92 & 0x1F);
    v94 = v155 + __ROL4__(v93 ^ v92, v93 & 0x1F);
    v95 = a2[408626] + __ROL4__(v94 ^ v93, v94 & 0x1F);
```

This basically 24 rounds of some `ROL + XOR` encryption, can be simplified like this:

```csharp
for (int iRound = 0; iRound < 24; iRound++)
{
    var newRight = magicConstants[iRound] + Rol(right ^ left, right & 0x1F);
    left = right;
    right = newRight;
}
```

The `magicConstants` array contained the seemingly constant values from memory dump and where the following:

```
0x83f19eee      0xda45ed22      0x0f746d84      0x5956ab6d
0x8917c0ef      0x7a5cf3b6      0x796712dd      0x6009fb1f
0x6a5bc569      0x376c57d3      0xe9ba0d38      0xbe82e078
0x77856cc1      0xa273cfee      0xd4142c83      0x017374a6
0xa3aeae68      0x02b52304      0x0e3d4b9e      0x1eb080bf
0x30a8374b      0x84f10f0f      0x02823509      0xd0dabfab
0xc85353c6      0x768e268e      0x0cdd1b42      0xddf3d584
0xfbdba0d4      0xa15d7381      0x83f4a3f6      0xd4eac3ea
```

I saw from dumping the memory / registers that it breaks 8-byte input / output blocks into two 4-byte ones. So the whole encryption looked similar to a [Feistel cipher](https://en.wikipedia.org/wiki/Feistel_cipher) to me, so I reversed the encryption the same way as illustrated here:

![alt](https://upload.wikimedia.org/wikipedia/commons/thumb/f/fa/Feistel_cipher_diagram_en.svg/1022px-Feistel_cipher_diagram_en.svg.png)

I got this decryption code which worked great on the first block:

```csharp
for (int iRound = 23; iRound >= 0; iRound--)
{
    var newLeft = Ror(right - magicConstants[iRound], left & 0x1f) ^ left;
    right = left;
    left = newLeft;
}
```

I tested some of my test inputs and it could decrypted them which was a good sign!

I also tried to decrypt the `output.txt`'s first block and I the following `plaintext` which was also really good sign :) :

```
TWCTF{Fa
```

So  tried to find out the padding and block cipher mode, but I did not find anything. But meanwhile I found out that the `magicConstants` array (which I thought were constants indeed) changes with every new block and it does not depend on the input, so I simply dumped this array out from `gdb` with the following command `x/32wx 0x78e068` for every block :D. This actually worked and I could decrypt the whole `output.txt` and 

I got the flag:

```
TWCTF{Fat3_Gr4nd_Ord3r_1s_fuck1n6_h07}
```

This was my complete code to decrypt the flag (C#):
```csharp
public static UInt32 Rol(UInt32 x, uint n) => (x << (int)n) | (x >> (32 - (int)n));
public static UInt32 Ror(UInt32 x, uint n) => (x >> (int)n) | (x << (32 - (int)n));

static void Holy()
{
    var tables = new[] {
        @"0x83f19eee      0xda45ed22      0x0f746d84      0x5956ab6d
          0x8917c0ef      0x7a5cf3b6      0x796712dd      0x6009fb1f
          0x6a5bc569      0x376c57d3      0xe9ba0d38      0xbe82e078
          0x77856cc1      0xa273cfee      0xd4142c83      0x017374a6
          0xa3aeae68      0x02b52304      0x0e3d4b9e      0x1eb080bf
          0x30a8374b      0x84f10f0f      0x02823509      0xd0dabfab
          0xc85353c6      0x768e268e      0x0cdd1b42      0xddf3d584
          0xfbdba0d4      0xa15d7381      0x83f4a3f6      0xd4eac3ea",
        @"0xa8780381      0xd325b893      0x2889f25f      0x093c9281
          0x0ca31370      0xf01abbbe      0x069b1eeb      0x335b65cd
          0xdba0f812      0x26641f2e      0xcdcd48e0      0x2ffb8009
          0x75077d6d      0x8f23624a      0x71c8f20a      0xe254b801
          0x443ba936      0x6f4f4a2f      0x8aba595f      0x9a8530a6
          0xc42a5a0e      0x9ad8308d      0x42628dbd      0xabab10de
          0x9f95660e      0xae0ee93c      0x9e704772      0x9e0fe2c0
          0x53e83f2b      0x37dd53c7      0xdfa1fe01      0x04fbed0d",
        @"0x77354950      0x113b306d      0x3f8a1235      0xe3af6ed1
          0xf54cd1e9      0x9efb71e8      0x298d44ba      0x8f672270
          0xe9a97023      0x7100d45b      0x08f2a5e4      0xee09e4a5
          0xc6539fc7      0xc8538753      0xf59e1b4b      0xd268290e
          0x76f1d203      0x9917e9b2      0x908a32d4      0xe8d20101
          0x6092f88e      0x84fc73ec      0xcbd92758      0x44a66424
          0x82779517      0xec39befe      0xd9fe6b2d      0x2520232c
          0xdda34a8d      0x1e5fe69a      0xd99e98ba      0x66aa19e2",
        @"0x105426f8      0x2945d55f      0x5a6ec101      0x3c60fc75
          0xbc365fa3      0x5576699c      0x99548715      0x1c08bd1f
          0xd5375697      0x1f16fc4c      0x541be791      0x169314ff
          0xddbfc2db      0x9c131e7f      0xec9b6a6e      0x19700898
          0x630bc067      0x5154dfc8      0x739a5761      0x9ebce304
          0x6d8f9d46      0x369056a4      0x5bc4e09e      0xa139bbe8
          0x93023d62      0xe5979177      0x73911ea2      0xed9a6998
          0x6aad6804      0xc6ec99aa      0xaf8f109c      0x81793378",
        @"0x6e15b6ed      0xf259349e      0xfed4fdd8      0x759a482b
          0x4b150fd6      0xd42698f1      0x85d88ce1      0x253796ee
          0x941af694      0x0997b347      0xcdb22ebb      0x365ef56c
          0x458f3e90      0xa1c536c3      0x00e1284d      0x5f557b37
          0xadf6dff8      0x6260a096      0x3db81ff5      0x7a8e070a
          0x7a0609fa      0x9e6ded19      0x377743d5      0x8ead5a5b
          0x69bf4721      0x04ea93a4      0xc2c34e47      0xee0b5f03
          0x9a03038a      0xde6ba695      0xc7997ad9      0x0c195d2d",
        @"0x8e76e215      0xf2b7cd8a      0xc22ad5b1      0x6d820441
          0xa95785d3      0x46eaa7a3      0x4a3177ba      0x3d1e369c
          0x1256c8de      0x8a1cdcbc      0x1720bd2e      0xd8593e50
          0x9acb6187      0x5792d112      0xf40d5b16      0x70777c3a
          0xfc87a56c      0x66083a93      0x03469feb      0xe07d4161
          0xc1bbf3df      0x4e957f64      0xa38e9e34      0x691b0ca9
          0x15867b09      0xc390f252      0xc87e2d48      0x40d9b7f3
          0x0ae2dd28      0x1dd6bb77      0x45272187      0x3bcf1886",
        @"0x14662049      0xfae28cae      0xe82852e7      0x632b5e0b
          0xf023f3be      0xf18f0644      0x12633c3f      0x95613356
          0xf6cb92cd      0x18da0111      0x42f0c135      0x8cc959a5
          0xf38ed50e      0x49bb5328      0x0b99ccc5      0x99955cb1
          0x30aeae81      0xa4433dc4      0xcc8667af      0xb9d10e05
          0xd245ff26      0xddc7239f      0xc13c60dc      0x605be54d
          0x7bf4d4a7      0x992b9ad7      0x8e2cfb86      0xab55993b
          0xcf592117      0xcfe5ab0f      0x30e8705a      0xfc3300ec"
    };

    var tables2 = tables.Select(x => Conversion.HexToBytes(x.Replace(" ", "").Replace("0x", "").Replace("\r\n", "")).Chunk(4).Select(y => BitConverter.ToUInt32(y.Reverse().ToArray(), 0)).ToArray()).ToArray();

    (uint, uint) Encrypt((uint, uint) data, int round)
    {
        uint left = tables2[round][0] + data.Item1;
        uint right = tables2[round][1] + data.Item2;

        for (int iRound = 0; iRound < 24; iRound++)
        {
            var newRight = tables2[round][iRound + 2] + Rol(right ^ left, right & 0x1F);
            left = right;
            right = newRight;
        }

        return (left, right);
    }

    (uint, uint) Decrypt((uint, uint) data, int round)
    {
        uint left = data.Item1;
        uint right = data.Item2;

        for (int iRound = 23; iRound >= 0; iRound--)
        {
            var newLeft = Ror(right - tables2[round][iRound + 2], left & 0x1f) ^ left;
            right = left;
            left = newLeft;
        }

        return (left - tables2[round][0], right - tables2[round][1]);
    }

    var str = "0123456789abcdef".PadRight(24,'\0');
    var result = "";
    for (int i = 0; i < str.Length; i += 8)
    {
        var firstAsInt = BitConverter.ToUInt32(Encoding.ASCII.GetBytes(str.Substring(i, 4)).Reverse().ToArray(), 0);
        var secondAsInt = BitConverter.ToUInt32(Encoding.ASCII.GetBytes(str.Substring(i + 4, 4)).Reverse().ToArray(), 0);

        var encrypted = Encrypt((firstAsInt, secondAsInt), i / 8);
        var (firstAsInt2, secondAsInt2) = Decrypt(encrypted, i / 8);

        if (firstAsInt2 != firstAsInt || secondAsInt2 != secondAsInt)
            Debugger.Break();

        result += BitConverter.ToString(BitConverter.GetBytes(encrypted.Item1).Reverse().ToArray()).Replace("-", "").ToLower();
        result += BitConverter.ToString(BitConverter.GetBytes(encrypted.Item2).Reverse().ToArray()).Replace("-", "").ToLower();
    }

    var resultDesc = String.Join("|", result.Chunk(8).Select(x => new string(x)));

    var expected = "4e6fa474bbf4eb0092fa0410e882753a1bb4e13183fd98a9";

    Console.WriteLine(result);
    Console.WriteLine(expected);

    if (result != expected)
        Debugger.Break();

    //  d4f5f0aa8aeee7c83cd8c039fabdee6247d0f5f36edeb24ff9d5bc10a1bd16c12699d29f54659267
    var flagDec0 = Decrypt((0xd4f5f0aa, 0x8aeee7c8), 0);
    var flagDec1 = Decrypt((0x3cd8c039, 0xfabdee62), 1);
    var flagDec2 = Decrypt((0x47d0f5f3, 0x6edeb24f), 2);
    var flagDec3 = Decrypt((0xf9d5bc10, 0xa1bd16c1), 3);
    var flagDec4 = Decrypt((0x2699d29f, 0x54659267), 4);
    var flag  = Encoding.ASCII.GetString(BitConverter.GetBytes(flagDec0.Item1).Reverse().ToArray()) + Encoding.ASCII.GetString(BitConverter.GetBytes(flagDec0.Item2).Reverse().ToArray());
        flag += Encoding.ASCII.GetString(BitConverter.GetBytes(flagDec1.Item1).Reverse().ToArray()) + Encoding.ASCII.GetString(BitConverter.GetBytes(flagDec1.Item2).Reverse().ToArray());
        flag += Encoding.ASCII.GetString(BitConverter.GetBytes(flagDec2.Item1).Reverse().ToArray()) + Encoding.ASCII.GetString(BitConverter.GetBytes(flagDec2.Item2).Reverse().ToArray());
        flag += Encoding.ASCII.GetString(BitConverter.GetBytes(flagDec3.Item1).Reverse().ToArray()) + Encoding.ASCII.GetString(BitConverter.GetBytes(flagDec3.Item2).Reverse().ToArray());
        flag += Encoding.ASCII.GetString(BitConverter.GetBytes(flagDec4.Item1).Reverse().ToArray()) + Encoding.ASCII.GetString(BitConverter.GetBytes(flagDec4.Item2).Reverse().ToArray());
}
```