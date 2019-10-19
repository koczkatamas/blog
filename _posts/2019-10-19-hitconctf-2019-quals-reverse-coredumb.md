---
layout: post
title: "HITCON CTF 2019 Quals: Reverse - CoreDumb"
modified: 2019-10-19
tags: hitconctf, hitconctf2019quals, reverse
---

So this challenge was around that we got a Core file instead of a runnable linux binary which checked our flag. 

To be frank, I don't really know what difference should it mean, maybe the file cannot be run and debugged this way? As for someone who usually reverse-engineer binaries statically first and I only use `gdb` for secondary analysis of more complex code parts, it did not really mean any difference I think.

## The main function

First step was to find out the main, which I had no idea how to do in (larger) core dump file, so I searched for `xor` instructions where I kind of failed to find the real main, so then I searched the strings in the binary and found ones like `Congratz ! The flag is hitcon{%s} :)` which of course give me instant success of finding the real main via cross-referencing the usages of this symbol. The main was at `sub_555555554C7E`.

I reverse-engineered the main function and got this code:

```c
00000000 CodeStruct      struc ; (sizeof=0x10, mappedto_34)
00000000 codePtr         dq ?
00000008 xorKeyAndLen    dq ?
00000010 CodeStruct      ends

void __fastcall sub_555555554C7E(__int64 a1, __int64 a2)
{
  signed int i; // [rsp+10h] [rbp-140h]
  char *flagPtr; // [rsp+18h] [rbp-138h]
  __int64 basePtr; // [rsp+28h] [rbp-128h]
  CodeStruct codes[5]; // [rsp+30h] [rbp-120h]
  char flagBuffer[55]; // [rsp+80h] [rbp-D0h]
  int v7; // [rsp+B8h] [rbp-98h]
  char tmpBuf[55]; // [rsp+C0h] [rbp-90h]
  int v9; // [rsp+F8h] [rbp-58h]
  __int64 v10; // [rsp+100h] [rbp-50h]
  __int64 v11; // [rsp+108h] [rbp-48h]
  __int64 v12; // [rsp+110h] [rbp-40h]
  __int64 v13; // [rsp+118h] [rbp-38h]
  __int64 v14; // [rsp+120h] [rbp-30h]
  __int64 v15; // [rsp+128h] [rbp-28h]
  __int64 v16; // [rsp+130h] [rbp-20h]
  int v17; // [rsp+138h] [rbp-18h]
  unsigned __int64 canary; // [rsp+148h] [rbp-8h]

  canary = __readfsqword(0x28u);
  setOutputBuffering(qword_7FFFF7DCFA00, 0LL, 2LL, 0LL);
  setOutputBuffering(qword_7FFFF7DD0760, 0LL, 2LL, 0LL);
  setOutputBuffering(qword_7FFFF7DD0680, 0LL, 2LL, 0LL);
  codes[0].codePtr = (char *)code1;
  codes[1].codePtr = (char *)code2;
  codes[2].codePtr = (char *)code3;
  codes[3].codePtr = (char *)code4;
  codes[4].codePtr = (char *)code5;
  for ( i = 1; i <= 5; ++i )
  {
    *((_DWORD *)&basePtr + 4 * i) = codeXorKeys[i - 1];// packs xorKey and len values into codes[i].xorKeyAndLen
    *((_DWORD *)&basePtr + 4 * i + 1) = codeLengths[i - 1];
  }
  basePtr = 0x1100000000LL;
  if ( (unsigned int)RUN_TEST_CODE(testCode, 0x1100000000LL) == 0x1337 )
  {
      // ... zeroes out stack values ...
    flagPtr = flagBuffer;
    printf("Please enter the flag: ");
    read(0LL, flagBuffer, 55LL);
    while ( *flagPtr )
    {
      if ( *flagPtr == '\n' || *flagPtr == '\r' )
      {
        *flagPtr = 0;
        break;
      }
      ++flagPtr;
    }
    if ( (unsigned int)strlen(flagBuffer) != 52 )
      fail();
    copyString(tmpBuf, flagBuffer, 10);
    RUN_ENC_CODE_WITH_2_ARGS(codes[0].codePtr, codes[0].xorKeyAndLen, tmpBuf, 10LL);
    zeroBuffer(tmpBuf, 55);
    copyString(tmpBuf, &flagBuffer[10], 8);
    RUN_ENC_CODE_WITH_1_ARG(codes[1].codePtr, codes[1].xorKeyAndLen, tmpBuf);
    zeroBuffer(tmpBuf, 55);
    copyString(tmpBuf, &flagBuffer[18], 18);
    RUN_ENC_CODE_WITH_2_ARGS(codes[2].codePtr, codes[2].xorKeyAndLen, tmpBuf, 18LL);
    zeroBuffer(tmpBuf, 55);
    copyString(tmpBuf, &flagBuffer[36], 12);
    RUN_ENC_CODE_WITH_2_ARGS(codes[3].codePtr, codes[3].xorKeyAndLen, tmpBuf, 12LL);
    zeroBuffer(tmpBuf, 55);
    copyString(tmpBuf, &flagBuffer[48], 4);
    RUN_ENC_CODE_WITH_1_ARG(codes[4].codePtr, codes[4].xorKeyAndLen, tmpBuf);
    printf("Congratz ! The flag is hitcon{%s} :)\n", flagBuffer, a2);
  }
  else
  {
    putsMaybe("Test failed !");
  }
  if ( __readfsqword(0x28u) != canary )
    stackCheckFail();
}
```

So our flag will be 52 characters long (without `hitcon{}`), and it is splitted into 5 parts with the following lengths: `10, 8, 18, 12, 4`.

There are 5 separate checker code called for every flag part.

The `RUN_ENC_CODE_WITH_1_ARG` and `RUN_ENC_CODE_WITH_2_ARGS` methods decrypt these encrypted flag part checker function's bytecode with a 4-byte repeating XOR key and then call them with 1 or 2 args. As you can see from the code above, the first argument was always the flag (part) buffer's address, while the second (if used) was the buffer's length.

Although it is clearly visible from the code where the XOR key comes from:
```c
load:0000555555756AE0 ; unsigned int codeXorKeys[5]
load:0000555555756AE0 codeXorKeys     dd 8EB5034Ah, 0C6FFDA44h, 85EA3FE1h, 42AD9EF2h, 77E2535Ch
load:0000555555756AE0                                         ; DATA XREF: sub_555555554C7E+FE↑o
load:0000555555756B00 codeLengths     dd 10Bh, 1B1h, 2E4h, 3E6h, 0BFh
load:0000555555756B00                                         ; DATA XREF: sub_555555554C7E+134↑o
```

I must have some brainfart or something at the time of the competition because I somehow did not use the XOR key during the competition (I assumed we don't know these values - I just discovered them now at the time of writing this writeup... #fail) so instead of using these values I assumed every code part will start with

```
55                                push    rbp
48 89 E5                          mov     rbp, rsp
```
and simply calculated the XOR key from the first 4 `ciphertext ^ plaintext` bytes:

```csharp
var baseDir = @"g:\Dropbox\hack\hitcon19\challs\coredump\";
var code = File.ReadAllBytes($"{baseDir}core-3c5a47af728e9968fd7a6bb41fbf573cd52677bc");

var xorKeyTest = CryptoUtils.Xor(code.Skip(0x4A6C).Take(4).ToArray(), new byte[] { 0x55, 0x48, 0x89, 0xE5 });
for (int i = 0; i < 0x11;  i++) code[0x4A6C + i] ^= xorKeyTest[i % 4]; // testCode

var xorKeyCode1 = CryptoUtils.Xor(code.Skip(0x3FCC).Take(4).ToArray(), new byte[] { 0x55, 0x48, 0x89, 0xE5 });
for (int i = 0; i < 0x10B; i++) code[0x3FCC + i] ^= xorKeyCode1[i % 4]; // code1

var xorKeyCode2 = CryptoUtils.Xor(code.Skip(0x40EC).Take(4).ToArray(), new byte[] { 0x55, 0x48, 0x89, 0xE5 });
for (int i = 0; i < 0x1B1; i++) code[0x40EC + i] ^= xorKeyCode2[i % 4]; // code2

var xorKeyCode3 = CryptoUtils.Xor(code.Skip(0x42AC).Take(4).ToArray(), new byte[] { 0x55, 0x48, 0x89, 0xE5 });
for (int i = 0; i < 0x2E4; i++) code[0x42AC + i] ^= xorKeyCode3[i % 4]; // code3

var xorKeyCode4 = CryptoUtils.Xor(code.Skip(0x45AC).Take(4).ToArray(), new byte[] { 0x55, 0x48, 0x89, 0xE5 });
for (int i = 0; i < 0x3E6; i++) code[0x45AC + i] ^= xorKeyCode4[i % 4]; // code4

var xorKeyCode5 = CryptoUtils.Xor(code.Skip(0x49AC).Take(4).ToArray(), new byte[] { 0x55, 0x48, 0x89, 0xE5 });
for (int i = 0; i < 0xBF;  i++) code[0x49AC + i] ^= xorKeyCode5[i % 4]; // code5
File.WriteAllBytes($"{baseDir}decrypted", code);
```

Well, whatever, after decryption, I reverse-engineered the various checker functions.

## Checker #1

This is the decompiled and somewhat renamed first checker function:

```c
__int64 __fastcall sub_555555756020(char *input, int inputLen)
{
  __int64 result; // rax
  __int64 v3; // rsi
  unsigned __int64 v4; // rt1
  int i; // [rsp+18h] [rbp-48h]
  int j; // [rsp+18h] [rbp-48h]
  unsigned int success; // [rsp+1Ch] [rbp-44h]
  char xorKey[4]; // [rsp+20h] [rbp-40h]
  char encData[10]; // [rsp+25h] [rbp-3Bh]
  char v10; // [rsp+2Fh] [rbp-31h]
  char tmpBuf[10]; // [rsp+30h] [rbp-30h]
  __int64 v12; // [rsp+40h] [rbp-20h]
  int v13; // [rsp+48h] [rbp-18h]
  __int16 v14; // [rsp+4Ch] [rbp-14h]
  unsigned __int64 canary; // [rsp+58h] [rbp-8h]

  canary = __readfsqword(0x28u);
  strcpy(xorKey, "DuMb");
  *(_QWORD *)tmpBuf = 0LL;
  *(_QWORD *)&tmpBuf[8] = 0LL;
  v12 = 0LL;
  v13 = 0;
  v14 = 0;
  *(_QWORD *)encData = 0x413317635722649LL;
  *(_WORD *)&encData[8] = 0x5E4E;
  v10 = 0;
  success = 1;
  for ( i = 0; i < inputLen; ++i )
    tmpBuf[i] = (xorKey[i % 4] - 7) ^ input[i];
  for ( j = 0; j < inputLen; ++j )
  {
    if ( tmpBuf[j] != encData[j] )
      success = 0;
  }
  result = success;
  v4 = __readfsqword(0x28u);
  v3 = v4 ^ canary;
  if ( v4 != canary )
    result = (*(__int64 (__fastcall **)(char *, __int64))stackCheckFail)(input, v3);
  return result;
}
```

It's a simple repeating XOR cipher with the key `DuMb` == `0x624D7544` modified by subtracting 7 from every key byte.

Decrypted with the following code:

```csharp
var flagPart1 = EncodingHelper.GetString(CryptoUtils.Xor(Conversion.HexToBytes("49 26 72 35 76 31 13 04 4E 5E".Replace(" ", "")), BitConverter.GetBytes(0x624D7544).Select(x => (byte)(x - 7)).ToArray()));
```

And got the first part of our flag: `tH4nK_U_s0`.

## Checker #2

The decompiled code:

```c
__int64 __fastcall sub_555555756140(char *input)
{
  __int64 result; // rax
  __int64 v2; // rsi
  unsigned __int64 v3; // rt1
  unsigned int inputPart1; // [rsp+14h] [rbp-5Ch]
  unsigned int inputPart2; // [rsp+18h] [rbp-58h]
  signed int iRound; // [rsp+1Ch] [rbp-54h]
  unsigned int v7; // [rsp+20h] [rbp-50h]
  unsigned int v8; // [rsp+24h] [rbp-4Ch]
  signed int i; // [rsp+28h] [rbp-48h]
  int key[4]; // [rsp+30h] [rbp-40h]
  int encValue[8]; // [rsp+40h] [rbp-30h]
  unsigned __int64 v12; // [rsp+68h] [rbp-8h]

  v12 = __readfsqword(0x28u);
  v7 = 1;
  encValue[0] = 0x95CB8DBD;
  encValue[1] = 0xF84CC79;
  encValue[2] = 0xB899A876;
  encValue[3] = 0xA5DAB55;
  encValue[4] = 0x9A8B3BBA;
  encValue[5] = 0x70B238A7;
  encValue[6] = 0x72B53CF1;
  encValue[7] = 0xD47C0209;
  for ( iRound = 0; iRound <= 3; ++iRound )
  {
    inputPart1 = (unsigned __int8)input[iRound];
    inputPart2 = (unsigned __int8)input[iRound + 4];
    v8 = 0;
    key[0] = 'C';
    key[1] = '0';
    key[2] = 'R';
    key[3] = '3';
    for ( i = 0; i <= 31; ++i )
    {
      inputPart1 += (((inputPart2 >> 5) ^ 16 * inputPart2) + inputPart2) ^ (key[v8 & 3] + v8);
      v8 += 0x1337DEAD;
      inputPart2 += (((inputPart1 >> 5) ^ 16 * inputPart1) + inputPart1) ^ (key[(v8 >> 11) & 3] + v8);
    }
    if ( inputPart1 != encValue[2 * iRound] )
      v7 = 0;
    if ( inputPart2 != encValue[2 * iRound + 1] )
      v7 = 0;
  }
  result = v7;
  v3 = __readfsqword(0x28u);
  v2 = v3 ^ v12;
  if ( v3 != v12 )
    result = ((__int64 (__fastcall *)(char *, __int64))dword_555555755DEC)(input, v2);
  return result;
}
```

Hmmm this looked like a [Feistel cipher](https://en.wikipedia.org/wiki/Feistel_cipher), but as the input was checked by only 2-bytes, I did not really reversed the cipher, simply brute-forced the 4 rounds with the possible `256**2 == 65536` possibilities with the following code:

```csharp
var key = "C0R3";
var encValue = new uint[8];
encValue[0] = 0x95CB8DBD;
encValue[1] = 0xF84CC79;
encValue[2] = 0xB899A876;
encValue[3] = 0xA5DAB55;
encValue[4] = 0x9A8B3BBA;
encValue[5] = 0x70B238A7;
encValue[6] = 0x72B53CF1;
encValue[7] = 0xD47C0209;

for (var iRound = 0; iRound <= 3; ++iRound)
{
    for (int bf = 0; bf < 256 * 256; bf++)
    {
        var c1 = (char)(bf % 256);
        var c2 = (char)(bf / 256);
        var inputPart1 = (uint)c1;
        var inputPart2 = (uint)c2;
        var v8 = 0;
        for (var i = 0; i <= 31; ++i)
        {
            inputPart1 += (uint)((((inputPart2 >> 5) ^ 16 * inputPart2) + inputPart2) ^ (key[v8 & 3] + v8));
            v8 += 0x1337DEAD;
            inputPart2 += (uint)((((inputPart1 >> 5) ^ 16 * inputPart1) + inputPart1) ^ (key[(v8 >> 11) & 3] + v8));
        }

        if (inputPart1 != encValue[2 * iRound])
            continue;
        if (inputPart2 != encValue[2 * iRound + 1])
            continue;
        Console.WriteLine($"Found: {iRound} {c1} {c2}");
    }
}
```

Which gave me the following result:
```
Found: 0 _ h
Found: 1 m _
Found: 2 u F
Found: 3 C 0
```

So the second part of the flag was: `_muCh_F0`.

## Checker #3

The decompiled code:

```c
__int64 __fastcall sub_555555756300(_BYTE *input, int inputLen)
{
  __int64 *v2; // rax
  _BYTE *v3; // ST18_8
  _BYTE *v4; // rax
  _BYTE *v5; // rax
  __int64 result; // rax
  __int64 v7; // rsi
  unsigned __int64 v8; // rt1
  unsigned int v9; // [rsp+10h] [rbp-D0h]
  signed int i; // [rsp+14h] [rbp-CCh]
  __int64 *v11; // [rsp+18h] [rbp-C8h]
  __int64 v13; // [rsp+30h] [rbp-B0h]
  __int64 v14; // [rsp+38h] [rbp-A8h]
  __int64 v15; // [rsp+40h] [rbp-A0h]
  char v16; // [rsp+48h] [rbp-98h]
  __int64 v17; // [rsp+50h] [rbp-90h]
  __int64 v18; // [rsp+58h] [rbp-88h]
  __int64 v19; // [rsp+60h] [rbp-80h]
  __int64 v20; // [rsp+68h] [rbp-78h]
  __int64 v21; // [rsp+70h] [rbp-70h]
  __int64 v22; // [rsp+78h] [rbp-68h]
  __int16 v23; // [rsp+80h] [rbp-60h]
  char charTable[64]; // [rsp+90h] [rbp-50h]
  unsigned __int64 canary; // [rsp+D8h] [rbp-8h]

  canary = __readfsqword(0x28u);
  v17 = 0LL;
  v18 = 0LL;
  v19 = 0LL;
  v20 = 0LL;
  v21 = 0LL;
  v22 = 0LL;
  v23 = 0;
  strcpy(charTable, "*|-Ifnq20! \nAZd$r<Xo\\D/{KC~a4Tz7)Y^:x`\v}Ss1yOmiv#\r%]@[_N(Hj,VQug");
  v13 = '#A_A%Q`4';
  v14 = '}H/A%Z:T';
  v15 = '\vQ[ASm%{';
  v16 = 0;
  v9 = 1;
  v11 = &v17;
  while ( &input[inputLen] - input > 2 )
  {
    v2 = v11;
    v3 = (char *)v11 + 1;
    *(_BYTE *)v2 = charTable[(unsigned __int8)(*input >> 2)];
    v4 = v3++;
    *v4 = charTable[16 * *input & 0x30 | (unsigned __int8)(input[1] >> 4)];
    *v3 = charTable[4 * input[1] & 0x3C | (unsigned __int8)(input[2] >> 6)];
    v5 = v3 + 1;
    v11 = (__int64 *)(v3 + 2);
    *v5 = charTable[input[2] & 0x3F];
    input += 3;
  }
  for ( i = 0; i <= 23; ++i )
  {
    if ( *((unsigned __int8 *)&v17 + i) != *((char *)&v13 + i) )
      v9 = 0;
  }
  result = v9;
  v8 = __readfsqword(0x28u);
  v7 = v8 ^ canary;
  if ( v8 != canary )
    result = (*(__int64 (__fastcall **)(_BYTE *, __int64))byte_555555755DFB)(input, v7);
  return result;
}
```

Ok, this looked like a custom base64 decoder with a custom charset, so I don't really reverse-engineered or renamed variables further and as I had such implementation from previous CTFs, I just tried to decode the custom-base64-value with the following code:

```csharp
var b64table = EncodingHelper.GetString(Conversion.HexToBytes("2A 7C 2D 49 66 6E 71 32 30 21 20 0A 41 5A 64 24 72 3C 58 6F 5C 44 2F 7B  4B 43 7E 61 34 54 7A 37 29 59 5E 3A 78 60 0B 7D  53 73 31 79 4F 6D 69 76 23 0D 25 5D 40 5B 5F 4E  28 48 6A 2C 56 51 75 67  ".Replace(" ", "")));
var b64data = EncodingHelper.GetString(Conversion.HexToBytes("34 60 51 25 41 5F 41 23    54 3A 5A 25 41 2F 48 7D  7B 25 6D 53 41 5B 51 0B".Replace(" ", "")));
var part3 = EncodingHelper.GetString(new Base64Converter(b64table).Decode(b64data));
```

(`b64table` = `2A 7C 2D 49 ...` == `charTable` = `*|-I`...; `b64data` = `34 60 51 25` == `v13`-`v16` but reversed)

This gave me the third part of the flag: `r_r3c0v3r1ng_+h3_f`

## Checker #4

The decompiled code:

```c
__int64 __fastcall sub_555555756600(__int64 a1, int a2)
{
  int v2; // ST2C_4
  int v3; // ST24_4
  __int64 result; // rax
  __int64 v5; // rsi
  unsigned __int64 v6; // rt1
  int i; // [rsp+10h] [rbp-490h]
  signed int j; // [rsp+10h] [rbp-490h]
  int v9; // [rsp+10h] [rbp-490h]
  int k; // [rsp+10h] [rbp-490h]
  int v11; // [rsp+14h] [rbp-48Ch]
  int v12; // [rsp+14h] [rbp-48Ch]
  unsigned int v13; // [rsp+18h] [rbp-488h]
  int v14; // [rsp+1Ch] [rbp-484h]
  int v15[252]; // [rsp+30h] [rbp-470h]
  __int64 v16; // [rsp+423h] [rbp-7Dh]
  int v17; // [rsp+42Bh] [rbp-75h]
  char v18; // [rsp+42Fh] [rbp-71h]
  __int64 v19; // [rsp+430h] [rbp-70h]
  __int64 v20; // [rsp+438h] [rbp-68h]
  __int64 v21; // [rsp+440h] [rbp-60h]
  __int64 v22; // [rsp+448h] [rbp-58h]
  __int16 v23; // [rsp+450h] [rbp-50h]
  char v24; // [rsp+452h] [rbp-4Eh]
  __int64 v25; // [rsp+460h] [rbp-40h]
  __int64 v26; // [rsp+468h] [rbp-38h]
  __int64 v27; // [rsp+470h] [rbp-30h]
  __int64 v28; // [rsp+478h] [rbp-28h]
  __int64 v29; // [rsp+480h] [rbp-20h]
  __int64 v30; // [rsp+488h] [rbp-18h]
  __int16 v31; // [rsp+490h] [rbp-10h]
  unsigned __int64 v32; // [rsp+498h] [rbp-8h]

  v32 = __readfsqword(0x28u);
  memset(v15, 0, 0x3E8uLL);
  v19 = '0d_sa3lP';
  v20 = '54Rc_t\'n';
  v21 = '!h+_n1_h';
  v22 = '1+CnUf_s';
  v23 = 'n0';
  v24 = 0;
  v25 = 0LL;
  v26 = 0LL;
  v27 = 0LL;
  v28 = 0LL;
  v29 = 0LL;
  v30 = 0LL;
  v31 = 0;
  v16 = 1503432207557809451LL;
  v17 = 0xE57D5243;
  v18 = 0;
  v11 = 0;
  v13 = 1;
  for ( i = 0; i <= 245; ++i )
    v15[i] = i;
  for ( j = 0; j <= 245; ++j )
  {
    v11 = (*((unsigned __int8 *)&v19 + j % 34) + v15[j] + v11) % 246;
    v2 = v15[j];
    v15[j] = v15[v11];
    v15[v11] = v2;
  }
  v14 = 0;
  v9 = 0;
  v12 = 0;
  while ( v14 < a2 )
  {
    v9 = (v9 + 1) % 246;
    v12 = (v15[v9] + v12) % 246;
    v3 = v15[v9];
    v15[v9] = v15[v12];
    v15[v12] = v3;
    *((_BYTE *)&v25 + v14) = v15[(v15[v9] + v15[v12]) % 246] ^ *(_BYTE *)(v14 + a1);
    ++v14;
  }
  for ( k = 0; k < a2; ++k )
  {
    if ( *((_BYTE *)&v25 + k) != *((_BYTE *)&v16 + k) )
      v13 = 0;
  }
  result = v13;
  v6 = __readfsqword(0x28u);
  v5 = v6 ^ v32;
  if ( v6 != v32 )
    result = ((__int64 (__fastcall *)(int *, __int64))loc_555555755E17)(&v15[250], v5);
  return result;
}
```

Ok now this seemed to be a custom RC4 implementation (the constants `256` from RC4 were modified to `246`), so I did not bother to reverse it further. The key (`v19`) was `Pl3as_d0n't_cR45h_1n_+h!s_fUnC+10n`.

So I modified my existing RC4 implementation the same way and decrypted the payload:

```csharp
byte[] CustomRc4(byte[] key, int length)
{
    var result = new byte[length];

    int j = 0;
    var box = new int[246];

    for (int i = 0; i < 246; i++)
        box[i] = i;

    for (int i = 0; i < 246; i++)
    {
        j = (j + box[i] + key[i % key.Length]) % 246;

        var swapTmp = box[i];
        box[i] = box[j];
        box[j] = swapTmp;
    }

    j = 0;
    for (int i = 0; i < length; i++)
    {
        var iBox = (i + 1) % 246;
        j = (j + box[iBox]) % 246;

        var swapTmp = box[iBox];
        box[iBox] = box[j];
        box[j] = swapTmp;

        result[i] = (byte)(box[(box[iBox] + box[j]) % 246]);
    }

    return result;
}

var rc4key = Conversion.HexToBytes(" 50 6C 33 61 73 5F 64 30  6E 27 74 5F 63 52 34 35   68 5F 31 6E 5F 2B 68 21 73 5F 66 55 6E 43 2B 31 30 6E  ".Replace(" ", ""));
var encFlag = Conversion.HexToBytes("2B 55 5D 93 A0 43 DD 14 43 52 7D E5  ".Replace(" ", ""));
var part4 = EncodingHelper.GetString(CryptoUtils.XorEqual(encFlag, CustomRc4(rc4key, encFlag.Length)));
```

This gave me the fourth part of the flag: `L4g_1_Luv_y0`.

## Checker #5

The decompiled code:

```c
__int64 __fastcall sub_555555756A00(char *input)
{
  int idx2; // eax
  int idx; // [rsp+Ch] [rbp-1Ch]
  signed int i; // [rsp+10h] [rbp-18h]
  unsigned int v5; // [rsp+14h] [rbp-14h]
  unsigned int v6; // [rsp+18h] [rbp-10h]

  idx = 0;
  v5 = 1;
  v6 = -1;
  while ( input[idx] )
  {
    idx2 = idx++;
    v6 ^= input[idx2];
    for ( i = 7; i >= 0; --i )
      v6 = (v6 >> 1) ^ -(v6 & 1) & 0xEDB88320;
  }
  if ( v6 != 0x29990129 )
    v5 = 0;
  return v5;
}
```

Hmmm, I did not really want to reverse this function, so I wrote a quick bruteforcer again.

I guessed the first character of the 4-byte input will be `u` as the last part ended with basically `Love yo`, so I had a pretty good guess, it will be `Love you`.

```csharp
for (uint b1 = 0; b1 < 256; b1++)
for (uint b2 = 0; b2 < 256; b2++)
for (uint b3 = 0; b3 < 256; b3++)
{
    var v6 = (uint)0xffffffff;
    v6 ^= (byte)'u';
    for (var i = 7; i >= 0; --i)
        v6 = (uint)((v6 >> 1) ^ -(v6 & 1) & 0xEDB88320);
    v6 ^= b1;
    for (var i = 7; i >= 0; --i)
        v6 = (uint)((v6 >> 1) ^ -(v6 & 1) & 0xEDB88320);
    v6 ^= b2;
    for (var i = 7; i >= 0; --i)
        v6 = (uint)((v6 >> 1) ^ -(v6 & 1) & 0xEDB88320);
    v6 ^= b3;
    for (var i = 7; i >= 0; --i)
        v6 = (uint)((v6 >> 1) ^ -(v6 & 1) & 0xEDB88320);
    if (v6 == 0x29990129)
        Console.WriteLine($"Found! u{(char)b1}{(char)b2}{(char)b3}");
}
```

Which gave me the fifth and final part of the flag: `u_<3`.

## The final flag

So putting all the parts together give me the full flag:

```
hitcon{tH4nK_U_s0_muCh_F0r_r3c0v3r1ng_+h3_fL4g_1_Luv_y0u_<3}
```
