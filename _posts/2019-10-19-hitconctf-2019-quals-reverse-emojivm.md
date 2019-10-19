---
layout: post
title: "HITCON CTF 2019 Quals: Reverse - EmojiVM"
modified: 2019-10-19
tags: hitconctf, hitconctf2019quals, reverse
---

This challenge was a VM implemented where every instruction was an emoji. For the first part of the challenge we had to reverse a flag checker program written in this instruction set.

## The challenge

The following emojis where mapped the following instructions:

```
NOP: 🈳
ADD: ➕
SUB: ➖
MUL: ❌
MOD: ❓ 
XOR: ❎
AND: 👫
IS_LESS: 💀
IS_EQ: 💯
JMP: 🚀
JMP_IF: 🈶
JMP_IF_FALSE: 🈚
PUSH_EMOJI: ⏬
POP: 🔝
LD: 📤
ST: 📥
NEW: 🆕
FREE: 🆓
READ: 📄
POP_OBJ: 📝
FLUSH: 🔡
POP_INT64: 🔢
EXIT: 🛑
```

And to the following values:

```
0: 😀
1: 😁
2: 😂
3: 🤣
4: 😜
5: 😄
6: 😅
7: 😆
8: 😉
9: 😊
10: 😍
```

## The disassembler

The following code disassembles the `chal.evm` file and outputs the disassembly.

It also skips NOPs and constant numeric operations (additional and multiply), so single-digit constants converted into their original number.

```csharp
enum OpCode { NOP, ADD, SUB, MUL, MOD, XOR, AND, IS_LESS, IS_EQ, JMP, JMP_IF, JMP_IF_FALSE,
              PUSH_EMOJI, POP, LD, ST, NEW, FREE, READ, POP_OBJ, FLUSH, POP_INT64, EXIT, 
              NUM_0, NUM_1, NUM_2, NUM_3, NUM_4, NUM_5, NUM_6, NUM_7, NUM_8, NUM_9, NUM_10,
              PUSH_VAL, STORE_OBJ_VAL };

class Instruction
{
    public OpCode OpCode { get; set; }
    public long Value { get; set; }
    public int FileOffset { get; set; }
    public int InstructionIdx { get; set; }
    public bool IsNum => OpCode.NUM_0 <= OpCode && OpCode <= OpCode.NUM_10;
    public bool IsPush => OpCode == OpCode.PUSH_EMOJI || OpCode == OpCode.PUSH_VAL;

    public int ObjectIdx { get; set; }
    public int ByteIdx { get; set; }
    public bool IsStore => OpCode == OpCode.ST;

    public override string ToString() => 
        OpCode == OpCode.PUSH_VAL ? $"PUSH {Value}" : 
        OpCode == OpCode.STORE_OBJ_VAL ? $"obj{ObjectIdx}[{ByteIdx}] = {Value}" : 
        $"{OpCode}";

    public static Instruction Push(long argument, Instruction orig = null) => 
        new Instruction() { OpCode = OpCode.PUSH_VAL, Value = argument, FileOffset = orig?.FileOffset ?? 0, 
            InstructionIdx = orig?.InstructionIdx ?? 0 };
    public static Instruction Store(int objectIdx, int byteIdx, long value) => 
        new Instruction() { OpCode = OpCode.STORE_OBJ_VAL, ObjectIdx = objectIdx, ByteIdx = byteIdx, Value = value };
}

class InstrFilter
{
    public int SourceLen { get; set; }
    public Func<Instruction[], bool> Matcher { get; set; }
    public Func<Instruction[], Instruction> Converter { get; set; }

    public InstrFilter(int sourceLen, Func<Instruction[], bool> tester, Func<Instruction[], Instruction> converter)
    {
        SourceLen = sourceLen;
        Matcher = tester;
        Converter = converter;
    }
}

static void EmojiDecode()
{
    var baseDir = @"g:\Dropbox\hack\hitcon19\challs\emojivm_reverse\";
    var opCodes = File.ReadAllLines($"{baseDir}opcodes_enc.txt").Select(
          (codePoint, i) => new { codePoint, opCode = (OpCode)i }).ToArray();

    var prgSrc = File.ReadAllText($"{baseDir}chal.evm");
    var prg0 = new List<Instruction>();
    for (int i = 0; i < prgSrc.Length;)
    {
        var opCodeInfo = opCodes.Single(x => prgSrc.Substring(i, x.codePoint.Length) == x.codePoint);
        prg0.Add(new Instruction() { FileOffset = i, InstructionIdx = prg0.Count, OpCode = opCodeInfo.opCode });
        i += opCodeInfo.codePoint.Length;
    }

    Instruction[] RunFilters(Instruction[] source, InstrFilter[] filters)
    {
        var tail = new Instruction[10];
        for (int i = 0; i < source.Length;)
        {
            var hadMatch = false;
            foreach (var filter in filters)
            {
                var filterInput = source.Skip(i).Concat(tail).Take(filter.SourceLen).ToArray();
                if (filter.Matcher(filterInput))
                {
                    source = source.Take(i).Concat(new[] { filter.Converter(filterInput) })
                        .Concat(source.Skip(i + filter.SourceLen)).ToArray();
                    hadMatch = true;
                    break;
                }
            }

            if (!hadMatch)
                i++;
        }
        return source;
    }

    Instruction[] RunFiltersMulti(Instruction[] source, InstrFilter[] filters)
    {
        while (true)
        {
            var oldSourceLen = source.Length;
            source = RunFilters(source, filters);
            if (source.Length == oldSourceLen)
                break;
        }
        return source;
    }

    var prg1 = RunFiltersMulti(prg0.ToArray(), new[]
    {
        new InstrFilter(2, ins => ins[0].IsPush && ins[1].IsNum, 
            ins => Instruction.Push(ins[1].OpCode - OpCode.NUM_0, ins[0])),

        new InstrFilter(3, ins => ins[0].IsPush && ins[1].IsPush && ins[2].OpCode == OpCode.MUL, 
            ins => Instruction.Push(ins[0].Value * ins[1].Value, ins[0])),

        new InstrFilter(3, ins => ins[0].IsPush && ins[1].IsPush && ins[2].OpCode == OpCode.ADD,
            ins => Instruction.Push(ins[0].Value + ins[1].Value, ins[0])),
    });

    var prg2 = RunFiltersMulti(prg1, new[] { new InstrFilter(4, 
          ins => ins[0].IsPush && ins[1].IsPush && ins[2].IsPush && ins[3].OpCode == OpCode.ST, 
          ins => Instruction.Store((int)ins[2].Value, (int)ins[1].Value, ins[0].Value)) });

    var prg1src = prg1.Select(x => $"{x.InstructionIdx}: {x}").ToArray();
    File.WriteAllLines($"{baseDir}prg1src.txt", prg1src);
}
```

## The manually decompiled code

The disassembed code was manually decompiled to this more readable version:

```c
3:    obj0 = new(60)

12:   obj0 = "*************************************\n\0"
675:  print(pop) obj0
678:  obj0 = "*                                   *\n\0"
1341: print(pop) obj0
1344: obj0 = "*             Welcome to            *\n\0"
2070: print(pop) obj0
2073: obj0 = "*        EmojiVM 😀😁🤣🤔🤨😮       *\n\0"
3216: print(pop) obj0
3219: obj0 = "*       The Reverse Challenge       *\n\0"
4017: print(pop) obj0
4020: obj0 = "*                                   *\n\0"
4683: print(pop) obj0
4686: obj0 = "*************************************\n\0"
5349: print(pop) obj0
5352: obj0 = "\n\0\0"
5373: print(pop) obj0
5376: obj0 = "Please input the secret:\0"
5951: print(pop) obj0

5954: obj1 = new(30)
5963: obj2 = new(30)
5972: obj3 = new(30)
5981: obj4 = new(30)

5990: obj2 = "\x18\x05\x1d\x10\x42\x09\x4a\x24\x00\x5b\x08\x17\x40\x00\x72\x30\x09\x6c\x56\x40\x09\x5b\x05\x1a\x00" (len=25)
6363: obj4 = "\x8e\x63\xcd\x12\x4b\x58\x15\x17\x51\x22\xd9\x04\x51\x2c\x19\x15\x86\x2c\xd1\x4c\x84\x2e\x20\x06\x00" (len=25)

6808: obj1 = input = READ()

6811: obj5 = new(5)  ==>  VAR0 (input_len = 0), VAR1 (input_idx = 0), VAR2 (idx_mod4 = 0), VAR3, VAR4

6814: JMP 7052(==inputEnd)     if (input[input_idx] == '\0')
6870: JMP 6997(==inputNewLine) if (input[input_idx] == '\n')

6926: input_len++
6939: input_idx++
6981: JMP 6814

inputNewLine:
  6997: input[input_idx] = '\0'
  7036: JMP 7052(==inputEnd)

inputEnd:
  7052: JMP 8550(==FAIL) if (input_len != 24)

# check dashes (format: ABCD-EFGH-IJKL-MNOP-QRST)
7111: input_idx = 0
7118: JMP 7294(==checkDash) if ((input_idx+1) % 5 == 0)

7177: input_idx++
7190: JMP 7118 if (input_idx < 24)
7278: JMP 7401(==dashesAreOkay)

checkDash:
  7294: JMP 8550(==FAIL) if (input[input_idx] != '-')

7385: JMP 7177

dashesAreOkay:
  7401: input_idx = 0
  7408: idx_mod4 = input_idx % 4
  7421: JMP 7750(==mod4_0) if (idx_mod4 == 0)
  7474: JMP 7820(==mod4_1) if (idx_mod4 == 1)
  7527: JMP 7887(==mod4_2) if (idx_mod4 == 2)
  7580: JMP 7969(==mod4_3) if (idx_mod4 == 3)

bigLoop1:
  7633: input_idx++
  7646: JMP 7408 if (input_idx < 24)

  7734: JMP 8075

mod4_0:
  7750: input[input_idx] + 30
  7767: obj3[input_idx] = input[input_idx] + 30
  7804: JMP 7633(==bigLoop1)

mod4_1:
  7820: obj3[input_idx] = (input[input_idx] - 8) ^ 7
  7871: JMP 7633(==bigLoop1)

mod4_2:
  7887: obj3[input_idx] = ((input[input_idx] + 44) ^ 68) - 4
  7953: JMP 7633(==bigLoop1)

mod4_3:
  7969: obj3[input_idx] = (input[input_idx] ^ 101) ^ (172 & 20)
  8059: JMP 7633(==bigLoop1)


8075: input_idx = 0
8082: idx_mod4 = 0
8089: JMP 8284 if (obj3[input_idx] == obj4[input_idx])


8151: idx_mod4--
8167: input_idx++
8223: JMP 8089 if (input_idx < 24)


8268: JMP 8342


8284: idx_mod4++
8326: JMP 8167


8342: JMP 8550(==FAIL) if (idx_mod4 != 24)


8401: input_idx = 0

decodeFlag:
  8408: obj2[input_idx] ^= input[input_idx]
  8433: input_idx++
  8446: JMP 8408(==decodeFlag) if (input_idx < 24)


8534: JMP 8700(==WIN)

fail:
  8550: obj0 = "😭\n\0" (LOUDLY CRYING FACE)
  8652: print(pop) obj0
  8684: JMP 8825(==EXIT)

win:
  8700: obj0 = "😍\n\0" (smiling face with heart-shaped eyes)
  8802: print(pop) obj0
  8805: print(pop) obj2
  8808: obj0 = "\n\0"
  8822: print(pop) obj0
  8825: EXIT
```

## Reversing the flag checker

So the important part of the above code is that it takes our input, converts it byte-by-byte with 4 separate functions (uses the algorithm based on input byte's index `mod 4`) and compares to the expected value.

And the "dash checking" parts are actually was misinterpreted by me while reversing the challenge, I did not really realize this until I wrote this writeup.. :D

## Solver

The following code reverses the conversion operation and gives us the flag:

```csharp
var flagKey = EncodingHelper.GetBytes("\x18\x05\x1d\x10\x42\x09\x4a\x24\x00\x5b\x08\x17\x40\x00\x72\x30\x09\x6c\x56\x40\x09\x5b\x05\x1a\x00");
var toMatch = EncodingHelper.GetBytes("\x8e\x63\xcd\x12\x4b\x58\x15\x17\x51\x22\xd9\x04\x51\x2c\x19\x15\x86\x2c\xd1\x4c\x84\x2e\x20\x06\x00");
var input = toMatch.Select((x,i) => (byte)(
    i % 4 == 0 ? x - 30 : 
    i % 4 == 1 ? (x ^ 7) + 8 : 
    i % 4 == 2 ? ((x + 4) ^ 68) - 44 :
    x ^ 101 ^ (172 & 20))).ToArray();
var flag = EncodingHelper.GetString(CryptoUtils.XorEqual(flagKey, input));
```

## The flag

```
hitcon{R3vers3_Da_3moj1}
```