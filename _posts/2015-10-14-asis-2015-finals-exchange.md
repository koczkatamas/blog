---
layout: post
title: "ASIS 2015 Finals: (rev200) Exchange"
modified: 2015-10-14
tags: asis, asis2015finals, reverse
---

Exchange is a 200 pts reversing challenge.

It "encrypts" the flag and saves the result to the flag_encrypted file, which was given to us.

After reversing the code, I found out what is the purpose of different functions:

0x18B0 - int* asciiToBigInt(char* input, int input): converts an ASCII string (right padded with \x00 bytes to 128 len) to an internal representation (I call it "bigInt") where every base 10 digit is stored as a 4 byte int containing byte 0x00 - 0x09. The data is in little endian order. So the last digit is the first integer.

For example if the input is "A", then it is padded to "A"+"\x00"*127, which can be represented as big integer as:
{% highlight text %}
45644552252363489844689389609877581127018946730957002823331856543955562216240478920414261820142538442862528914811095969718052089738035470554824542935803976892792629189907252120936110445628891085017384343302833495994061696688515965999235750723256915686006965603508239787486605414067115468024602193068650659840
{% endhighlight %}

So the internal representation will be as integer: 0,4,8,9,...,4,6,5,4. As bytes: 00000000 04000000 0800000000 0900000000 ...

0x25F0 - void bigIntToDecStr(int *input, char *outBuf): converts internal representation to decimal number string: "45644...59840"
0x276C - void bigIntToHex(int *a1, char *a2): converts internal representation to hex string: "410000...000000"
0x1780 - int* decStrToBigInt(char *inputDecStr): converts decimal number string to internal representation: "45644...59840" => 0,4,8,9,...,4,6,5,4
0x0f82 - void bigIntMultiply(int *output, int *input1, int *input2): output = input1 * input2 for bigints
0x21a0 - void bigIntAdd(int *result, int *a, int *b): result = a + b for bigints
0x1730 - __int64 hexCharToNum(int a1): converts one hex character to numerical representation: "0" -> 0, "A" -> 10, "F" -> 15
0x2540 - void divideBy2(int *input): input /= 2 for bigints
0x13B0 - int* algoAvg(int *input1, int *input2, __int64 roundNum): this is the main magic method, can be summarized as this:

{% highlight python %}
while round--:
  tmp = (a + b) / 2
  a = b
  b = tmp
{% endhighlight %}
  
As the round number was too much and it would be days to run, I patched the binary and lowered the round from 0x0f0000000000000f to 0x0f000f which should give me almost the correct result.

![alt]({{ site.url }}/images/asis2015finals/exchange1.png)

Also it OR-ed with small random values, which did not cause significant result, but could make my debugging harder, so I patched those out as well.

![alt]({{ site.url }}/images/asis2015finals/exchange2.png)

I found out quickly that the result is (1*input1 + 2*input2)/3, but it calculates it a much slower way.

Knowing these functions the main method can be summarized as this:

 - read flag as first argument (argv[1])
 - converts the flag to a decimal number string => flagStr
 - selects a random value between 1 and 127
 - chunks the flagStr into two parts, the length of the first part is the previously generated random value
 - calculates avg1 = algoAvg(part1, part2) = (part1 + 2*part2) / 3
 - calculates avg2 = algoAvg(part2, 2*part1) = (part2 + 4*part1) / 3
 - converts avg1 and avg2 to hex and writes them out to flag_encrypted file
 
Although I don't understand exactly but in the cases I tested the two parts are separated by the 0x00, 0x01, 0x02 byte series.

So decrypting the flag can be done by:

 - splitting the flag_enc file into two parts (avg1 and avg2), the parts are separated by 0x000102
 - calculating (equations are determined by doing some basic math) 
   - input2 = (4 * avg1 - avg2) * 3 / 7
   - input1 = 3 * avg1 - 2 * input2;
 - joining the two parts* (as decimal strings)
 - converting the big integer to ASCII
 
* I had to bruteforce a little as the input1's last digits were not correct, so I tried to add 0..255 to input1 before joining the strings and doing this until I found "ASIS{"

The plaintext was: 
{% highlight text %}
Woow! you are good at math! So the flag is ASIS{93b838ecffa1b11c2f5bcf77c2596494}, good luck :-(ÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿY
{% endhighlight %}

### Exploit code

{% highlight csharp %}
var enc = File.ReadAllBytes("flag_enc");
int splitPos = 0;
for (; splitPos < enc.Length - 3; splitPos++)
    if (enc[splitPos] == 0 && enc[splitPos + 1] == 1 && enc[splitPos + 2] == 2)
        break;

var avg1real = new BigInteger(enc.Take(splitPos).Reverse().Concat(new byte[1]).ToArray());
var avg2real = new BigInteger(enc.Skip(splitPos + 3).Reverse().Concat(new byte[1]).ToArray());

var input2restReal = (avg1real * 4 - avg2real) * 3 / 7;
var input1restReal = avg1real * 3 - 2 * input2restReal;

for (int i = 0; i < 255; i++)
{
    var fullNumRest = BigInteger.Parse((input1restReal + i).ToString() + input2restReal);
    var flag = Encoding.Default.GetString(fullNumRest.ToByteArray().Reverse().ToArray());
    if (flag.Contains("ASIS{"))
        Debugger.Break();
}
{% endhighlight %}