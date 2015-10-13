---
layout: post
title: ASIS 2015 Finals: Fake
modified: 2015-10-14
tags: asis, asis2015finals, reverse
---

Fake was a fairly simple binary. You had to supply a 64 bit integer in decimal form as argv[1] and it multiplied with different values, shifted some and printed out as ASCII.

As we could suspect that the output is the flag (it was 40 bytes long instead of the 38 byte + null terminating zero), and the flag is starting with "ASIS{" + 3 hex digit (0-9a-f), we would easily bruteforce the solution as there are only 16**3 = 4096 possibilities.

The only problem we had to solve is it multiplied two 64 bit integers, which caused overflow. So when we calculated the input value, we had to solve a very basic congruence.

{% highlight c %}
argv1num = strtol(argv[1], 0LL, 10);
v5 = 1019660215 * argv1num;
{% endhighlight %}

This C# snippet generated every possible inputs:

{% highlight csharp %}
var charset = "0123456789abcdef";
var solv = new List<string>();
foreach (var c1 in charset)
    foreach (var c2 in charset)
        foreach (var c3 in charset)
        {
            var p1 = "ASIS{" + c1 + c2 + c3;
            var v1 = BitConverter.ToUInt64(p1.Select(x => (byte)x).ToArray(), 0);
            var maxVal = (BigInteger)1 << 63;
            var num = MathUtils.SolveLinearCongruence(1019660215, v1, maxVal).Single();
            var num2 = num % maxVal;
            solv.Add(num2.ToString());
        }
File.WriteAllLines("solv.txt", solv);
{% endhighlight %}

Testing them was done by the following bash script:

{% highlight bash %}
while read p; do
  ./fake $p >> flags.txt
done <solv.txt
{% endhighlight %}

And grepping the result gave me only valid flag:

{% highlight bash %}
kt@ubuntu:~/ctf/asisfinals2015$ cat flags.txt|grep -E [0-9a-z]{32}
ASIS{f5f7af556bd6973bd6f2687280a243d9}
{% endhighlight %}