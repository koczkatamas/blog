---
layout: post
title: "ASIS 2015 Finals: Simple (crypto75)"
modified: 2015-10-15
tags: asis asis2015finals crypto
---

*This challenge was solved by and the write up was written by one of my teammates, NGG*

This was a simple xor-cipher, but each word had a different 1-byte xor-key.

This python code printed out lots of possibilities.

{% highlight python %}
x = '110d00_000a0701_1a00_00120812_171b1a171500111a150011_001b_071006001901_0900_787100_00091b00_00130805120f0908_0900_5143594353445602000105_140b0a000b_00021500151e141514_1b00_0a15000b0b0c0b02_1000131117_000f05_0a030000031b0908_001b_101f1c001a1d14_435340424400'
for i in xrange(32, 128):
    print map(lambda y: ''.join(map(lambda c: chr(ord(c)^i), binascii.unhexlify(y))), x.split('_'))
{% endhighlight %}

Going through the results by hand, I could restore an english sentence which meant that the flag is
{% highlight text %}
ASIS{md5(asisctf2015)} = ASIS{7fc5bed10f3d903f1e69190a16562fcb}
{% endhighlight %}