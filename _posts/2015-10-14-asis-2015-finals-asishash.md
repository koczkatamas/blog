---
layout: post
title: "ASIS 2015 Finals: ASIS Hash (rev150)"
modified: 2015-10-14
tags: asis asis2015finals reverse
---

This challenge was a simple reversing challenge.

The first step was NOPing out the ptrace "anti-debug" call and finding out the main hash function which was at the 0x401B40 address.

![alt]({{ site.url }}/images/asis2015finals/asishash.png) 

This accepted the flag as an input and used big integer math to calculate it's hash. This hash was compared to a static buffer (there was a little trick that only every 4th number was used from that buffer).

The hash function can be summarized with this python code:

{% highlight python %}
result = 0
for c in flag:
    result = result * 33 + (ord(c) ^ 0x8f)
{% endhighlight %}

And we know that the hash of the real flag was:

{% highlight text %}
27221558106229772521592198788202006619458470800161007384471764
{% endhighlight %}

So we could calculate the flag easily with the following code snippet:

{% highlight python %}
p = 'abcdef0123456789'
def f(h, l, x):
   if l == 0:
       if h == 210839978725:
           yield 'ASIS{' + x
   else:
       for c in p:
           if ((ord(c)^0x8f) % 33) == h%33:
               for r in f((h - (ord(c)^0x8f))//33, l-1, c+x):
                   yield r
h0 = 27221558106229772521592198788202006619458470800161007384471764
x = list(f((h0-(ord('}')^0x8f))//33, 32, '}'))
print x
{% endhighlight %}

The flag was:

{% highlight text %}
ASIS{d5c808f5dc96567bda48be9ba82fc1d6}
{% endhighlight %}