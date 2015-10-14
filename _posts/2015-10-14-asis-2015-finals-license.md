---
layout: post
title: "ASIS 2015 Finals: License"
modified: 2015-10-15
tags: asis asis2015finals reverse
---

*This challenge was solved by and the write up was written by one of my teammates, nguyen*

We got x64 ELF binary 'license'

![alt]({{ site.url }}/images/asis2015finals/license1.png)

Decompile result of main function starts with opening a file ```_a\nb\tc_```, since it is inconvenient to create file with such name, we replace the filename with following command

{% highlight bash %}
hexdump -ve '1/1 "%.2X"' license | sed 's/5F610A6209635F/6B657966696C65/g' | xxd -r -p > license_patch
{% endhighlight %}

now we create a file name "keyfile" and get following error.

![alt]({{ site.url }}/images/asis2015finals/license2.png)

from next logic, we can see that size of keyfile should satisfy some equation.

![alt]({{ site.url }}/images/asis2015finals/license3.png) 

which is

{% highlight text %}
44242*X^5 - 45235*X^4 - 1256*X^3 + 14392*X^2 - 59762*X - 1949670109068 = 0
{% endhighlight %}

we solve this using z3 solver and found out that size should be 34 byte.
next, the file should contain 5 newlines

![alt]({{ site.url }}/images/asis2015finals/license4.png)
 
the file contents needs to be separated with newline and each line has to contain 6bytes which will be compared after XORing with hardcoded XORed key:

{% highlight text %}
iKWoZLVc4LTyGrCRedPhfEnihgyGxWrCGjvi37pnPGh2f1DJKEcQZMDlVvZpEHHzUfd4VvlMzRDINqBk;1srRfRvvUW
{% endhighlight %}

![alt]({{ site.url }}/images/asis2015finals/license5.png)

As a result, the following equation should be satisfied.

{% highlight python %}
s.add(l4 == 0x686779477857)
s.add(l1 ^ l2 == 0x694b576f5a4c)
s.add(l2 ^ l4 ^ 0x232323232323 == 0x5663344c5479)
s.add(l3 ^ l4 == 0x477243526564)
s.add(l3 ^ (l4 ^ l5 ^ 0x232323232323) == 0x506866456e69)
{% endhighlight %}

solving this equation with z3 yields

{% highlight python %}
l1 = 128008166266177
l2 = 32055189049101
l3 = 51768215280947
l4 = 114793625647191
l5 = 57419521861678
{% endhighlight %}

generating keyfile with these keys concatenated with newline
we get following result

{% highlight bash %}
root@ubuntu:~/tmp# ./license
program successfully registered to ASIS{8d2cc30143831881f94cb05dcf0b83e0}
root@ubuntu:~/tmp#
{% endhighlight %}