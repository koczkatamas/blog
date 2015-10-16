---
layout: post
title: "ASIS 2015 Finals: (crypto300) RSASR"
modified: 2015-10-15
tags: asis asis2015finals crypto
---

*This challenge was solved by and the write up was written by one of my teammates, NGG.*

The task was to factorize an RSA public key, but we knew that the primes were emirps (<https://en.wikipedia.org/wiki/Emirp>).

This can be done by a simple backtrack algorithm, we try to guess the digits of both primes starting from the outermost.

*KT's note: we found out that they were emirps by factorizing some small public moduluses with [Yafu](http://sourceforge.net/projects/yafu/). And we had to factorize only one public key as the cipher text was 129 bytes, but only 1028 bits (started with 08 which is ~4 bits) and the smallest public key which was larger than 1028 bits was the n in the python code (it is ~1029 bits btw).*

{% highlight python %}
n = 6528060431134312098979986223024580864611046696815854430382374273411300418237131352745191078493977589108885811759425485490763751348287769344905469074809576433677010568815441304709680418296164156409562517530459274464091661561004894449297362571476259873657346997681362092440259333170797190642839587892066761627543
def t(a, b, k):
	# sqrt(n) has 155 digits, so we need to figure out 77 digits on each side
    if k == 77:
        if a*b == n:
            print a, b
        return
    for i in xrange(10):
        for j in xrange(10):
			# we try to guess the last not-already-guessed digits of both primes
            a1 = a + i*(10**k) + j*(10**(154-k))
            b1 = b + j*(10**k) + i*(10**(154-k))
            if a1*b1 > n:
				# a1 and b1 are too large
                continue
            if (a1+(10**(154-k)))*(b1+(10**(154-k))) < n:
				# a1 and b1 are too small
                continue
            if ((a1*b1)%(10**(k+1))) != (n%(10**(k+1))):
				# The last digits of a1*b1 (which won't change later) doesn't match n
                continue
			# this a1 and b1 seem to be a possible match, try to guess remaining digits
            t(a1, b1, k+1)

# the primes have odd number of digits (155), so we try all possible middle digits (it simplifies the code)
for i in xrange(10):
    t(i*(10**77), i*(10**77), 0)
{% endhighlight %}

{% highlight python %}
p = 72432241732033981541049204016745025006867436329489703868293535625696723664804764149457845005290546241606890061226796845022216057745054630401792003744462109
q = 90126444730029710403645054775061222054869762216009860614264509250054875494146740846632769652653539286830798492363476860052054761040294014518933023714223427
{% endhighlight %}

And the flag was:
{% highlight text %}
ASIS{e3bdadf44ee8d2e097096b4d82efd8ed}
{% endhighlight %}