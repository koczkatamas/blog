---
layout: post
title: "HITCON 2015 Quals: Rsabin"
modified: 2015-10-19
tags: hitcon hitcon2015quals
---
*This challenge was solved by and the write up was written by one of my teammates, NGG.*

There was a message encrypted with something between RSA and Rabin encryption schemes.
{% highlight python %}
n = p*q = 20313365319875646582924758840260496108941009482470626789052986536609343163264552626895564532307
e = 31415926535897932384
c = m^e % n = 19103602508342401901122269279664114182748999577286972038123073823905007006697188423804611222902
{% endhighlight %}

We factorized n with yafu.
{% highlight python %}
p = 123722643358410276082662590855480232574295213977
q = 164184701914508585475304431352949988726937945291
{% endhighlight %}

e doesn't have a modular inverse because it's even, so first we RSA-decrypted with its "odd part".

{% highlight python %}
e = 32 * 981747704246810387
{% endhighlight %}

RSA-decrypting with e/32 gave that

{% highlight text %}
m^32 % n = 6915497960347690034670190613920812775692185594434656280771177353647840352326299910999240632820
{% endhighlight %}

Decrypting it with Rabin 5 times in a row gave several possibilities for m % n.

m % n is one of:

{% highlight text %}
1170873348295885335059944818034561278496937179514286352764111586578035361653036340797178495797
6441791373850850303735177662669226594971314531797606586938114159564488393181507111460739720503 
13871573946024796279189581177591269513969694950673020202114872377044854770083045515434824811804 
19142491971579761247864814022225934830444072302956340436288874950031307801611516286098386036510 
4169292882246487226436372571580328445408188970955313275707356349635909107039805208587333631745 
8531407715482423717693263787976379790064568800203420573643404440830910301390203966050312684262 
11781957604393222865231495052284116318876440682267206215409582095778432861874348660845251848045 
16144072437629159356488386268680167663532820511515313513345630186973434056224747418308230900562
{% endhighlight %}

There was an assert in the encryption code that said the length of the flag is 50 (which means 400 bits), but these numbers were around 310 bits only.

We needed to find a multiple of n to add to m%n so that m will be 400 bits, and hex-decoding it gives 'hitcon{...}'.

We had lower and upper limits because of the needed string's beginning, we had to brute-force between those values and check if it only contains ascii characters and it ends with '}'.

It was too slow, but we could speed up the process by finding one possible multiplier such that it ends with '}', and then try every 256th multipliers only (because those are the ones that start with '}')

Here is the full python code that does the part after decrypting with RSA.

{% highlight python %}
def modular_sqrt(a, p):
   if legendre_symbol(a, p) != 1:
       return 0
   elif a == 0:
       return 0
   elif p == 2:
       return p
   elif p % 4 == 3:
       return pow(a, (p + 1) / 4, p)
   s = p - 1
   e = 0
   while s % 2 == 0:
       s /= 2
       e += 1
   n = 2
   while legendre_symbol(n, p) != -1:
       n += 1
   x = pow(a, (s + 1) / 2, p)
   b = pow(a, s, p)
   g = pow(n, s, p)
   r = e
   while True:
       t = b
       m = 0
       for m in xrange(r):
           if t == 1:
               break
           t = pow(t, 2, p)
       if m == 0:
           return x
       gs = pow(g, 2 ** (r - m - 1), p)
       g = (gs * gs) % p
       x = (x * gs) % p
       b = (b * g) % p
       r = m

def legendre_symbol(a, p):
   ls = pow(a, (p - 1) / 2, p)
   return -1 if ls == p - 1 else ls

def mul_inv(a, b):
   b0 = b
   x0, x1 = 0, 1
   if b == 1: return 1
   while a > 1:
       q = a / b
       a, b = b, a%b
       x0, x1 = x1 - q * x0, x0
   if x1 < 0: x1 += b0
   return x1

def chinese_remainder(n, a, lena):
   p = i = prod = 1; sm = 0
   for i in range(lena): prod *= n[i]
   for i in range(lena):
       p = prod / n[i]
       sm += a[i] * mul_inv(p, n[i]) * p
   return sm % prod

e = 31415926535897932384L
c = 19103602508342401901122269279664114182748999577286972038123073823905007006697188423804611222902L
p = 123722643358410276082662590855480232574295213977L
q = 164184701914508585475304431352949988726937945291L
n = p*q
pl = 6915497960347690034670190613920812775692185594434656280771177353647840352326299910999240632820L

def f(g):
    for x in list(g):
        assert(x != 0)
        a, b = modular_sqrt(x,p), modular_sqrt(x,q)
        if a == 0 or b == 0:
            return
        yield chinese_remainder([p,q], [a, b], 2)
        yield chinese_remainder([p,q], [p-a, b], 2)
        yield chinese_remainder([p,q], [a, q-b], 2)
        yield chinese_remainder([p,q], [p-a, q-b], 2)

import binascii
def s(y):
    z = '{0:x}'.format(y)
    if len(z) % 2:
        z = '0'+z
    return binascii.unhexlify(z)
l0 = list(f(f(f(f(f([pl]))))))
st = int(binascii.hexlify('hitcon{'+43*'\0'),16)
end = int(binascii.hexlify('hitcon|'+43*'\0'),16)
for u in l0:
    print 'U', u
    assert(pow(u, e, n) == c)
    v = (st//n)*n+u
    while v < end:
        sv = s(v)
        if sv[-1] == '}':
            while v < end:
                for c2 in sv:
                    if ord(c2) > 127:
                        break
                else:
                    print sv
                v += 256*n
                sv = s(v)
        v += n
{% endhighlight %}
        
The flag was 

{% highlight text %}
hitcon{Congratz~~! Let's eat an apple pi <3.14159}
{% endhighlight %}