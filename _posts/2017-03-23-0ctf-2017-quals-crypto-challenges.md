---
layout: post
title: "0CTF 2017 Quals: Crypto challenges"
modified: 2017-03-23
tags: 0ctf, 0ctf2017quals, crypto
---
*These challenges were solved by and the writeups were written by one of my teammates, @ngg.*

=== Integrity

There was an encryption scheme, we had to calculate encrypt('admin') based on that we could encrypt anything other than the string 'admin'.

The scheme looked like this:
{% highlight text %}
encrypt(name) = iv + aescbc(key, iv, plaintext = (md5(pkcs7pad(name)) + pkcs7pad(name)))
{% endhighlight %}

md5 length is exactly a block size, so 
{% highlight text %}
pkcs7pad(md5(pkcs7pad(name)) + name) = md5(pkcs7pad(name)) + pkcs7pad(name)
{% endhighlight %}

This means that 
{% highlight text %}
encrypt(md5(pkcs7pad('admin')) + 'admin') = iv + aescbc(key, iv, md5(...) + md5(pkcs7pad(name)) + pkcs7pad(name))
{% endhighlight %}

If we cut the first block out from this then the rest is exactly `encrypt('admin')` with the `iv` set to `md5(...)`.

Sending this to the server gave me 
{% highlight text %}
flag{Easy_br0ken_scheme_cann0t_keep_y0ur_integrity}
{% endhighlight %}

=== OneTimePad1 && OneTimePad2

Both tasks were about breaking a random generator. The hardest part was to understand the ideas and math based on the given python codes.

They were based on finite field arithmetics of GF(2)[x]/P(x).

If you do not know what I'm talking about then visit https://en.wikipedia.org/wiki/Finite_field_arithmetic first.

 - For OneTimePad1 `P(x) = x**256 + x**10 + x**5 + x**2 + 1`, which meant that the field is `GF(2**256)` because `P(x)` is irreducible over `GF(2)`.
 - For OneTimePad2 `P(x) = x**128 + x**7 + x**2 + x + 1`, which is the standard GCM polynomial (the field is `GF(2**128)`).

 - In OneTimePad1 the `process(m, k)` function did the math, it calculated `(m+k)**2` where `m` and `k` are field elements.
 - In OneTimePad2 the two helper functions were `process1(m, k)` calculated `m*k` where `m` and `k` are field elements and
`process2(a, b)` calculated `a*b` where `a` and `b` are 2x2 matrices over this field.

In both problems the random generated worked like the following pseudo-python code:
{% highlight python %}
def rng():
	next = urandom(32 if OneTimePad1 else 16)
	seed = urandom(32 if OneTimePad1 else 16)
	while True:
		yield next
		next, seed = calculate(next, seed)
{% endhighlight %}

== OneTimePad1

In OneTimePad1 the calculate function returned (process(next, seed), seed) and the flag and two known strings were one time pad encrypted
with its first 3 outputs respectively. Based on the second and third encrypted string we knew the second and third generated random numbers (`r2` and `r3`), we had to calculate the first (`r1`).

`r3 = process(r2, seed) = (r2+seed)**2`, this means that `seed = sqrt(r3)+r2`.

Calculating square roots over binary fields are easy because squaring is a linear function.
(This might seem strange, but `(x+y)**2 = x**2 + 2*x*y + y**2 = x**2 + y**2` so it's really linear).

Being linear means that there exists a matrix `S` such that `x**2 = x*S` for every `x`.

Calculating ``S is straightforward, it happens to be invertible so we can calculate square roots as well (every field element has exactly 1 square root).

We now know seed and we also know that `r1 = sqrt(r2)+seed` so we can decrypt the flag: 
{% highlight text %}
flag{t0_B3_r4ndoM_en0Ugh_1s_nec3s5arY}
{% endhighlight %}

== OneTimePad2

In OneTimePad2 the calculate function was more complicated.

`A` and `B` were two known constants, the function calculated `M = [[A,B],[0,1]]**seed` and returned `M[0][0]*next + M[0][1]` and it also changed `seed` to `seed**2`.

We can see by induction that `[[A,B],[0,1]]**seed = [[A**seed, B*(1+A+A**2+...+A**(seed-1))],[0,1]] = [[A**seed, B*(A**seed - 1)/(A - 1)],[0,1]]`.

One time pad was used here as well but know we knew the first 4 plaintexts and we had to calculate the following ones.
`r2 = A**seed * r1 + B*(A**seed - 1)/(A-1)`

To get seed from this we first calculated `A**seed` as `((A-1)*r2 + B)/((A-1)*r1 + B)` and then had to calculate the discrete logarithm
`seed = Log(A, A**seed)`.

This last part was the hardest for me as I couldn't get Sage to solve it (I tried in lots of different ways but it always threw NotImplementedExceptions...).

After the competition I've read hellman's writeup (http://mslc.ctf.su/wp/0ctf-2017-quals-onetimepad-1-and-2/), he found a way to do this in Sage.

I knew that Mathematica cannot do this either, so I had no better idea than to look for any implementation on the web and read articles on how solve this if I have to implement my own.

Fortunately I found some promising references in Magma's documentation and I could solve this with the free online version at http://magma.maths.usyd.edu.au/calc/ with the following script:

{% highlight text %}
K<x> := GF(2,128); # this automatically uses the standard GCM polynomial for modulus
A := x^127 + x^126 + x^122 + x^121 + x^119 + x^117 + x^114 + x^112 + x^110 + x^109 + x^108 + x^106 + x^105 + x^104 + x^102 + x^101 + x^100 + x^99 + x^98 + x^97 + x^96 + x^94 + x^91 + x^90 + x^88 + x^87 + x^86 + x^82 + x^81 + x^77 + x^76 + x^75 + x^72 + x^71 + x^70 + x^68 + x^66 + x^65 + x^64 + x^63 + x^62 + x^60 + x^56 + x^55 + x^53 + x^50 + x^48 + x^43 + x^42 + x^40 + x^38 + x^37 + x^34 + x^32 + x^29 + x^24 + x^23 + x^22 + x^21 + x^18 + x^17 + x^16 + x^15 + x^12 + x^11 + x^9 + x^8 + x^7 + x^6 + x^5 + x^4 + x^3 + x^2 + 1;
An := x^123 + x^117 + x^116 + x^114 + x^113 + x^112 + x^110 + x^109 + x^108 + x^107 + x^104 + x^99 + x^98 + x^97 + x^95 + x^93 + x^91 + x^89 + x^87 + x^84 + x^83 + x^82 + x^81 + x^80 + x^78 + x^74 + x^69 + x^68 + x^66 + x^62 + x^57 + x^53 + x^52 + x^51 + x^45 + x^43 + x^42 + x^41 + x^38 + x^37 + x^35 + x^33 + x^32 + x^31 + x^30 + x^29 + x^28 + x^25 + x^22 + x^19 + x^18 + x^17 + x^15 + x^14 + x^13 + x^12 + x^10 + x^8 + x^5 + x^2 + 1;
Log(A, An);
{% endhighlight %}

After this we knew r1 and seed, so I just modified the original code to use these and to encrypt the ciphertext instead (one time pad is an involution).

This gave me 
{% highlight text %}
flag{LCG1sN3ver5aFe!!}
{% endhighlight %}
