---
layout: post
title: "HITCON 2016 Quals: Omegamon (rev400)"
modified: 2016-10-10
tags: hitcon, hitcon2016quals, reverse
---

While reversing the code it became clear that the most part of the code are for handling BigInteger operations.

The only interestring structure is this, it contains the current digit count of the BigInteger and the digits as dwords (one dword contains one digit 0-9):

{% highlight text %}
00000000 BigInteger      struc ; (sizeof=0x404, mappedto_14)
00000000 length          dd ?
00000004 items           dd 256 dup(?)
00000404 BigInteger      ends
{% endhighlight %}

The functions were pretty trivial after finding what's going on, there were basic BigInteger methods like Add, Subtract, Multiply, Modulo, Remainder, ModPow, GCD, comparisons (Eq, Neq), etc.

The only weird one (0xBDB) was the one which calculated this: `(x ** (n!)) % N`. (`x` and `n` are parameters the function and `N` is a global constant modulus).

After finished reversing these methods, only main remained which does the following:

- converts N to BigInteger format
  - N = `70175232617155622721369403112218008731727137018442195462238305570433409024579`, it can be factorized into (I used factordb.com):
  - p = 208467877680031083617459630285634936973 and 
  - q = 336623720633184311690592367893275345423
- calls srand(33177711) and generates 256 rand() numbers and converts them to BigInteger
- runs the following loop:

{% highlight c %} 
{% raw %}
   for(flagCounter = 1; ; flagCounter++){
       vec6 = (rand[0] ** (flagCounter!)) - 1;
       for(j = 1; j <= 255; ++j){
           vec6 = gcd(vec6, (rand[j] ** (flagCounter!)) - 1);
           if(vec6 == 1) 
                break;
       }
       
       if(vec6 != 1)
           break;
   }
   
   printf("flag is: hitcon{%lx%016lx}\n", *((_QWORD *)&flagCounter + 1), (_QWORD)flagCounter);
{% endraw %}
{% endhighlight %}

Of course it will never finish as it would take too long time.

So I asked my cryptopal (@ngg) how to solve this and he said, let's get the factors of (p-1)*(q-1) and probably the largest one will the flag. These were the factors: 2^3 * 3 * 13 * 17 * 19^2 * 20543 * 692191 * 735733 * 12243443 * 3981441750675421269733 * 71865286827970831870811761.

So I tried to submit: `hitcon{3b72110158a74799635e71}` (71865286827970831870811761 = 0x3b72110158a74799635e71) which was not the correct flag :(

Then I tried the second largest factor (3981441750675421269733) which gave us the correct flag:

{% highlight text %}
hitcon{d7d59a91a825da0ee5}
{% endhighlight %}
