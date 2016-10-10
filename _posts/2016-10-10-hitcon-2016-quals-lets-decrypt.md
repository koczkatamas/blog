---
layout: post
title: "HITCON 2016 Quals: Let's Decrypt (crypto100)"
modified: 2016-10-10
tags: hitcon, hitcon2016quals, crypto
---

After checking the source code of the challenge, it was clear that the flag was used for two purposes: as AES key and as an IV.

AES is secure enough not to crack the key, but we can find out the IV with the following 'trick':
(the images at https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#CBC is always a good source of material to help thinking through what happens)

I replaced the first block of example encrypted text with the second block (so the blocks were in the following order now: c2\|c2\|c3), I kept the third block, so the padding remained correct and I decrypted it.

{% highlight text %}
Encrypted: e04f07e4dcd6cf096b47ba48b357814ee04f07e4dcd6cf096b47ba48b357814e4a89ef1cfad33e1dd28b892ba7233285
Decrypted: 7e009b446efd0ba5221b7f1a13f34ce9cc7bf2c48246e4e51f7cb53eda8495e36865206c617a7920646f67
{% endhighlight %}

If we write down how the encrypted blocks created, we get this (p = plaintext, c = ciphertext, ^ = xor, E = AES encrypt, \|\| = block boundary):

{% highlight text %}
original ciphertext: c1 = E(p1 ^ IV)  ||  c2 = E(p2 ^ c1)  ||  c3 = E(p3 ^ c2)
modified ciphertext: c2 = E(p2 ^ c1)  ||  c2 = E(p2 ^ c1)  ||  c3 = E(p3 ^ c2)
decrypted modified ciphertext: dec1 = p2 ^ c1 ^ IV  ||  ...
{% endhighlight %}

So if we want to know the IV (=FLAG) we can do this this way: IV = dec1 ^ p2 ^ c1 as we know all the 'variables'.

Here is my C# code which do exactly this:

{% highlight csharp %}
static void LetsDecrypt()
{
    var cSample = Conversion.HexToBytes("4a5b8d0034e5469c071b60000ca134d9e04f07e4dcd6cf096b47ba48b357814e4a89ef1cfad33e1dd28b892ba7233285");
    var pSample = Encoding.Default.GetBytes("The quick brown fox jumps over the lazy dog");
    var cFake = Conversion.HexToBytes("e04f07e4dcd6cf096b47ba48b357814ee04f07e4dcd6cf096b47ba48b357814e4a89ef1cfad33e1dd28b892ba7233285");
    var pFake = Conversion.HexToBytes("7e009b446efd0ba5221b7f1a13f34ce9cc7bf2c48246e4e51f7cb53eda8495e36865206c617a7920646f67".Replace(" ", ""));
    var block2input = CryptoUtils.Xor(cSample.Take(16).ToArray(), pSample.Skip(16).Take(16).ToArray());
    var dec1 = pFake.Take(16).ToArray(); // c1 ^ p2 ^ flag
    var flag = Encoding.Default.GetString(CryptoUtils.Xor(dec1, block2input));
}
{% endhighlight %}

The flag was
{% highlight text %}
hitcon{R4nd0m IV plz XD}
{% endhighlight %}