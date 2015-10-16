---
layout: post
title: "ASIS 2015 Finals: Particles (for175)"
modified: 2015-10-15
tags: asis asis2015finals forensics
---

*This challenge was solved by and the write up was written by one of my teammates, gym.*

In this challenge we are provided with a pcap of a zsync transfer. Zsync is a file transfer program that allows you to download a file from a remote server, where you have a copy of an older version of the file on your computer already. Zsync downloads only the new parts of the file, and transfers them over HTTP. 

The zsync headers are the following:

{% highlight text %}
zsync: 0.6.2
Filename: Particles
MTime: Wed, 12 Aug 2015 05:35:27 +0000
Blocksize: 2048
Length: 1125888
Hash-Lengths: 2,2,4
URL: Particles
SHA-1: 9be3800b49e84e0c014852977557f21bcde2a775
{% endhighlight %}

Each transfer contains the hash of the file and blocks that are being transferred. We can see that the SHA1 hash of the original file is:

{% highlight text %}
9be3800b49e84e0c014852977557f21bcde2a775
{% endhighlight %}

Searching for this hash value we can find out that the original file is the Operation Potatoe viruses dropper (<https://github.com/eset/malware-ioc/blob/master/potao/README.adoc>). Some further search leads us to <https://www.hybrid-analysis.com/sample/61dd8b60ac35e91771d9ed4f337cd63e0aa6d0a0c5a17bb28cac59b3c21c24a9?environmentId=4> where we can aquire the original sample.

At this point we can either examine the headers manually and restore the final file (each header contains the blocks and the number of bytes being transferred):

{% highlight http %}
HTTP/1.1 206 Partial Content
Date: Fri, 09 Oct 2015 16:09:56 GMT
Server: Apache/2.4.9 (Win64) PHP/5.5.12
Last-Modified: Fri, 09 Oct 2015 10:22:06 GMT
ETag: "112e00-521a959f56f80"
Accept-Ranges: bytes
Content-Length: 1024
Content-Range: bytes 73728-74751/1125888
Connection: close
{% endhighlight %}

Or we can use the Xplico (<http://www.xplico.org/>) opensource network forensics tool to do this for us.

The final file is a windows binary with the modified dropper code, running it in a windows vm we receive an error message that prints the 32 bit hash value.

{% highlight text %}
ASIS{c295c4f709efc00a54e77a027e36860c} is the flag.
{% endhighlight %}

### KT's alternative, "facepalm" solution

Meanwhile gym solved the challenge, I searched for every SHA-1 in the pcap.

{% highlight text %}
9be3800b49e84e0c014852977557f21bcde2a775 - the real malware sample
e227c6d298358d53374decb9feaacb463717e2d9 - no results
2d27f6e5bafdf23c7a964a325ebf3a5ee9ca4b18 - no results
8f1fa762c3bf865d0298e7a8fd3640c606962122 - no results
7e05370d87196157bc35f920d7fcf27668f8e8af - no results
e8c7d65370947b40418af55bdc0f65e06b7b0c59
{% endhighlight %}

And at the last hash throw the following result: <https://www.hybrid-analysis.com/sample/688a3ac91914609e387111e6382911ecd0aefe9f4f31bed85438b65af390cf6f?environmentId=1>

And if I scrolled down to the middle of the page I saw the following screenshot:

![alt]({{ site.url }}/images/asis2015finals/particles.png) 

I liked this part especially as this looked like exactly as a flag. :)

![alt]({{ site.url }}/images/asis2015finals/particles2.png) 

It was the flag of course. :D

First I thought maybe this was the intended solution, but then I saw the upload date and it was clear that somebody (probably an other team) uploaded the malware sample meanwhile the CTF, so it was a really facepalm moment for me. :)

And in spite of that the flag could be found this easily only a few team solved the challenge.

gym was not too happy when I told him that I just sent in the flag meanwhile he was working hard on solving the challenge :)