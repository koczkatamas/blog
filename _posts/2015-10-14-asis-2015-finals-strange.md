---
layout: post
title: "ASIS 2015 Finals: (for150) Strange"
modified: 2014-12-24
tags: asis, asis2015finals, crypto
---

We got a PNG file with a size of 15MB.

You cannot open the file as some programs simply freeze, others show out of memory exceptions, or other errors.

Loading into Wireshark for example shows the file’s basic information like it’s width and height.

![alt]({{ site.url }}/images/asis2015finals/strange1.png)
 
It is a very huge file, so that explains why we cannot open it earlier.

We have to make some educated guesses. Looking into the file contents you can see that the IDAT part of the file is full of zeros:

![alt]({{ site.url }}/images/asis2015finals/strange2.png)
 
So I used one of my helper method which gave me a quick summary of the contents of the file:

{% highlight text %}
\x89PNG\x0d\x0a\x1a\x0a\x00\x00\x00\x0d
IHDR\x00\x05C\x9b\x00\x05C\x9b\x01\x03\x00\x00\x00\xa5\xa5\x12\xb1\x00\x00\x00\x06
PLTE@\x00\xe0\xe0\x00@\xa3~c\xab\x00\xdb\xfd\xf1
IDATx\xda\xec\xc1\x01\x0d\x00\x00\x00\xc2\xa0\xf7Om\x0f\x07\x04\x0c
<7207787x00>
\xbc\x19\x00\x00\x00\xff\xff...\xa0\xf7Om\x10\x81\x0c
<7207829x00>
\xe0\xd5\x00\x00\x00\xff\xff\x01\x00\x00\xff\xffn\x1f\xdb\x89\x8e.\xf3\xe9\x00\x00\x00\x00
IEND\xaeB`\x82
{% endhighlight %}

The IDAT header contains zlib compressed data (as this is the only supported encoding method). So there is some information in the middle of the file.

As the file’s BitDepth is 1, this means the 1 byte contains 8 pixel information, so the uncompressed RAW bitmap data is 344987 * (344987 // 8 + 1) = ~15Gb.

As I did not want to decompress this much data to my hard disk I wrote a C# script to seek into the middle of the image data (so to about 7.4GB) and read the middle of the file and extracted a few MB’s of RAW data.

I created a summary of this too:
{% highlight text %}
<2154200x00>\xf1\xfc...36 bytes...\xcf\x0a
<43085x00>\xf1\xf9\x8...\xe7\x0a
<43085x00>\xf5\xf3\xef...\xcf\x0a
[...10 times again...]
<2154300x00>
{% endhighlight %}

What we see is 40 bytes data in the middle of every row.
So I simply recovered these bits with the following code snippet:
{% highlight csharp %}
long strideLen = 344987 / 8 + 1 + 1;
for (int i = 0; i < 16; i++)
    rows.Add(Conversion.BytesToHex(png2.Skip(baseOffset + i * (int)strideLen + 21542).Take(40).ToArray()));
{% endhighlight %}

And converted the bytes to bits aka. pixels in this case (with my web-based conversion toolset hosted on https://kt.pe/tools.html) and replaced "1" characters with space " " to make it more readable:
{% highlight text %}
....000       00000     0    00000      0             000     0000        00    00   000               000      000    0              0    000     000000      00                     0000      000      000     00           000000        0      00       00     000        00    00   000     0000     0000        00  00    
    000      00  000    0   00  000    0            000 00   00  00       00   00  000 00             00 00    00 00   0              0  000 00    0           00                    00  00    00 00   000 00   00            0             0      00       00    00 00       00   00   00 00   00  00   00  00       00   00   
    0 0     00     0    0  00     0    0            00   00  0    00     000   00  00   00           00   00  00   00  0              0  00   00  00          000                    0    00  00   00  00   00  00           00             0     000      000   00   00     000   00  00   00  0    00  0    00     000    0   
   00 00    00     0    0  00     0    0     000    00   00  0    00    0000  0000 00   00   00000   0        0    00  0 000     0000 0  00   00  00         0000    0000    00000   0     0  0    00  0     0 0000  00000   00        0000 0    0000     0000   0          0000  0000 0    00  0    00  0     0    0000    0   
   0  00    000         0  000         0    00 00   00   0        0     0 00   00  00   0   000 00   0 000    0     0  000 000  00  000  00   0   00000      0 00   00  00  000 00   0    00  0     0       00  00  000 00   00000    00  000    0 00     0 00   0 000      0 00   00  0     0       0   0    00    0 00    0   
   0   0     00000      0   00000      0   00   00   00000      000    0  00   00   00000   0    00  000 00   0     0  00   00  0    00   00000   00  00    0  00   0    0  0    00  00   00  0     0       00  00  0    00  00  00   0    00   0  00    0  00   000 00    0  00   00  0     0     000   00   00   0  00    0   
  00   00       0000    0      0000    0   0     0  00   00       00  00  00   00  00   00       00  00   00  0     0  0     0  0    00  00   00       00  00  00   0            00   000000  0     0     000   00       00       00  0    00  00  00   00  00   00   00  00  00   00  0     0       00   000000  00  00    0   
  0000000          00   0         00  00   0000000  0     0       00  0   00   00  0     0   000000  0     0  0     0  0     0 00     0  0     0        0  0   00   0        000000        0  0     0    00     00   000000        0 00     0  0   00   0   00   0     0  0   00   00  0     0       00        0  0   00    00  
 00     0   0      00   0  0      00  0    0        0     0  0     0 00000000  00  0     0  00   00  0     0  0    00  0     0  0    00  0     0        0 00000000  0       00   00       00  0    00   00      00  00   00        0  0    00 00000000 00000000  0     0 00000000  00  0    00  0     0       00 00000000   00  
 00     00  00     00   0  00     00   0   0     0  0    00  0    00      00   00  0    00  0    00  00   00  00   00  00   00  0    00  0    00  0    00      00   0    0  0    00  00   0   00   00  00       00  0    00  0    00  0    00      00       00   00   00      00   00  00   00  0    00  00   0       00    0   
 0      00   000  00    0   000  00    0    00 00   000 00   00  00       00   00  000 00   00  000   00 00    00 00   000 00   000 000  000 00   00  00       00   00  00  00  000  00  00    00 00   00       00  00  000  00  00   000 000      00       00    00 00       00   00   00 00   00  00   00  00       00    0   
00       0    00000     0    00000     0     000     0000     0000        00   00   0000     000  00   000      000    0 000     0000 0   0000     0000        00    0000    000  00  0000      000    0000000  00   000  00  0000     0000 0      00       00     000        00   00    000     0000     0000        00    0   
{% endhighlight %}

The flag was: 
{% highlight text %}
ASIS{e834f8a60bd854ca902fa5d4464f0394}
{% endhighlight %}