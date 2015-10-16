---
layout: post
title: "ASIS 2015 Finals: Big Lie (for100)"
modified: 2015-10-15
tags: asis asis2015finals forensics
---

*This challenge was solved by and the write up was written by one of my teammates, gym.*

In this challange we are provided with a pcap file, loading it in wireshark and after a quick glance at the exported objects we can see they were using 0bin pastebin (<https://github.com/sametmax/0bin>).

0bin encrypts the data client side and provides a decryption key. This key if appended to the URL with a hash mark '#' is used to decrypt the received data. Ideally this part of the URL should not be sent to the server, thus the server operators cannot know the content of the paste.

However in the pcap 0bin is used in conjunction with piwik, witch send the entire URL in the request, thus we have the key to decrypt the data.

{% highlight http %}
GET /piwik.php?action_name=0bin%20-%20encrypted%20pastebin&idsite=1&rec=1&r=776276&h=11&m=27&s=12&url=http%3A%2F%2F0bin.asis.io%2Fpaste%2FTINcoc0f%23-krvZ7lGwZ4e2JQ8n%2B3dfsMBqyN6Xk6SUzY7i0JKbpo&urlref=http%3A%2F%2F0bin.asis.io%2F&_id=dd17974841486b63&_idts=1443081356&_idvc=1&_idn=0&_refts=0&_viewts=1443081356&send_image=0&pdf=1&qt=0&realp=0&wma=0&dir=0&fla=1&java=1&gears=0&ag=0&cookie=1&res=1440x900&gt_ms=108 HTTP/1.1
{% endhighlight %}

We can find three such key-id pairs in the pcap, the first one results in a fake flag, the second one has expired and the third one gives us an ASCII art of the real flag.

The last url:
<http://0bin.asis.io/paste/1ThAoKv4#Zz-nHPnr0vGGg3s/7/RWD2pnZPZl580x9Y2G3IUehfc>

The ascii art:
![alt]({{ site.url }}/images/asis2015finals/biglie.png)

And the flag is
{% highlight text %}
ASIS{e29a3ef6f1d71d04c5f107eb3c64bbbb}
{% endhighlight %}