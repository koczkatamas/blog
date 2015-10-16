---
layout: post
title: "ASIS 2015 Finals: (trivia75) Calm down"
modified: 2015-10-14
tags: asis asis2015finals Trivia
---

We got a big file with a lot of flag-like stuff:

{% highlight text %}
----------Which one is flag?----------
ASIS{3ec56380920f6b4a8ab7c85fa f6f2667}
ASIS{b3532aebaf2de7ea0fecdcf 80d91b29b}
ASIS{5148d9cb3d97d7d1e9d74dc5 0942393c}
ASIS{e9d89880e2c 31c00ef8008e830ff5268}
ASIS{fcf88f318445bed04cc2fe5 8dca9e65b}
ASIS{50480fe0160c98e7e1a7cd1266c 2d8e1}
ASIS{137db0 a81079449a5303d94e46cce011}
ASIS{6ecc4428eb9ed4bfe6ce989096 62a43b}
ASIS{44dc19a4af8a4747 0019394dcb58a4b8}
ASIS{2fa89f c6b0a188b83448f6e9372830b4}
ASIS{a222df308beb2112419dd 1223b76f614}
ASIS{fd96df4b589bd9eb9fc9b 60ffef82b62}
ASIS{2ff7139510ce5124efdb65c65 47b4c5e} 
{% endhighlight %}

Running a grep solved the challenge (-a: text mode, -E: extended grep):

{% highlight bash %}
kt@ubuntu:~/ctf/asisfinals2015$ grep -aE ASIS\{[0-9a-f]{32}\} flagBag.txt
ASIS{f3b79f17a02b7b85dcc11c2b59b7e1c0}
{% endhighlight %}