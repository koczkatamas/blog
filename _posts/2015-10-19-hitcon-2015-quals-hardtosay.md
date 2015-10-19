---
layout: post
title: "HITCON 2015 Quals: Hardtosay"
modified: 2015-10-19
tags: hitcon hitcon2015quals
---
*This challenge was solved by and the write up was written by one of my teammates, akg.* 

{% highlight ruby %}
`$#{~-$.}` -> executes $0 which is "sh\n"
$. is 1
~-1 is 0
{% endhighlight %}