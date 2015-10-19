---
layout: post
title: "HITCON 2015 Quals: Piranha Gun"
modified: 2015-10-19
tags: hitcon hitcon2015quals
---
*This challenge was solved by and the write up was written by one of my teammates, nguyen.*

{% highlight bash %}
cat README
{% endhighlight %}

The Piranha Gun can be found in "jungle.chest".

{% highlight bash %}
# umount /chest
umount /chest

# cd /chest
cd /chest

# ls
ls
jungle.chest

# cat jungle.chest
cat jungle.chest
{% endhighlight %}

The flag was:

{% highlight text %}
hitcon{Wh1re d!d Y0u F1nd the Jungle Key}
{% endhighlight %}