---
layout: post
title: "HITCON 2015 Quals: Giraffes Coffee"
modified: 2015-10-19
tags: hitcon hitcon2015quals
---
*This challenge was solved by one of my teammates, hege and me and the write up was written by me.* 

View the source code of the site:

{% highlight text %}
<!-- Cong that you notice this line, 
          the source code in the index.phps -->
{% endhighlight %}
          
Download the PHP source code: <http://52.69.0.204/index.phps>

SQL injection is a red herring as every input is escaped properly.

So it should be a mt_rand "vulnerability".

If we register a new account and call multiple reset calls with our new user then we get a lot of tokens. These tokens should be "unxored" with our IPv4 address, so we can the clean mt_rand() results.

Then if we can predict the new mt_rand() result and send in to verify as admin then we will get the admin password.

The only problem is that there were a lot of players and had to get consecutive mt_rand values. So we used Keep-Alive which solved this problem (we used the same thread, so the internal state of Mersenne Twister is not changes).

Mersenne Twister usually can be calculated backwards, but the problem is PHP throws out the LSB bit, so this won't work.

On the other hand bruteforcing the seed is difficult as the we dont have the first outputs of the MT generator.

But it turned out that untwister (<https://github.com/altf4/untwister>) on one of my teammate's barebone server (with 32 CPUs) can bruteforce the seed in 20 minutes... :)

So I generated the next value and called verify with that value and logged in as admin with the new admin password.

The flag was:
{% highlight text %}
hitcon{howsgiraffesfeeling?no!youonlythinkofyourself}
{% endhighlight %}