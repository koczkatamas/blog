---
layout: post
title: "ASIS 2015 Finals: Impossible (web225)"
modified: 2015-10-14
tags: asis asis2015finals web
---

*This challenge was solved and the write up was written by one of my teammates, hege and me*  

Steps to solve this challenge:

 - Find robots.txt: <http://impossible.asis-ctf.ir/robots.txt> and the backup folder
 - Download the backup: <http://impossible.asis-ctf.ir/backup/1444419635.tar.gz>
 - Understand the source code and search for security vulnerabilities in it
 - Find the fishy md5() == comparison
 
{% highlight php %}
if (md5($username) == $user_data[0]) {
    return array($username, base64_decode($user_data[1])); 
}
{% endhighlight %}

 - Process the user data and search for vulnerable username
 - Find 
{% highlight text %}
{ user = "adm2salwg", userMd5 = "0e004561083131340065739640281486", email = "adam_sal2003@yahoo.com", active = "1" }
{% endhighlight %} 
 - Find an other MD5 "collision" (as a lot of already known collision found on the web are "already used")
 - Our collision was: 
{% highlight text %}
MD5("D8WKOXN880XR") == "0e299238785153218472769311512731"
{% endhighlight %} 
 - Register a new user with this username ("D8WKOXN880XR")
 - The get_user function will match adm2salwg's user info instead of our new user's thus leaking out adm2salwg's password: ```1W@ewes$%rq0```
 - Login with ```adm2salwg``` / ```1W@ewes$%rq0```
 - Profit:
 
{% highlight text %}
ASIS{d9fb4932eb4c45aa793301174033dff9}
{% endhighlight %}