---
layout: post
title: "ASIS 2015 Finals: Flag Hunter (misc75)"
modified: 2015-10-14
tags: asis asis2015finals misc
---

A website showed the world map, clicking on your country (depending on your IP) gave you a part of the flag:

![alt]({{ site.url }}/images/asis2015finals/flaghunt1.png)

Clicking on other country said you cannot do that:

![alt]({{ site.url }}/images/asis2015finals/flaghunt2.png)

Solution was: using a few proxies, TOR, Hola VPN, etc the gather the 6 parts of the flag and then figure out in which order should we concatenate them (from the 6! = 720 possibilites). We know that the SHA256(SHA256("ASIS{...}")) hash should match with the hash of the real flag (which was used by the ASIS scoreboard in a client-side javascript code).

Usually on every ASIS CTF we have to use this trick, so if you haven't know it yet, then don't forget for next year. :)