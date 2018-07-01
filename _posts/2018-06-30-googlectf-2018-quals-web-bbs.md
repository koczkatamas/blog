---
layout: post
title: "GoogleCTF 2018 Quals: Web - BBS"
modified: 2018-06-30
tags: googlectf, gctf, gctf2018quals, web
---

Last weekend I played on the Google CTF 2018 Quals which was one of the best CTFs I played recently. They separated the easy challenges into a "beginner's quest" so we got only the medium-hard ones. I think this was a really good choice and made the whole CTF experience more pleasant. Also as with other CTFs, changing to dynamic scoring was also a welcomed change.

I started solving all the web challenges as our web guy was missing on Saturday and nobody else is really into web, and as I am kind of a jack of all trades when comes to CTFs, I looked into the web one. At the end (I mean at the _really_ end but I will talk about this later) we solved all the web challenges, including BBS which was only solved 3 teams at the end of the CTF.

![alt]({{ site.url }}/images/gctf2018quals/bbs_chall_desc.png)

# Introduction to the challenge

BBS was... well... a BBS ([wikipedia article](https://en.wikipedia.org/wiki/Bulletin_board_system)) in a form of really old school website.

![alt]({{ site.url }}/images/gctf2018quals/bbs_website.png)

The functionality of the website was really simple: you could register (`Home > New`), you could login (`Home > Open`), contact the admin (`Home > Contact` - this menu did not do anything, but more about later):

![alt]({{ site.url }}/images/gctf2018quals/bbs_menu.png)

After registering and logging in you could post to your board and modify your profile settings:

![alt]({{ site.url }}/images/gctf2018quals/bbs_signed_in.png) ![alt]({{ site.url }}/images/gctf2018quals/bbs_profile.png)

You could only upload PNG files (really file type mattered, not the extension) and it was resized to a 64x64 PNG (in every case, even if you uploaded a PNG with the exact same size). The resized PNG was saved to https://bbs.web.ctfcompetition.com/avatar/<md5_hash_of_the_resized_png>