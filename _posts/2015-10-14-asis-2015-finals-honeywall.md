---
layout: post
title: "ASIS 2015 Finals: (crypto250) Honeywall"
modified: 2015-10-15
tags: asis asis2015finals crypto
---

*This challenge was solved by and the write up was written by one of my teammates, NGG.*

There was a server on which there was a message and there were about 1300 users (My solution used only one).

When a client connected to the server a random prime was generated (e <= 65537).

Each user had a modulus (N).

There were two permitted operations:

 - GET(user_id, msg_id): the server replied with ```[N_{user_id}, (msg_{msg_id}**e) % N_{user_id}]```
 - ADD(user_id, new_msg): the server replied with ```[N_{user_id}, (new_msg**e) % N_{user_id}]```

The task was to recover msg_0.

Solution:

 - ADD some random message m to user_0. We can simply bruteforce e by raising our message to every possible power.
 - GET msg_0 with user_0, this way we know e and c = (msg_0**e) % N_0
 - Reconnect to the server (this generates a new e2), and repeat the previous steps to get e2 and ```c2 = (msg_0**e2) % N_0```
 - Find x and y integers such that x*e + y*e2 = 1 (with the Extended Euclidean Algorithm) 
 - Calculate ```(c**x * c2**y) % N_0``` = ```(msg_0**(e*x) * msg_0**(e2*y)) % N_0``` = ```(msg_0**(e*x+e2*y)) % N_0``` = ```msg_0 % N_0 = msg_0```
 - msg_0 contained the flag.