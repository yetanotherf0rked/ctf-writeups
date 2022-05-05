# Spending spring days crafting packets at NahamCon 2022  (3 of 3)
# /!\ writeup still in draft state

*A CTF writeup of Networking challenges at NahamCon2022<br/>
Part 3 of 3: The Smuggler<br/>
by [f0rked](https://github.com/yetanotherf0rked) - 2022-05-05*

To end this serie, we'll cover **The Smuggler** challenge.

**Tools used:** 


**Challenges:**
- **1. Contemporaneous Open** - hard - 14 solves - 500 points - first blooded by **StaticFlow**
-  **2. Freaky Flag Day** - hard - 9 solves - 500 points - first blooded by **Maple Bacon**
- **\>\>** **3. The smuggler** - hard - 8 solves - 500 points - first blooded by **ekofisk**

## The Smuggler
> **Author: @Kkevsterrr#7469** 
Argh! We've got a custom border firewall to filter out DNS requests that aren't so cool before we send them on to 1.1.1.1 for processing. To get the flag, all you need to do is to send us DNS request for `nahamcon.com` to which 1.1.1.1 will accept and correctly respond. The problem is that our firewall is going to refuse to send any well-formed DNS request for `nahamcon.com`. Your task is to craft a (technically malformed/non-compliant) DNS request to which 1.1.1.1 will still correctly respond (but that our firewall will ignore) to sneak your request by our pesky firewall. A DNS smuggler, you be!  
 <br/>Fun fact - this challenge is modeled after a real vulnerability in the Great Firewall of China's DNS censorship system.


### Further Lectures
- [Using nfqueue with python](https://byt3bl33d3r.github.io/using-nfqueue-with-python-the-right-way.html)
- [Scapy docs](https://scapy.readthedocs.io/)
- [About calculating checksums with Scapy on Stack Overflow](https://stackoverflow.com/questions/5953371/how-to-calculate-a-packet-checksum-without-sending-it)
- [python-netfilterqueue on Github](https://github.com/oremanj/python-netfilterqueue)
- [Netfilter project](https://www.netfilter.org/)
- [TCP Flags on KeyCDN](https://www.keycdn.com/support/tcp-flags)