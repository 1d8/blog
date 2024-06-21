---
title: Diving Into LLMNR Poisoning
---

**Description: This post will dive into the topic of LLMNR poisoning, specifically what the LLMNR protocol is, how we could poison it, and diving into what it looks like in a packet capture**

# Lab Setup

In my lab setup, I have 3 machines:
* Kali Linux machine representing the **threat actor**
	* IP address - **192.168.56.107**
* Windows workstation representing the **victim**
	* IP address - **192.168.56.118**
* Windows server representing the **Domain Controller (DC)**
	* IP address - **192.168.56.114**

# What is LLMNR?

**Link-Local Multicast Name Resolution (LLMNR)** is a protocol that allows for hosts on a Windows network to perform name resolution without the need for a DNS server or DNS configuration. Instead, hosts query each other for resolutions on the network. It can be thought of as a *peer-to-peer DNS resolution*.
When a *query* from a Windows host fails, such as when the DNS server it queries doesn't have an *answer*, the host will then broadcast an LLMNR query to the entire network and ask all hosts within the LAN if they have that particular host's IP address. This is where a **LLMNR Poisoning** could occur if a **threat actor** answers the query for them and provides the IP address of a malicious server! 

# What is LLMNR Poisoning?

**LLMNR Poisoning** is an attack where an attacker listens for LLMNR resolution queries & answers with their own IP address (or with another IP address) in order to redirect **victim** traffic. Once the **victim** has been redirected to connect to a server that a **threat actor** controls, then the **threat actor** could request the **victim** to send their hash in order to connect them to a "server". Then the **threat actor** would then deny them access after receiving their NTLM hash!

* This can lead to *credential theft* & *relay attacks*

Here is an illustration that shows how LLMNR poisoning could occur (credit to [TCM Security](https://tcm-sec.com/llmnr-poisoning-and-how-to-prevent-it/)): 

![](https://tcm-sec.com/wp-content/uploads/2023/09/llmnr-overview.png)

# How to Perform LLMNR Poisoning

We'll be using the [Responder](https://github.com/lgandx/Responder) tool in order to perform LLMNR poisoning. This tool doesn't just perform LLMNR poisoning, but also poisons other protocols such as NBT-NS and MDNS and also has built-in server capabilities that play the role of a rogue authentication server which allows us to capture the **victim's** credentials.

Let's start running our **Responder** server by running: 

`sudo responder -I eth0 -wFv`

* The `-I` flag specifies the network adapter name that we'll be running **Responder** on
	* You can run `sudo ifconfig` in order to view the adapter you wish to use
* The `-w` flag starts the WPAD rogue proxy server
	* The `-F` flag forces NTLM/basic authentication to occur. This will give the **victim** an authentication prompt
* The `-v` flag tells the tool to run in *verbose* mode

Now **Responder** should be running:

![](https://i.imgur.com/aQatgJn.png)

We can now open up **Wireshark** and begin sniffing packets!

Now it's time to trigger an event that we can poison! We can trigger an LLMNR event by hopping on our **victim** machine, the Windows workstation, then we can open up *File Explorer* and attempt to access a network share by typing:

`\\FileShareNameHere` into the search bar:

![](https://i.imgur.com/2rgbLni.png)

After you've hit enter, you'll see on our **kali** machine that we've poisoned some answers to various queries that were sent by the **victim**, and that we've baited the victim into authenticating to our server:

![](https://i.imgur.com/kPV9zYE.png)

As a result, we got the **victim's** NTLMv2 hash!

# Diving into the Packet Capture

Remember that we had **Wireshark** running in the background while we performed this attack, let's revisit the packet capture and see what it looks like!
As you can see, our **victim** machine, **192.168.56.118**, has performed various queries on the network for both **MDNS** & **LLMNR** to find the IP address of the `1d8` hostname:

![](https://i.imgur.com/6xDmgCL.png)

Expanding the **LLMNR** query, we see that it's sending a multicast query on the network.

![](https://i.imgur.com/tl68rni.png)

We know that this is a *multicast query* by its IP address: `224.0.0.252`
So any host on the LAN that have **LLMNR** enabled, such as our **kali** machine, can receive this query and respond to it. 

Unfortunately, a legitimate host couldn't provide an answer and instead, our **kali** machine, **192.168.56.107**, provides an answer to both the **LLMNR** & **MDNS** query:

![](https://i.imgur.com/0Njg3Fk.png)

As we can see, the IP address that it answered with to this query is the IP address of our **kali** machine, meaning that it's telling the **victim** that our **kali** machine is the file server its looking for:

![](https://i.imgur.com/oS6w149.png)

Then, the **victim** attempts to access the supposed file server our **kali** machine is hosting via SMB which is what we see here:

![](https://i.imgur.com/KsfClbo.png)

So first the SMB connection occurs, then our **kali** machine tells the **victim** that they must authenticate which I believe is done by the `NTLMSSP_CHALLENGE` packet which is when the **victim** sends us their NTLMv2 hash. Then we deny them access in the `STATUS_ACCESS_DENIED` packet!

![](https://i.imgur.com/6YeEpEx.png)

We can dive deeper into the `NTLMSSP_CHALLENGE` & `NTLMSSP_AUTH` packets in order to derive the NTLMv2 hash that the victim sends to us!
First, let's grab the **NTLM Server Challenge** which is located in the `NTLMSSP_CHALLENGE` packet:

![](https://i.imgur.com/lKjS5Sd.png)

After you've grabbed the **NTLM Server Challenge** string, let's move on to the `NTLMSSP_AUTH` packet where we will grab the **NTLMv2 Response** & the **NTProofStr**:

![](https://i.imgur.com/BrpZrnF.png)

In addition to this, grab the **User name** & **Domain name**: 

![](https://i.imgur.com/mjhJVGc.png)

ow you should have the following data:

* Domain name - `redteamleaders
* Username - `issacb`
* NTLMv2 Response - ```64c782b8df92803689f35dbc8ab199f8010100000000000080e5402181f4d90164c75b6fa2dc93b50000000002000800340051004a00470001001e00570049004e002d003100520054004f00460046004700330055005600550004003400570049004e002d003100520054004f0046004600470033005500560055002e00340051004a0047002e004c004f00430041004c0003001400340051004a0047002e004c004f00430041004c0005001400340051004a0047002e004c004f00430041004c000700080080e5402181f4d901060004000200000008003000300000000000000000000000002000003e857568e45f48b52909d6bb01b941570bfee9b49bf7fdb3371bc1e2de0adbdc0a001000000000000000000000000000000000000900100063006900660073002f003100640038000000000000000000```
* NTProofStr - `64c782b8df92803689f35dbc8ab199f8`
* NTLM Server Challenge - `32c3c92b5c816475`

Looking at the **NTLMv2 Response** and the **NTProofStr**, we notice that the **NTLMv2 Response** has the **NTProofStr** prepended to it. Remove it and keep them separate so now it will look like this:

```
010100000000000080e5402181f4d90164c75b6fa2dc93b50000000002000800340051004a00470001001e00570049004e002d003100520054004f00460046004700330055005600550004003400570049004e002d003100520054004f0046004600470033005500560055002e00340051004a0047002e004c004f00430041004c0003001400340051004a0047002e004c004f00430041004c0005001400340051004a0047002e004c004f00430041004c000700080080e5402181f4d901060004000200000008003000300000000000000000000000002000003e857568e45f48b52909d6bb01b941570bfee9b49bf7fdb3371bc1e2de0adbdc0a001000000000000000000000000000000000000900100063006900660073002f003100640038000000000000000000
```

And now we can rebuild the NTLMv2 hash that **Responder** captured earlier (*NOTE: The hash that we captured earlier with Responder is going to look different from the one we are rebuilding now. This is just because I ran the poisoning attack several times and am using the packet capture from the latest run*) 

The format of the NTLMv2 hash is:

`username::domain:NTLMServerChallenge:NTProofStr:NTLMV2ResponseWithoutNTProofStr`

```
issacb::redteamleaders:32c3c92b5c816475:64c782b8df92803689f35dbc8ab199f8:010100000000000080e5402181f4d90164c75b6fa2dc93b50000000002000800340051004a00470001001e00570049004e002d003100520054004f00460046004700330055005600550004003400570049004e002d003100520054004f0046004600470033005500560055002e00340051004a0047002e004c004f00430041004c0003001400340051004a0047002e004c004f00430041004c0005001400340051004a0047002e004c004f00430041004c000700080080e5402181f4d901060004000200000008003000300000000000000000000000002000003e857568e45f48b52909d6bb01b941570bfee9b49bf7fdb3371bc1e2de0adbdc0a001000000000000000000000000000000000000900100063006900660073002f003100640038000000000000000000
```

We've now reassembled successfully the NTLMv2 hash. We can now run `hashcat` on it to crack it using your favorite wordlist:

`hashcat -m 5600 hash wordlist`

![](https://i.imgur.com/kFNYrVb.png)

And as you can see, we've cracked it!

# References

* https://en.wikipedia.org/wiki/Multicast_address
* https://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/
* https://tcm-sec.com/llmnr-poisoning-and-how-to-prevent-it/
