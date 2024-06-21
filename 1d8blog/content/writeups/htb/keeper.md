---
title: Keeper Writeup
---

# Initial Recon

Starting off with an initial `nmap` scan of our target host: `nmap -sV -sC 10.10.11.227 -oA keeper`:

![](https://i.imgur.com/uQE2cIF.png)

We see that there's 3 open ports:
* `22` - SSH
* `80` - HTTP
* `8000` - HTTP

I wasn't able to connect to port `8000` and kept receiving an *Unable to connect error*:

![](https://i.imgur.com/mLVlkU4.png)

But connecting to port `80`, we find that there's a hyperlink that's pointing to a virtual host (vHost) at the `tickets.keeper.htb/rt/` domain:

![](https://i.imgur.com/cXC9YkI.png)

Let's add this vHost to our `/etc/hosts` file so that way we can connect to it. Add the following entry into the `/etc/hosts` file:

```bash
10.10.11.227	keeper.htb tickets.keeper.htb
```

Attempting to connect to the base domain of `keeper.htb` leads us to the same page:

![](https://i.imgur.com/9ig7qRc.png)

But connecting instead to `tickets.keeper.htb` leads a login page for a service known as **Requests Tracker**:

![](https://i.imgur.com/qmiLn3d.png)

We also get a version number which is `4.4.4`! The link to the **Requests Tracker** software could be found [here](https://github.com/bestpractical/rt) and if you read the configuration settings, within step 7, it states the default credentials to be: `root:password`!

# Initial Access

We can login with these default credentials. Looking at the users on the ticket tracker, we see there's only 2 users:

![](https://i.imgur.com/2RRMYPv.png)

1. `root`
2. `lnorgaard`

If we click the `lnorgaard` user, we'll find that there's a comment that has the default credentials for this user:

![](https://i.imgur.com/Vtb9peW.png)

Let's use the `lnorgaard:Welcome2023!` credentials to login via SSH to the target machine:

![](https://i.imgur.com/D9YrwdL.png)

# Privilege Escalation

Going to the `/home/lnorgaard` directory & listing all files, we'll find 2 interesting files:

* `passcodes.kdbx`
* `KeePassDumpFull.dmp`

These files appear to be KeePass-related files which is a password manager. One of them appears to be a process dump:

![](https://i.imgur.com/My3o1FS.png)

while the `passcodes.kdbx` is a KeePass password database file:

![](https://i.imgur.com/GMRLmA8.png)

These two files lead me to believe that the privilege escalation component of this box may be related to [CVE-2023-32784](https://nvd.nist.gov/vuln/detail/CVE-2023-32784) which is a vulnerability in which the master password can be recovered from a KeePass password dump! 

One thing to note is that the vulnerability details state that the first character of the master password isn't recoverable, so we'll likely have to guess this one.

Searching `CVE-2023-32784 exploit Github` reveals various results, I chose to use [this Python one](https://github.com/z-jxy/keepass_dump). We can run it via: `python3 keepass_dump.py -f KeePassDumpFull.dmp`:

![](https://i.imgur.com/JdAwdic.png)

The extracted master password appears to be: `dgrd med flde`, though recall that the first character of the master password isn't recoverable. Looking this up as it appears to be a phrase, I came across several articles relating to a Danish pudding:

![](https://i.imgur.com/Bfn8vmQ.png)

Knowing this, and that the user we gained initial access with was `lnorgaard`, and that their Language was set to `Danish` on the Request Tracker system:

![](https://i.imgur.com/T0qQFlC.png)

I took an educated guess that it's likely that the master password for the KeePass database was indeed the Danish dessert `rødgrød med fløde

Let's import the `passcodes.kdbx` file into KeePass and use the discovered master password!

*Note: You can install [KeePass here](https://keepass.info/download.html)!*

After inputting the master password, you'll see 2 inputs within the **Network** passwords:

![](https://i.imgur.com/jGTBQ4f.png)

1. A password for the ticketing system for the `lnorgaard` user
2. A Putty SSH key for the `root` user:
	* ![](https://i.imgur.com/eRBlkAd.png)

This SSH key is in Putty format, but we can copy it & paste it into a file & convert it into OpenSSH format in order to use it to login as the `root` user:
First copy the entire key to a file:

![](https://i.imgur.com/QwjtUNZ.png)

Then we can use `puttygen` in order to convert the SSH key into OpenSSH format
*NOTE: You may need to install `putty-tools` in order to convert it!*

First, we can convert it & output a private SSH key by running: `puttygen <Putty SSH key> -O private-openssh -o rootprivkey.txt`

Then we can login to the target by specifying the `rootprivkey.txt` file with the `-i` option:

![](https://i.imgur.com/XVvYWJY.png)

And we've successfully rooted the box!
