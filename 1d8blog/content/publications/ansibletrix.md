---
title: Ansible Trix
---

**Description: This post contains a set of Ansible commands that I've used recently to explore systems (both Linux & Windows) & enumerate different information about them!**

# `Setup` Ansible Module

We can use the `setup` Ansible module which returns a wealth of information about the machine we're accessing! We can run it as a one-liner by running: `ansible all -i <IP Address>, -m setup -e "ansible_user=<username> ansible_password=<password> ansible_shell_type=powershell ansible_connection=ssh host_key_checking=false"` and this would output:

![](https://i.imgur.com/AKwqCMH.png)

And a ton more of information that got cut off in the screenshot! 

This module works for both Windows & Linux systems:

![](https://i.imgur.com/pmq47y5.png)![](https://i.imgur.com/qpDVEv6.png)

# Running System Commands With `raw` Module

We can also run system commands easily by putting the command within quotes & passing it as an argument & using the `raw` module: `ansible all -i <IP Address>, -m raw -e "ansible_user=<username> ansible_password=<password> ansible_shell_type=powershell ansible_connection=ssh host_key_checking=false" -a "whoami"`: 

![](https://i.imgur.com/RNfu9Uv.png)

We can quickly execute any system commands to gather more information about a remote system this way!

# Enumerating Installed Software On Remote System

`ansible all -i <IP Address>, -m raw -e "ansible_user=<username> ansible_password=<password> ansible_shell_type=powershell ansible_connection=ssh host_key_checking=false" -a 'Get-WmiObject -Query "SELECT * FROM Win32_Product" | Select-Object Name, Version, Vendor'`:

![](https://i.imgur.com/hC8jzVA.png)

# Enumerating Running Services On Linux Systems

We can use the `service_facts` module to get information about installed services on a Linux system by running: `ansible all -i <IP Address>, -m service_facts -e "ansible_user=<username> ansible_password=<password> ansible_shell_type=sh ansible_connection=ssh"`:

![](https://i.imgur.com/2pHbIlh.png)

But this also gives us information about services that aren't actively running, we can narrow down on only *running* services by piping the output into `grep` & grepping for the keyword *running*:

![](https://i.imgur.com/1Urf4JD.png)

But this will only return the keyword *running* without any other information about the service. We can utilize the `-B 3` arguments within `grep` which will output 3 lines before the actual keyword match, which will give us the *service name* and the *source* in addition to the *state* of the service:

![](https://i.imgur.com/vwiHmib.png)

We could exclude the *source* as well by using `grep -v source` to exclude it if we only wanted the *service name* & the *service state* by running `ansible all -i <IP Address>, -m service_facts -e "ansible_user=<username ansible_password=<password> ansible_shell_type=sh ansible_connection=ssh" | grep -i running -B 2 | grep -v source`:

![](https://i.imgur.com/vHWeGiW.png)

# Enumerating Running Services On Windows Systems

If we wanted to do the same on Windows, we can use the `ansible.windows.win_service_info` module. But it's a bit more difficult as the amount of information returned by this module is exponentially more when compared to its Linux counterpart. 

Running `ansible all -i <IP Address>, -m ansible.windows.win_service_info -e "ansible_user=<username> ansible_password=<password> ansible_shell_type=powershell ansible_connection=ssh" | more`:

![](https://i.imgur.com/9J4uMz8.png)

Or, instead of using this module, you could create your own Ansible module which is what I decided to do!

*NOTE: The module that I created provides far less information than the `win_service_info` module. I just created it for the fun and learning experience that comes with creating a custom module*

When creating a custom module in Ansible, you have to keep in mind the target operating system that the module will be designed to be used in. For example, if you develop a module written in `Python`, the target system must have a `Python` interpreter installed in order for the module to run. 

*You might be able to compile the Python executable so it can run as a .`exe` on a Windows host without the need for an interpreter but I haven't tested this yet (:*

I wanted to develop a custom module for Windows, so my option for it to run natively on Windows systems without the need to install anything extra is `Powershell`!

You can access my custom Ansible module [here](https://github.com/1d8/ansible-mods/tree/main/service_enum)!

This module can take 1 of 2 possible arguments that would be passed to the `desired_state` argument which correlates to the type of service to return:

* `running` services
* `stopped` services

An example playbook that uses this module to enumerate `running` services would look like this:

```yml
- name: Use service_enum Module
  hosts: all
  vars:
    ansible_shell_type: powershell
    ansible_shell_executable: powershell.exe
  tasks:
    - name: Run custom module
      service_enum:
        desired_state: running
      register: result


    - name: Print result
      debug:
        var: result.msg
```

Then we could run it via: `ansible-playbook -i <IP Address>, playbook.yml -e "ansible_user=<username> ansible_password=<password> ansible_shell_type=powershell ansible_connection=ssh host_key_checking=false"`:

![](https://i.imgur.com/c3nQAoP.png)
