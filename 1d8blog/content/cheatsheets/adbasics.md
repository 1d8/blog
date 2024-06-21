---
title: Active Directory (AD) Basics
---

**Description: Notes taken from the TryHackMe room AD Basics. Will likely add to this as I progress in my AD adventure**

# Overview

* What AD is?
* What an AD domain is?
* What components go into an AD domain
* Forests & Domain trusts
* etc

# Windows Domains

**Windows Domains** is a group of users & computers under the administration of a given business

* The main idea/goal is centralizing the administration of those components of a Windows network into a single repository called **Active Directory (AD)**

The server running the AD services is called the **Domain Controller (DC)**

Advantages of having a config'd Windows domain include:

* **Centralized Identity Management** - All users across the network can be config'd from AD with minimal effort
	* User *identities* can be controlled
* **Managing Security Policies** - You can config security policies directly from AD & apply them to users & computers across the network as necessary
	* EX: You can config a password policy & apply it to the entire domain just from the DC!

## Real-World Example

Within your university, you login using your student ID & password, right? You can login to any computer on campus using those credentials, as long as that computer is connected to the university's AD domain.

You can login without your account having to be registered onto each computer.

How this works is since the computers are connected to the school's domain, the domain handles all the authentication. Your account isn't locally stored on that computer, but instead it's stored on the DC of the school's domain

All authentication is handled by the AD network!

AD also helps your school restrict you from being able to perform certain options on any computer you login to. Such as opening control panel or an elevated cmd prompt!

# Active Directory

Core of any Windows Domain are the **Active Directory Domain Services (AD DS)**

* ADDS contains info of all the *objects* that exist in your network
	* EX: users, groups, machines, printers, shares, & more

## Users

1 of the most common object types in AD are *Users*

Users are 1 of the objects known as **security principals**

**Security Principals** in AD can be authenticated by the domain & can be assigned privileges over domain **resources** (EX: Files or printers)

* A **Security Principal** is an object that can act upon network resources

Users can be used to represent 2 types of entities:

1. **People** - Users will generally represent people in your org that need network access (EX: Employees)
2. **Services** - You can also define users to be used by services (EX: IIS, MSSQL). Every service requires a user to run
	* Service users are different from regular users since they only have the privileges necessary to run their respective service

## Machines

Machines/computers are another object type within an AD network.

Each time a computer joins an AD domain, a *machine object* is created

Machines are considered *security principals* as well & are assigned an account like any regular user

* This account has limited rights within the domain
* The machines are local admins on their assigned computer & they're generally not supposed to be accessed by anyone except the computer itself
	* But if you do have the password to the *Machine Account*, you can login

*NOTE: Machine Account passwords are auto rotated out & are generally comprised of 120 random characters*

**Machine Accounts** also follow a specific naming scheme:

* It's the computer name followed by a dollar sign
* So if the computer is named `DC01`, then its `DC01$`
* Or if the computer name is `TOM-PC`, then the *Machine Account Name* would be `TOM-PC1$`

## Security Groups

In Windows, you can define/create user groups & assign access rights to files or other network resources to the entire group instead of to each individual user

* Easier to manage groups than individual users
* When you add users to existing group, they inherit all the group's privileges

**Security Groups** are also considered security principals & can have privileges over resources on the network.

Groups can contain both users & machines/computers as members.

* Groups can also include other groups (sub-groups)

There's several default groups in a domain that can be used for granting specific privileges to users, such as:

* **Domain Admins** - Users in this group have admin privileges over entire domain.
	* Default - they can administer any computer on the domain, including DCs
* **Server Operators** - Users in this group can administer DCs but can't change any admin group memberships
* **Backup Operators** - Users in this group can access any file, ignoring their permissions. Used to perform backups of data on computers
* **Account Operators** - Users in this group can create/modify other accounts in the domain
* **Domain Users** - Includes all existing user accounts in the domain
* **Domain Computers** - Includes all existing computers in the domain
* **Domain Controllers (DCs)** - Includes all existing DCs in the domain

A complete list of default security groups is detailed in [Microsoft's documentation](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups)

## Active Directory Users & Computers

Configure users, groups, or machines in AD, login to the DC & search for *Active Directory Users & Computers* form the start menu.

Here, you'll see a hierarchy of users, computers, & groups within the domain.

Objects here are organized in **Organizational Units (OUs)**

* OUs are container objects that allow you to classify users & machines
* OUs are mainly used to define sets of users w/similar policing requirements
	* EX: Sales employees are likely to have different policies applied to them than the IT employees
* A user can only be part of 1 OU at a time

OUs may have a hierarchy to them as well. For example, you may have a OU defined for each state your organization operates in, then within each state OU, you'd have a different OU for each department.

It's normal to see OUs mimic the business structure since it helps to efficiently deploy baseline policies that can apply to entire departments. 

Windows also auto creates default OUs, including:

* **Builtin** - Contains default groups avaialble to any Windows host
* **Computers** - Any machine joining the network will be put here by default
* **Domain Controllers (DCs)** - Default OU that contains the DCs in your network
* **Users** - Default users & groups that apply to a domain-wide context
* **Managed Service Accounts** - Holds accounts used by services in Windows domain

## Security Groups vs OUs

Both OUs & Security groups are used to classify users & computers, yet they serve different purposes:

* OUs - useful for *applying policies* to users & computers which contain specific configs that pertain to sets of users depending on their role in the organization
	* A user can only be part of 1 OU at a time so it wouldn't make sense to apply 2 different policies to 1 user
* Security Groups are used to grant permissions over resources
	* EX: If you want to allow users to access a shared folder
	* A user can be part of many groups which is required for access to multiple resources

# Managing Users in AD

## Deleting OUs

If you try to delete an OU from a domain, you may get an error that looks like the following:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/38edaf4a8665c257c62556096c69cb6f.png)

This is due to the fact that by default, OUs are protected against accidental deletions. So in order to delete an OU, you must enable **Advanced Features** in the **View** menu option:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/15b282b6e3940f4c26c477a8c21f8266.png)

Then, you right-click the OU That you wish to delete, go to the properties of it, and you'll see an option that is a checkbox stating **Protect object from accidential deletion**. Uncheck this box:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/ad6b6d886c0448d14ce4ec8c62250256.png)

After you've unchecked the box, apply the changes, then try right-click the OU & deleting it again!

*NOTE: If you delete an OU, then any users, groups, or sub-OUs will also be deleted*

## Delegation 

In AD, you can give/**delegate** specific users some control over OUs

* **Delegation** allows you to grant users specific privileges to perform advanced tasks on OUs without needing a DA to step in
	* A common use case is granting `IT support` the necessary privileges to reset other low-privilege user's passwords. So for example, you can grant a specific IT user the control of resetting passwords for the Sales, Marketing, & Management OU to an IT user.

To delete control over the *Sales OU* to a user named *Phillip* (Our IT user), right-click the OU & select **Delegate Control**:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/74f8d615658a03aeb1cfdb6767d0a0a3.png)

Then you'll be asked who you want to delegate control over this OU to, select *Add*, then type in the name of the user you want to give control to:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/2814715e1dbadaef334973028e02da69.png)

Then click ok & on the next step, you select the *Tasks* that you want to delegate to the user you previously entered:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/3f81df2b38e35ca5729aee7a76c6b220.png)

*In our case, we're delegating the Reset user passwords & force password change at next logon task since it's supposed to be IT being able to reset users' passwords*

After clicking next a few more times, the user should be delegated control over the OU you specified along with the tasks that you specified!

## Resetting A User's Password via Powershell

If you wanted to reset a user's passwords via **Active Directory Users & Computers**, there's a chance that the user you're trying to use may have permissions to reset other users' passwords, but not open **Active Directory Users & Computers**. 

So a good alternative to do so is by using Powershell!

We can use the following command to reset a user's password:

`Set-ADAccountPassword <username> -Reset -NewPassword $(ConvertTo-SecureString "Password" -AsPlainText -Force)`

*NOTE: In this case, we're resetting the password and setting the new password to 'Password'. If you instead wanted to manually enter the new password which would be the more secure option, you'd run:*

`Set-ADAccountPassword <username> -Reset -NewPassword (Read-Host -AsSecureString -Prompt 'New Password')`

Then if you wanted to force the user to change the password at next logon, you'd run:

`Set-ADUser -ChangePasswordAtLogon $true -Identity <username>`

# Managing Computers in AD

By default, all machines that join a domain (except for the DCs) will be put in an OU called *Computers*.

Within the *Computers* OU, you'll likely see servers, laptops, & PCs. 

* Having all these different types of machines in 1 OU likely isn't the best idea since it's likely we'd want to apply different policies for servers & different policies for workstations that users regularly use

There is no one rule for all for organizing machines in AD, but you may want to segregate your devices by their use. Devices may be divided into 3 categories:

1. **Workstations** - likely to be the most common devices within an AD domain. Each user within the domain likely will login to a workstation. This is the device they'll do their daily work & browsing activities. Workstations should never have a privileged user signed into them
2. **Servers** - generally used to provide services to users or other servers
3. **Domain Controllers (DCs)** - allow you to manage the AD domain. These are often considered the most sensitive devices in the network since they hold the hashed passwords for all user account within the env.
	* OU is created by default 

# Group Policies

The main idea of organizing users & computers in OUs is to be able to deploy different policies for each OU individually. 

* This way, we can push different configs & security baselines for users depending on the department that they're in

Windows manages policies through **Group Policy Objects (GPOs)**

* GPOs are a collection of a settings that can be applied to OUs
* GPOs can contain policies aimed at either *users* or *computers* & allow you to set a baseline on specific machines & identities

To configure GPOs, type *Group Policy Management Tool* into the start menu of a DC!

To config Group Policies, you first create a GPO under **Group Policy Objects** & then link it to the GPO where you want the policies to apply. There are existing GPOs within your machine:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/d82cb9440894c831f6f3d58a2b0538ed.png)

In the above pic, there's 3 GPOs that were created:

* Default Domain Policy
* RDP Policy

These 2 policies are linked to the `thm.local` domain while the 3rd GPO, Default Domain Controllers Policy, is only linked to the DCs OU only meaning they only apply to the DCs within the `thm.local` domain!

*NOTE: Any GPO will apply to the OU it's linked to as well as any sub-OUs that are within that OU!*

* EX: The *Sales* OU will be affected by the Default Domain Policy since it's an OU within the `thm.local` domain!

## Diving Into Default Domain Policy

Let's see what's inside a GPO! 

When you select a GPO, it shows its **scope** which is where the selected GPO is linked in the AD, or where it's meant to be applied.

For the Default Domain Policy, it's only linked to the `thm.local` domain:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/06d5e70fbfa648f73e4598e18c8e9527.png)

You can apply **Security Filtering** to GPOs which means the GPO would only apply to specific users/computers under a specified OU

* By default though, GPOs will apply to the **Authenticated Users** group which includes all users/PCs

To see the actual content of the GPO, go to the **Settings** tab:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/c9293853549d5126b77bf2de8086e076.png)

* *NOTE: Each GPO has configs that apply to computers only & configs that apply to users only*

In the case of the Default Domain Policy, it only contains *Computer Configurations*:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/c9293853549d5126b77bf2de8086e076.png)

You can explore the GPO's configs by expanding the *show* tab on the right-side of each config

Since the Default Domain Policy GPO applies to the entire domain, any change to it would affect all computers

To edit a GPO, right-click it & click **Edit**:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/b71d8de9e74d129d0ad4142863deadc4.png)

This opens a new window where you can edit all the available configs within the GPO!

If you need a config option explained, you can click the *Explain* tab within the config properties:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/de35e7c03fafcb5b9df5457181e32652.png)

## GPO Distribution

GPOs are distributed within a domain via network share named `SYSVOL` which is stored on the DC!

* Typically, all domain users should have access to their share over the network in order to sync their GPOs periodically
* The `SYSVOL` share points to the folder `C:\Windows\SYSVOL\sysvol\` on each of the DCs in the network

Once a change is made to any GPO, it can take up to 2 hours for each computer to catch up

* But if you want to force any particular computer to sync its GPOs immediately, you can run: `gpupdate /force` on the computer that you want to update the GPO on

# Authentication Methods

On Windows domains, all credentials are stored in the DCs

* When a user tries to authenticate to a service using domain credentials, the service asks the DC to verify if the credentials are correct

2 protocols are used for network authentication in Windows domains:

1. **Kerberos** - Used by any recent Windows version. Default protocol in any recent domain
2. **NetNTLM** - Legacy authentication protocol kept for compatibility purposes

NetNTLM is obsolete, but most networks have both these authentication protocols enabled

## Kerberos Authentication

Kerberos authentication is the default authentication protocol for any recent Windows version.

Users who logon to a service using Kerberos are assigned *tickets*

* *Tickets* can be thought of as proof of a previous authentication

Users with tickets can present them to a service to show the service that they've authenticated into the network before & are able to use that particular service.

When Kerberos is used for authentication, the following happens:

1. The user sends their username & a timestamp encrypted using a key derived from their password to the **Key Distribution Center (KDC)** which is a service that's installed on the DC that's in charge of creating Kerberos tickets on the network
	* The KDC then creates & sends back a **Ticket Granting Ticket (TGT)** which allows a user to request additional tickets to access specific services.
		* This allows users to request tickets without having to send their credentials every time they want to access a service
	* Along with the TGT, a **Session Key** is given to the user which they need to generate the following requests
	* The TGT is encrypted using the **krbtgt** account's password hash & therefore a user can't access the contents since they don't know the **krbtgt** password
	* The TGT contains a copy of the Session Key as part of its contents & the KDC doesn't have a need to store the Session Key since it can recover a copy by decrypting the TGT if necessary
		* The DC contains the **krbtgt** account's password 

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/d36f5a024c20fb480cdae8cd09ddc09f.png)

2. When a user wants to connect to a service on the network (EX: a share, website, or database), they'll use their TGT to ask the KDC for a **Ticket Granting Service (TGS)**
	*  TGS are tickets that allow connections that allow connection only to the specific service that the TGS was created for
	* To request a TGS, the user sends their *username* & a *timestamp* encrypted using a Session Key, along with the TGT & a **Service Principal Name (SPN)** which indicates the service & server name that we want to access
	* Then the KDC sends a TGS back along with a **Service Session Key** which is necessary to authenticate to the service we want to access
		* The TGS is encrypted using a key derived from the **Service Owner Hash**. The *Service Owner* being the user or machine account that the service runs under
		* The TGS contains a copy of the *Service Session Key* on its encrypted contents so the *Service Owner* can access it by decrypting the TGS
![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/84504666e78373c613d3e05d176282dc.png)
3. The TGS can then be sent to the service you want to access in order to authenticate & establish a connection.
	* The service uses its configured account's password hash to decrypt the TGS & validate the *Service Session Key*
![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/8fbf08d03459c1b792f3b6efa4d7f285.png)
## NetNTLM Authentication
NetNTLM works using a *challenge-response* mechanism. 

The entire process of NetNTLM authentication works as follows:
![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/2eab5cacbd0d3e9dc9afb86169b711ec.png)

1. Client sends an authentication request to the server they want to access
2. Server generates a random number & sends it as a challenge to the client
3. Client combines their NTLM password hash with the challenge (& other known data) to generate a response to the challenge & sends it back to the server for verification
4. The server forwards the challenge & response to the DC for verification
5. The DC uses the challenge to recalculate the response & compares it to the original response sent by the client
	* If both match, the client is authenticated
	* If they don't match, access is denied
	* The authentication result (authenticated/not authenticated) is sent back to the server
6. The server forwards the authentication result to the client

*NOTE: The user's password or password hash is never transmitted through the network for the sake of security*
*NOTE 2: The described process only apply if a domain account is used to authenticate. If a local account is used, then the server can verify the response to the challenge itself without needing to interact with the DC since the password hash is stored locally on its SAM*
# Trees, Forests, & Trusts
Up until now, these notes have been focused on managing a single domain, the role of the DC & how it joins computers, servers, & users.

But as organizations grow larger, their networks do as well. So it's likely larger organizations won't have a single domain, but rather they may need multiple!
## Trees
Scenario: Your company expands internationally & now operates in a new country! Due to this, there's different laws & regulations your organization must abide by which means you have to update your GPOs to comply!
You also now have IT employees in both countries & each team must manage the resources for their respective countries without interfering w/the other team.
* You could technically create a complex OU structure & use delegations, but having a large AD structure may be difficult to manage & confusing
* The solution: **Adding a new domain!**
AD supports integrating multiple domains so you can partition your network into units which can be independently managed.
* This means you could have 2 domains for 2 different countries where your organization operates and manage them separately, but they'd still be under the same **Tree**
* So if you have 2 domains that share the same namespace, they can be joined into a **Tree**
For example, the `thm.local` domain was split into 2 subdomains for UK & US branches (`uk.thm.local` & `us.thm.local`) So with this, you could build a tree with a root domain of `thm.local`:
![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/abea24b7979676a1dcc0c568054544c8.png)
This partitioned structure gives us better control over who can access what in the domain
* The IT people in the `uk.thm.local` domain will have their own DC that manages the UK resources
	* EX: A UK employee wouldn't be able to manage US users
* This way, DAs of each branch have complete control over their respective DCs, but not the other branch's DCs
* Policies can also be config'd independently for each domain within the tree!
## Forests
The domains you manage can also be config'd in different namespaces
Scenario: Say your organization grows & acquires another company, known as `MHT Inc.`. 
When both companies merge, you'll likely have different domain trees for each company, each managed by its own IT department. 
The union of several trees with different *namespaces* into the same network is known as a **forest**:
![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/03448c2faf976db890118d835000bab7.png)
## Trust Relationships
Having multiple domains organized into trees & forests allow you to have a nice compartmentalized network for efficient management & resources.
But at a certain point, a user at the `THM UK` may need to access a file share on of of the `MHT ASIA` servers.
* This essentially means a user within `Domain A` in the same forest must access a resource stored within `Domain B` in the same forest!
	* In order for this to happen, domains arranged in trees & forests are joined together by **Trust Relationships**
A **Trust Relationship** between domains allows you to authorize a user from domain `THM UK` to access resources from domain `MHT EU`
The simplest trust relationship that can be established is a **1-Way Trust Relationship**
* In a 1-way trust, if `Domain A` trusts `Domain B`, then this means a user on `Domain B` is authorized  to access resources on `Domain A`, but since this trust is 1-way, then users in `Domain A` can't access resources on `Domain B` since `Domain B` doesn't trust `Domain A`
![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/af95eb1a4b6c672491d8989f79c00200.png)
**2-Way Trust Relationships** can also be made to allow both domains to mutually authorize users from the other.
* By default, joining several domains under a tree or forest forms a 2-way trust relationship
*NOTE: Having a trust relationship between domains doesn't auto grant access to all resources on other domains. Once a trust relationship is established, you have the chance to authorize users across different domains!*
