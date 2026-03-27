## Windows Active Directory penetration testing
Technical notes, AD pentest methodology, list of tools, scripts and Windows commands that are useful for internal penetration tests and assumed breach exercises (red teaming).<br>
>The output files included here are the results of tools, scripts and Windows commands that I ran against a vulnerable Windows AD lab that I created to test attacks/exploits and deliver hands-on penetration testing training sessions.

### Table of contents 
> #### <i> Classic internal penetration test methodology - Windows Active Directory attack paths </i>

- [Step 1. Bypassing Network Access Control (NAC) - if any](#STEP-1-BYPASSING-NETWORK-ACCESS-CONTROL-NAC---if-any-)
- [Step 2. Reconnaissance](#STEP-2-RECONNAISSANCE-)
- [Step 3. Gaining access](#STEP-3-GAINING-ACCESS-)
- [Step 4. Post-exploitation and local privilege escalation](#STEP-4-POST-EXPLOITATION-and-LOCAL-PRIVILEGE-ESCALATION-)
- [Step 5. Network lateral movement and privileged accounts hunting](#STEP-5-NETWORK-LATERAL-MOVEMENT-and-PRIVILEGED-ACCOUNTS-HUNTING-)
- [Step 6. Windows domain compromise (Privilege escalation to become 'Domain Admin' + Persistence)](#STEP-6-WINDOWS-DOMAIN-COMPROMISE-Privilege-escalation-to-become-Domain-Admin--Persistence-)
- [Step 7. Forest root domain compromise (Privilege escalation to become 'Enterprise Admin')](#STEP-7-FOREST-ROOT-DOMAIN-COMPROMISE-Privilege-escalation-to-become-Enterprise-Admin-)
- Others
  - [Defense evasion techniques - Bypassing AV, EDR and SIEM solutions](#DEFENSE-EVASION-TECHNIQUES---BYPASSING-ANTIVIRUS-EDR-AND-SIEM-SOLUTIONS)
  - [List of useful tools and scripts](#LIST-OF-USEFUL-TOOLS--SCRIPTS)
  - [Useful resources](#USEFUL-RESOURCES)

----------------
#### STEP 1. BYPASSING NETWORK ACCESS CONTROL (NAC) - if any 🔐
<i>If a NAC solution is implemented, the purpose of this phase will be to bypass it to get access to the internal network and start the internal penetration test.</i>
```
1. Pre-connect scenario => NAC checks are made before granting any access to the internal network
-------------------------------------------------------------------------------------------------
➤ MAC address spoofing technique
  - Bypass MAC address filtering solution by spoofing the MAC address of a whitelisted device (e.g. printer, smart TV in meeting room, VOIP phone)
➤ Pre-authenticated device technique
  - Bypass wired network 802.1x protection (NAC) by placing a rogue device (with 2 network adapters) between a pre-authenticated device and the network switch. 
    Using scripts like 'fenrir-ocd' or 'nac_bypass-setup.sh', the traffic will then flow through the rogue device which will be able to log into the network and smuggle network packets.
➤ Captive portal bypass technique
  - Hack the captive authentication portal used to control network access
➤ VOIP hopping and VLAN hopping techniques
➤ ...
```
```
2. Post-connect scenario => Network access is temporarily granted while NAC checks are ran against your laptop
--------------------------------------------------------------------------------------------------------------
➤ MAC address randomization technique
  - Change your MAC address automatically (e.g. every minute) with a script to obtain a new IP address prior getting blocked
    and keep accessing the network resources.
➤ ...
```

-----------------
#### STEP 2. RECONNAISSANCE 🕵
<i>The purpose of the reconnaissance phase is to gather as much as possible information about the targets (Windows domains and internal network). It includes Windows domain(s) enumeration, DNS enumeration, targeted network scans...</i>
```
1. Black-box penetration test (we start with no account)
--------------------------------------------------------
➤ On our laptop connected to the LAN or Wifi, we run commands like 'ipconfig /all', 'ip a' and 'nslookup' to identify:
   - the IP address range of the user network (our laptop IP address is part of it)
   - the IP address range of a production (server) network/VLAN (thanks to the IP address of the DNS server which is usually also the IP address of a Domain Controller)
➤ Network sniffing
➤ Reconnaissance using DNS queries (e.g. reverse IP lookup, DNS zone transfer) and the naming convention of the hostnames
   Examples:
   - Domain Controllers have often a hostname like 'pr<bla>dc1', 'dv<bla>ad2', 'usdc02', 'prodfrdc3', etc.
   - Web servers have often a hostname like 'prweb01', 'wwwserver02', 'win2k16iis03', 'devJBOSS04', etc.
   - Database servers have often a hostname like 'sqlsrv01', 'prdbserver02', 'prodorasrv08', 'devmongodb14', etc. 
   - Citrix servers have often a hostname like 'prctxsrv1', 'printctx02', 'citrixsrv02', etc.
➤ Targeted network scans (e.g. Nmap and NSE scripts)
```
```
2. Grey-box penetration test (we start with 1 low-privileged Windows account)
-----------------------------------------------------------------------------
➤ AD and Windows domain information gathering (enumerate accounts, groups, computers, ACLs, password policies, GPOs, Kerberos delegation, ...)
➤ Numerous tools and scripts can be used to enumerate a Windows domain
   Examples:
   - Windows native DOS and Powershell commands (e.g. 'net' commands, PowerShell ActiveDirectory module)
   - Sysinternals tools (e.g. ADexplorer.exe)
   - PowerView framework / SharpView
   - Powershell scripts like ADrecon.ps1
   - SharpHound/RustHound + BloodHound
   - PingCastle
   - Purple Knight
   - ADCollector
   - ADFind
```

-----------------
#### STEP 3. GAINING ACCESS 🔓
<i>The purpose of this phase is to gain (unauthorized) access to several internal systems (e.g. servers, file shares, databases) by exploiting common security issues such as: default/weak passwords, OS security misconfiguration, insecure network protocols and unpatched known vulnerabilities.</i>
```
1. Black-box penetration test (we start with no account)
--------------------------------------------------------
➤ LLMNR & NBT-NS poisonning attacks (tool: Responder) to collect NTLMv2 password hashes from the network + Offline password cracking (tools: John, hashcat)
➤ DNS poisoning attacks via IPv6 DHCP requests (tool: MITM6) to collect NTLMv2 password hashes from the network + Offline password cracking (tools: John, hashcat)
➤ NTLM relay attacks (tool: Ntlmrelayx) by exploiting vulnerabilities like PetitPotam and PrinterBug or poisonning attacks (LLMNR / NBT-NS / DNS & IPV6)
➤ Default/weak admin credentials for a software installed on a Windows server that will lead to a RCE
   Examples:
   - Web servers (e.g. Tomcat, WebLogic, JBoss) => Webshell upload
   - Jenkins, JIRA, Splunk => OS command execution
   - CMS (e.g. WordPress, DNN, Kentico, Drupal, Liferay) => Webshell upload
   - Databases (e.g. MSSQL, Oracle, PostgreSQL, Sybase) => OS command execution
   - PhpMyAdmin => Webshell upload
   - SAP => OS command execution
➤ Windows password spray attacks (goal: find accounts protected by an easy guessable password or even a blank password / be careful not to lock accounts)
➤ Anonymous access to data storage spaces (e.g. FTP/TFTP/NFS) + Windows clear-text credentials hardcoded in scripts, logs and configuration files 
➤ Upload of malicious SCF or URL files to anonymously writable Windows network shares + collect NTLMv2 password hashes + Offline password cracking (tools: John, hashcat)
➤ Enumerate PXE boot media potentially provided from an SCCM server and then try to retrieve Windows credentials via PXE boot media (tools: pxethiefy, PXEthief)
➤ Unpatched/obsolete systems prone to an unauthenticated Remote Code Execution (RCE) vulnerability with a public exploit available
   Examples:
   - Windows: WSUS RCE (CVE-2025-59287), MS17-010 (EternalBlue), CVE-2020-1472 (Zerologon, risky to run in a production environment), old MS08-067, ...
   - Web servers: WebLogic RCE (CVE-2023-21839, CVE-2022-21371, CVE-2020-14882, CVE-2019-2725), Apache Struts RCE (CVE-2017-9805), JBoss RCE (CVE-2017-12149), Java RMI RCE, ...
   - CMS: Telerik (CVE 2019-18935, CVE-2017-9248), Kentico (CVE-2019-10068), Drupal (DrupalGeddon2/CVE-2018-7600), DotNetNuke (CVE-2017-9822), ...
   - Citrix (ADC & Gateway): Citrix Bleed2 (CVE-2025-6543), Citrix Bleed (CVE-2023-4966), CVE-2023-3519, CVE-2020-8193, CVE-2019-19781
   - Atlassian software: Jira (CVE-2019-11581), Confluence (CVE-2022-26134)
   - Applications using the Java library Log4j: CVE-2021-44228 (Log4shell)
   - Outlook: ProxyLogon (CVE-2021-26855), ProxyNotShell (CVE-2022-41040, CVE-2022-41082)
   - React Server Component: React2Shell (CVE-2025-55182)
```
```
2. Grey-box penetration test (we start with 1 low-privileged Windows account)
-----------------------------------------------------------------------------
➤ All the attacks listed above in the 'black-box pentest' section
➤ Kerberoasting attack (request Kerberos TGS for services with an SPN and retrieve crackable hashes) + Offline password cracking (tools: John, hashcat)
➤ AS-REP Roasting attack (retrieve crackable hashes/encrypted TGT for users without kerberoast pre-authentication enabled) + Offline password cracking (tools: John, hashcat)
➤ Find clear-text passwords in files shared on Domain Shares, NAS, SharePoint sites, internal github accessible to all Domain users
➤ Find a Windows server that is insecurely sharing configuration files, cron job scripts and executable files with write permissions granted to all Domain users 
   + Privesc by adding a backdoor in a cron job script or modifying a configuration file, ...
➤ Upload of malicious SCF or URL files to Windows network shares (writable by any authenticated users) + collect NTLMv2 password hashes + Offline password cracking (tools: John, hashcat)
➤ Clear-text passwords stored in AD fields (e.g. account description, comments)
➤ Citrix servers accessible to all Domain users + Citrix jailbreak to get a Windows CMD or PowerShell console + Local privesc 
➤ WsuXploit attack – Compromising Windows machines via malicious Windows Update (i.e. tru to inject 'fake' updates into non-SSL WSUS traffic)
➤ Find and exploit ADCS misconfiguration (very often ADCS misconfiguration can lead to a Domain Admin account compromise)
➤ NLTM Relay techniques + ADCS attacks (i.e. ESC8 - NTLM Relay to AD CS HTTP Endpoints)
➤ Unpatched/obsolete systems prone to an authenticated Remote Code Execution vulnerability with a public exploit available 
   Examples:
   - Windows:
     - CVE-2025-33073 (NTLM reflection SMB flaw)
     - Certifried vulnerability (CVE-2022-26923)
     - noPAC / SamAccountName impersonation vulnerability (CVE-2021-42278/CVE-2021-42287)
     - PrintNightmare vulnerability (CVE-2021-1675 & CVE-2021-34527)
     - Drop-the-MIC vulnerabilities (CVE-2019-1040 & CVE-2019-1166)
     - KrbRelayUp local privesc technique
     - ...
   - Outlook: CVE-2020-0688
➤ ...
```

---------------
#### STEP 4. POST-EXPLOITATION and LOCAL PRIVILEGE ESCALATION 🛠
<i>The purpose of the post-exploitation phase is to determine the value of the systems compromised during the previous phase (e.g. sensitivity of the data stored on it, usefulness in further compromising the network) and to escalate privileges to obtain local administrator rights. This phase also involves harvesting credentials and potentially taking over any privileged accounts currently logged into the compromised systems. Additionally, compromised systems can be configured as pivot to reach machines that are located in other network segments.</i>

>Case 1 - You hacked a Windows server or laptop
```
1. Windows local privilege escalation techniques to become local administrator and/or "NT AUTHORITY\SYSTEM"
------------------------------------------------------------------------------------------------------------
➤ Exploiting OS security misconfiguration 
   Examples:
   - weak service permissions (file & binpath)
   - service unquoted path
   - autorun and weak file permissions
   - privileged scheduled tasks and weak file permissions
   - weak registry permissions
   - dll hijacking
   - weak passwords and password re-use
   - clear-text passwords stored in scripts, unattended install files, configuration files (e.g. Web.config), ...
   - AlwaysInstallElevated trick
   - bring your own vulnerable driver
  
➤ Exploiting an unpatched local Windows vulnerability 
  (e.g. KrbrelayUp, PrintNightmare, SeriousSam/HiveNightmare, Windows Installer LPE, Juicy/Rotten/Hot Potato exploits,...)

➤ Exploiting an unpatched vulnerability affecting a third party software running with high privileges
```
```
2. Dumping Windows credentials from memory and registry hives (requires local admin priv)
-----------------------------------------------------------------------------------------
➤ Dumping the registry hives (SAM, SYSTEM, SECURITY)
   Examples:
   - Reg save
   - Reg export / Registry Editor (GUI)
   - Esentutl
   - VSSadmin
   - Diskshadow + Robocopy
   - NetExec
   - SecretsDump (Impacket)
   - SharpSecDump
   - Mimikatz (lsadump::sam)
   - OLD/Legacy - pwdumpX
   
➤ Memory dumping of the LSASS process 
   Examples:
   - Mimikatz / invoke-mimikatz.ps1
   - NanoDump / invoke-nanodump.ps1
   - Lsassy
   - SafetyDump
   - PPLBlade
   - SharpKatz
   - ProcDump (Sysinternals tool)
   - Task manager + "Create dump file" of lsass.exe
   - Process Explorer (Sysinternals tool) + "Create dump" of lsass.exe
   - Process Hacker + "Create dump file" of lsass.exe
   - Dumping lsass with rundll32 and comsvcs.dll
   - Dumpert
   - SQLDumper (included with Microsoft SQL) 
   - ...
```
```
3. Gathering other credentials
-------------------------------
   - Look for clear-text passwords hardcoded in scripts, configuration files (e.g. Web.config, tomcat-users.xml), backup files, log files, ...
   - Dumping KeePass master password from memory using tools like 'Keethief', 'KeePassHax' or 'KeePwn'
   - Extracting clear-text passwords from 'mstsc.exe' using API Hooking (e.g. RdpThief, SharpRDPThief)
   - The LaZagne application can be used to retrieve passwords stored in browsers, DBA tools (e.g. dbvis, SQLdevelopper) and Sysadmin tools (e.g. WinSCP, PuttyCM, OpenSSH, VNC, OpenVPN)
   - The script SessionGopher.ps1 can be used to find and decrypt saved session information for remote access tools (PuTTY, WinSCP, FileZilla, SuperPuTTY, RDP)
```
```
4. Take over privileged accounts (requires local admin priv)
------------------------------------------------------------
➤ Use Windows Token impersonation technique to execute arbirary OS commands as another privileged account (victim) also logged on the same Windows server
➤ RDP session hijacking technique (e.g., using the native Windows command "c:\windows\system32\tscon.exe")
➤ Add a malicious script or a malware in the Windows start-up folder of a server to force any privileged users (victims) to run it when they logon
  (e.g., "\\REMOTE-COMPUTER-NAME\C$\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\malware.exe")
➤ Create a malicious scheduled task that is triggered at log on of any user and that executes a malicious script with the victim user's privileges
➤ Modify the registry RUN keys so every time a user logs on the Windows server a malware or a malicious script is run with its privileges
➤ ...
```
.
> Case 2 - You hacked a Web server
```
1 - Upload a webshell that allows you to execute OS commands and browse, upload, and download files on the underlying Windows server
2 - Abuse the SeImpersonatePrivilege (which is granted by default to Web server services on Windows) using a Potato‑family exploit
    to escalate privileges and gain local admin access on the underlying Windows server
3 - Apply the hacking techniques described in Case 1 to continue your assessment or expand your access
```
.
>Case 3 - You hacked a MSSQL/PostgreSQL/Oracle database
```
1 - Identify and exploit a database security misconfiguration to obtain DBA privileges
2 - Dump the local database password hashes, attempt to crack them using tools such as Hashcat, and reuse any recovered db credentials to compromise additional databases.
3 - Then leverage your DBA rights and built‑in database features (such as stored procedures) to execute OS commands on the underlying Windows server
4 - Abuse the SeImpersonatePrivilege (which is granted by default to database services on Windows) using a Potato‑family exploit
    to escalate privileges and gain local admin access on the underlying Windows server
5 - Apply the hacking techniques described in Case 1 to continue your assessment or expand your access
```

-----------------
#### STEP 5. NETWORK LATERAL MOVEMENT and PRIVILEGED ACCOUNTS HUNTING 🕸
<i>The purpose of the lateral movement phase is to identify Windows servers and laptops on which high privileged user and service accounts are logged (e.g. administrator of all servers and/or databases, administrator of all workstations/laptops, Domain Admin account). Then try to log into these Windows servers and laptops (for example by re-using the credentials harvested during the previous phase) and take over the high privileged accounts using various hacking techniques (e.g., dumping credentials from memory, token impersonation). </i>
```
1. Network lateral movement techniques 
--------------------------------------
➤ Use native Windows commands and protocols such as: RDP, PowerShell Remoting (WinRM), WMIC, PsExec, Windows built-in SSH client & server, etc.
➤ Use hacking tools such as: Evil-WinRM, NetExec, Impacket framework (e.g., WMIexec, SMBexec), etc.
➤ Use hacking techniques such as: Pass-The-Hash, Pass-The-Ticket, Over-Pass-The-Hash and Pass-The-Certificate 
```
```
2. Network pivoting techniques 
------------------------------
➤ Use a C2 post-exploitation agent (e.g. Meterpreter, Cobalt Strike, Sliver, Havoc) + SOCKS proxy + proxychains
➤ SSH tunnelling using Putty.exe or Plink.exe (e.g. local/remote port forwarding)
➤ Remote access tools (RAT) such as TeamViewer and AnyDesk portable software, Chrome Remote Desktop, VNC, ...
➤ Tunneling/pivoting tools such as Ligolo-ng, Rpivot, Socat, Chisel, ...
➤ Pivoting with TCP tunnelling over HTTP via Webshells (e.g. Neo-reGeorg, Pivotnacci, Tunna, Fulcrom webshells/clients)
```
```
3. Privileged accounts hunting
------------------------------
➤ Windows native commands (e.g. 'qwinsta /server:hostname' OR 'query user /server:hostname')
➤ PowerView and various PowerShell scripts (e.g. Invoke-UserHunter, Get-NetLoggedon, ADrecon)
➤ Windows Sysinternals command-line tool 'PsLoggedOn' (i.e. psloggedon.exe \\computername username)
➤ BloodHound
```
```
4. Take over privileged accounts (requires local admin priv)
------------------------------------------------------------
➤ Dump Windows credentials of privileged accounts from memory and registry hives + Pass-The-Hash technique
➤ Use Windows Token impersonation technique to execute arbirary OS commands as another privileged account (victim) also logged on the same Windows server
➤ RDP session hijacking technique (e.g., using the native Windows command "c:\windows\system32\tscon.exe")
➤ Add a malicious script or a malware in the Windows start-up folder of a server to force any privileged users (victims) to run it when they logon
  (e.g., "\\REMOTE-COMPUTER-NAME\C$\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\malware.exe")
➤ Create a malicious scheduled task that is triggered at log on of any user and that executes a malicious script with the victim user's privileges
➤ Modify the registry RUN keys so every time a user logs on the Windows server a malware or a malicious script is run with its privileges
➤ ...
```
-----------------
#### STEP 6. WINDOWS DOMAIN COMPROMISE (Privilege escalation to become "Domain Admin" + Persistence) 🔥 
<i>The purpose of this phase is to take full control over the target Windows domain.</i>

```
1. Privilege escalation to become "Domain Admin"
------------------------------------------------
➤ Exploiting AD / Windows domain security misconfigurations
   Examples:
   - Abusing poor AD tiering practices
     > Take over an account member of the group 'Domain Admins' (or any other Tier 0 account) running on a member Windows server or laptop (e.g. dumping creds from memory, token impersonation, RDP session hijacking)
   - Abusing weak ACL or GPO permissions
   - Abusing LAPS misconfiguration
   - Exploiting password robustness issues + poor AD tiering practices
     > Recover and crack the password of a Domain Admin (or any other Tier 0 account) using techniques such as Kerberoasting, LLMNR poisoning, or NBT‑NS poisoning.
   - Exploiting password reuse issues
     > The same password is used to protect multiple high privileged accounts and low-privileged accounts 
     > The same password is used to protect the default local administrator account of the Windows servers and the Domain Controllers (i.e. no hardening, no LAPS)
➤ Exploiting Active Directory Certificate Services (ADCS) misconfiguration
   Examples:
   - Abusing misconfigured Certificate Templates - ESC1 & ESC2
   - Abusing misconfigured Enrolment Agent Templates - ESC3
   - Abusing vulnerable Certificate Template Access Control - ESC4
   - Abusing vulnerable PKI Object Access Control - ESC5
   - Abusing "EDITF_ATTRIBUTESUBJECTALTNAME2" flag issue - ESC6
   - Abusing vulnerable Certificate Authority Access Control - ESC7
   - Abusing NTLM Relay to AD CS HTTP Endpoints – ESC8
   - Abusing "no Security Extension" issue - ESC9
   - Abusing weak Certificate Mappings - ESC10
   - Abusing NTLM relay to ICPR - ESC11
   - Abusing ADCS CA on YubiHSM - ESC12
   - Abusing Issuance Policy - ESC13
   - Abusing EKUwu Application Policies (CVE-2024-49019) - ESC15
➤ Take over a Windows server hosting Tier 0 services such as WSUS, SCCM, or ADCS and leverage it to gain control over the Domain Controllers.
➤ Compromise an account member of the default security group 'DNSAdmins' and take over the Windows domain by executing a DLL as 'NT AUTHORITY\SYSTEM' on the Domain Controller (known privesc)
➤ Compromise an account member of the default security groups 'Backup Operators' or 'Server Operators' and take over the Windows domain by backuping the NTDS.dit file and HKLM\SYSTEM and then extracting the password hash of 'Domain admins' accounts (known privesc)
➤ Compromise an account member of the default security group 'Account Operators' that can be used to privesc and take over the Windows domain (known privesc)
➤ Find a backup/snapshot of a Windows Domain Controller on a NAS/FTP/Share and extract the password hashes (NTDS.DIT + SYSTEM) of high privileged acccounts (e.g. Domain Admins, Enterprise Admins, krbtgt account)
➤ Abusing Microsoft Exchange for privilege escalation ('PrivExchange' vulnerability)
➤ Exploiting an unpatched vulnerability on a DC with a public exploit available (e.g. CVE-2020-1472  Zerologon, risky to run in a production environment)
➤ Hack the Hypervisor (e.g. vCenter) on which the Domain Controllers are running, then perform a snapshot of the DCs, copy/download their memory dump files (.vmsn & .vmem) and finally extract the password hashes of high privileged acccounts (e.g. Domain Admins, Administrators of DC, krbtgt account)
➤ Kerberos Unconstrained Delegation attack (+ Printer Bug or PetitPotam)
➤ Kerberos Constrained Delegation attack
➤ Kerberos Resource-based Constrained Delegation attack
➤ ...
```
```
2. AD password dumping & cracking (NTDS) 
----------------------------------------
➤ Dump and extract the password hashes of all the Windows domain accounts (file 'NTDS.DIT' + SYSTEM registry hive)
   Examples:
   - Ntdsutil + Secretsdump
   - Wbadmin + Secretsdump
   - Diskshadow + Secretsdump
   - VSSadmin + Secretsdump
   - Secretsdump
   - NetExec
   - CrackMapExec (legacy)
   - Mimikatz (dcsync technique)
   - ...
➤ Crack (with John or Hashcat) the password hashes of all the Windows domain accounts
```
```
3. Creating persistence (examples)
----------------------------------
➤ Use the KRBTGT account’s password hash to forge of a Kerberos Golden ticket with Domain Administrator privileges
➤ Keep temporarily the password hash of a highly-privileged service account (e.g. Domain Admin) with a password set to never expire
➤ Modify temporarily the ACLs to allow an account that you control to perform DCsync attack
➤ Request a certificate (ADCS) for a highly-privileged account (e.g. Domain Admin) 
➤ Add temporarily an account in a default AD security group such as 'Domain Admins', 'BUILTIN\Administrators' or 'Account Operators' 
➤ ...
```
-----------------
#### STEP 7. FOREST ROOT DOMAIN COMPROMISE (Privilege escalation to become "Enterprise Admin") 🔥🔥 
<i>The purpose of this phase is to take full control over the Forest root domain and all the other domains in the target network.</i>
```
➤ Forge a Kerberos Golden Ticket (TGT) with a 'SID History' for the Forest 'Enterprise Admins' group
➤ Forge an inter-realm trust ticket (cross-domain trust kerberos ticket) and then create TGS for the services LDAP/CIFS/HOST/... in the parent domain 
➤ Take over other Windows domains due to password re-use across domains for high privileged accounts
➤ Take over other Windows domains thanks to AD Forest Trusts and/or misconfiguration (e.g. the group 'Domain Admins' of the domain A is member of the group 'Domain Admins' of the domain B) 
➤ ...
```
-----------------
#### DEFENSE EVASION TECHNIQUES - BYPASSING ANTIVIRUS, EDR and SIEM SOLUTIONS
> During penetration tests, it is important to know how to bypass at least antivirus solutions to be able to identify and exploit vulnerabilities without being blocked.
> 
> In general, during Red Team exercises, in addition to assessing the security posture of a company by trying to achieve specific goals (e.g., becoming 'Domain Admin' of the Windows prod environment(s), getting unauthorized access to critical applications, "crown-jewel" data and email boxes of VIP/C-level employees, etc.), we also want to evaluate the effectiveness of the Security Operation Center (SOC) and its detection capabilities. Thus, it is important for red teamers to know how to be stealthy and bypass security detection solutions such as AV, EDR, SIEM, IDS/IPS, etc. 
For instance, in Red teaming, avoid at all costs using "noisy & easy to detect" hacking tools (e.g. Mimikatz, Metasploit C2) and techniques (e.g. aggressive and wide network port and vulnerability scans).
```
1. Common antivirus bypass techniques - With a low privilege account
--------------------------------------------------------------------
➤ Use living-off-the-land and fileless techniques
  - Download & execute malicious PowerShell scripts (with AMSI bypass), PE files and shellcodes directly into memory such as encrypted/obfuscated C2 agents (e.g. Cobalt Strike, Sliver, Metasploit, Havoc)
  - Use 'Living Off The Land' binaries, scripts and libraries (https://lolbas-project.github.io) to perform arbitrary code execution, file operations, UAC bypass, persistence, ...
➤ Regularly obfuscate and recompile your favorite (open source) hacking tools and scripts
➤ Write your own hacking tools and scripts
➤ Use PE/Dll packers and shellcode loaders that implement defense evasion techniques such as:
  - Code obfuscation & payload encryption
  - AMSI & ETW bypass
  - Anti-Debugging techniques
  - Sandbox evasion techniques
➤ Abuse potential AV exclusions set for files, folders, processes, and process-opened files
➤ Use portable legitimate SysAdmin tools and native OS commands/binaries which are less likely to be blocked by AV solutions than hacking tools
  For examples:
  - Portable SysAdmin tools: putty & plink, sysinternals tools, teamviewer, anydesk, mobaxterm, dbvisualizer, ...
  - Native OS commands/binaries: REG SAVE to extract the registry keys, WinRM for lateral movement, TSCON for RDP session hijacking, ...
➤ If you can read the Bitlocker recovery key of your Windows laptop in Microsoft Intune (or in the AD) then you can use it to decrypt your laptop's hard drive and delete the AV files
➤ ...
```
```
2. Common antivirus bypass techniques - With local admin privileges
-------------------------------------------------------------------
➤ All the AV bypass techniques listed in the previous section
➤ Kill the anti-malware (AV) protected processes using "Bring Your Own Vulnerable Driver" (BYOVD) techniques
➤ Install VirtualBox or VMware Workstation on a compromised Windows laptop/workstation and run hacking tools and scripts inside a VM to avoid detection
➤ If the AV configuration panel is not password protected on a Windows computer, very often you can use local admin rights to:
  - Disable or downgrade the AV protection
  - Set new AV exclusions for your hacking tools, etc.
➤ If the AV anti-tampering protections are disabled on a Windows computer, very often you can use local admin rights to:
  - Modify the registry keys or rename the AV executable files and then restart it to disable the AV software
  - Suspend the AV processes with PsSuspend (sysinternals)
  - Uninstall the AV software
➤ ...
```
```
3. Common Endpoint Detection & Response (EDR) bypass techniques - With a low privilege account
----------------------------------------------------------------------------------------------
➤ Use as much as possible the Sysadmin tools already installed on the compromised systems to "blend in" among the legitimate system administrators
➤ Abuse potential EDR exclusions (whitelist) set for files, folders, processes, and process-opened files
➤ Find server(s) in the network that have not been yet onboarded in the EDR solution & use them as a pivot (e.g. obfuscated/encrypted C2 implant + socks proxy)
➤ Write your own hacking tools/exploits when possible or carefully modify, obfuscate and test open-source ones before using them
➤ Use living-off-the-land and fileless techniques
➤ Use PE/Dll packers and shellcode loaders that implement defense evasion techniques such as:
  - Code obfuscation & payload encryption
  - AMSI & ETW bypass
  - Anti-Debugging techniques
  - Sandbox evasion techniques
  - Import Address Table (IAT) obfuscation
  - NTDLL unhooking techniques
  - use of direct syscalls
  - use of indirect syscalls
  - module stomping technique
  - suspended process method
  - ...
➤ If you can read the Bitlocker recovery key of your Windows laptop in Microsoft Intune (or in the AD) then you can use it to decrypt your laptop's hard drive and delete the EDR files
➤ ...
```
```
4. Common Endpoint Detection & Response (EDR) bypass techniques - With local admin privileges
---------------------------------------------------------------------------------------------
➤ All the EDR bypass techniques listed in the previous section
➤ Kill the anti-malware (EDR) protected processes using "Bring Your Own Vulnerable Driver" (BYOVD) techniques
➤ Disable or uninstall the EDR agent if it is not protected by a password
➤ Add a rule in the local Windows firewall that will prevent the EDR agent to send alerts to the EDR appliance/server
➤ Add a wrong IP address for the EDR appliance/server in the '/etc/hosts' file to prevent the EDR agent to send alerts to the EDR appliance/server
➤ Install VirtualBox or VMware Workstation on a compromised Windows laptop/workstation and run hacking tools and scripts inside a VM to avoid detection
➤ Modify the registry keys or rename the EDR executable files on a compromised Windows machine and then restart it to disable the EDR software
➤ ...
```
```
5. Common techniques to bypass SIEM detection use cases / rules (e.g., YARA/SIGMA rules, audit trail based detections)
---------------------------------------------------------------------------------------------------------------------
➤ Use Windows/Linux OS command-line obfuscation techniques
➤ Use in priority less-known tools and command aliases
➤ Avoid using "one-liner" commands that are easier to catch in event log files
➤ Copy and rename Windows/Linux native binaries before using them is sometimes sufficient to bypass basic detection
➤ Modify the scritps/binaries/Dlls that are used by existing scheduled task(s) or service(s) instead of creating a new scheduled task or install a new service
➤ Modify directly configuration files and/or registry keys instead of running well-known and 'flagged' OS native binaries and commands
➤ Detecting activities done with a legitmate Windows IT admin GUI tool is sometimes more complex for SOC analysts than detecting activities done with a command line tool
➤ ...
```
-----------------
#### LIST OF USEFUL TOOLS & SCRIPTS

| TOPIC | TOOL | URL | DESCRIPTION | 
| :-----: | :-----: | :-----: | :------: |
| Recon, Audit, Post-Exploitation | Windows Sysinternals | </br>https://docs.microsoft.com/en-us/sysinternals/ | Adexplorer, procdump, procmon, autorun, ...  |
| Recon, Audit, Post-Exploitation | Windows native commands | - | Windows native DOS commands (e.g. net commands, nltest) and PowerShell commands (including AD module) |
| Recon, Audit | ADRecon | </br> https://github.com/adrecon/ADRecon | Active Directory gathering information tool |
| Recon, Audit | ADCollector | </br> https://github.com/dev-2null/ADCollector |  Tool to quickly extract valuable information from the AD environment for both attacking and defending | 
| Recon, Audit | NMAP | </br> https://nmap.org | Network port scanner and (NSE) scripts | 
| Recon, Audit | PingCastle | </br> https://www.pingcastle.com | Active Directory security audit tool  |  
| Recon, Audit | BloodHound | </br> https://github.com/BloodHoundAD/BloodHound | Tool to easily identify complex Windows domain attack paths |
| Recon, Audit | ACLight | </br> https://github.com/cyberark/ACLight | A tool for advanced discovery of privileged accounts including Shadow Admins|
| Recon, Audit | ADACLScanner | </br> https://github.com/canix1/ADACLScanner |A tool with GUI used to create reports of access control lists (DACLs) and system access control lists (SACLs) in Active Directory|
| Recon, Audit | Liza | </br> http://www.ldapexplorer.com/en/liza.htm | Active Directory Security, Permission and ACL Analysis |
| Recon, Audit | LAPSToolkit | </br> https://github.com/leoloobeek/LAPSToolkit | LAPS auditing for pentesters |
| Gaining Access | Rubeus | </br> https://github.com/GhostPack/Rubeus | Toolset for raw Kerberos interaction and abuses |
| Audit, Privesc | Certify | </br> https://github.com/GhostPack/Certify | C# tool to enumerate and abuse misconfigurations in Active Directory Certificate Services (AD CS) |
| Audit, Privesc | Certipy | </br> https://github.com/ly4k/Certipy | Python tool to enumerate and abuse misconfigurations in Active Directory Certificate Services (AD CS) |
| Audit, Privesc | PassTheCert | </br> https://github.com/AlmondOffSec/PassTheCert | Proof-of-Concept tool to authenticate to an LDAP/S server with a certificate through Schannel |
| Gaining Access, MITM | Responder | </br> https://github.com/lgandx/Responder | LLMNR/NBTNS/mDNS poisoner and NTLMv1/2 relay |
| Gaining Access, MITM | Inveigh | </br> https://github.com/Kevin-Robertson/Inveigh | .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers |
| Gaining Access, MITM | Smbrelayx & Ntlmrelayx |  </br> https://github.com/fortra/impacket/tree/master/examples | SMB and NTLM relay tools which are part of the Python offensive security framework 'Impackets' |
| Recon, Gaining Access | Vulnerability scanners |  </br> (https://github.com/greenbone/openvas-scanner/releases) (https://www.tenable.com/) (https://www.qualys.com/) (https://www.rapid7.com/products/nexpose/) | e.g. OpenVAS, Nessus, Qualys, Nexpose, ... | 
| Recon, Gaining Access | SMBmap | </br> https://github.com/ShawnDEvans/smbmap | SMB enumeration tool | 
| Recon, Gaining Access | SauronEye | </br> https://github.com/vivami/SauronEye | Search tool to find files containing passwords in network shares | 
| Gaining Access | SharpSpray | </br> https://github.com/iomoath/SharpSpray | Active Directory password spraying tool. Auto fetches user list and avoids potential lockouts | 
| Gaining Access | Hydra | </br> https://github.com/vanhauser-thc/thc-hydra | Online password bruteforce tool | 
| Post-Exploitation, Privesc | Mimikatz | </br> https://github.com/gentilkiwi/mimikatz | Extract plaintexts passwords, hash, PIN code and kerberos tickets from memory|
| Post-Exploitation, Creds dumping | SharpKatz | </br> https://github.com/b4rtik/SharpKatz | Porting in C# of mimikatz sekurlsa::logonpasswords, sekurlsa::ekeys and lsadump::dcsync commands |
| Post-Exploitation, Creds dumping | Nanodump | </br> https://github.com/helpsystems/nanodump | The swiss army knife of LSASS dumping |
| Password cracking | Hashcat | </br> https://github.com/hashcat/hashcat/ | World's fastest and most advanced password recovery utility |
| Password cracking | John the Ripper | </br> https://www.openwall.com/john/ | Offline password cracker |
| Post-Exploitation, Privesc | PowerSploit (incl. PowerView & PowerUp) | </br> https://github.com/PowerShellMafia/PowerSploit | PowerShell offensive security framework |
| Recon, Audit, Post-Exploitation, Privesc | PowerSharpPack | </br> https://github.com/S3cur3Th1sSh1t/PowerSharpPack/ | Many usefull offensive CSharp Projects wraped into Powershell for easy usage |
| Post-Exploitation, Privesc | PrivescCheck  | </br> https://github.com/itm4n/PrivescCheck | This script aims to enumerate common Windows configuration issues that can be leveraged for local privilege escalation |
| Post-Exploitation, Privesc  | Seatbelt | </br> https://github.com/GhostPack/Seatbelt | C# project that performs a number of security oriented host-survey "safety checks" relevant from both offensive & defensive security perspectives |
| Post-Exploitation, Privesc | KrbRelayUp  | </br> https://github.com/Dec0ne/KrbRelayUp | KrbRelayUp - a universal no-fix local privilege escalation in windows domain environments where LDAP signing is not enforced (the default settings) |
| Privesc | Juicy-potato exploit | </br> https://github.com/ohpe/juicy-potato | Local privesc tool |
| Privesc | Rotten-potato exploit | </br> https://github.com/breenmachine/RottenPotatoNG | Local privesc tool |
| Privesc | God-potato exploit | </br> https://github.com/BeichenDream/GodPotato | Local privesc tool |
| Privesc | Efs-Potato exploit | </br> https://github.com/zcgonvh/EfsPotato | Local privesc tool |
| Post-Exploitation, Privesc | Nightly builds of common C# offensive tools | </br> https://github.com/Flangvik/SharpCollection | Nightly builds of common C# offensive tools, fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines |
| Post-Exploitation, Privesc | SharpImpersonation | </br> https://github.com/S3cur3Th1sSh1t/SharpImpersonation | A user impersonation tool via Token or Shellcode injection |
| Post-Exploitation, Privesc | Tokenvator | </br> https://github.com/0xbadjuju/Tokenvator | Windows Tokens impersonation tool|
| AD Privesc | BloodyAD | </br> https://github.com/CravateRouge/bloodyAD |BloodyAD is an Active Directory Privilege Escalation Framework |
| Post-Exploitation, Defense evasion | AMSI.fail | <br> https://amsi.fail | It generates obfuscated PowerShell snippets that break or disable AMSI for the current process  |
| Post-Exploitation, Defense evasion | Nuke-AMSI | <br> https://github.com/anonymous300502/Nuke-AMSI | AMSI bypass tool |
| Post-Exploitation, Defense evasion | SharpKiller | </br> https://github.com/S1lkys/SharpKiller | AMSI bypass tool |
| Post-Exploitation, Defense evasion | ProtectMyTooling | </br> https://github.com/mgeeky/ProtectMyTooling | Multi-Packer wrapper letting us daisy-chain various packers, obfuscators and other Red Team oriented weaponry.|
| Post-Exploitation, Defense evasion | IronSharpPack | </br> https://github.com/BC-SECURITY/IronSharpPack | Repository of popular C# offensive security projects (e.g., Rubeus, Certify) embedded into IronPython scripts that execute an AMSI bypass and then reflective load the C# projects |
| Post-Exploitation, Defense evasion | Pyramid | </br> https://github.com/naksyn/Pyramid | Perform post-exploitation task in an evasive manner, executing offensive tooling from a signed binary (e.g. python.exe) by importing their dependencies in memory |
| Post-Exploitation, Defense evasion | FilelessPELoader | </br> https://github.com/SaadAhla/FilelessPELoader | Load, decrypt and execute in-memory remote AES encrypted PE |
| Post-Exploitation, Defense evasion | EAPrimer | </br> https://github.com/m8sec/EAPrimer | Load and execute in-memory remote .Net assemblies (C# projects) after bypassing AMSI |
| Post-Exploitation, Defense evasion | BetterNetLoader | </br> https://github.com/racoten/BetterNetLoader | Load and execute in-memory remote .Net assemblies (C# projects) with AMSI and ETW bypass |
| Post-Exploitation, Defense evasion | Invoke-Obfuscation | </br> https://github.com/danielbohannon/Invoke-Obfuscation | PowerShell scripts obfuscator|
| Post-Exploitation, Defense evasion | Chameleon | </br> https://github.com/klezVirus/chameleon | PowerShell scripts obfuscator|
| Post-Exploitation C2, Network Lateral Movement, Pivoting | Cobalt Strike | </br> https://www.cobaltstrike.com | Cobalt Strike gives you a post-exploitation agent and covert channels to emulate a quiet long-term embedded actor in your customer's network |
| Post-Exploitation C2, Network Lateral Movement, Pivoting | Metasploit | </br> https://www.metasploit.com | Penetration testing framework and post-exploitation C2 | 
| Post-Exploitation C2, Network Lateral Movement, Pivoting | Sliver | </br> https://github.com/BishopFox/sliver| Open source cross-platform adversary emulation/red team framework |
| Post-Exploitation C2, Network Lateral Movement, Pivoting | Havoc | </br> https://github.com/HavocFramework/Havoc| Havoc is a modern and malleable post-exploitation command and control framework|
| Post-Exploitation C2, Network Lateral Movement, Pivoting | Covenant | </br> https://github.com/cobbr/Covenant| Covenant is a collaborative .NET C2 framework for red teamers|
| Recon, Gaining Access, Network Lateral Movement, Pivoting | Impacket Framework | </br> https://github.com/SecureAuthCorp/impacket | Python offensive security framework (e.g. WMIexec.py, SMBexec.py, Secretsdump.py) |
| Recon, Gaining Access, Network Lateral Movement, Pivoting | NetExec | </br> https://github.com/Pennyw0rth/NetExec | Swiss army knife for pentesting Windows networks|
| Recon, Gaining Access, Network Lateral Movement, Pivoting | CrackMapExec (legacy)| </br> https://github.com/byt3bl33d3r/CrackMapExec | Swiss army knife for pentesting Windows networks|
| Recon, Gaining Access, Network Lateral Movement, Pivoting | SharpMapExec | </br> https://github.com/cube0x0/SharpMapExec | Swiss army knife for pentesting Windows networks |
| Network Lateral Movement, Pivoting | Powercat | </br> https://github.com/besimorhino/powercat | PowerShell TCP/IP swiss army knife like netcat | 
| Network Lateral Movement, Pivoting | Invoke-TheHash  | </br> https://github.com/Kevin-Robertson/Invoke-TheHash | It contains PowerShell functions for performing pass-the-hash WMI and SMB tasks |
| Network Lateral Movement, Pivoting | Chisel  | </br> https://github.com/jpillora/chisel https://github.com/shantanu561993/SharpChisel | Chisel is a fast TCP/UDP tunnel, transported over HTTP, secured via SSH |
| Network Lateral Movement, Pivoting | Rpivot  | </br> https://github.com/klsecservices/rpivot | Socks4 reverse proxy for penetration testing |
| Network Lateral Movement, Pivoting | Ligolo  | </br> https://github.com/sysdream/ligolo | Reverse Tunneling made easy for pentesters, by pentesters |
| Network Lateral Movement, Pivoting | Ligolo-ng  | </br> https://github.com/nicocha30/ligolo-ng | A simple, lightweight and fast tool that allows to establish tunnels from a reverse TCP/TLS connection using a tun interface |
| NAC bypass | Fenrir  | </br> https://github.com/Orange-Cyberdefense/fenrir-ocd | Tool/script designed to bypass wired network 802.1x protection (NAC) |

----------------
#### USEFUL RESOURCES
```
Miscellaneous - Windows Penetration Testing & Red Teaming
---------------------------------------------------------
➤ Active Directory and Internal Pentest Cheatsheets
  + https://swisskyrepo.github.io/InternalAllTheThings/
  + https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md

➤ Active Directory Kill Chain Attack & Defense
  + https://github.com/infosecn1nja/AD-Attack-Defense

➤ Red Teaming Tactics and Techniques
  + https://www.ired.team
  + https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse
  + https://github.com/mantvydasb/RedTeaming-Tactics-and-Techniques

➤ MITRE ATT&CK® - A globally-accessible knowledge base of adversary tactics and techniques based on real-world observations
  + https://attack.mitre.org/tactics/enterprise/;
  + https://attack.mitre.org/mitigations/M1015/ (Active Directory Configuration)

➤ Evaluation matrix of Command and Control (C2) frameworks
  + https://www.thec2matrix.com/matrix
```
```
Microsoft Security Guidelines
-----------------------------
➤ Best Practices for Securing Active Directory - https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory)
➤ Reducing the Active Directory Attack Surface - https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/reducing-the-active-directory-attack-surface
➤ Securing Domain Controllers Against Attack - https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/securing-domain-controllers-against-attack
➤ Implementing Least-Privilege Administrative Models - https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models
➤ Planning a bastion environment - https://learn.microsoft.com/en-us/microsoft-identity-manager/pam/planning-bastion-environment
➤ Monitoring Active Directory for Signs of Compromise - https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/monitoring-active-directory-for-signs-of-compromise
➤ Attractive Accounts for Credential Theft - https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/attractive-accounts-for-credential-theft
➤ Evolution from the legacy AD tier model / Enterprise access model - https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-access-model
➤ Tier model for partitioning administrative privileges - https://learn.microsoft.com/en-us/microsoft-identity-manager/pam/tier-model-for-partitioning-administrative-privileges
  + Tier 0: Domain Controllers, PKI servers (ADCS), SCCM servers, Hypervisors (e.g., vCenter/ESXi), ...
  + Tier 1: Windows Servers
  + Tier 2: Laptops and Workstations
➤ ACSC Essential Eight - https://learn.microsoft.com/en-us/compliance/essential-eight/e8-overview#what-are-the-essential-eight-pillars
  + Application Control
  + Patch Applications
  + Configure Microsoft Office Macro Settings
  + User Application Hardening
  + Restrict Administrative Privileges
  + Patch Operating Systems
  + Multifactor authentication
  + Regular Backups
➤ ...
```
```
CIS benchmarks - Windows Secure Configuration Guidelines
--------------------------------------------------------
➤ Windows servers - https://www.cisecurity.org/benchmark/microsoft_windows_server/
➤ Windows laptops/workstations - https://www.cisecurity.org/benchmark/microsoft_windows_desktop
➤ Windows SQL database servers - https://www.cisecurity.org/benchmark/microsoft_sql_server
```
