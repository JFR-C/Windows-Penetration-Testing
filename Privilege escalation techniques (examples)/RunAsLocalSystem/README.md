### RunAsLocalSystem
---------------------------------------
This C program enables a user with local administrator rights on a Windows machine to launch a CMD as Local System using the privilege 'SeDebugPrivilege'.


#### USAGE

- STEP 1 - Compile the source code.  
  <i/> OPSEC advice: remove all existing comments and most 'printf' statements from the source code before compiling.</i>
```
Example with Visual Studio 2022 Developer Command Prompt v17.14.14:
-------------------------------------------------------------------
Basic:
+ C:\path-to-project\RunAsLocalSystem> cl RunAsLocalSystem.c /link advapi32.lib
```

- STEP 2 - Run the tool as local administrator to launch a CMD as Local System.
```
C:\temp> RunAsLocalSystem.exe
[+] SeDebugPrivilege enabled.
[+] SYSTEM cmd.exe launched!

    Microsoft Windows [version 10.0.19045.6456]
    (c) Microsoft Corporation. Tous droits réservés.
    
    C:\Windows\system32> whoami
    nt authority\system
```

#### LICENSE
GNU General Public License v3.0
