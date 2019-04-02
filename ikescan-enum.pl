#!/usr/bin/perl -w
# A perl script that I've completely rewritten.  Benedict Lam-Hang
# A script that runs through a set of transforms (common/priority and full)
# against given hosts and finds what transforms are supported for a host.
#
# Reference: http://www.ietf.org/rfc/rfc2409.txt
# Reference: http://www.nta-monitor.com/wiki/index.php/Ike-scan_User_Guide
# Reference: http://permalink.gmane.org/gmane.comp.security.scapy.general/272
#
use strict;
use Switch;
use Getopt::Long;

# Default settings
my($aggressive) = 0;
my($full) = 0;
my($help);
my($input);
my($id) = "Ben10";
my($sleep) = 1;
my($transextra);
my($debug) = 0;
my($output) = 0;
my($raw) = 0;

my(%enc_priority) = (1=>"DES", 5=>"3DES", 7=>"AES");
my(@keysize) = (128, 192, 256);
my(%hash_priority) = (1=>"MD5", 2=>"SHA1");
my(%auth_priority) = (1=>"Preshared Key", 3=>"RSA Signature", 64221=>"Hybrid Mode InitRSA (Checkpoint)", 65001=>"XAUTH InitPreShared (Cisco)", 65005=>"XAUTH InitRSA", 65008=> "XAUTH RespRSAEncryption");
my(%dh_priority) = (1=>"DH Group 1", 2=>"DH Group 2", 5=>"DH Group 5");
my(%enc,%hash,%auth,%dh);
my(@transforms) = ();
my(@transforms_valid) = ();
my(@ips) = ();

# GetOptions
Getopt::Long::Configure("bundling");
GetOptions(
	"a|aggressive"	=> \$aggressive,
	"f|full"	=> \$full,
	"h|help"	=> \$help,
	"i|input=s"	=> \$input,
	"n|id=s"	=> \$id,
	"s|sleep=f"	=> \$sleep,
	"t|trans=s"	=> \$transextra,
	"d|debug"	=> \$debug,
	"o|output=i"	=> \$output,
	"r|raw"		=> \$raw
) || exit(1);

# Print usage and exit
Usage() if $help;

# Reads from file if -i, --input is supplied
@ips=readFile($input) if $input;

# If no arguments and -i is NOT supplied take standard input.
# Else use arguments (Note: arguments and -i work in conjunction.
if ($#ARGV<0 && !$input) {
   enterStdin();
} else {
   while (@ARGV) {
   push @ips, shift(@ARGV);
   }
}

foreach (@ips) {
   Enumeration($_);
}

### Subroutines ###############################################################

# Usage()
# - Prints out the options for the program. Exit the program.
sub Usage {
my $usage = qq/Usage:
$0 [options]

Options:
   -h, --help		Display this usage message!
   -a, --aggressive	Sets enumeration to aggressive mode (default main mode)
   -f, --full		Performs enumeration on wider selection of transforms
   -i, --input		Reads addresses from specific file
   -n, --id		Sets id for aggressive mode (not used in main mode)
   -s, --sleep		Sets wait time between each ike-scan request (def=1s)
   -t, --trans		Adds another parameter within the transform
   -v, --vuln		Prints out associated vulnerabilities. (e.g DES, MD5)
   -d, --debug		Dumps out verbose response back through ike-scan
   -o, --output		Output format:  1. Normal  2. Descriptive
/;
print $usage;
exit(0);
}#endsub


# INT_handler: Clean-up in case CTRL-C
sub INT_handler{
   #Check $output parameter, if flagged up
   switch ($output) {
      case 1 {outputTransformsText();}
      case 2 {outputTransformsVuln();}
      else {outputTransforms();}
   }#endswitch
   exit(0);
}


# enterStdin()
# - Takes multi-line input from STDIN, if no parameters given...
sub enterStdin {
   print "Enter IP addresses (CTRL-D to finish on empty line to finish)\n";
   @ips = <STDIN>;
}#endsub


# ReadFile(file)
# - Reads a file with a list of IP addresses.
sub readFile {
   my($filename)=@_;
   my(@lines);

   open(INFILE, "<$filename") || return "Unable to open $filename: $!\n";
   @lines=<INFILE>;
   close(INFILE);
   return @lines;
}#endsub


# checkIP(ip)
# - Checks to see if parameter is a valid IP address.
sub checkIP {
   my($ip)=@_;
   if ($ip=~/\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/) {return 1;}
   else {return 0;}
}#endsub


# Enumeration()
# - Perform initial check of IP address.
# - Runs ike-scan against collected transforms.
# - Output results.
sub Enumeration {
   my($ip) = @_;
   my($e,$b,$h,$a,$d);
   my($am)=($aggressive) ? " -A --id=$id": "";
   chomp($ip);
   my($cmd,$tr,$line,$valid);

   if (!checkIP($ip)) {
      print "[D] Skipping invalid IP address: $ip\n" if $debug;
      return;
   }
   if ($full) {setFullTransforms();} else {setLightTransforms();}
   collectTransforms();
   foreach (@transforms) {
      $tr=$_; $valid=0;
      print "[D] sleep $sleep\n" if $debug;
      sleep $sleep;
      print "\n" if $debug;

      #$cmd="echo ike-scan --trans=\"($tr)\"$am $ip";
      $cmd="ike-scan --trans=\"($tr)\"$am $ip";
      print "[D] Running: $cmd\n" if $debug;

      $SIG{'INT'} = 'INT_handler';
      open(CMD,"$cmd |") || die "Failed: $!\n";
      while ( <CMD> ) {
         $line=$_; chomp $line;
         print "[D] $line\n" if $debug;
         if ($line=~/Handshake returned/) {$valid=1;}
      }#endofwhile
      push @transforms_valid, $tr if $valid;
   }#endforeach @transforms
   print "[D] Number of transforms to be tested: " . ($#transforms+1) . "\n" if $debug;
   print "Tested IP Address: $ip\n";

   #Check $output parameter, if flagged up
   switch ($output) {
      case 1 {outputTransformsText();}
      case 2 {outputTransformsVuln();}
      else {outputTransforms();}
   }#endswitch
   @transforms=(); @transforms_valid=();
}#endsub


# collectTransforms()
# - builds an array of transforms to test...
# - For full set of transforms, transforms are prioritised based on common attributes.
sub collectTransforms {
   my($e,$b,$h,$a,$d);
   my($tr);
   my($xa)=($transextra) ? ",$transextra": "";

   foreach (sort keys %enc) {
      $e=$_;
      foreach (sort keys %hash) {
         $h=$_;
         foreach (sort keys %auth) {
            $a=$_;
            foreach (sort keys %dh) {
               $d=$_;
               if ($e==7) {
                  foreach (@keysize) {
                     $tr="1=$e,14=$_,2=$h,3=$a,4=$d$xa";
                     if (exists $enc_priority{$e} && exists $hash_priority{$h} && exists $auth_priority{$a} && exists $dh_priority{$d} && $full) {
                        unshift @transforms, $tr;
                     } else {
                        push @transforms, $tr;
                     }#endif existspriority
                  }#endforeach @keysize
               } else {
                  $tr="1=$e,2=$h,3=$a,4=$d$xa";
                  if (exists $enc_priority{$e} && exists $hash_priority{$h} && exists $auth_priority{$a} && exists $dh_priority{$d} && $full) {
                     unshift @transforms, $tr;
                  } else {
                     push @transforms, $tr;
                  }#endif existspriority
               }#endif e==7
            }#endforeach%dh
         }#endforeach%auth
      }#endforeach%hash
   }#endforeach%enc
}#endsub


# outputTransforms()
# - Just prints out the transform string that was accepted by the server
sub outputTransforms {
   my($out)="";

   foreach (sort @transforms_valid) {
      $out.=$_."\n";
   }#endforeach @transforms_valid
   print "Number of valid transforms: " . ($#transforms_valid+1) . "\n";
   print $out;
}#endsub


# outputTransformsText()
# - Reuses the transforms from (%enc,%hash,%auth,%dh) to print out actual names
sub outputTransformsText {
   my(@tr_array)=();
   my(@tr_element)=();
   my(%tr_hash)=();
   my(%enc_supp,%hash_supp,%auth_supp,%dh_supp);
   my($tr)="";
   my($out)="";

   foreach (sort @transforms_valid) {
      $tr=$_;
      @tr_array=split(/,/, $tr);
      foreach(@tr_array){
         @tr_element=split(/=/,$_);
         $tr_hash{$tr_element[0]}=$tr_element[1];
      }#endforeach @tr_array

      # Flag up 'vulnerable' types... enc=DES, hash=MD5 being important 
      if ($tr_hash{'1'} eq 1 || $tr_hash{'2'} eq 1) {$out.="*";}
      # Flag up 'vulnerable' types... auth=preshared, dh=1 being moderate
      if ($tr_hash{'3'} eq 1 || $tr_hash{'4'} eq 1) {$out.="+";}

      #Generate a text list of authenticated
      $enc_supp{$enc{$tr_hash{'1'}}}=1;
      $hash_supp{$hash{$tr_hash{'2'}}}=1;
      $auth_supp{$auth{$tr_hash{'3'}}}=1;
      $dh_supp{$dh{$tr_hash{'4'}}}=1;

      # Check for AES and include keysize where necessary
      if ($tr_hash{'14'}) {
         $out.= $enc{$tr_hash{'1'}}."-". $tr_hash{'14'} .",". $hash{$tr_hash{'2'}} .",". $auth{$tr_hash{'3'}} .",". $dh{$tr_hash{'4'}} ."\n";
      } else {
         $out.=$enc{$tr_hash{'1'}} .",". $hash{$tr_hash{'2'}} .",". $auth{$tr_hash{'3'}} .",". $dh{$tr_hash{'4'}} ."\n";
      }#endtr_hash
   }#endforeach @transforms_valid
   print "Number of valid transforms: " . ($#transforms_valid+1) . "\n";
   print $out . "\n";
   print "Summary of accept algorithms:\n";
   print "Encryption: ".join(", ",sort keys %enc_supp)."\n";
   print "Hash: ".join(", ",sort keys %hash_supp)."\n";
   print "Authentication: ".join(", ",sort keys %auth_supp)."\n";
   print "DH Group: ".join(", ",sort keys %dh_supp)."\n";
}#endsub


# outputTransformsVuln()
# - Reuses the transforms from (%enc,%hash,%auth,%dh) to print out actual names
sub outputTransformsVuln {
   my(@tr_array)=();
   my(@tr_element)=();
   my(%tr_hash)=();
   my($des_supp,$md5_supp,$psk_supp,$dh1_supp);
   my($tr)="";
   my($trans_vulns)=0;
   my($out)="";

   foreach (sort @transforms_valid) {
      $tr=$_;
      @tr_array=split(/,/, $tr);
      foreach(@tr_array){
         @tr_element=split(/=/,$_);
         $tr_hash{$tr_element[0]}=$tr_element[1];
      }#endforeach @tr_array

      # Flag up 'vulnerable' types... enc=DES, hash=MD5 being important 
      # Flag up 'vulnerable' types... auth=preshared, dh=1 being moderate

      #Generate a text list of authenticated
      $des_supp=1 if ($tr_hash{'1'} == 1);
      $md5_supp=1 if ($tr_hash{'2'} == 1);
      $psk_supp=1 if ($tr_hash{'3'} == 1);
      $dh1_supp=1 if ($tr_hash{'4'} == 1);

      if ($tr_hash{'1'}==1 || $tr_hash{'2'}==1 || $tr_hash{'3'}==1 || $tr_hash{'4'} == 1) {
         $trans_vulns++;
         # Flag up 'vulnerable' types... enc=DES, hash=MD5 being important 
         if ($tr_hash{'1'} eq 1 || $tr_hash{'2'} eq 1) {$out.="*";}
         # Flag up 'vulnerable' types... auth=preshared, dh=1 being moderate
         if ($tr_hash{'3'} eq 1 || $tr_hash{'4'} eq 1) {$out.="+";}
         if ($tr_hash{'14'}) {
            $out.= $enc{$tr_hash{'1'}}."-". $tr_hash{'14'} .",". $hash{$tr_hash{'2'}} .",". $auth{$tr_hash{'3'}} .",". $dh{$tr_hash{'4'}} ."\n";
         } else {
            $out.= $enc{$tr_hash{'1'}} .",". $hash{$tr_hash{'2'}} .",". $auth{$tr_hash{'3'}} .",". $dh{$tr_hash{'4'}} ."\n";
         }#endtr_hash{14}
      }#endtr_hash(1)
   }#endforeach @transforms_valid
   print "Number of vulnerable transforms: " . $trans_vulns . "\n";
   print $out . "\n";
   print "Summary of vulnerable algorithms supported:\n";
   print "Encryption: DES\n" if $des_supp;
   print "Hash: MD5\n" if $md5_supp;
   print "Authentication: Preshared Key\n" if $psk_supp;
   print "DH Group: 1\n" if $dh1_supp;
   print "Aggressive Mode: Yes\n" if $aggressive && $trans_vulns;
}#endsub


# setLightTransforms()
# - Set the encryption, hash, authentication, dh group set to the common transforms seen
sub setLightTransforms {
   %enc = %enc_priority;
   %hash = %hash_priority;
   %auth = %auth_priority;
   %dh = %dh_priority;
}


# setFullTransforms()
# - Set the encryption, hash, authentication, dh group set to most transforms seen
sub setFullTransforms {
   %enc = (1=>"DES", 2=>"IDEA", 3=>"Blowfish", 4=>"RC5", 5=>"3DES", 6=>"CAST", 7=>"AES", 8=>"Camellia");
   %hash = (1=>"MD5", 2=>"SHA1", 3=>"Tiger", 4=>"SHA2-256", 5=>"SHA2-384", 6=>"SHA2-512");
   %auth = (
	1=>"Preshared Key",
	2=>"DSS Signature",
	3=>"RSA Signature",
	4=>"RSA Encryption",
	5=>"Revised RSA Encryption",
	6=>"ElGamel Encryption",
	7=>"Revised ElGamel Encryption",
	8=>"ECDSA Signature",
	64221=>"Hybrid InitRSA",
	64222=>"Hybrid RespRSA",
	64223=>"Hybrid InitDSS",
	64224=>"Hybrid RespDSS",
	65001=>"XAUTH InitPreShared",
	65002=>"XAUTH RespPreShared",
	65003=>"XAUTH InitDSS",
	65004=>"XAUTH RespDSS",
	65005=>"XAUTH InitRSA",
	65006=>"XAUTH RespRSA",
	65007=>"XAUTH InitRSAEncryption",
	65008=>"XAUTH RespRSAEncryption",
	65009=>"XAUTH InitRSARevisedEncryption",
	65010=>"XAUTH RespRSARevisedEncryption"
   );
   %dh = (
	1=>"DH Group 1: modp768",
	2=>"DH Group 2: modp1024",
	3=>"EC2N 155",
	4=>"EC2N 185",	
	5=>"DH Group 5: modp1536",
	14=>"DH Group 14: modp2048",
	15=>"DH Group 15: modp3072",
	16=>"DH Group 15: modp4096",
	17=>"DH Group 15: modp6144",
	18=>"DH Group 15: modp8192"
   );
}

