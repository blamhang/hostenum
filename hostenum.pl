#!/usr/bin/perl
#
# Host Enumeration
#
# Using nbtscan, nmap, ldapsearch for linux to identify Windows info.
# Given an IP address range, following will be identified:
# - NetBIOS name
# - FQDN hostname
# - Domain/Workgroup Name
# - Role of host (DC, Domain Member Server, Workgroup Server)
# - Operating System (SP?)

# Use Perl Modules 
# Note to check following:
# 1. Perl installed (perl -v)
# 2. Perl modules installed (e.g. CPAN; install File::Which.pm)
# 3. External Programs exist (i.e. --depend or manually nbtscan, nmap, etc)
use strict;
use warnings;
use 5.010;
use Data::Dumper qw(Dumper);
use Getopt::Long qw(GetOptions);

# Constants Defined
use constant VERSION => 0.01;

# Execution Start Time
my $exectime=time();
my $datetime=localtime();

# GetOptions
# https://perlmaven.com/scope-of-variables-in-perl
my $flag_help; my $flag_version;
my $flag_csv; my $flag_table;
my $flag_outall; my $flag_outcsv; my $flag_outtable;
my $flag_debug; my $flag_depend; my $flag_ldap;
GetOptions( "h|?|help"  =>  \$flag_help
	,"v|version"  =>  \$flag_version
	,"c|csv"  =>  \$flag_csv
	,"d|debug"  =>  \$flag_debug 
	,"depend"  =>  \$flag_depend
	,"l|ldap"  =>  \$flag_ldap
	,"o|outall"  =>  \$flag_outall
	,"outcsv"  =>  \$flag_outcsv
	,"outtable"  =>  \$flag_outtable
	,"t|table"  =>  \$flag_table
);

# Time Debug
print "[DEBUG] Time: $datetime\n" if $flag_debug;

# Depend Option
# (runDependency() && exit) if $flag_depend;
if ($flag_depend) { runDependency(); exit; }

# Version Option
getVersion() and exit if $flag_version;

# Help Option (also display when no arguments supplied)
getHelp() and exit if $flag_help or scalar @ARGV==0;


# Get $ARGV[0] (only 1 variable used)
# ERROR! $ips=@ARGV if $#ARGV>0; ERROR!
# ERROR! $ips=$ARGV[0] if $#ARGV>0; ERROR!
# ERROR! $ips=@ARGV if scalar @ARGV>0; ERROR!
my $ips="";
$ips=$ARGV[0];

# DEBUG print
print "[DEBUG] @ARGV\n" if $flag_debug;
print "[DEBUG] $ips is a valid IP address\n" if $flag_debug && validIP($ips);
print "[DEBUG] $ips is a valid dash IP address range\n" if $flag_debug && validRangeDash($ips);
print "[DEBUG] $ips is a valid slash IP address range\n" if $flag_debug && validRangeSlash($ips);

# check if $ips is a valid IP or range
die "$ips is not valid argument. Argument must be an IP address or range.\n" unless validRangeDash($ips) || validRangeSlash($ips) || validIP($ips);

# print Dumper \%found;
my %found=enumHosts($ips);
my $outputCSV=printCSV(%found);
my $outputTable=printTable(%found);

print $outputCSV if $flag_csv;
print $outputTable if $flag_table;
print $outputCSV if !$flag_csv and !$flag_table;

if ($flag_outall) { $flag_outcsv=1; $flag_outtable=1; }
writeFile($outputCSV,'output.csv') if $flag_outcsv;
writeFile($outputTable,'output.txt') if $flag_outtable;

$exectime=time()-$exectime;
print "Execution Time: $exectime seconds\n";

exit;

##### FUNCTIONS (MAIN) #########################################################

# enumHosts
# - enumHosts given $ips
# - return %hashes
sub enumHosts {
   my ($ips) = @_;
   my %found;

   # nbtscan
   my @nbtscan_results=qx/nbtscan -vv -h -s \":\" $ips/;
   # Debug: echo back nbtscan
   # print Dumper \@nbtscan_results;
   if ($flag_debug) {
      print "[DEBUG]\n[DEBUG] nbtscan -vv -h -s \":\" $ips\n";
      foreach (@nbtscan_results) {print "[DEBUG] $_";}
   }

   # Process nbtscan_results
   %found=processNBT(@nbtscan_results);
   # Process nmap-smb-os-discovery results
   %found=processSMB(%found);
   # Process ldapsearch results
   %found=processLDAP(%found) if $flag_ldap;

   return %found;
}


# processNBT
# Take array of nbtscan results and do something
sub processNBT{
   my (@nbtscan_results)=@_;
   my %found;
   my @line;

   foreach(@nbtscan_results){
      @line=split(/:/,$_);
      # $line[0]=IP; $line[1]=NAME; $line[2]=TAG
      # Trim split data
      foreach (@line) {$_ =~ s/^\s+|\s+$//g;}

      # Get IP address and to found IP addresses if applicable   
      if(!exists($found{$line[0]})) {
         $found{$line[0]}={ip => $line[0]};
      }
      # Get Hostname
      if($line[2] eq 'Workstation Service') {
         $found{$line[0]}{'hostname'}=$line[1];
      }
      # Get Domain/Workgroup Name
      if($line[2] eq 'Domain Name') {
         $found{$line[0]}{'groupname'}=$line[1];
      }
      # Get whether DC or not
      if($line[2] eq 'Domain Controllers') {
         $found{$line[0]}{'dc'}=1;
      }
      # Get if MSBROWSE found
      # CHECK/ADD CONDITION: and $line[2] eq 'Master Browser'
      if($line[1] =~ /_MSBROWSE_/) {
         $found{$line[0]}{'msbrowse'}=$line[1];
      }
   }

   # Run through all IPs again and identify roles
   foreach (keys %found) {
      # DC with MSBROWSE = DC w/ Children
      $found{$_}{'children'}=1 if( exists($found{$_}{'dc'}) and exists($found{$_}{'msbrowse'}) );
      # Not DC and No MSBROWSE = Part of Domain (DM)
      $found{$_}{'dm'}=1 if( !exists($found{$_}{'dc'}) and !exists($found{$_}{'msbrowse'}) );
      # Not DC and MSBROWSE = Part of workgroup (WKG)
      $found{$_}{'wkg'}=1 if( !exists($found{$_}{'dc'}) and exists($found{$_}{'msbrowse'}) );

      # Determine Role: DC w/ Kids; DC; DM; WKG
      if (exists $found{$_}{'children'}) {
         $found{$_}{'role'}='DC w/Kids';
      } elsif (exists $found{$_}{'dc'}) {
         $found{$_}{'role'}='DC';
      } elsif (exists $found{$_}{'dm'}) {
         $found{$_}{'role'}='DM';
      } elsif (exists $found{$_}{'wkg'}) {
         $found{$_}{'role'}='WKG';
      } else {
         # Really shouldn't get here. Analyse nbtscan/nmap results for bugs
         $found{$_}{'role'}='N/A';
      }
   }

   return %found;
}


# processSMB
# - process SMB OS Discovery on found IPs
# - nmap smb-os-discovery.nse to get OS details and FQDN
# - return %found
sub processSMB {
   my (%found) = @_;
   my @smbos_results;
   my @line;

   foreach my $i (keys %found) {
      @smbos_results=qx!nmap --script smb-os-discovery.nse -p139,445 $i 2>&1 | grep -i 'OS:\\|FQDN:'!;
      # Debug: echo back nmap smb-os-discovery
      # print Dumper \@smbos_results;
      if ($flag_debug) {
         print "[DEBUG]\n[DEBUG] nmap --script smb-os-discovery.nse -p139,445 $i 2>&1 | grep -i 'OS:\\|FQDN:'\n";
         foreach (@smbos_results) {print "[DEBUG] $_";}
      }

      foreach (@smbos_results) {
         @line=split(/:/,$_);
         # $line[0]=Name; $line[1]=Description;
         # Trim split data
         foreach (@line) {$_ =~ s/^[\s\|]+|[\s\|]+$//g;}

         $found{$i}{'os'}=$line[1] if $line[0]=~ /OS/;
         $found{$i}{'fqdn'}=$line[1] if $line[0]=~ /FQDN/;
      }
   }
   return %found;
}


# processLDAP
# - processLDAP on found IP
# - return %found
sub processLDAP {
   my (%found) = @_;
   my @ldapsearch_results;
   my @line;

   foreach my $i (sortbyIP(keys %found)) {
      @ldapsearch_results=qx!ldapsearch -x -h $i -s base | grep -i dnsHostName!;

      # Debug: echo back ldapsearch results
      if ($flag_debug) {
         print "[DEBUG]\n[DEBUG] ldapsearch -x -h $i -s base | grep -i dnsHostName\n";
         foreach (@ldapsearch_results) {print "[DEBUG] $_";}
      }


      foreach (@ldapsearch_results) {
         @line=split(/:/,$_);
         # $line[0]=Name; $line[1]=Description;
         # Trim split data
         foreach (@line) {$_ =~ s/^[\s\|]+|[\s\|]+$//g;}

         $found{$i}{'fqdn'}=$line[1] if $line[0]=~ /dnsHostName/;
      }
   }
   return %found;
}


# printCSV
# Output in CSV format
sub printCSV {
   my (%found) = @_;
   my $csv;

   # Store(Print) Header
   $csv.= "\nIP\tHostname\tGroupname\tRole\tOS\tFQDN\n";

   foreach my $i (sortbyIP(keys %found)) {
      # Store(Print) actual record for $i
      $csv.= $i."\t".$found{$i}{'hostname'}."\t".$found{$i}{'groupname'}."\t".$found{$i}{'role'}."\t".$found{$i}{'os'}."\t".$found{$i}{'fqdn'}."\n";

   }
   return $csv;
}


# printTable
# Output in formatted table format
sub printTable {
   my (%found) = @_;
   my $role;
   my $table;
   my %col_len=('ip'=>7, 'hostname'=>4, 'groupname'=>5, 'role'=>4, 'os'=>4, 'fqdn'=>4);

   foreach my $i (sortbyIP(keys %found)) {
      $role=($found{$i}{'role'}eq'DC w/Kids') ? 'DCwK' : $found{$i}{'role'};

      $col_len{'ip'}=length $i if (length $i > $col_len{'ip'});
      $col_len{'hostname'}=length $found{$i}{'hostname'} if (length $found{$i}{'hostname'} > $col_len{'hostname'});
      $col_len{'groupname'}=length $found{$i}{'groupname'} if (length $found{$i}{'groupname'} > $col_len{'groupname'});
      # $col_len{'role'}=4;
      $col_len{'os'}=length $found{$i}{'os'} if (length $found{$i}{'os'} > $col_len{'os'});
      $col_len{'fqdn'}=length $found{$i}{'fqdn'} if (length $found{$i}{'fqdn'} > $col_len{'fqdn'});
   }

   #print Dumper \%col_len;

   # Store(Print) $line_header
   my $ch='-'; my $cv='|'; my $cj='+';
   my $line_separator=$cj. $ch x ($col_len{'ip'}+2) .$cj. $ch x ($col_len{'hostname'}+2) .$cj. $ch x ($col_len{'groupname'}+2) .$cj. $ch x ($col_len{'role'}+2) .$cj. $ch x ($col_len{'os'}+2) .$cj. $ch x ($col_len{'fqdn'}+2) .$cj. "\n";
   my $line_header;
   $line_header=$cv.' IP'. ' ' x ($col_len{'ip'}-1);
   $line_header.=$cv.' Host'. ' ' x ($col_len{'hostname'}-3);
   $line_header.=$cv.' Group'. ' ' x ($col_len{'groupname'}-4);
   $line_header.=$cv.' Role ';
   $line_header.=$cv.' OS'. ' ' x ($col_len{'os'}-1);
   $line_header.=$cv.' FQDN'. ' ' x ($col_len{'fqdn'}-3);
   $line_header.=$cv."\n";

   $table.="$line_separator$line_header$line_separator";

   # Store(Print) each $line_row from found IPs
   my $line_row;
   foreach my $i (sortbyIP(keys %found)) {
      $role=($found{$i}{'role'}eq'DC w/Kids') ? 'DCwK' : $found{$i}{'role'};
      $line_row=$cv.' '.$i.' 'x(1+$col_len{'ip'}-length $i);
      $line_row.=$cv.' '.$found{$i}{'hostname'}.' 'x(1+$col_len{'hostname'}-length $found{$i}{'hostname'});
      $line_row.=$cv.' '.$found{$i}{'groupname'}.' 'x(1+$col_len{'groupname'}-length $found{$i}{'groupname'});
      $line_row.=$cv.' '.$found{$i}{'role'}.' 'x(1+$col_len{'role'}-length $found{$i}{'role'});
      $line_row.=$cv.' '.$found{$i}{'os'}.' 'x(1+$col_len{'os'}-length $found{$i}{'os'});
      $line_row.=$cv.' '.$found{$i}{'fqdn'}.' 'x(1+$col_len{'fqdn'}-length $found{$i}{'fqdn'});
      $line_row.=$cv."\n";
      $table.=$line_row;
   }
   $table.=$line_separator;

   return $table;
}

# writeFile
# 
sub writeFile {
   my ($str,$filename)=@_;
   $filename="default.log" if $filename eq "";
 
   open(FH, '>', $filename) or die "Can't create file: $!\n";
   print FH $str;
   close(FH);
   print "[DEBUG] Wrote to $filename successfully!\n" if $flag_debug;
   return;
}


##### FUNCTIONS (HELPER) #######################################################

# validIP
# - check parameter is a valid IP address
sub validIP {
   my($ip) = @_;
   if($ip =~ m/^(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$/) {
      return 1
   } else {
      return 0
   }
}

# sortbyIP
# - sort array of IPs
sub sortbyIP {
   my(@unsorted)=@_;
   my(@sorted)=map substr($_,4),sort map pack('C4a*', split(/\./), $_), @unsorted;
   return @sorted;
}

# validRangeDash
# - check to see if valid range based on first part of parameter split by dash
sub validRangeDash {
   my($range) = @_;
   return 0 if($range !~ /-/);
   my @dashed = split /-/, $range;
   return validIP($dashed[0]);
}

# validRangeSlash
# - check to see if valid range based on first part of parameter split by slash
sub validRangeSlash {
   my($range) = @_;
   return 0 if($range !~ /\//);
   my @slashed = split /\//, $range;
   return validIP($slashed[0]);
}

# runDependency
sub runDependency {
   my @cmds= ('nbtscan', 'nmap', 'smbclient', 'ldapsearch');
   my $cmd_output='';

   foreach ( @cmds ) {
      $cmd_output=qx!$_ 2>&1!;
      if (defined $cmd_output) {
         print "$_ is present...\n";
      } else {
         print "$_ is MISSING...\n";
      }
   }

}

# getVersion
sub getVersion {
my $prog="host_enum.pl";
my $version=VERSION;
print <<VERS;
$prog v$version
VERS
}

# getHelp
sub getHelp {
my $prog="host_enum.pl";
my $version=VERSION;
print <<HELP;
$prog v$version
$prog -? -h --help	Help
$prog -v --version	Version Info
$prog -d --debug	Debug/Verbose Mode
$prog --depend	Check Dependencies
$prog -l --ldap	Run with ldapsearch
$prog --csv	Print final results in CSV format
$prog --table	Print final results in table format
$prog -o --outall	Dump output to file all formats
$prog --outcsv	Dump output to file (output.csv) in CSV format
$prog --outtable	Dump output to file (output.txt) in table format
HELP
}

