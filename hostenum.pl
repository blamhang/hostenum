#!/usr/bin/perl
#
# hostenum - Host Enumeration Information Gathering Collation Script
# Copyright (C) 2019 Benedict Lam-Hang
#
# Using nbtscan, nmap, smbclient/ldapsearch for linux to identify Windows info.
# Given an IP address range, following will be identified:
# - NetBIOS name
# - FQDN hostname
# - Domain/Workgroup Name
# - Role of host (DC, Domain Member Server, Workgroup Server)
# - Operating System (SP?)
#
# This tool may be used for legal purposes only.  Users take full responsibility
# for any actions performed using this tool.  The author accepts no liability
# for damage caused by this tool.  If these terms are not acceptable to you, then
# you are not permitted to use this tool.
#
# In all other respects the GPL version 2 applies:
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
#
# Use Perl Modules 
# Note to check following:
# 1. Perl installed (perl -v)
# 2. External Programs exist (i.e. --depend or manually nbtscan, nmap, etc)
use strict;
use warnings;
use 5.010;
use Data::Dumper qw(Dumper);
use Getopt::Long qw(GetOptions);

# Constants Defined
use constant VERSION => 0.02;

# Execution Start Time
my $exectime=time();
my $datetime=localtime();

# GetOptions
# https://perlmaven.com/scope-of-variables-in-perl
my $flag_help; my $flag_version;
my $flag_csv; my $flag_table;
my $flag_outall; my $flag_outcsv; my $flag_outtable;
my $flag_debug; my $flag_depend; my $flag_ldap;
my $str_input;
GetOptions( "h|?|help"  =>  \$flag_help
	,"v|version"  =>  \$flag_version
	,"c|csv"  =>  \$flag_csv
	,"d|debug"  =>  \$flag_debug 
	,"depend"  =>  \$flag_depend
	,"i|input=s"  =>  \$str_input
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
getHelp() and exit if $flag_help or (scalar @ARGV==0 and !$str_input);

# Get $ARGV[0] (only 1 variable used)
# ERROR! $ips=@ARGV if $#ARGV>0; ERROR!
# ERROR! $ips=$ARGV[0] if $#ARGV>0; ERROR!
# ERROR! $ips=@ARGV if scalar @ARGV>0; ERROR!
my $ips="";
$ips=$ARGV[0];

# check if $ips is a valid IP or range
die "$ips is not valid argument. Argument must be an IP address or range.\n" unless $str_input || validRangeDash($ips) || validRangeSlash($ips) || validIP($ips);

# print Dumper \%found;
my %found;
if ($str_input) {
   %found=enumFile($str_input);
} else {
   # DEBUG print
   print "[DEBUG] @ARGV\n" if $flag_debug;
   print "[DEBUG] $ips is a valid IP address\n" if $flag_debug && validIP($ips);
   print "[DEBUG] $ips is a valid dash IP address range\n" if $flag_debug && validRangeDash($ips);
   print "[DEBUG] $ips is a valid slash IP address range\n" if $flag_debug && validRangeSlash($ips);
   %found=enumHosts($ips);
}
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

   # Process Hosts
   %found=processHosts(@nbtscan_results);

   return %found;
}


# enumFile
# - enumFile of IP address given $fileinput
# - return %hashes
sub enumFile {
   my ($fileinput) = @_;
   my @lines=readFile($fileinput);
   my %found;
   my @nbtscan_results; my @nbtscan1;

   foreach my $ip (@lines) {
      chomp $ip;
      if (validIP($ip)) {
         @nbtscan1=qx/nbtscan -vv -h -s \":\" $ip/;
         splice @nbtscan_results, scalar @nbtscan_results, 0, @nbtscan1;
         # Debug: echo back nbtscan
         # print Dumper \@nbtscan1;
         if ($flag_debug) {
            print "[DEBUG]\n[DEBUG] nbtscan -vv -h -s \":\" $ip\n";
            foreach (@nbtscan1) {print "[DEBUG] $_";}
         }
      } else {
         if ($flag_debug) {
            print "[DEBUG]\n[DEBUG] nbtscan -vv -h -s \":\" $ip\n";
            print "[DEBUG] $ip is not a valid IP address.\n";
         }
      }
   }

   # Process Hosts
   %found=processHosts(@nbtscan_results);

   return %found;
}


# processHosts
# Take array of nbtscan results and create %found of hosts and run appropriate
# tools to get further information, i.e. nmap smb-os-discovery (default) or
# ldapsearch/smblicent (ldap). Returns %found.
sub processHosts {
   my (@nbtscan_results)=@_;
   my %found;

   # Process nbtscan_results
   %found=processNbtscan(@nbtscan_results);

   if ($flag_ldap) {
      # Process smbclient results
      %found=processSmbclient(%found);
      # Process ldapsearch results
      %found=processLDAP(%found);
   } else {
      # Process nmap-smb-os-discovery results
      %found=processNmapSMB(%found);
   }

   return %found;
}


# processNbtscan
# Take array of nbtscan results and produce a %found hash array
sub processNbtscan{
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


# processNmapSMB
# - process SMB OS Discovery on found IPs
# - nmap smb-os-discovery.nse to get OS details and FQDN
# - adds to %found
# - return %found
sub processNmapSMB {
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

      # Check to if OS/FQDN not observed
      $found{$i}{'os'}="N/A" if (! exists $found{$i}{'os'});
      $found{$i}{'fqdn'}="N/A" if (! exists $found{$i}{'fqdn'});
   }
   return %found;
}


# processSmbclient
# - process smbclient -L on found IPs
# - smbclient to get OS details and FQDN
# - adds to %found
# - return %found
sub processSmbclient {
   my (%found) = @_;
   my @smbclient_results;
   my $osmatch='OS='; my $sqbe=']';
   my $pos1; my $pos2;

   foreach my $i (sortbyIP(keys %found)) {
      # OS is only displayed in STDERR...
      @smbclient_results=qx!smbclient -L $i -U''%'' -c 'q' 2>&1 | grep -i $osmatch!;

      # Debug: echo back smbclient results
      if ($flag_debug) {
         print "[DEBUG]\n[DEBUG] smbclient -L $i -U''%'' -c 'q' 2>&1 | grep -i $osmatch\n";
         foreach (@smbclient_results) {print "[DEBUG] $_";}
      }

      foreach (@smbclient_results) {
         $pos1=index($_,$osmatch);
         $pos2=index($_,$sqbe,$pos1);
         # Add 4 chars to pos to further offset, OS=[
         $found{$i}{'os'}=substr($_,$pos1+4,$pos2-$pos1-4);
      }

      # Check to if OS/FQDN not observed
      $found{$i}{'os'}="N/A" if (! exists $found{$i}{'os'});
   }
   return %found;
}


# processLDAP
# - processLDAP on found IP
# - adds to %found
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

      # Check to if OS/FQDN not observed
      $found{$i}{'fqdn'}="N/A" if (! exists $found{$i}{'fqdn'});
   }
   return %found;
}


# printCSV
# Output in CSV format
sub printCSV {
   my (%found) = @_;
   my $csv;

   # Store(Print) Header
   $csv= "\nIP\tHostname\tGroupname\tRole\tOS\tFQDN\n";

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


# readFile
# read contents of a file in and array of @lines
sub readFile {
   my ($filename)=@_;
   my(@lines);

   open(INFILE, "<$filename") || return "[ERROR] $filename: $!\n";
   @lines=<INFILE>;
   close(INFILE);
   return @lines;
}


# writeFile
# write contents of a $str to a $filename
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
$prog v$version  Copyright (C) 2019 Benedict Lam-Hang
Host enumeration script that gather details for given IP addresses.

This is a free software and it comes with absolutely no warranty.
You can use, distribute and modify it under terms of GNU GPL.

Usage: $prog [-?|-h|--help] [-v|--version] [-d|--debug] [--depend]
	[-i|--input=FILE] [-l|--ldap] [-c|--csv] [-t|--table] [-o|--outall]
	[--outcsv] [--outtable]

Help options:
  -?, -h, --help       Shows this help message
  -v, --version	       Print version
  -d, --debug          Debug output including output from wrapped commands
  --depend             Check dependencies to see which commands are missing

Input options:
  -i, --input=FILE     Input from list of IP addresses in a file
  -l, --ldap           Perform ldapsearch/smbclient instead of nmap (default)

Output options:
  -c, --csv            Dump output to screen in CSV format
  -t, --table          Dump output to screen in table format
  -o, --outall	       Dump output to file all formats	
  --outcsv             Dump output to file (output.csv) in CSV format
  --outtable           Dump output to file (output.txt) in table format
HELP
}

