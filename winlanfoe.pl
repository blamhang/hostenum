#!/usr/bin/env perl
################################################################################
# winlanfoe - Windows information collation tool
# Copyright (C) 2012 Richard Hatch;  Updated 2019: Benedict Lam-Hang
# 
# This tool may be used for legal purposes only.  Users take full responsibility
# for any actions performed using this tool.  The author accepts no liability
# for damage caused by this tool.  If these terms are not acceptable to you,
# then you are not permitted to use this tool.
#
# In all other respects the GPL version 2 applies:
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation; either version 2 of the License, or (at your option) any later
# version.
# 
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
################################################################################
use strict;
use warnings;
use Getopt::Long qw(GetOptions);

# Constants Defined
use constant VERSION => 0.5;

# Script Description
my $script_name = 'winlanfoe.pl';
my $version = " ".$script_name." v".VERSION."\n";

my $note = <<NOTE;

 Note: OS Version is taken from enum4linux. More precise results possible with:
 # msfcli auxiliary/scanner/smb/smb_version RHOSTS=1.2.3.4 e
 # msfconsole -x "use auxiliary/scanner/smb/smb_version set RHOSTS 1.2.3.4; exploit; exit"
 # nmap --script=smb-os-discovery.nse 1.2.3.4
  -or- Examining nessus output.

NOTE

# Usage Information
my $usage = "
 Parses enum4linux output for Windows for hostname, workgroup/domain, domain-member, OS.

 Usage:
 ./$script_name enum4linux-10.0.0.1.out [ enum4linux-10.0.0.2.out ]
 -or- 
 ./$script_name -f   # To search the current directory tree for enum4linux files

 Tip:
 To create an output file run enumlinux as follows:
 # enumlinux.pl -a 10.0.0.1 > enum4linux-10.0.0.1.out

 To run a batch of IP addresses, save IPs in a file loop through those addresses as follows:
 # for i in `cat ips.txt`; do enum4linux.pl -a \$i > enum4linux-\$i.out; done
";

# Always Print Version
print $version;

# Get Argument Information & Relevant Files
my $file;
my @src_files = ();
my $flag_usage; my $flag_find;

GetOptions( "h|?|usage"  =>  \$flag_usage
   ,"f|find"  =>  \$flag_find
);

# Display $usage if no arguments or $flag_usage
if ($flag_usage) { die $usage; }
if ($#ARGV < 0 and !$flag_find) { die $usage; }

# If $flag_find defined, use current directory
if ($flag_find) {
   #@src_files = qx!find $find_dir -type f | grep -i enum4linux!;
   @src_files = qx!find | grep -i enum4linux!;
} else {
   @src_files =  <@ARGV>;
}

# Print note before start processing
print $note;

my $rec = {}; #temp record. used to record information prior to inserting into %hosts
my $hostname;
my $wg_domain_name;
my $wg_or_domain;
my $domain;
my $msbrowse;
my $OS = "";
my $is_DC;   
my %hosts;

my @Domain_WG_Names = (); #holds the names of domains/workgroups identified
my @Domain_Controllers = (); #holds the hostnames of domain controllers identified (by Domain Controllers entry)
my @Domains = (); #holds the names of domain names positively identified (by Domain Controllers entry)
my %hosts_info = (); #holds the host information for each host (enum4linux output) encountered
my @Workgroups = (); #holds the names of workgroups, i.e. domain names for which no domain controller found

#These are used for formating the output
my $Max_Domain_Length = 0;
my $Max_Workgroup_length = 0;
my $Max_Hostname_Length = 0;
my $Max_OS_Length = 0;
my $Max_IP_Length = 0;

my $filename = "";
my $ip = "";

#Temporary variables
my $h; 
my $t;
my $k;
my $i;

# Foreach src_files identified.
foreach (@src_files) {
   $filename = $_;

   $hostname = "";
   $wg_domain_name=  "";
   $wg_or_domain = "";
   $domain = "";
   $msbrowse = 0;
   $OS = "";
   $is_DC = 0;

   # Open file found if can't be opened, skip
   unless (open(FILE, "<$filename")) {
      print "WARNING: Can't open $filename for reading.  Skipping...\n";
      next;
   }

   while (<FILE>) {
      chomp;
      my $line = $_;

      # Get IP address
      if ($line =~ /(\d+\.\d+\.\d+\.\d+)/) {
         $ip = $1;
      }

      # Look for Workstation Service for HOSTNAME
      # Remember what maximum length for display
      if ($line =~ /\s*([A-Za-z0-9-_.]+)\s.*\sWorkstation\sService/) {
         $hostname = $1;
         if (length($hostname) > $Max_Hostname_Length) {
            $Max_Hostname_Length = length($hostname);
         }
      }

      # Look for Domain/Workgroup Name for GROUPNAME
      if ($line =~ /\s*([A-Za-z0-9-_.]+)\s.*\sDomain\/Workgroup\sName/) { 
         $wg_domain_name = $1;
      }

      # Look for Domain Controllers for DC and Domain
      if ($line =~ /\s*([A-Za-z0-9-_.]+)\s.*\sDomain\sControllers/) {
         $is_DC = 1;
         $domain = $1;
      }

      # Look for __MSBROWSE__
      if ($line =~ /\s*..__MSBROWSE__.\s/) {
         $msbrowse = 1;
      }

      # Look for OS Version
      # Remember what maximum length for display
      if ($line =~ /\s*OS\=\[(.*)\]\sServer=/) {
         $OS = $1;
         if ("$OS" eq "Windows 5.1") {
            $OS = "Windows 5.1 (XP)";
         }
         if ("$OS" eq "Windows 5.0") {
            $OS = "Windows 5.0 (2000)";
         }
         if (length($OS) > $Max_OS_Length) {
            $Max_OS_Length = length($OS);
         }
      }

      # If OS not identified
      if ("x$OS" eq "x") {
         $OS = "** Not identified **";
      }

   }#end while <FILE>

   # Initialise temporary record
   $rec = {};
   $rec->{hostname} = $hostname;
   $rec->{IP} = $ip;
   $rec->{OS} = $OS;
   $rec->{IS_DC} = $is_DC;
   $rec->{Domain_WG_Name} = $wg_domain_name;

   # Add to array if not GROUPNAME not seen before   
   if (! is_in_domains_array($wg_domain_name)) {
      push @Domain_WG_Names, $wg_domain_name;
   }

   # Add to domains array if GROUPNAME is a domain 
   if ($is_DC) {
      if (! is_in_domains_array($wg_domain_name)) {
         push @Domains, $wg_domain_name;
      }
   }

   # Add to workgroups array if not a DC and has MSBROWSE 
   if (! $is_DC and $msbrowse) {
      if (! is_in_workgroups_array($wg_domain_name)) {
         push @Workgroups, $wg_domain_name;
      }
   }

   # Add record to list
   $hosts_info{ $rec->{hostname} } = $rec; #add tempoary record to list

}#end while shift

# Calculate max length for Domains for output
foreach $h (@Domains) {
   if (length($h) > $Max_Domain_Length) {
      $Max_Domain_Length = length($h);
   }
} #end foreach $h (@Domains)

# Calculate max length for Workgroups for output
foreach $h (@Workgroups) {
   if (length($h) > $Max_Workgroup_length) {
      $Max_Workgroup_length = length($h);
   }
} #end foreach $h (@Workgroups)

# Set max length of Domains/Workgroups
my $Max_Dom_WG_Length = $Max_Domain_Length;
if ($Max_Workgroup_length > $Max_Domain_Length) {
   $Max_Dom_WG_Length = $Max_Workgroup_length;
}

# Sort by Domain/Workgroup name
@Domains = sort(@Domains);
@Workgroups = sort(@Workgroups);

# Output Domain information
foreach $h (@Domains) {
   foreach $i (keys %hosts_info) {
      if ($hosts_info{$i}{Domain_WG_Name} eq $h) {#we found a member of current domain
         print "Domain: ";
         $k = sprintf("%-*s", $Max_Dom_WG_Length+2, "$h, ");
         print $k;

         print "Hostname: ";
         $k = sprintf("%-*s", $Max_Hostname_Length+2, "$i, ");
         print "$k";

         print "IP: ";
         $k = sprintf("%-*s", $Max_IP_Length+2, "$hosts_info{$i}{IP}, ");
         print $k;

         print "OS: ";
         $k = sprintf("%-*s", $Max_OS_Length+2, "$hosts_info{$i}{OS}, ");
         print $k;

         if ($hosts_info{$i}{IS_DC} == 1) {
            print "Domain Controller";
         }

         print "\n";
      }#end we found a member of the current domain
   }#end foreach $i keys %hosts_info
}#end foreach $h (@Domains)

print "\n";

# Output Workgroup information
foreach $h (@Workgroups) {
   foreach $i (keys %hosts_info) {
      if ($hosts_info{$i}{Domain_WG_Name} eq $h) { #we found a workgroup member
         print "Wrkgrp: ";
         $k = sprintf("%-*s", $Max_Dom_WG_Length+2, "$h, ");
         print $k;

         print "Hostname: ";
         $k = sprintf("%-*s", $Max_Hostname_Length+2, "$i, ");
         print "$k";

         print "IP: ";
         $k = sprintf("%-*s", $Max_IP_Length+2, "$hosts_info{$i}{IP}, ");
         print $k;

         print "OS: ";
         $k = sprintf("%-*s", $Max_OS_Length+2, "$hosts_info{$i}{OS}, ");
         print $k;

         print "\n";
      }#end if we found a workgroup member
   }#end foreach $i keys %hosts_info
}#end foreach $h 

print "\n";

################################################################################
# Helper Functions

# is_in_domain_array figures out if string argument is in @Domains
sub is_in_domains_array #(wg_dom_name)
{
   my $searchStr = $_[0];
   my $found;
   $found = 0;
   for my $i (@Domains)
   {
      if ("$i" eq "$searchStr")
      {
         $found = 1;
      }
   }
   $found; #return value
}#end sub is_in_domains_array

# is_in_workgroup_array figures out if string argument is in @Workgroups
sub is_in_workgroups_array #(wg_dom_name)
{
   my $searchStr = $_[0];
   my $found;
   $found = 0;
   for my $i (@Workgroups)
   {
      if ("$i" eq "$searchStr")
      {
         $found = 1;
      }
   }
   $found; #return value
}#end sub is_in_domains_array

#EOF

