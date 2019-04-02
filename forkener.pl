#!/usr/bin/perl -w
# Execute commands in parallel when they are stored in a file.
use strict;
use warnings;
use Parallel::ForkManager;
use LWP::Simple;
use Getopt::Std;

my $version = "Version: 0.1";
my $heredoc = <<ENDS;
# ============================================================================ #
# Author: Benedict Lam-Hang
#
# Usage: perl $0 [options] <#_of_process> <inputfile> 
#        perl $0 [options] <#_of_process> <inputfile> <outputprefix> 
#   E.g. perl $0 10 FB_inputFile.txt
#        perl $0 10 FB_inputFile.txt FB_VLAN_
#
# Options:
# -d  default TCP scan
# -o  OS detection in addition to service version detection
# -s  slow down scan speed to T3 from T4
# -t  full TCP scan
# -u  default UDP scan
# ============================================================================ #
ENDS


my %opts;
# d=default ports, s=T3 scan, t=TCP, u=UDP default
getopts('dostu', \%opts);

# Only run command if 2/3 arguments. arg0=# of processes; arg1=filename; arg2=name.
if($#ARGV < 1 || $#ARGV > 2){
   printf "# ERROR: Missing arguments. See usage below.\n$heredoc";
   exit;
}
my $num_of_processes=$ARGV[0];
my $filename=$ARGV[1];
my $name = ($#ARGV==2) ? $ARGV[2] : "";
my $cmd; my $ext;
my $_os; my $_speed;

# Create a file handle
open FH, "$ARGV[1]" or die "Cannot open filename[$filename]:$!\n";

my @IPS = undef;
# Decide whether full OS detection (-A) or default service version detection (-sV)
$_os = ($opts{o}) ? '-A' : '-sV';
# Decide whether slower scan (-T3) or default fast scan (-T4)
$_speed = ($opts{s}) ? '-T3' : '-T4';

# Decide whether to run full tcp-scan (t), udp-scan (u), default tcp-scan (d)
if ($opts{t}) {
   $ext = "-tcp";
   #$cmd = "nmap -sS -p1-8041,8046-8181,8183-65535 -P0 $_os $_speed -oA $name";
   $cmd = "nmap -sS -p- -P0 $_os $_speed -oA $name";
} elsif ($opts{u}) {
   $ext = "-udp";
   $cmd = "nmap -sU -P0 $_os $_speed -oA $name";
} elsif ($opts{d}) {
   $ext = "-tcpdef";
   $cmd = "nmap -sS -P0 $_os $_speed -oA $name";
} else {
   $ext = "-tcpdef";
   $cmd = "nmap -sS -P0 $_os $_speed -oA $name";
}

chomp(@IPS = <FH>); # trim trailing spaces.

# Close the file handle
close FH;

my $pm = new Parallel::ForkManager($num_of_processes);

#
# Setup a callback for when a child finishes up so we can get it's exit code
#
$pm->run_on_finish(
    sub {
        my ($pid, $exit_code, $ident) = @_;
        print "** ID[$ident] just got out of the pool with PID[$pid] and exit code[$exit_code] \n";
    }
);

$pm->run_on_start(
    sub {
        my ($pid, $ident)=@_;
        print "** ID[$ident] started with PID[$pid] \n";
    }
);

$pm->run_on_wait(
    sub {
        #print "** Have to wait for one children ...\n"
    },
    0.5
);

my $id = 0;

for my $fn (@IPS) {
    my $line="";
    $pm->start($id++) and next;
    $fn=$cmd.$fn.$ext." ".$fn;  

    print "[$fn] will be executed.\n";
    open(IPS,"$fn |") || die "Failed: $!\n";
    while ( <IPS> ) {
        $line=$_; chomp $line;
        print "[D] $line\n";

    }
    close IPS;
    $pm->finish;
};


print "Waiting for Children...\n";
$pm->wait_all_children;
print "Everybody[$num_of_processes] is out of the pool!\n";

sub HELP_MESSAGE() {print $heredoc;}
sub VERSION_MESSAGE() {print $version."\n";}

