hostenum
========
Host enumeration script that gather details for given IP addresses.

Details include:
* NetBIOS name
* FQDN hostname
* Domain/Workgroup Name
* Role of host (DC, Domain Member Server, Workgroup Server)
* Operating System (SP?)

This is a free software and it comes with absolutely no warranty.
You can use, distribute and modify it under terms of GNU GPL.


## Usage
```
Usage: hostenum.pl [-?|-h|--help] [-v|--version] [-d|--debug] [--depend]
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
```

## Examples
Examples of hostenum usage

#### Check Dependencies
```
$ hostenum.pl --depend
nbtscan is MISSING...
nmap is MISSING...
smbclient is present...
ldapsearch is MISSING...
```

#### Default Host Enumeration with csv output to screen
```
$ hostenum.pl 10.88.88.0/24
10.88.88.0	Sendto failed: Permission denied
10.88.88.255	Sendto failed: Permission denied

IP	Hostname	Groupname	Role	OS	FQDN
10.88.88.21	DUMMYDC1	DUMMY	DC	Windows Server 2008 R2 Enterprise 7601 Service Pack 1	N/A
10.88.88.30	PCS-VM-WIN2K3	PORT	WKG	Windows Server 2003 3790 Service Pack 2 (Windows Server 2003 5.2)	N/A	
10.88.88.201	BLAMHANG-VM-MIN	WORKGROUP	DM	Windows 6.1 (Samba 4.3.11-Ubuntu)	blamhang-vm-mint	N/A
Execution Time: 10 seconds
```

#### Host Enumeration with csv output to screen
```
$ hostenum.pl -c 10.88.88.29-36
IP	Hostname	Groupname	Role	OS	FQDN
10.88.88.30	PCS-VM-WIN2K3	PORT	WKG	Windows Server 2003 3790 Service Pack 2 (Windows Server 2003 5.2)	N/A
```

#### Host Enumeration on list of IPs with default output
```
$ hostenum.pl -i ips.txt
IP	Hostname	Groupname	Role	OS	FQDN
10.88.88.21	DUMMYDC1	DUMMY	DC	Windows Server 2008 R2 Enterprise 7601 Service Pack 1	DummyDC1.dummy.dummytest.me
IP	Hostname	Groupname	Role	OS	FQDN
10.88.88.30	PCS-VM-WIN2K3	PORT	WKG	Windows Server 2003 3790 Service Pack 2 (Windows Server 2003 5.2)	N/A
```

#### Default Host Enumeration with table output to screen
```
$ hostenum.pl -t 10.88.88.20-36
+-------------+---------------+------------+------+-------------------------------------------------------+-----------------------------+
| IP          | Host          | Group      | Role | OS                                                    | FQDN                        |
+-------------+---------------+------------+------+-------------------------------------------------------+-----------------------------+
| 10.88.88.21 | DUMMYDC1      | DUMMY      | DC   | Windows Server 2008 R2 Enterprise 7601 Service Pack 1 | DummyDC1.dummy.dummytest.me |
| 10.88.88.30 | PCS-VM-WIN2K3 | PORT       | WKG  | Windows Server 2003 3790 Service Pack 2               | N/A                         |
+-------------+---------------+------------+------+-------------------------------------------------------+-----------------------------+
```

#### Host Enumeration with debug/verbose output
This outputs to file in all formats (-o) and uses ldapsearch/smbclient (-l) instead of nmap smb-os-discovery.nse script
```
$ hostenum.pl -d -o -l 10.88.88.29-36
[DEBUG] Time: Thu Mar 21 23:55:32 2019
[DEBUG] 10.88.88.20-36
[DEBUG] 10.88.88.20-36 is a valid dash IP address range
[DEBUG]
[DEBUG] nbtscan -vv -h -s ":" 10.88.88.20-36
[DEBUG] 10.88.88.21:DUMMYDC1       :Workstation Service
[DEBUG] 10.88.88.21:DUMMY          :Domain Name
[DEBUG] 10.88.88.21:DUMMY          :Domain Controllers
[DEBUG] 10.88.88.21:DUMMYDC1       :File Server Service
[DEBUG] 10.88.88.21:DUMMY          :Domain Master Browser
[DEBUG] 10.88.88.21:MAC:08:00:27:65:b2:be
[DEBUG] 10.88.88.30:PCS-VM-WIN2K3  :Workstation Service
[DEBUG] 10.88.88.30:PORT     :Domain Name
[DEBUG] 10.88.88.30:PCS-VM-WIN2K3  :File Server Service
[DEBUG] 10.88.88.30:PORT     :Browser Service Elections
[DEBUG] 10.88.88.30:PORT     :Master Browser
[DEBUG] 10.88.88.30:__MSBROWSE__:Master Browser
[DEBUG] 10.88.88.30:MAC:08:00:27:51:43:1b
[DEBUG]
[DEBUG] smbclient -L 10.88.88.21 -U''%'' -c 'q' 2>&1 | grep -i OS=
[DEBUG] Domain=[DUMMY] OS=[Windows Server 2008 R2 Enterprise 7601 Service Pack 1] Server=[Windows Server 2008 R2 Enterprise 6.1]
[DEBUG]
[DEBUG] smbclient -L 10.88.88.30 -U''%'' -c 'q' 2>&1 | grep -i OS=
[DEBUG] Domain=[PCS-VM-WIN2K3] OS=[Windows Server 2003 3790 Service Pack 2] Server=[Windows Server 2003 5.2]
[DEBUG] Domain=[PCS-VM-WIN2K3] OS=[Windows Server 2003 3790 Service Pack 2] Server=[Windows Server 2003 5.2]
[DEBUG]
[DEBUG] ldapsearch -x -h 10.88.88.21 -s base | grep -i dnsHostName
[DEBUG] dnsHostName: DummyDC1.dummy.dummytest.me
ldap_sasl_bind(SIMPLE): Can't contact LDAP server (-1)
[DEBUG]
[DEBUG] ldapsearch -x -h 10.88.88.30 -s base | grep -i dnsHostName

IP	Hostname	Groupname	Role	OS	FQDN
10.88.88.21	DUMMYDC1	DUMMY	DC	Windows Server 2008 R2 Enterprise 7601 Service Pack 1	DummyDC1.dummy.dummytest.me
10.88.88.30	PCS-VM-WIN2K3	PORT	WKG	Windows Server 2003 3790 Service Pack 2	N/A
[DEBUG] Wrote to output.csv successfully!
[DEBUG] Wrote to output.txt successfully!
Execution Time: 1 seconds
```
