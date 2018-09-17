nagios-xenserver
================

Nagios check plugin for xenserver
---------------------------------

	Usage: ./check_xenserver.py hostname username password <check_{sr,mem,cpu,hosts}> [warning level %] [critical level %]
see online help for more informations

 - Uses https by default to connect to XenServer, if you have a pool, use a poolmaster IP/FQDN
 - Uses (python) XenAPI, download it from XenServer http://www.xenserver.org/partners/developing-products-for-xenserver.html and parse_rrd

Credit for most of the code goes to ppanula, check http://exchange.nagios.org/directory/Plugins/System-Metrics/Storage-Subsystem/check_sr-2Epy/details for original code


Version history:
----------------
 - v1.0: Initial release
 - v1.1: Config file support + return code for check_hosts
 - v1.2: Bug fixes : return status for SRs and Mem, perfdata format
		 Features : service output for SRs and Mem,
 - v1.3: Rewrite of the argument parsing
         Code refactoring
         Ability to check a single SR
 
Todo:
-----
 - Add VMs status check 
 - Add Multipath enable checking
