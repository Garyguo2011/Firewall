curl https://www.google.com






% TCP Checking configuration

% Ip address matching test

	% Drop tcp from google.com :: curl https://www.google.com :: [Pass]
	pass tcp 74.125.239.0/24 any

	% Drop icmp from google.com :: ping www.google.com :: [DROP]
	drop icmp 74.0.0.0/8 any

	% Drop icmp from www.ibearhost.com :: ping www.ibearhost.com :: [DROP]
	drop icmp 173.236.189.55 any

	% Drop tcp from www.ibearhost.com :: curl http://www.ibearhost.com :: [DROP]
	drop tcp 173.236.189.48/28 any

	% Drop icmp from any ip :: traceroute www.ibearhost.com :: [PASS]
	pass        icmp any 11-11

	% Drop icmp form any cn ip :: ping www.amazon.cn :: [DROP]
	pass icmp cn 7-9

	% Allow ssh to us server :: ssh cs168-du@star.cs.berkeley.edu :: [DROP]
	pass tcp     us      22

	% Allow udp :: traceroute www.berkeley.edu :: [PASS]
	pass udp          169.229.216.200 30000-60000         

	% Drop ssh to star.cs.berkeley.edu :: [drop]
	drop tcp 128.32.42.27 10-30

	% 
	pass dns *.com         

	%
	drop dns *.deanza.edu         
 
	pass dns *

	pass dns www.stanford.edu