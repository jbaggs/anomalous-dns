##! AnomalousDNS is a module for tracking and correlating abnormal DNS behaviour.
##!
##! This file contains global settings.
##! Logic for individual events is grouped by type in separate files. 
##! 
##! Requires https://github.com/sethhall/domain-tld 
##!
##! Author Jeremy Baggs

module AnomalousDNS;

export {
	## Event generated when connection duration limit is exceeded
	global conn_duration_exceeded: event(c: connection);

	## Event generated when connection packet limit is exceeded
	global conn_packets_exceeded: event(c: connection);

	## Event generated when unique query per domain limit is exceeded
	global domain_query_exceeded: event(c: connection, domain: string);

	## Event generated when DNS query size threshold is passed
	global oversized_query: event(c: connection, domain: string, qsize: count);

	## Event generated when DNS answer size threshold is passed
	global oversized_answer: event(c: connection, len: count);

	## Event generated when a blacklisted query type is detected
	global blacklisted_qtype: event(c: connection, query: string, qtype: count);

	## Event generated when a query type not in the whitelist is detected
	global unusual_qtype: event(c: connection, query: string, qtype: count);

	## Generate connection notices
	global conn_notice: bool = T &redef; 

        ## Generate unique domain query notices
        global dquery_notice: bool = T &redef;

	## Generate oversized notices
	global os_notice: bool = T &redef;

	## Generate query type notices
	global qtype_notice: bool = T &redef;

	## Local servers that receive exceptions for DNSSEC in Oversized_Answer and Domain_Query_Limit,
	## and query type 10 (if Trust Anchor Telemetry).
	const local_dns_servers: set[addr] &redef;

	## Recursive resolvers receive the same treatment as local dns servers, but are tracked seperately
	## in an-dns-domain.zeek. This allows for a higher query limit than forwarding resolvers, 
	## and / or additional whitelisting.
	const recursive_resolvers: set[addr] &redef;

	## Hosts not to track in an-dns-domain.zeek.
	const domain_untracked: set[addr] &redef;

	## DNSSEC query types, and PTR
	const server_ignore_qtypes = [12,43,48] &redef;
}
