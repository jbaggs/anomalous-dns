##! AnomalousDNS: domain submodule. 
##!
##! This submodule tracks unique DNS queries to domains. It is intended to help
##! identify low throughput exfiltration and DNS command and control traffic.
##! It is important to note that it is a domain centered metric. Attributing 
##! the traffic to a specific endpoint requires further analysis. 
##!
##! Care should be taken in tuning this submodule.
##! Various content delivery networks, and possibly your own network, 
##! will set it off until properly tuned. A well crafted whitelist is key.
##!
##! Author: Jeremy Baggs

module AnomalousDNS;

export {
	redef enum Notice::Type += {
		Domain_Query_Limit,
	};
	## Threshold for unique queries to a domain per query period
	const domain_query_limit  =  8 &redef;

	## Domain query threshold for recursive resolvers
	const recursive_domain_query_limit  =  12 &redef;

	## Time until queries expire from tracking.
	const query_period = 60min;
}

# Whitelist from domain-whitelist.zeek replaces the pattern below 
# when set to load in __load__.zeek
const domain_whitelist: pattern = /\.(in-addr\.arpa|ip6\.arpa)$/ &redef;

# Additional whitelisting for recursive resolvers.
# Whitelist from recursive-whitelist.zeek replaces the pattern below 
# when set to load in __load__.zeek
#
# The default pattern below is for exempting queries of the form: "_.foo.baz",
# for nameservers that are implementing QNAME Minimisation.
# See: https://tools.ietf.org/html/rfc7816.html#section-3
const recursive_whitelist: pattern = /^(_\..*)$/ &redef;

# Data structures for tracking unique queries to domains
global domain_query: table[string] of set[string] &read_expire=query_period+1min;
global domain_query_hosts: table[string] of set[addr] &read_expire=query_period+1min;

global recursive_domain_query: table[string] of set[string] &read_expire=query_period+1min;
global recursive_domain_query_hosts: table[string] of set[addr] &read_expire=query_period+1min;

function notify(c: connection, domain: string, queries: count, hosts: set[addr])
	{
	local hostlist = "hosts:";
	for (h in hosts)
		hostlist = cat(hostlist," ",h);
	NOTICE([$note=Domain_Query_Limit,
	$conn=c,
	$msg=fmt("Unique queries (%sq, < %s) to domain: %s exceeded threshold.",
		queries,cat(query_period),domain),
	$sub=hostlist,
	$identifier= cat(domain,c$id$orig_h),
	$suppress_for=30min
	]);
	}

function track_query(c: connection, query: string)
	{
	local domain  =  DomainTLD::effective_domain(query);
	if (c$id$orig_h in recursive_resolvers )
		{
		if (domain ! in recursive_domain_query)
			{
			recursive_domain_query[domain]=set(query) &write_expire=query_period;
			recursive_domain_query_hosts[domain]=set(c$id$orig_h) &write_expire=query_period;
			}

		else
			{
			add recursive_domain_query[domain][query];
			add recursive_domain_query_hosts[domain][c$id$orig_h];
			}
		if (|recursive_domain_query[domain]| > recursive_domain_query_limit)
			{
			event AnomalousDNS::domain_query_exceeded(c,domain);
			if (dquery_notice)
				notify(c, domain, |recursive_domain_query[domain]|, recursive_domain_query_hosts[domain]);
			}
		}
	else
		{
		if (domain ! in domain_query)
			{
			domain_query[domain]=set(query) &write_expire=query_period;
			domain_query_hosts[domain]=set(c$id$orig_h) &write_expire=query_period;
			}

		else
			{
			add domain_query[domain][query];
			add domain_query_hosts[domain][c$id$orig_h];
			}
		if (|domain_query[domain]| > domain_query_limit)
			{
			event AnomalousDNS::domain_query_exceeded(c,domain);
			if (dquery_notice)
				notify(c, domain, |domain_query[domain]|, domain_query_hosts[domain]);
			}
		}
	}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
	{
	if (c$id$orig_h in recursive_resolvers )
		{
		if ( qtype ! in server_ignore_qtypes && recursive_whitelist ! in query && domain_whitelist ! in query)
			track_query(c, query);
		}
	else if (c$id$orig_h in local_dns_servers)
		{
		if ( qtype ! in server_ignore_qtypes  && domain_whitelist ! in query)
			track_query(c, query);
		}
	else if (c$id$orig_h ! in domain_untracked && domain_whitelist ! in query)
		track_query(c, query);
	}
