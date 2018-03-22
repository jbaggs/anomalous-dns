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
	const domain_query_limit  =  7 &redef;
}

# Whitelist from domain-whitelist.bro replaces the pattern below 
# when set to load in __load__.bro
const domain_whitelist: pattern = /\.(in-addr\.arpa|ip6\.arpa)$/ &redef;

# Time until queries expire from tracking.
const query_period = 60min;

# Data structure for tracking unique queries to domains
global domain_query: table[string] of set[string] &read_expire=query_period+1min;

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
	{
	if (domain_whitelist ! in query)
		{
		local domain  =  DomainTLD::effective_domain(query);
		if (domain ! in domain_query)
			{
			domain_query[domain]=set(query) &write_expire=query_period;
			}
		else 
			{
			add domain_query[domain][query];
			}	
		if (|domain_query[domain]| > domain_query_limit)
			{
			event AnomalousDNS::domain_query_exceeded(c,domain);
			if (dquery_notice)
				{
				NOTICE([$note=Domain_Query_Limit,
					$conn=c,
					$msg=fmt("Unique queries (%sq /%s) to domain: %s exceeded threshold.", 
						|domain_query[domain]|,cat(query_period),domain),
					$sub=fmt("Most recent query from: %s", cat(c$id$orig_h)),   
					$identifier=cat(c$id$orig_h),
					$suppress_for=5min
					]);
				}
			}
		}
	}
