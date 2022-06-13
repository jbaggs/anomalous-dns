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

	## Data structures for tracking unique queries to domains
	## In cluster operation, these tables are  distributed uniformly across
	## proxy nodes.
	global domain_query: table[string] of set[string] &read_expire=query_period+1min;
	global domain_query_hosts: table[string] of set[addr] &read_expire=query_period+1min;

	global recursive_domain_query: table[string] of set[string] &read_expire=query_period+1min;
	global recursive_domain_query_hosts: table[string] of set[addr] &read_expire=query_period+1min;

}

# Record type containing the fields used for query tracking 
type QueryInfo: record {
	# The query to track
	query: string;
	# ETLD of the query
	domain: string &optional;
	# The host that made the query
	host:    addr;
};

# Whitelist from domain-whitelist.zeek replaces the pattern below 
# when set to load in __load__.zeek
const domain_whitelist: pattern = /\.(in-addr\.arpa|ip6\.arpa)$/ &redef;

# Additional whitelisting for recursive resolvers.
# Whitelist from recursive-whitelist.zeek replaces the pattern below 
# when set to load in __load__.zeek
#
# The default pattern below is for exempting queries of the form: "_.foo.bar",
# for nameservers that are implementing QNAME minimisation.
# See: https://tools.ietf.org/html/rfc7816.html#section-3
const recursive_whitelist: pattern = /^(_\..*)$/ &redef;

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

event add_recursive_domain_query(info: QueryInfo)
	{
	if ( info$domain ! in recursive_domain_query )
		{
		recursive_domain_query[info$domain]=set(info$query) &write_expire=query_period;
		recursive_domain_query_hosts[info$domain]=set(info$host) &write_expire=query_period;
		}

	else    
		{
		add recursive_domain_query[info$domain][info$query];
		add recursive_domain_query_hosts[info$domain][info$host];
		}
	}

event add_domain_query(info: QueryInfo)
	{
	if ( info$domain ! in domain_query )
		{
		domain_query[info$domain]=set(info$query) &write_expire=query_period;
		domain_query_hosts[info$domain]=set(info$host) &write_expire=query_period;
		}

	else
		{
		add domain_query[info$domain][info$query];
		add domain_query_hosts[info$domain][info$host];
		}
	}

function track_query(c: connection, query: string)
	{
	local info = QueryInfo($query = query, $host = c$id$orig_h);
	local hosts: set[addr] &redef;
	local queries: set[string] &redef;
	info$domain  =  DomainTLD::effective_domain(query);
	if ( info$host in recursive_resolvers )
		{
		if ( info$domain in recursive_domain_query )
			{
			queries = recursive_domain_query[info$domain];
			hosts = recursive_domain_query_hosts[info$domain];
			add hosts[info$host];
			add queries[query];
			if ( |queries| > recursive_domain_query_limit )
				{
				event domain_query_exceeded(c, info$domain);
				if ( dquery_notice )
					notify(c, info$domain, |queries|, hosts);
				}
			}
		Cluster::publish_hrw(Cluster::proxy_pool, info$query, add_recursive_domain_query, info);
		event add_recursive_domain_query(info);
		}

	else
		{
		if ( info$domain in domain_query )
			{
			queries = domain_query[info$domain];
			hosts = domain_query_hosts[info$domain];
			add hosts[info$host];
			add queries[query];
			if ( |queries| > domain_query_limit )
				{
				event domain_query_exceeded(c, info$domain);
				if ( dquery_notice )
					notify(c, info$domain, |queries|, hosts);
				}
			}
		Cluster::publish_hrw(Cluster::proxy_pool, info$query, add_domain_query, info);
		event add_domain_query(info);
		}
	}

event Cluster::node_up(name: string, id: string)
	{
	if ( Cluster::local_node_type() != Cluster::WORKER )
		return;

	# Drop local suppression cache on workers to force HRW key repartitioning.
	AnomalousDNS::domain_query = table();
	AnomalousDNS::domain_query_hosts = table();
	AnomalousDNS::recursive_domain_query = table();
	AnomalousDNS::recursive_domain_query_hosts = table();
        }

event Cluster::node_down(name: string, id: string)
	{
	if ( Cluster::local_node_type() != Cluster::WORKER )
		return;

        # Drop local suppression cache on workers to force HRW key repartitioning.
	AnomalousDNS::domain_query = table();
	AnomalousDNS::domain_query_hosts = table();
	AnomalousDNS::recursive_domain_query = table();
	AnomalousDNS::recursive_domain_query_hosts = table();
	}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
	{
	if ( c$id$orig_h in recursive_resolvers )
		{
		if ( qtype ! in server_ignore_qtypes && recursive_whitelist ! in query && domain_whitelist ! in query )
			track_query(c, query);
		}

	else if ( c$id$orig_h in local_dns_servers )
		{
		if ( qtype ! in server_ignore_qtypes  && domain_whitelist ! in query )
			track_query(c, query);
		}

	else if ( c$id$orig_h ! in domain_untracked && domain_whitelist ! in query )
		track_query(c, query);
	}
