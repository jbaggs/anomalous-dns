##! AnomalousDNS: query type submodule. 
##!
##! This submodule is intended for blacklisting query types that should not be 
##! seen in normal DNS communication. There is also an optional whitelist, 
##! that can be used to aid in reporting / discovery. 
##! 
##! Author: Jeremy Baggs

module AnomalousDNS;

export {
	redef enum Notice::Type += {
		Blacklisted_Query_Type,
		Unusual_Query_Type,
	};
	## Query type blacklist (type 10 "NULL" is obsolete (rfc883) used in iodine and possibly other tunnels)
	const query_type_blacklist = [10,65399] &redef;

	## Whitelisted query types. If active, all unlisted types will generate Unusual_Query_Type notices / events.
	const query_type_whitelist = [1,6,12,16,28,32,33] &redef;

	## Default is to not whitelist
	global query_type_use_whitelist = F &redef;
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
	{
	if (qtype in query_type_blacklist)
		{
		event AnomalousDNS::blacklisted_qtype(c, query, qtype);
		if (qtype_notice)
			{
			NOTICE([$note=Blacklisted_Query_Type,
				$conn=c,
				$msg=fmt("Query: %s", query),
				$sub=fmt("Query type: %s \"%s\"", qtype,DNS::query_types[qtype]),
				$identifier=cat(c$id$orig_h,c$id$resp_h),
				$suppress_for=5min
				]);
			}
		}

	if (query_type_use_whitelist == T  && qtype !in query_type_whitelist)
		{
		event AnomalousDNS::unusual_qtype(c, query, qtype);
		if (qtype_notice)
			{
			NOTICE([$note=Unusual_Query_Type,
				$conn=c,
				$msg=fmt("Query: %s", query),
				$sub=fmt("Query type: %s \"%s\"", qtype,DNS::query_types[qtype]),
				$identifier=cat(c$id$orig_h,c$id$resp_h),
				$suppress_for=5min
				]);
			}
		}
	}
