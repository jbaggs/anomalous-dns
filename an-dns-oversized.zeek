##! AnomalousDNS: oversized submodule.
##!
##! This submodule measures the size of DNS queries and responses. Tunneled 
##! connections more concerned with moving data than stealth (e.g. iodine)
##! can set impressive numbers here.
##!
##! Author: Jeremy Baggs
##!
##! oversized logic based on work by  Brian Kellogg

module AnomalousDNS;

export {
	redef enum Notice::Type += {
		Oversized_Query,
		Oversized_Answer,
	};
	## Oversize query threshold (characters)
	const oversize_query = 90 &redef;

	## Oversize response threshold (bytes)
	const oversize_response = 544 &redef;

	## Ignore PTR and NB record types in requests
	const oversize_ignore_qtypes = [12,32] &redef;

	## Ignore NetBios port
	const oversize_ignore_ports: set[port] = {137/udp, 137/tcp} &redef;

	##Name patterns to ignore in queries 
	const oversize_ignore_names = /wpad|isatap|autodiscover|gstatic\.com$|domains\._msdcs|mcafee\.com$/ &redef;

	## Oversize response threshold for local servers (bytes)
	const server_oversize_response = 3584 &redef;
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
	{
	if (|query| > oversize_query && oversize_ignore_names ! in query 
		&& qtype ! in oversize_ignore_qtypes && c$id$orig_p ! in oversize_ignore_ports)
		{
		local domain  =  DomainTLD::effective_domain(query);
		event AnomalousDNS::oversized_query(c,domain,|query|);
		if (os_notice)
			{
			NOTICE([$note=Oversized_Query,
				$conn=c,
				$msg=fmt("Query: %s", query),
				$sub=fmt("Query type: %s \"%s\"", qtype,DNS::query_types[qtype]),
				$identifier=cat(c$id$orig_h,c$id$resp_h),
				$suppress_for=30min
				]);
			}
		}
	}

event dns_message(c: connection, is_orig: bool, msg: dns_msg, len: count)
	{
	local o_resp = oversize_response;
	local local_server = F;
	if (c$id$orig_h in local_dns_servers || c$id$orig_h in recursive_resolvers)
		{
		o_resp = server_oversize_response;
		local_server = T;
		}
	if (len > o_resp && ! (local_server && c$dns$qtype in server_ignore_qtypes)
		&& c$id$orig_p ! in oversize_ignore_ports && c$id$resp_p ! in oversize_ignore_ports)
		{
		event AnomalousDNS::oversized_answer(c,len);
		if (os_notice)
			{
			NOTICE([$note=Oversized_Answer,
				$conn=c,
				$msg=fmt("Message length: %sB", len),
				$identifier=cat(c$id$orig_h,c$id$resp_h),
				$suppress_for=30min
				]);
			}
		}
	}
