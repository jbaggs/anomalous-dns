##! AnomalousDNS is a module for tracking and correlating abnormal DNS behaviour.
##!
##! This is the main file, containg global settings, and logic for the "tunneling"
##! event. Logic for individual events is grouped by type in separate files. 
##! 
##! Requires https://github.com/sethhall/domain-tld 
##!
##! Author Jeremy Baggs

module AnomalousDNS;

export {
	redef enum Notice::Type += {
		Tunneling,
	};
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

	## Event generated when it is determined tunneling is occuring
	global tunneling: event(c: connection);

	## Generate connection notices
	global conn_notice: bool = T &redef; 

        ## Generate unique domain query notices
        global dquery_notice: bool = T &redef;

	## Generate oversized notices
	global os_notice: bool = T &redef;

	## Generate query type notices
	global qtype_notice: bool = T &redef;

	## Generate tunneling notices
	global tunnel_notice: bool = T &redef;

	## Local servers that receive exceptions for DNSSEC in Oversized_Answer and Domain_Query_Limit,
	## or query type 10 (if Trust Anchor Telemetry).
	const local_dns_servers: set[addr] &redef;

	## Recursive resolvers receive the same treatment as local dns servers, but are tracked seperately
	## in an-dns-domain.zeek. This allows for a higher query limit than forwarding resolvers, 
	## and / or additional whitelisting.
	const recursive_resolvers: set[addr] &redef;

	## Hosts not to track in an-dns-domain.zeek.
	const domain_untracked: set[addr] &redef;

}

## DNSSEC query types, and PTR
const server_ignore_qtypes = [12,43,48] &redef;

## Connection duration limit for tunneling event
const conn_duration_limit_tun = 90secs &redef;

## Connection packet limit for tunneling event
const conn_pkts_limit_tun  = 21 &redef;

## Settings for triggering a tunneling event based on 
## domain_query_exceed, oversized_query, and oversized answer 
## abreviated as dqe, oq, and oa respectively, are as follows:
## 
## Each vector of 3 elements is a combination of event thresholds.
## When each event is triggered n or more times, a tunnel event is thrown.
## The exception is an all zero vector, which is interpreted as "do nothing".
##
## The following will trigger tunneling events with either a combination of
## domain query exceeded & oversized query, or  a combination of
## domain query exceeded and oversized answer:
##
## const dqe_oq_oa: ... (
## vector(1, 1, 0),
## vector(1, 0, 1));
##
## The following does the same, as (0, 0, 0) is skipped:
##
## const dqe_oq_oa: ... (
## vector(1, 1, 0),
## vector(1, 0, 1),
## vector(0, 0, 0));
##
## Same as above, but also trigger on 7 or more  "oversized answer" events:
##
## const dqe_oq_oa: ... (
## vector(1, 1, 0),
## vector(1, 0, 1),
## vector(0, 0, 7));
##
## Off:
##
## const dqe_oq_oa: ... (
## vector(0, 0, 0));
##
## Off:
##
## const dqe_oq_oa: ... (
## vector(0, 0, 0),
## vector(0, 0, 0),
## vector(0, 0, 0));
##
## There is no limit imposed on the number of 3 element vectors, though any
## sane combination of settings can be accomplished with 3 or less.  

## domain_query_exceeded, oversized_query, and oversized answer settings
const dqe_oq_oa:  vector of vector of count = vector(
vector(1, 0, 1),
vector(1, 1, 0),
vector(0, 0, 3));

# Data structure for tracking query and answer events
global tracked_session: table[string] of vector of count &read_expire=2hrs;

function update_counts(uid: string, counts: vector of count)
	{
	if (uid in tracked_session)
		tracked_session[uid] = tracked_session[uid] + counts;
	else
		tracked_session[uid] = counts;
	}

function test_session(uid:string , v: vector of vector of count): string
	{
	for (i in v)
		{
		if (cat(v[i]) != cat(vector(0,0,0))
		&& tracked_session[uid][0] >= v[i][0]
		&& tracked_session[uid][1] >= v[i][1]
		&& tracked_session[uid][2] >= v[i][2])
			return cat(v[i]);
		}
		return "PASSED";
	}

function dqe_oq_oa_notice(c: connection, result: string)
	{
	local ident: string;
	if (c$id?$resp_h)
		ident = cat(c$id$orig_h,c$id$resp_h);
	else
		ident = cat(c$id$orig_h);
	NOTICE([$note=Tunneling,
		$conn=c,
		$msg="Event triggered on thresholds for domain query exceeded, oversized query, and oversized answer events.",
		$sub=fmt("Thresholds triggering event [dqe, oq, oa] :  %s", result),
		$identifier=ident,
		$suppress_for=10min
		]);
	}

event domain_query_exceeded(c: connection, domain: string)
	{
	update_counts(c$uid, vector(1,0,0));	
	local result = test_session(c$uid, dqe_oq_oa);
	if (result != "PASSED")
		{
		event AnomalousDNS::tunneling(c);
		if (tunnel_notice)
			dqe_oq_oa_notice(c,result);
		}
	}

event oversized_query(c: connection, domain: string, qsize: count)
	{
	update_counts(c$uid, vector(0,1,0));	
	local result = test_session(c$uid, dqe_oq_oa);
	if (result != "PASSED")
		{
		event AnomalousDNS::tunneling(c);
		if (tunnel_notice)
			dqe_oq_oa_notice(c,result);
		}
	}

event oversized_answer(c: connection, len: count)
	{
	update_counts(c$uid, vector(0,0,1));	
	local result = test_session(c$uid, dqe_oq_oa);
	if (result != "PASSED")
		{
		event AnomalousDNS::tunneling(c);
		if (tunnel_notice)
			dqe_oq_oa_notice(c,result);
		}
	}

event conn_duration_exceeded(c: connection)
        {
        if (c$duration > conn_duration_limit_tun)
		{
		event AnomalousDNS::tunneling(c);
		if (tunnel_notice)
			{
			NOTICE([$note=Tunneling,
				$conn=c,
				$msg=fmt("Connection duration (%ss) exceeded limit.", c$duration),
				$identifier=cat(c$id$orig_h,c$id$resp_h),
				$suppress_for=30min
				]);
			}
		}
	}

event conn_packets_exceeded(c: connection)
	{
	if (c$orig?$num_pkts && c$orig$num_pkts > conn_pkts_limit_tun)
		{
		event AnomalousDNS::tunneling(c);
		if (tunnel_notice)
			{
			NOTICE([$note=Tunneling,
				$conn=c,
				$msg=fmt("Connection packets (%s) exceeded limit.", c$orig$num_pkts),
				$identifier=cat(c$id$orig_h,c$id$resp_h),
				$suppress_for=30min
				]);
			}
		}	
	}

event blacklisted_qtype(c: connection, query: string,  qtype: count)
	{
	event AnomalousDNS::tunneling(c);
	if (tunnel_notice)
		{
		NOTICE([$note=Tunneling,
			$conn=c,
			$msg=fmt("Query: %s", query),
			$sub=fmt("Blacklisted query type: %s \"%s\"", qtype,DNS::query_types[qtype]),
			$identifier=cat(c$id$orig_h,c$id$resp_h),
			$suppress_for=10min
			]);
		}
	}
