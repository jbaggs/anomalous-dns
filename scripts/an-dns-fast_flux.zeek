##! Original detection code: Seth Hall
##! Updated by: Brian Kellogg for Bro 2.3 - 12/9/2014 (removed log and added notices)
##! Updated for zeek and adapted for AnomalousDNS framework 20200903 Jeremy Baggs
##!
##! Description: Detect Fast Flux DNS requests.
##!
##! This script requires the MaxMind GeoLite2-ASN database.
##! Follow the instructions in: https://docs.zeek.org/en/current/frameworks/geoip.html
##! replacing "GeoLite2-City" with "GeoLite2-ASN". 
##!
##! Uncomment "@load ./an-dns-fast_flux" and "@load ./fast_flux-whitelist"
##! in "__load__.zeek" to enable.

module AnomalousDNS;

export {        
	redef enum Notice::Type += {
		Fast_Flux_Detected,
		Fast_Flux_Query,
	};

	type fluxer_candidate: record {
		A_hosts: set[addr]; # set of all hosts returned in A replies
		ASNs: set[count]; # set of ASNs from A lookups
        };

	type query_info: record { 
		query: string; # the candidate query
		candidate: fluxer_candidate;
	};

        ## TTL value over which we ignore DNS responses
        const TTL_threshold = 30min &redef;

	## Tracked fluxer candidates.
	##
	## In cluster operation, this table is uniformly distributed across
	## proxy nodes.
	global detect_fast_fluxers: table[string] of fluxer_candidate &write_expire=TTL_threshold + 1min;

	## The set of detected fluxers. 
	##
	## In cluster operation, this set is uniformly distributed across
	## proxy nodes.
	global fast_fluxers: set[string] &write_expire=1day;
	
	## Constants for flux score ("fluxiness") calculation 
	## from "Measuring and Detecting Fast-Flux Service Networks"
	## See: http://user.informatik.uni-goettingen.de/~krieck/docs/2008-ndss.pdf
	const flux_host_count_weight = 1.32 &redef;
	const flux_ASN_count_weight = 18.54 &redef;
	const flux_threshold = 142.38 &redef;

	## asn_disparity value below which fluxer_candidate records are removed (Default disabled)
	## If enabled, care should be taken to not make this value too large, as it could
	## allow evasion of detection through grouping DNS replies by ASN.
	const ASN_disparity_floor_enable = F &redef;
	const ASN_disparity_floor = 0.001 &redef;

	}

const ff_whitelist: pattern = /PATTERN_LOADED_FROM_FILE/ &redef;

event track_fluxer(query: string)
        {
        add fast_fluxers[query];
        }

function check_dns_fluxiness(c: connection, ans: dns_answer, fluxer: fluxer_candidate): bool
	{
	# Track the candidate so long as it remains a candidate
	local tracking = T;
	# +0.0 is to "cast" values to doubles
	local ASN_disparity = (|fluxer$ASNs|+0.0) / (|fluxer$A_hosts|+0.0);
	local score = ASN_disparity * ((flux_host_count_weight * |fluxer$A_hosts|) + (flux_ASN_count_weight * |fluxer$ASNs|));
	if ( score > flux_threshold )
		{
		event AnomalousDNS::fast_flux_detected(c, ans$query, score);
		Cluster::publish_hrw(Cluster::proxy_pool, ans$query, track_fluxer, ans$query);
		event track_fluxer(ans$query);
		# Candidate promoted to confirmed fluxer
		tracking = F;
		if ( ff_notice )
			{
			NOTICE([$note=Fast_Flux_Detected,
				$msg=fmt("Flux score for %s is %f (%d hosts in %d distinct ASNs %f asns/ips)",
				ans$query, score, |fluxer$A_hosts|, |fluxer$ASNs|, ASN_disparity),
				$sub=fmt("hosts: %s ASNs: %s  TTL:%s",cat(fluxer$A_hosts),cat(fluxer$ASNs), ans$TTL),
				$conn=c, $suppress_for=30min, $identifier=cat(ans$query,c$id$orig_h)]);
			}
		}

	else if ( ASN_disparity_floor_enable == T && ASN_disparity < ASN_disparity_floor )
		# Candidate is not looking promising
		tracking = F;

	return tracking;
	}

event Cluster::node_up(name: string, id: string)
	{
	if ( Cluster::local_node_type() != Cluster::WORKER )
		return;

        # Drop local suppression cache on workers to force HRW key repartitioning.
	AnomalousDNS::detect_fast_fluxers = table();
	AnomalousDNS::fast_fluxers = set();
	}

event Cluster::node_down(name: string, id: string)
	{
	if ( Cluster::local_node_type() != Cluster::WORKER )
		return;

	# Drop local suppression cache on workers to force HRW key repartitioning.
	AnomalousDNS::detect_fast_fluxers = table();
	AnomalousDNS::fast_fluxers = set();
	}

event track_ff_candidate(info: query_info)
	{
	detect_fast_fluxers[info$query] = info$candidate;
	}

event remove_ff_candidate(query: string)
	{
	delete detect_fast_fluxers[query];
	}

event dns_A_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr)
	{
	if ( ans$TTL > TTL_threshold )
		return;

	# Don't keep any extra state about false positives
	if ( ff_whitelist in ans$query )
		return;

	local candidate: fluxer_candidate; 
	local check_flux = F;
	if ( ans$query in detect_fast_fluxers )
		{
		candidate = detect_fast_fluxers[ans$query];
		check_flux = T;
		}

	add candidate$A_hosts[a];
	local autonomous_system = lookup_autonomous_system(a);
	if ( autonomous_system?$number )
		add candidate$ASNs[autonomous_system$number];
	if ( check_flux )
		{
		local tracking = check_dns_fluxiness(c, ans, candidate);
		if ( tracking )
			{
			Cluster::publish_hrw(Cluster::proxy_pool, ans$query, track_ff_candidate, query_info($query = ans$query, $candidate = candidate));
			event track_ff_candidate(query_info($query = ans$query, $candidate = candidate));
			}
		
		else
			{
			Cluster::publish_hrw(Cluster::proxy_pool, ans$query, remove_ff_candidate, ans$query);
			event remove_ff_candidate(ans$query);
			}
		}

	else
		{
		Cluster::publish_hrw(Cluster::proxy_pool, ans$query, track_ff_candidate, query_info($query = ans$query, $candidate = candidate));
		event track_ff_candidate(query_info($query = ans$query, $candidate = candidate));
		}
	}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
	{
	if (query in fast_fluxers)
		{
		event AnomalousDNS::fast_flux_query(c, query);
			if ( ff_notice )
			{
			NOTICE([$note=Fast_Flux_Query,
				$msg=fmt("Query for previously detected fast flux DNS record: %s from:  %s", query,cat(c$id$orig_h)),
				$conn=c, $suppress_for=30min, $identifier=cat(query,c$id$orig_h)]);
			}
		}
	}
