##! AnomalousDNS: connection submodule.
##!
##! DNS "connections" are typically short and consist of few packets.
##! These events firing are a good indication something is not right.  
##! 
##! Author: Jeremy Baggs

module AnomalousDNS;

export {
	redef enum Notice::Type += {
		Conn_Duration,
		Conn_Packets,
	};
	## Connection duration limit 
	const conn_duration_limit = 45secs &redef;

	## Connection packets limit, measured on origin 
	const conn_pkts_limit  = 12 &redef;
}

event dns_message(c: connection, is_orig: bool, msg: dns_msg, len: count)
	{
	if ( c$duration > conn_duration_limit )
		{
		event AnomalousDNS::conn_duration_exceeded(c);
		if( conn_notice )
			{
			NOTICE([$note=Conn_Duration,
				$conn=c,
				$msg=fmt("Connection duration (%ss) exceeded limit.", c$duration),
				$identifier=cat(c$id$orig_h,c$id$resp_h),
				$suppress_for=30min
				]);
			}
		}

        if ( c$orig?$num_pkts && c$orig$num_pkts > conn_pkts_limit )
                {
                event AnomalousDNS::conn_packets_exceeded(c);
		if ( conn_notice )
			{
			NOTICE([$note=Conn_Packets,
				$conn=c,
				$msg=fmt("Connection packets (%s) exceeded limit.", c$orig$num_pkts),
				$identifier=cat(c$id$orig_h,c$id$resp_h),
				$suppress_for=30min
				]);
			}
                }

	}
