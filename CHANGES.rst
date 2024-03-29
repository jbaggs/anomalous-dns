Changes
=======
Changes in version 2.0.3:
-------------------------
* replace deprecated lookup_asn function (Removing in Zeek 6.1)

Changes in version 2.0.0:
-------------------------

* Added cluster support. 

In cluster operation, tables for tracking anomalous DNS queries, 
and fast-flux candidates, will be spread across proxy nodes. 

Changes in version 1.2.3:
_________________________

* Added an-dns-fast_flux for the detection of fast flux DNS requests. 

This script requires the MaxMind GeoLite2-ASN database, and is disabled by default. 
Follow the instructions in the module's comments to configure and enable. 

Changes in version 1.2.2:
_________________________

* Set default recursive-whitelist pattern to match queries related to QNAME Minimisation. 

`(SEE: RFC 7816 section 3)
<https://tools.ietf.org/html/rfc7816.html#section-3>`_

Changes in version 1.2.0:
_________________________

* The "tunneling" event has been removed, as it was seldom used and perhaps overly ambitious.
* Package converted to zeek / zkg.

Changes in version 1.0.2:
_________________________

* Added ability to track recursive resolvers seperately in an-dns-domain.zeek.
* Added tracking of hosts that query a specific domain.
* Added "domain_untracked" constant, for defining hosts to ignore in an-dns-domain module.
* Increased default oversize_response to 544 bytes, and server_oversized_response to 3584 bytes.
* Added PTR (type 12) to server_ignore_qtypes.
* Changed the default suppression time for an-dns-domain notices to 30 min, to be a bit less noisy.

