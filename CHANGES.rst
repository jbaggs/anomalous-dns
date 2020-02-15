Changes
=======
Changes in version 1.0.1:
_________________________

* Added ability to track recursive resolvers seperately in an-dns-domain.bro.
* Added tracking of hosts that query a specific domain.
* Added "domain_untracked" constant, for defining hosts to ignore in an-dns-domain module.
* Increased default oversize_response to 544 bytes, and server_oversized_response to 3584 bytes.
* Added PTR (type 12) to server_ignore_qtypes.
* Changed the default supression time for an-dns-domain notices to 30 min, to be a bit less noisy.

