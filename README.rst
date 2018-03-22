Anomalous-DNS
==========
A set of bro scripts providing a module for tracking and correlating abnormal
DNS behavior. Detection of tunneling and C&C through connection duration and
volume, request and answer size, DNS request type, and unique queries per domain. 

Requirements
____________
domain-tld 
https://github.com/sethhall/domain-tld 

Installation
------------

* Clone this repository to the "site" folder of your Bro system

    git clone https://github.com/jbaggs/anomalous-dns.git

* Edit local.bro adding a line to load the module

    @load anomalous-dns

If you install domain-tld somewhere other than site/packages, you
may need to update the location in __load__.bro

Documentation
_____________

Current documentation consists of inline comments. 
