Anomalous-DNS
==========
A set of zeek (bro) scripts providing a module for tracking and correlating abnormal
DNS behavior. Detection of tunneling and C&C through connection duration and
volume, request and answer size, DNS request type, and unique queries per domain. 

Requirements
____________

domain-tld 
https://github.com/sethhall/domain-tld 

Installation
------------

::
    bro-pkg install jbaggs/anomalous-dns

Documentation
_____________

Current documentation consists of inline comments. 
