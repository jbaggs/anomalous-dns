##! Sample domain whitelist. 
##! The domain query limit script is more effective with a sparse list,
##! longer patterns, and specific servers listed when possible.

module AnomalousDNS;
redef domain_whitelist = /\.(in-addr\.arpa|ip6\.arpa|ls\.apple\.com|itunes\.apple\.com|push\.apple\.com)$|^(itunes\.apple\.com|time-ios\.apple\.com|configuration\.apple\.com|pancake\.apple\.com|xp\.apple\.com|ocsp\.apple\.com|mesu\.apple\.com|apple\.com)$/;
