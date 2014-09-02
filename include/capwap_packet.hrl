-define('id-kp-capwapAC', {1,3,6,1,5,5,7,3,18}).
-define('id-kp-capwapWTP', {1,3,6,1,5,5,7,3,19}).

-record(capwap_header, {
	  radio_id,
	  wb_id,
	  flags              = [],
	  radio_mac          = undefined,
	  wireless_spec_info = undefined
}).

-record(fragment, {type, keepalive, fragmentid, fstart, fend, last, header, payload}).

-include("capwap_packet_gen.hrl").
