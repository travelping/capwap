-record(capwap_header, {
	  radio_id,
	  wb_id,
	  flags              = [],
	  radio_mac          = undefined,
	  wireless_spec_info = undefined
}).

-include("capwap_packet_gen.hrl").
