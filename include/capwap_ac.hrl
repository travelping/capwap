-record(wpa_config, {
	  ssid,
	  privacy,
	  rsn,
	  secret,
	  peer_rekey,
	  group_rekey,
	  strict_group_rekey
	 }).

-record(wlan, {
	  wlan_identifier,

	  bss,
	  ssid,
	  suppress_ssid,
	  privacy,
	  wpa_config,

	  state,

	  group_tsc,
	  gtk_index,
	  gtk,

	  group_rekey_state,
	  group_rekey_timer
         }).
