-record(wtp, {
	  psm_idle_timeout,
	  psm_busy_timeout,
	  max_stations,
	  echo_request_interval,
	  discovery_interval,
	  idle_timeout,
	  data_channel_dead_interval,
	  ac_join_timeout,
	  admin_pw,
	  wlan_hold_time,
	  radios
	 }).

-record(wtp_radio, {
	  radio_id,
	  radio_type,
	  channel,
	  wlans
	 }).

-record(wtp_wlan, {
	  wlan_id,
	  ssid,
	  suppress_ssid
	 }).
