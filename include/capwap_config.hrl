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
	  operation_mode,
	  channel,
	  beacon_interval,
	  dtim_period,
	  short_preamble,
	  rts_threshold,
	  short_retry,
	  long_retry,
	  fragmentation_threshold,
	  tx_msdu_lifetime,
	  rx_msdu_lifetime,
	  tx_power,
	  channel_assessment,
	  energy_detect_threshold,
	  band_support,
	  ti_threshold,
	  diversity,
	  combiner,
	  antenna_selection,
	  report_interval,
	  wlans
	 }).

-record(wtp_wlan, {
	  wlan_id,
	  ssid,
	  suppress_ssid
	 }).
