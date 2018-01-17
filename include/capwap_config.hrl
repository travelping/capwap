%% Copyright (C) 2013-2017, Travelping GmbH <info@travelping.com>

%% This program is free software: you can redistribute it and/or modify
%% it under the terms of the GNU Affero General Public License as published by
%% the Free Software Foundation, either version 3 of the License, or
%% (at your option) any later version.

%% This program is distributed in the hope that it will be useful,
%% but WITHOUT ANY WARRANTY; without even the implied warranty of
%% MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
%% GNU Affero General Public License for more details.

%% You should have received a copy of the GNU Affero General Public License
%% along with this program.  If not, see <http://www.gnu.org/licenses/>.

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
	  broken_add_wlan_workaround,
	  radios
	 }).

-record(wtp_radio, {
	  radio_id,
	  radio_type,
	  supported_rates,
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

	  supported_cipher_suites,

	  %% IEEE 802.11n settings
	  a_msdu,
	  a_mpdu,
	  deny_non_11n,
	  short_gi,
	  bandwidth_binding,
	  max_supported_mcs,
	  max_mandatory_mcs,
	  tx_antenna,
	  rx_antenna,

	  wlans
	 }).

-record(wtp_wlan_rsn, {
	  version,
	  capabilities,
	  group_cipher_suite,
	  cipher_suites,
	  akm_suites,
	  pmk_ids,
	  group_mgmt_cipher_suite,

	  management_frame_protection
	 }).

-record(wtp_wlan_config, {
	  wlan_id,
	  ssid,
	  suppress_ssid,
	  mac_mode,
	  vlan,
	  privacy,
	  management_frame_protection,
	  fast_transition,
	  mobility_domain,
	  secret,
	  rsn,
	  peer_rekey,
	  group_rekey,
	  strict_group_rekey
	 }).

-define(DEFAULT_RADIO(RadioId, RadioType),
   [{radio_id,                RadioId},
    {radio_type,              RadioType},
    {operation_mode,          '802.11g'},
    {channel,                 undefined},
    {beacon_interval,         100},
    {dtim_period,             1},
    {short_preamble,          supported},
    {rts_threshold,           2347},
    {short_retry,             7},
    {long_retry,              4},
    {fragmentation_threshold, 2346},
    {tx_msdu_lifetime,        512},
    {rx_msdu_lifetime,        512},
    {tx_power,                100},
    {channel_assessment,      csonly},
    {energy_detect_threshold, 100},
    {band_support,            16#7F},
    {ti_threshold,            1000},
    {diversity,               disabled},
    {combiner,                omni},
    {antenna_selection,       [1]},
    {report_interval,         300},
    {wlans,                   []}]
).
