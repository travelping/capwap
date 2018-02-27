%% Copyright (C) 2017, Travelping GmbH <info@travelping.com>

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

-module(capwap_packet_prop).

-compile([export_all, nowarn_export_all]).

-include_lib("capwap/include/capwap_packet.hrl").

-proptest(proper).
-proptest([triq,eqc]).

-ifndef(EQC).
-ifndef(PROPER).
-ifndef(TRIQ).
-define(PROPER,true).
%%-define(EQC,true).
%%-define(TRIQ,true).
-endif.
-endif.
-endif.

-ifdef(EQC).
-include_lib("eqc/include/eqc.hrl").
-define(MOD_eqc,eqc).

-else.
-ifdef(PROPER).
-include_lib("proper/include/proper.hrl").
-define(MOD_eqc,proper).

-else.
-ifdef(TRIQ).
-define(MOD_eqc,triq).
-include_lib("triq/include/triq.hrl").

-endif.
-endif.
-endif.

-define(equal(Expected, Actual),
    (fun (Expected@@@, Expected@@@) -> true;
	 (Expected@@@, Actual@@@) ->
	     ct:pal("MISMATCH(~s:~b, ~s)~nExpected: ~p~nActual:   ~p~n",
		    [?FILE, ?LINE, ??Actual, Expected@@@, Actual@@@]),
	     false
     end)(Expected, Actual) orelse error(badmatch)).

%%%===================================================================
%%% Tests
%%%===================================================================

%%--------------------------------------------------------------------
enc_dec_prop(Config) ->
    numtests(1000,
	     ?FORALL(Msg, msg_gen(),
		     begin
			 ct:pal("Msg: ~p", [Msg]),
			 [Enc] = capwap_packet:encode(control, Msg),
			 Dec = capwap_packet:decode(control, Enc),
			 ct:pal("Dec: ~p", [Dec]),
			 ?equal([Enc], capwap_packet:encode(control,
							  capwap_packet:decode(control, Enc)))
		     end)).

%%%===================================================================
%%% Generate PCAP with random (but valid CAPWAP packets)
%%%===================================================================

-define(PCAPNG_VERSION_MAJOR, 1).
-define(PCAPNG_VERSION_MINOR, 0).
-define(LINKTYPE_ETHERNET, 1).
-define(LINKTYPE_RAW, 101).

make_udp(NwSrc, NwDst, TpSrc, TpDst, PayLoad) ->
    Id = 0,
    Proto = gen_socket:protocol(udp),

    UDPLength = 8 + size(PayLoad),
    UDPCSum = capwap_tools:ip_csum(<<NwSrc:4/bytes-unit:8, NwDst:4/bytes-unit:8,
				     0:8, Proto:8, UDPLength:16,
				     TpSrc:16, TpDst:16, UDPLength:16, 0:16,
				     PayLoad/binary>>),
    UDP = <<TpSrc:16, TpDst:16, UDPLength:16, UDPCSum:16, PayLoad/binary>>,

    TotLen = 20 + size(UDP),
    HdrCSum = capwap_tools:ip_csum(<<4:4, 5:4, 0:8, TotLen:16,
				     Id:16, 0:16, 64:8, Proto:8,
				     0:16/integer, NwSrc:4/bytes-unit:8, NwDst:4/bytes-unit:8>>),
    IP = <<4:4, 5:4, 0:8, TotLen:16,
	   Id:16, 0:16, 64:8, Proto:8,
	   HdrCSum:16/integer, NwSrc:4/bytes-unit:8, NwDst:4/bytes-unit:8>>,
    list_to_binary([IP, UDP]).

format_pcapng(Data) ->
    TStamp = os:system_time(micro_seconds),
    Len = size(Data),
    pcapng:encode({epb, 0, TStamp, Len, [], Data}).

pcapng_shb() ->
    pcapng:encode({shb, {?PCAPNG_VERSION_MAJOR, ?PCAPNG_VERSION_MINOR},
		   [{os, <<"CAROS">>}, {userappl, <<"CAPWAP">>}]}).

pcapng_ifd(Name) ->
    pcapng:encode({ifd, ?LINKTYPE_RAW, 65535,
		   [{name,    Name},
		    {tsresol, <<6>>},
		    {os,      <<"CAROS">>}]}).

pcap_msg(Msg, Io) ->
    Data = capwap_packet:encode(Msg),
    Packet = make_udp(<<127,0,0,1>>, <<127,0,0,2>>, 8805, 8805, Data),
    Dump = format_pcapng(Packet),
    ok = file:write(Io, Dump).

gen_pcap(0, _Io) ->
    ok;
gen_pcap(Cnt, Io) ->
    {ok, Msg} = proper_gen:pick(msg_gen()),
    pcap_msg(Msg, Io),
    gen_pcap(Cnt - 1, Io).

gen_pcap(Cnt) ->
    {ok, Io} = file:open("capwap.pcap", [write, raw]),
    Header = << (pcapng_shb())/binary, (pcapng_ifd(<<"CAPWAP">>))/binary >>,
    file:write(Io, Header),
    gen_pcap(Cnt, Io),
    file:close(Io).

%%%===================================================================
%%% Internal functions
%%%===================================================================

flag() ->
    oneof([0,1]).

uint16() ->
    integer(0,16#ffff).

uint24() ->
    integer(0,16#ffffff).

uint32() ->
    integer(0,16#ffffffff).

uint64() ->
    integer(0,16#ffffffffffffffff).

ip4_address() ->
    binary(4).

ip6_address() ->
    binary(16).

mac_address() ->
    binary(6).

radio_id() ->
    integer(1,31).

wlan_id() ->
    integer(1,16).

session_id() ->
    integer(0,16#ffffffffffffffffffffffffffffffff).

seq_no() ->
    byte().

msg_gen() ->
    MsgType = msg_type(),
    {header(MsgType), {MsgType, seq_no(), ie()}}.

header(_) ->
    #capwap_header{
       radio_id = radio_id(),
       wb_id = 1
      }.

msg_type() ->
    oneof([
	   discovery_request,
	   discovery_response,
	   join_request,
	   join_response,
	   configuration_status_request,
	   configuration_status_response,
	   configuration_update_request,
	   configuration_update_response,
	   wtp_event_request,
	   wtp_event_response,
	   change_state_event_request,
	   change_state_event_response,
	   echo_request,
	   echo_response,
	   image_data_request,
	   image_data_response,
	   reset_request,
	   reset_response,
	   primary_discovery_request,
	   primary_discovery_response,
	   data_transfer_request,
	   data_transfer_response,
	   clear_configuration_request,
	   clear_configuration_response,
	   station_configuration_request,
	   station_configuration_response,
	   ieee_802_11_wlan_configuration_request,
	   ieee_802_11_wlan_configuration_response
	  ]).

simple_ie() ->
    oneof(
      [gen_ac_descriptor(),
       gen_ac_ipv4_list(),
       gen_ac_ipv6_list(),
       gen_ac_name(),
       gen_ac_name_with_priority(),
       gen_ac_timestamp(),
       gen_add_mac_acl(),
       gen_add_station(),
       gen_control_ipv4_address(),
       gen_control_ipv6_address(),
       gen_local_ipv4_address(),
       gen_local_ipv6_address(),
       gen_timers(),
       gen_transport_protocol(),
       gen_data_transfer_data(),
       gen_data_transfer_mode(),
       gen_decryption_error_report(),
       gen_decryption_error_report_period(),
       gen_delete_mac_acl_entry(),
       gen_delete_station(),
       gen_discovery_type(),
       gen_duplicate_ipv4_address(),
       gen_duplicate_ipv6_address(),
       gen_idle_timeout(),
       gen_ecn_support(),
       gen_image_data(),
       gen_image_identifier(),
       gen_image_information(),
       gen_initiate_download(),
       gen_location_data(),
       gen_maximum_message_length(),
       gen_mtu_discovery_padding(),
       gen_radio_administrative_state(),
       gen_radio_operational_state(),
       gen_result_code(),
       gen_returned_message_element(),
       gen_session_id(),
       gen_statistics_timer(),
       gen_wtp_board_data(),
       gen_wtp_descriptor(),
       gen_wtp_fallback(),
       gen_wtp_frame_tunnel_mode(),
       gen_wtp_mac_type(),
       gen_wtp_name(),
       gen_wtp_radio_statistics(),
       gen_wtp_reboot_statistics(),
       gen_wtp_static_ip_address_information(),
       gen_ieee_802_11_add_wlan(),
       gen_ieee_802_11_antenna(),
       gen_ieee_802_11_assigned_wtp_bssid(),
       gen_ieee_802_11_delete_wlan(),
       gen_ieee_802_11_direct_sequence_control(),
       gen_ieee_802_11_information_element(),
       gen_ieee_802_11_mac_operation(),
       gen_ieee_802_11_mic_countermeasures(),
       gen_ieee_802_11_multi_domain_capability(),
       gen_ieee_802_11_ofdm_control(),
       gen_ieee_802_11_rate_set(),
       gen_ieee_802_11_rsna_error_report_from_station(),
       gen_ieee_802_11_station(),
       gen_ieee_802_11_station_qos_profile(),
       gen_ieee_802_11_station_session_key(),
       gen_ieee_802_11_statistics(),
       gen_ieee_802_11_supported_rates(),
       gen_ieee_802_11_tx_power(),
       gen_ieee_802_11_tx_power_level(),
       gen_ieee_802_11_update_station_qos(),
       gen_ieee_802_11_update_wlan(),
       gen_ieee_802_11_wtp_quality_of_service(),
       gen_ieee_802_11_wtp_radio_configuration(),
       gen_ieee_802_11_wtp_radio_fail_alarm_indication(),
       gen_ieee_802_11_wtp_radio_information(),
       gen_tp_wtp_wwan_statistics_0_9(),
       gen_tp_wtp_wwan_statistics(),
       gen_tp_wtp_timestamp(),
       gen_tp_wtp_timestamp_1_1(),
       gen_tp_wtp_wwan_iccid(),
       gen_tp_ieee_802_11_wlan_hold_time(),
       gen_tp_data_channel_dead_interval(),
       gen_tp_ac_join_timeout(),
       gen_tp_ac_address_with_priority(),
       gen_wtp_apn_settings(),
       gen_wtp_administrator_password_settings(),
       gen_firmware_download_information(),
       gen_firmware_download_status(),
       gen_ieee_802_11_tp_wlan(),
       gen_apply_confirmation_timeout(),
       gen_power_save_mode(),
       gen_gps_last_acquired_position(),
       gen_ieee_802_11n_wlan_radio_configuration(),
       gen_ieee_802_11n_station_information(),
       gen_tp_ieee_802_11_encryption_capabilities(),
       gen_tp_ieee_802_11_update_key()]).

ie() ->
    ie_map(
      ?LET(I, integer(1,10), vector(I, simple_ie()))).

put_ie(IE, IEs) ->
    Key = element(1, IE),
    UpdateFun = fun(V) when is_list(V) -> V ++ [IE];
		   (undefined)         -> IE;
		   (V)                 -> [V, IE]
		end,
    maps:update_with(Key, UpdateFun, IE, IEs).

list2map(List) ->
    lists:foldl(fun put_ie/2, #{}, List).

ie_map(IEs) ->
    ?LET(L, IEs, list2map(L)).

sub_element() ->
    ?LET(I, integer(1,10), vector(I, {uint16(), binary()})).

vendor_sub_element() ->
    ?LET(I, integer(1,10), vector(I, {{uint32(), uint16()}, binary()})).

gen_ac_descriptor() ->
    #ac_descriptor{
       stations = uint16(),
       limit = uint16(),
       active_wtps = uint16(),
       max_wtps = uint16(),
       security = ?LET(S, list(oneof(['pre-shared', 'x509'])), lists:usort(S)),
       r_mac = oneof([reserved, supported, not_supported]),
       dtls_policy = ?LET(D, list(oneof(['enc-data', 'clear-text'])), lists:usort(D)),
       sub_elements = vendor_sub_element()
      }.

gen_ac_ipv4_list() ->
    #ac_ipv4_list{
       ip_address = ?LET(I, integer(1,10), vector(I, ip4_address()))
      }.

gen_ac_ipv6_list() ->
    #ac_ipv6_list{
       ip_address = ?LET(I, integer(1,10), vector(I, ip6_address()))
      }.

gen_ac_name() ->
    #ac_name{
       name = binary()
      }.

gen_ac_name_with_priority() ->
    #ac_name_with_priority{
       priority = byte(),
       name = binary()
      }.

gen_ac_timestamp() ->
    #ac_timestamp{
       timestamp = uint32()
      }.

gen_add_mac_acl() ->
    #add_mac_acl{
       macs = ?LET(I, integer(1,10), vector(I, mac_address()))
      }.

gen_add_station() ->
    #add_station{
       radio_id = radio_id(),
       mac = mac_address(),
       vlan_name = binary()
      }.

gen_control_ipv4_address() ->
    #control_ipv4_address{
       ip_address = ip4_address(),
       wtp_count = uint16()
      }.

gen_control_ipv6_address() ->
    #control_ipv6_address{
       ip_address = ip6_address(),
       wtp_count = uint16()
      }.

gen_local_ipv4_address() ->
    #local_ipv4_address{
       ip_address = ip4_address()
      }.

gen_local_ipv6_address() ->
    #local_ipv6_address{
       ip_address = ip6_address()
      }.

gen_timers() ->
    #timers{
       discovery = byte(),
       echo_request = byte()
      }.

gen_transport_protocol() ->
    #transport_protocol{
       transport = oneof([udp_lite, udp])
      }.

gen_data_transfer_data() ->
    #data_transfer_data{
       data_type = oneof([included, eof, error]),
       data_mode = oneof([reserved, crash_data, memory_dump]),
       data = binary()
      }.

gen_data_transfer_mode() ->
    #data_transfer_mode{
       data_mode = oneof([reserved, crash_data, memory_dump])
      }.

gen_decryption_error_report() ->
    #decryption_error_report{
       radio_id = radio_id(),
       macs = ?LET(I, integer(1,10), vector(I, mac_address()))
      }.

gen_decryption_error_report_period() ->
    #decryption_error_report_period{
       radio_id = radio_id(),
       report_interval = uint16()
      }.

gen_delete_mac_acl_entry() ->
    #delete_mac_acl_entry{
       macs = ?LET(I, integer(1,10), vector(I, mac_address()))
      }.

gen_delete_station() ->
    #delete_station{
       radio_id = radio_id(),
       mac = mac_address()
      }.

gen_discovery_type() ->
    #discovery_type{
	discovery_type =
	   oneof([unknown, static, dhcp, dns, 'AC-Referral'])
      }.

gen_duplicate_ipv4_address() ->
    #duplicate_ipv4_address{
       ip_address = ip4_address(),
       status = byte(),
       mac = mac_address()
      }.

gen_duplicate_ipv6_address() ->
    #duplicate_ipv6_address{
       ip_address = ip6_address(),
       status = byte(),
       mac = mac_address()
      }.

gen_idle_timeout() ->
    #idle_timeout{
       timeout = uint32()
      }.

gen_ecn_support() ->
    #ecn_support{
       ecn_support = oneof([limited, full])
      }.

gen_image_data() ->
    #image_data{
       data_type = oneof([included, eof, error]),
       data = binary()
      }.

gen_image_identifier() ->
    #image_identifier{
       vendor = uint32(),
       data = binary()
    }.

gen_image_information() ->
    #image_information{
       file_size = uint32(),
       hash = binary(16)
      }.

gen_initiate_download() ->
    #initiate_download{
      }.

gen_location_data() ->
    #location_data{
       location = binary()
      }.

gen_maximum_message_length() ->
    #maximum_message_length{
       maximum_message_length = uint16()
      }.

gen_mtu_discovery_padding() ->
    #mtu_discovery_padding{
       padding = binary()
      }.

gen_radio_administrative_state() ->
    #radio_administrative_state{
       radio_id = radio_id(),
       admin_state = reserved
      }.

gen_radio_operational_state() ->
    #radio_operational_state{
       radio_id = radio_id(),
       state = oneof([reserved, enabled, disabled]),
       cause = oneof([normal, radio_failure, software_failure, admin_set])
      }.

gen_result_code() ->
    #result_code{
       result_code = uint32()
      }.

gen_returned_message_element() ->
    #returned_message_element{
       reason = oneof([reserved, unknown_ie, unsupported_ie,
		       unknown_ie_value, unsupported_ie_value]),
       message_element = binary()
      }.

gen_session_id() ->
    #session_id{
       session_id = session_id()
      }.

gen_statistics_timer() ->
    #statistics_timer{
       statistics_timer = uint16()
      }.

gen_wtp_board_data() ->
    #wtp_board_data{
       vendor = uint32(),
       board_data_sub_elements = sub_element()
      }.

gen_wtp_descriptor() ->
    #wtp_descriptor{
       max_radios = byte(),
       radios_in_use = byte(),
       encryption_sub_element = ?LET(I, integer(1,10), vector(I, binary(3))),
       sub_elements = vendor_sub_element()
      }.

gen_wtp_fallback() ->
    #wtp_fallback{
       mode = oneof([reserved, enabled, disabled])
      }.

gen_wtp_frame_tunnel_mode() ->
    #wtp_frame_tunnel_mode{
       mode = ?LET(S, list(oneof(['native', '802.3'])), lists:usort(S))
      }.

gen_wtp_mac_type() ->
    #wtp_mac_type{
       mac_type = oneof([local, split, both])
      }.

gen_wtp_name() ->
    #wtp_name{
       wtp_name = binary()
      }.

gen_wtp_radio_statistics() ->
    #wtp_radio_statistics{
       radio_id = radio_id(),
       last_fail_type = oneof([unsuported, software, hardware, other]),
       reset_count = uint16(),
       sw_failure_count = uint16(),
       hw_failure_count = uint16(),
       other__failure_count = uint16(),
       unknown_failure_count = uint16(),
       config_update_count = uint16(),
       channel_change_count = uint16(),
       band_change_count = uint16(),
       current_noise_floor = uint16()
      }.

gen_wtp_reboot_statistics() ->
    #wtp_reboot_statistics{
       reboot_count_ = uint16(),
       ac_initiated_count = uint16(),
       link_failure_count = uint16(),
       sw_failure_count = uint16(),
       hw_failure_count = uint16(),
       other_failure_count = uint16(),
       unknown_failure_count = uint16(),
       last_failure_type = oneof([unsuported, ac_initiated, link_failure,
				  software, hardware, other])
      }.

gen_wtp_static_ip_address_information() ->
    #wtp_static_ip_address_information{
       ip_address = ip4_address(),
       netmask = ip4_address(),
       gateway = ip4_address(),
       static = byte()
      }.

gen_ieee_802_11_add_wlan() ->
    #ieee_802_11_add_wlan{
       radio_id = radio_id(),
       wlan_id = wlan_id(),
       capability = ?LET(S, list(oneof(['ess', 'ibss', 'cf-pollable', 'cf-poll-request',
					'privacy', 'short_preamble', 'pbcc',
					'channel_agility', 'spectrum_management', 'qos',
					'short_slot_time', 'apsd', 'reserved', 'dsss_ofdm',
					'delayed_block_ack'])), lists:usort(S)),
       key_index = byte(),
       key_status = oneof([per_station, static_wep, begin_rekeying, completed_rekeying]),
       key = binary(32),
       group_tsc = binary(6),
       qos = oneof([best_effort, video, voice, background]),
       auth_type = oneof([open_system, wep_shared_key]),
       mac_mode = oneof([local_mac, split_mac]),
       tunnel_mode = oneof([local_bridge, '802_3_tunnel', '802_11_tunnel']),
       suppress_ssid = byte(),
       ssid = binary()
      }.

gen_ieee_802_11_antenna() ->
    #ieee_802_11_antenna{
       radio_id = radio_id(),
       diversity = oneof([disabled, enabled]),
       combiner = oneof([left, right, omni, mimo]),
       antenna_selection = binary()
      }.

gen_ieee_802_11_assigned_wtp_bssid() ->
    #ieee_802_11_assigned_wtp_bssid{
       radio_id = radio_id(),
       wlan_id = wlan_id(),
       bssid = mac_address()
      }.

gen_ieee_802_11_delete_wlan() ->
    #ieee_802_11_delete_wlan{
       radio_id = radio_id(),
       wlan_id = wlan_id()
      }.

gen_ieee_802_11_direct_sequence_control() ->
    #ieee_802_11_direct_sequence_control{
       radio_id = radio_id(),
       current_chan = byte(),
       current_cca = oneof([edonly, csonly, edandcs, cswithtimer, hrcsanded]),
       energy_detect_threshold = uint32()
      }.

gen_ieee_802_11_information_element() ->
    #ieee_802_11_information_element{
       radio_id = radio_id(),
       wlan_id = wlan_id(),
       flags = ?LET(S, list(oneof(['beacon', 'probe_response'])), lists:usort(S)),
       ie = binary()
      }.

gen_ieee_802_11_mac_operation() ->
    #ieee_802_11_mac_operation{
       radio_id = radio_id(),
       rts_threshold = uint16(),
       short_retry = byte(),
       long_retry = byte(),
       fragmentation_threshold = uint16(),
       tx_msdu_lifetime = uint32(),
       rx_msdu_lifetime = uint32()
      }.

gen_ieee_802_11_mic_countermeasures() ->
    #ieee_802_11_mic_countermeasures{
       radio_id = radio_id(),
       wlan_id = wlan_id(),
       mac = mac_address()
      }.

gen_ieee_802_11_multi_domain_capability() ->
    #ieee_802_11_multi_domain_capability{
       radio_id = radio_id(),
       first_channel = uint16(),
       number_of_channels_ = uint16(),
       max_tx_power_level = uint16()
      }.

gen_ieee_802_11_ofdm_control() ->
    #ieee_802_11_ofdm_control{
       radio_id = radio_id(),
       current_chan = byte(),
       band_support = byte(),
       ti_threshold = uint32()
      }.

gen_ieee_802_11_rate_set() ->
    #ieee_802_11_rate_set{
       radio_id = radio_id(),
       rate_set = ?LET(I, integer(1,8), vector(I, byte()))
      }.

gen_ieee_802_11_rsna_error_report_from_station() ->
    #ieee_802_11_rsna_error_report_from_station{
       client_mac_address = mac_address(),
       bssid = mac_address(),
       radio_id = radio_id(),
       wlan_id = wlan_id(),
       tkip_icv_errors = uint32(),
       tkip_local_mic_failures = uint32(),
       tkip_remote_mic_failures = uint32(),
       ccmp_replays = uint32(),
       ccmp_decrypt_errors = uint32(),
       tkip_replays = uint32()
      }.

gen_ieee_802_11_station() ->
    #ieee_802_11_station{
       radio_id = radio_id(),
       association_id = uint16(),
       mac_address = mac_address(),
       capabilities = ?LET(S, list(oneof(['ess', 'ibss', 'cf-pollable', 'cf-poll-request',
					  'privacy', 'short_preamble', 'pbcc',
					  'channel_agility', 'spectrum_management', 'qos',
					  'short_slot_time', 'apsd', 'reserved', 'dsss_ofdm',
					  'delayed_block_ack'])), lists:usort(S)),
       wlan_id = wlan_id(),
       supported_rate = ?LET(I, integer(1,8), vector(I, byte()))
      }.

gen_ieee_802_11_station_qos_profile() ->
    #ieee_802_11_station_qos_profile{
       mac_address = mac_address(),
       p8021p = integer(0, 7)
      }.

gen_ieee_802_11_station_session_key() ->
    #ieee_802_11_station_session_key{
       mac_address = mac_address(),
       flags = ?LET(S, list(oneof(['akm_only', 'ac_crypto'])), lists:usort(S)),
       pairwise_tsc = binary(6),
       pairwise_rsc = binary(6),
       key = binary(32)
      }.

gen_ieee_802_11_statistics() ->
    #ieee_802_11_statistics{
       radio_id = radio_id(),
       tx_fragment_count = uint32(),
       multicast_tx_count = uint32(),
       failed_count = uint32(),
       retry_count = uint32(),
       multiple_retry_count = uint32(),
       frame_duplicate_count = uint32(),
       rts_success_count = uint32(),
       rts_failure_count = uint32(),
       ack_failure_count = uint32(),
       rx_fragment_count = uint32(),
       multicast_rx_count = uint32(),
       fcs_error__count = uint32(),
       tx_frame_count = uint32(),
       decryption_errors = uint32(),
       discarded_qos_fragment_count = uint32(),
       associated_station_count = uint32(),
       qos_cf_polls_received_count = uint32(),
       qos_cf_polls_unused_count = uint32(),
       qos_cf_polls_unusable_count = uint32()
      }.

gen_ieee_802_11_supported_rates() ->
    #ieee_802_11_supported_rates{
       radio_id = radio_id(),
       supported_rates = ?LET(I, integer(1,8), vector(I, byte()))
      }.

gen_ieee_802_11_tx_power() ->
    #ieee_802_11_tx_power{
       radio_id = radio_id(),
       current_tx_power = uint16()
      }.

gen_ieee_802_11_tx_power_level() ->
    #ieee_802_11_tx_power_level{
       radio_id = radio_id(),
       power_level = ?LET(I, integer(1,8), vector(I, binary(2)))
      }.

gen_ieee_802_11_update_station_qos() ->
    #ieee_802_11_update_station_qos{
       radio_id = radio_id(),
       mac_address = mac_address(),
       qos_sub_element = binary(8)
      }.

gen_ieee_802_11_update_wlan() ->
    #ieee_802_11_update_wlan{
       radio_id = radio_id(),
       wlan_id = wlan_id(),
       capability = ?LET(S, list(oneof(['ess', 'ibss', 'cf-pollable', 'cf-poll-request',
					'privacy', 'short_preamble', 'pbcc',
					'channel_agility', 'spectrum_management', 'qos',
					'short_slot_time', 'apsd', 'reserved', 'dsss_ofdm',
					'delayed_block_ack'])), lists:usort(S)),
       key_index = byte(),
       key_status = oneof([per_station, static_wep, begin_rekeying, completed_rekeying]),
       key = binary(32)
      }.

gen_ieee_802_11_wtp_quality_of_service() ->
    #ieee_802_11_wtp_quality_of_service{
       radio_id = radio_id(),
       tagging_policy = bitstring(5),
       qos_sub_element = binary(32)
      }.

gen_ieee_802_11_wtp_radio_configuration() ->
    #ieee_802_11_wtp_radio_configuration{
       radio_id = radio_id(),
       short_preamble = oneof([unsupported, supported]),
       num_of_bssids = byte(),
       dtim_period = byte(),
       bssid = mac_address(),
       beacon_period = uint16(),
       country_string = binary(4)
      }.

gen_ieee_802_11_wtp_radio_fail_alarm_indication() ->
    #ieee_802_11_wtp_radio_fail_alarm_indication{
       radio_id = radio_id(),
       type = oneof([receiver, transmitter]),
       status = byte()
      }.

gen_ieee_802_11_wtp_radio_information() ->
    #ieee_802_11_wtp_radio_information{
       radio_id = radio_id(),
       radio_type = ?LET(S, list(oneof(['802.11n', '802.11g',
					'802.11a', '802.11b'])), lists:usort(S))
      }.

gen_tp_wtp_wwan_statistics_0_9() ->
    #tp_wtp_wwan_statistics_0_9{
       timestamp = uint32(),
       wwan_id = byte(),
       rat = byte(),
       rssi = byte(),
       lac = uint16(),
       cell_id = uint32()
      }.

gen_tp_wtp_wwan_statistics() ->
    #tp_wtp_wwan_statistics{
       timestamp = uint32(),
       wwan_id = byte(),
       rat = byte(),
       rssi = byte(),
       creg = byte(),
       lac = uint16(),
       latency = uint16(),
       mcc = integer(0,16#3ff),
       mnc = integer(0,16#3ff),
       cell_id = uint32()
      }.

gen_tp_wtp_timestamp() ->
    #tp_wtp_timestamp{
       second = uint32(),
       fraction = uint32()
      }.

gen_tp_wtp_timestamp_1_1() ->
    #tp_wtp_timestamp_1_1{
       second = uint32()
      }.

gen_tp_wtp_wwan_iccid() ->
    #tp_wtp_wwan_iccid{
       wwan_id = byte(),
       iccid = binary()
      }.

gen_tp_ieee_802_11_wlan_hold_time() ->
    #tp_ieee_802_11_wlan_hold_time{
       radio_id = radio_id(),
       wlan_id = wlan_id(),
       hold_time = uint16()
      }.

gen_tp_data_channel_dead_interval() ->
    #tp_data_channel_dead_interval{
       data_channel_dead_interval = uint16()
      }.

gen_tp_ac_join_timeout() ->
    #tp_ac_join_timeout{
       ac_join_timeout = uint16()
      }.

gen_tp_ac_address_with_priority() ->
    #tp_ac_address_with_priority{
       priority = byte(),
       type = byte(),
       value = oneof([ip4_address(), ip6_address()])
      }.

gen_wtp_apn_settings() ->
    #wtp_apn_settings{
       apn = binary(),
       username = binary(),
       password = binary()
      }.

gen_wtp_administrator_password_settings() ->
    #wtp_administrator_password_settings{
       password = binary()
      }.

gen_firmware_download_information() ->
    #firmware_download_information{
       sha256_image_hash = binary(32),
       download_uri = binary()
      }.

gen_firmware_download_status() ->
    #firmware_download_status{
       status = oneof([reserved, in_progress, download_finished_successfully,
		       download_failed]),
       bytes_downloaded = uint32(),
       bytes_remaining = uint32()
      }.

gen_ieee_802_11_tp_wlan() ->
    #ieee_802_11_tp_wlan{
       radio_id = radio_id(),
       wlan_id = wlan_id(),
       capability = [],
       key_index = byte(),
       key_status = oneof([per_station, static_wep, begin_rekeying, completed_rekeying]),
       key = binary(32),
       group_tsc = binary(6),
       qos = oneof([best_effort, video, voice, background]),
       auth_type = oneof([open_system, wep_shared_key]),
       mac_mode = oneof([local_mac, split_mac]),
       tunnel_mode = oneof([local_bridge, '802_3_tunnel', '802_11_tunnel']),
       suppress_ssid = byte(),
       ssid = binary()
      }.

gen_apply_confirmation_timeout() ->
    #apply_confirmation_timeout{
       apply_confirmation_timeout = uint16()
      }.

gen_power_save_mode() ->
    #power_save_mode{
       idle_timeout = uint32(),
       busy_timeout = uint32()
      }.

gen_gps_last_acquired_position() ->
    #gps_last_acquired_position{
       timestamp = uint32(),
       wwan_id = byte(),
       gpsatc = binary()
      }.

gen_ieee_802_11n_wlan_radio_configuration() ->
    #ieee_802_11n_wlan_radio_configuration{
       radio_id = radio_id(),
       a_msdu = flag(),
       a_mpdu = flag(),
       deny_non_11n = flag(),
       short_gi = flag(),
       bandwidth_binding = flag(),
       max_supported_mcs = byte(),
       max_mandatory_mcs = byte(),
       tx_antenna = byte(),
       rx_antenna = byte()
      }.

gen_ieee_802_11n_station_information() ->
    #ieee_802_11n_station_information{
       mac_address = mac_address(),
       bandwith_40mhz = flag(),
       power_save_mode = oneof([static, dynamic, reserved, disabled]),
       sgi_20mhz = flag(),
       sgi_40mhz = flag(),
       ba_delay_mode = flag(),
       max_a_msdu = flag(),
       max_rxfactor = byte(),
       min_staspacing = byte(),
       hisuppdatarate = uint16(),
       ampdubufsize = byte(),
       htcsupp = byte(),
       mcs_set = binary(10)
      }.

gen_tp_ieee_802_11_encryption_capabilities() ->
    #tp_ieee_802_11_encryption_capabilities{
       radio_id = radio_id(),
       cipher_suites = ?LET(I, integer(1,8), vector(I, uint32()))
      }.

gen_tp_ieee_802_11_update_key() ->
    #tp_ieee_802_11_update_key{
       radio_id = radio_id(),
       wlan_id = wlan_id(),
       key_index = byte(),
       key_status = oneof([per_station, static_wep, begin_rekeying, completed_rekeying]),
       cipher_suite = uint32(),
       key = binary(32)
      }.
