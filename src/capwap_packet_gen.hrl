%% This file is auto-generated. DO NOT EDIT

msg_description(discovery_request) -> <<"Discovery Request">>;
msg_description(discovery_response) -> <<"Discovery Response">>;
msg_description(join_request) -> <<"Join Request">>;
msg_description(join_response) -> <<"Join Response">>;
msg_description(configuration_status_request) -> <<"Configuration Status Request">>;
msg_description(configuration_status_response) -> <<"Configuration Status Response">>;
msg_description(configuration_update_request) -> <<"Configuration Update Request">>;
msg_description(configuration_update_response) -> <<"Configuration Update Response">>;
msg_description(wtp_event_request) -> <<"WTP Event Request">>;
msg_description(wtp_event_response) -> <<"WTP Event Response">>;
msg_description(change_state_event_request) -> <<"Change State Event Request">>;
msg_description(change_state_event_response) -> <<"Change State Event Response">>;
msg_description(echo_request) -> <<"Echo Request">>;
msg_description(echo_response) -> <<"Echo Response">>;
msg_description(image_data_request) -> <<"Image Data Request">>;
msg_description(image_data_response) -> <<"Image Data Response">>;
msg_description(reset_request) -> <<"Reset Request">>;
msg_description(reset_response) -> <<"Reset Response">>;
msg_description(primary_discovery_request) -> <<"Primary Discovery Request">>;
msg_description(primary_discovery_response) -> <<"Primary Discovery Response">>;
msg_description(data_transfer_request) -> <<"Data Transfer Request">>;
msg_description(data_transfer_response) -> <<"Data Transfer Response">>;
msg_description(clear_configuration_request) -> <<"Clear Configuration Request">>;
msg_description(clear_configuration_response) -> <<"Clear Configuration Response">>;
msg_description(station_configuration_request) -> <<"Station Configuration Request">>;
msg_description(station_configuration_response) -> <<"Station Configuration Response">>;
msg_description(ieee_802_11_wlan_configuration_request) -> <<"IEEE 802.11 WLAN Configuration Request">>;
msg_description(ieee_802_11_wlan_configuration_response) -> <<"IEEE 802.11 WLAN Configuration Response">>;
msg_description(X) -> io_lib:format("~p", [X]).

message_type(discovery_request) -> {0, 1};
message_type(discovery_response) -> {0, 2};
message_type(join_request) -> {0, 3};
message_type(join_response) -> {0, 4};
message_type(configuration_status_request) -> {0, 5};
message_type(configuration_status_response) -> {0, 6};
message_type(configuration_update_request) -> {0, 7};
message_type(configuration_update_response) -> {0, 8};
message_type(wtp_event_request) -> {0, 9};
message_type(wtp_event_response) -> {0, 10};
message_type(change_state_event_request) -> {0, 11};
message_type(change_state_event_response) -> {0, 12};
message_type(echo_request) -> {0, 13};
message_type(echo_response) -> {0, 14};
message_type(image_data_request) -> {0, 15};
message_type(image_data_response) -> {0, 16};
message_type(reset_request) -> {0, 17};
message_type(reset_response) -> {0, 18};
message_type(primary_discovery_request) -> {0, 19};
message_type(primary_discovery_response) -> {0, 20};
message_type(data_transfer_request) -> {0, 21};
message_type(data_transfer_response) -> {0, 22};
message_type(clear_configuration_request) -> {0, 23};
message_type(clear_configuration_response) -> {0, 24};
message_type(station_configuration_request) -> {0, 25};
message_type(station_configuration_response) -> {0, 26};
message_type(ieee_802_11_wlan_configuration_request) -> {13277, 1};
message_type(ieee_802_11_wlan_configuration_response) -> {13277, 2};
message_type({0, 1}) -> discovery_request;
message_type({0, 2}) -> discovery_response;
message_type({0, 3}) -> join_request;
message_type({0, 4}) -> join_response;
message_type({0, 5}) -> configuration_status_request;
message_type({0, 6}) -> configuration_status_response;
message_type({0, 7}) -> configuration_update_request;
message_type({0, 8}) -> configuration_update_response;
message_type({0, 9}) -> wtp_event_request;
message_type({0, 10}) -> wtp_event_response;
message_type({0, 11}) -> change_state_event_request;
message_type({0, 12}) -> change_state_event_response;
message_type({0, 13}) -> echo_request;
message_type({0, 14}) -> echo_response;
message_type({0, 15}) -> image_data_request;
message_type({0, 16}) -> image_data_response;
message_type({0, 17}) -> reset_request;
message_type({0, 18}) -> reset_response;
message_type({0, 19}) -> primary_discovery_request;
message_type({0, 20}) -> primary_discovery_response;
message_type({0, 21}) -> data_transfer_request;
message_type({0, 22}) -> data_transfer_response;
message_type({0, 23}) -> clear_configuration_request;
message_type({0, 24}) -> clear_configuration_response;
message_type({0, 25}) -> station_configuration_request;
message_type({0, 26}) -> station_configuration_response;
message_type({13277, 1}) -> ieee_802_11_wlan_configuration_request;
message_type({13277, 2}) -> ieee_802_11_wlan_configuration_response;
message_type({Vendor, Type}) when is_integer(Vendor), is_integer(Type) -> {Vendor, Type}.

enum_tunnel_mode(local_bridge) -> 0;
enum_tunnel_mode('802_3_tunnel') -> 1;
enum_tunnel_mode('802_11_tunnel') -> 2;
enum_tunnel_mode(0) -> local_bridge;
enum_tunnel_mode(1) -> '802_3_tunnel';
enum_tunnel_mode(2) -> '802_11_tunnel'.

enum_mac_mode(local_mac) -> 0;
enum_mac_mode(split_mac) -> 1;
enum_mac_mode(0) -> local_mac;
enum_mac_mode(1) -> split_mac.

enum_auth_type(open_system) -> 0;
enum_auth_type(wep_shared_key) -> 1;
enum_auth_type(0) -> open_system;
enum_auth_type(1) -> wep_shared_key.

enum_qos(best_effort) -> 0;
enum_qos(video) -> 1;
enum_qos(voice) -> 2;
enum_qos(backgroung) -> 3;
enum_qos(0) -> best_effort;
enum_qos(1) -> video;
enum_qos(2) -> voice;
enum_qos(3) -> backgroung.

enum_key_status(per_station) -> 0;
enum_key_status(static_wep) -> 1;
enum_key_status(begin_rekeying) -> 2;
enum_key_status(completed_rekeying) -> 3;
enum_key_status(0) -> per_station;
enum_key_status(1) -> static_wep;
enum_key_status(2) -> begin_rekeying;
enum_key_status(3) -> completed_rekeying.

enum_status(reserved) -> 0;
enum_status(in_progress) -> 1;
enum_status(download_finished_successfully) -> 2;
enum_status(download_failed) -> 3;
enum_status(0) -> reserved;
enum_status(1) -> in_progress;
enum_status(2) -> download_finished_successfully;
enum_status(3) -> download_failed.

enum_type(receiver) -> 0;
enum_type(transmitter) -> 1;
enum_type(0) -> receiver;
enum_type(1) -> transmitter.

enum_short_preamble(unsupported) -> 0;
enum_short_preamble(supported) -> 1;
enum_short_preamble(0) -> unsupported;
enum_short_preamble(1) -> supported.

enum_current_cca(edonly) -> 1;
enum_current_cca(csonly) -> 2;
enum_current_cca(edandcs) -> 4;
enum_current_cca(cswithtimer) -> 8;
enum_current_cca(hrcsanded) -> 16;
enum_current_cca(1) -> edonly;
enum_current_cca(2) -> csonly;
enum_current_cca(4) -> edandcs;
enum_current_cca(8) -> cswithtimer;
enum_current_cca(16) -> hrcsanded.

enum_combiner(left) -> 1;
enum_combiner(right) -> 2;
enum_combiner(omni) -> 3;
enum_combiner(mimo) -> 4;
enum_combiner(1) -> left;
enum_combiner(2) -> right;
enum_combiner(3) -> omni;
enum_combiner(4) -> mimo.

enum_diversity(disabled) -> 0;
enum_diversity(enabled) -> 1;
enum_diversity(0) -> disabled;
enum_diversity(1) -> enabled.

enum_last_failure_type(unsuported) -> 0;
enum_last_failure_type(ac_initiated) -> 1;
enum_last_failure_type(link_failure) -> 2;
enum_last_failure_type(software) -> 3;
enum_last_failure_type(hardware) -> 4;
enum_last_failure_type(other) -> 255;
enum_last_failure_type(0) -> unsuported;
enum_last_failure_type(1) -> ac_initiated;
enum_last_failure_type(2) -> link_failure;
enum_last_failure_type(3) -> software;
enum_last_failure_type(4) -> hardware;
enum_last_failure_type(255) -> other.

enum_last_fail_type(unsuported) -> 0;
enum_last_fail_type(software) -> 1;
enum_last_fail_type(hardware) -> 2;
enum_last_fail_type(other) -> 255;
enum_last_fail_type(0) -> unsuported;
enum_last_fail_type(1) -> software;
enum_last_fail_type(2) -> hardware;
enum_last_fail_type(255) -> other.

enum_mac_type(local) -> 0;
enum_mac_type(split) -> 1;
enum_mac_type(both) -> 2;
enum_mac_type(0) -> local;
enum_mac_type(1) -> split;
enum_mac_type(2) -> both.

enum_mode(reserved) -> 0;
enum_mode(enabled) -> 1;
enum_mode(disabled) -> 2;
enum_mode(0) -> reserved;
enum_mode(1) -> enabled;
enum_mode(2) -> disabled.

enum_reason(reserved) -> 0;
enum_reason(unknown_ie) -> 1;
enum_reason(unsupported_ie) -> 2;
enum_reason(unknown_ie_value) -> 3;
enum_reason(unsupported_ie_value) -> 4;
enum_reason(0) -> reserved;
enum_reason(1) -> unknown_ie;
enum_reason(2) -> unsupported_ie;
enum_reason(3) -> unknown_ie_value;
enum_reason(4) -> unsupported_ie_value.

enum_cause(normal) -> 0;
enum_cause(radio_failure) -> 1;
enum_cause(software_failure) -> 2;
enum_cause(admin_set) -> 3;
enum_cause(0) -> normal;
enum_cause(1) -> radio_failure;
enum_cause(2) -> software_failure;
enum_cause(3) -> admin_set.

enum_state(reserved) -> 0;
enum_state(enabled) -> 1;
enum_state(disabled) -> 2;
enum_state(0) -> reserved;
enum_state(1) -> enabled;
enum_state(2) -> disabled.

enum_admin_state(reserved) -> 0;
enum_admin_state(enabled) -> 1;
enum_admin_state(disabled) -> 2;
enum_admin_state(0) -> reserved;
enum_admin_state(1) -> enabled;
enum_admin_state(2) -> disabled.

enum_data_type(included) -> 1;
enum_data_type(eof) -> 2;
enum_data_type(error) -> 5;
enum_data_type(1) -> included;
enum_data_type(2) -> eof;
enum_data_type(5) -> error.

enum_ecn_support(limited) -> 0;
enum_ecn_support(full) -> 1;
enum_ecn_support(0) -> limited;
enum_ecn_support(1) -> full.

enum_discovery_type(unknown) -> 0;
enum_discovery_type(static) -> 1;
enum_discovery_type(dhcp) -> 2;
enum_discovery_type(dns) -> 3;
enum_discovery_type('AC-Referral') -> 4;
enum_discovery_type(0) -> unknown;
enum_discovery_type(1) -> static;
enum_discovery_type(2) -> dhcp;
enum_discovery_type(3) -> dns;
enum_discovery_type(4) -> 'AC-Referral'.

enum_data_mode(reserved) -> 0;
enum_data_mode(crash_data) -> 1;
enum_data_mode(memory_dump) -> 2;
enum_data_mode(0) -> reserved;
enum_data_mode(1) -> crash_data;
enum_data_mode(2) -> memory_dump.

enum_transport(udp_lite) -> 1;
enum_transport(udp) -> 2;
enum_transport(1) -> udp_lite;
enum_transport(2) -> udp.

enum_r_mac(reserved) -> 0;
enum_r_mac(supported) -> 1;
enum_r_mac(not_supported) -> 2;
enum_r_mac(0) -> reserved;
enum_r_mac(1) -> supported;
enum_r_mac(2) -> not_supported.

decode_element(1, <<M_stations:16/integer,
                    M_limit:16/integer,
                    M_active_wtps:16/integer,
                    M_max_wtps:16/integer,
                    _:5,
                    M_security_pre_shared:1,
                    M_security_x509:1,
                    _:1,
                    M_r_mac:8/integer,
                    _:8,
                    _:5,
                    M_dtls_policy_enc_data:1,
                    M_dtls_policy_clear_text:1,
                    _:1,
                    M_sub_elements/binary>>) ->
    #ac_descriptor{stations = M_stations,
                   limit = M_limit,
                   active_wtps = M_active_wtps,
                   max_wtps = M_max_wtps,
                   security = [ 'pre-shared' || M_security_pre_shared =/= 0 ] ++ [ 'x509' || M_security_x509 =/= 0 ],
                   r_mac = enum_r_mac(M_r_mac),
                   dtls_policy = [ 'enc-data' || M_dtls_policy_enc_data =/= 0 ] ++ [ 'clear-text' || M_dtls_policy_clear_text =/= 0 ],
                   sub_elements = decode_vendor_subelements(M_sub_elements)};

decode_element(2, <<M_ip_address/binary>>) ->
    #ac_ipv4_list{ip_address = decode_ipv4_list(M_ip_address)};

decode_element(3, <<M_ip_address/binary>>) ->
    #ac_ipv6_list{ip_address = decode_ipv6_list(M_ip_address)};

decode_element(4, <<M_name/binary>>) ->
    #ac_name{name = M_name};

decode_element(5, <<M_priority:8/integer,
                    M_name/binary>>) ->
    #ac_name_with_priority{priority = M_priority,
                           name = M_name};

decode_element(6, <<M_timestamp:32/integer>>) ->
    #ac_timestamp{timestamp = M_timestamp};

decode_element(7, <<M_macs/binary>>) ->
    #add_mac_acl{macs = decode_mac_list(M_macs)};

decode_element(8, <<M_radio_id:8/integer,
                    M_mac_len:8/integer, M_mac:M_mac_len/bytes,
                    M_vlan_name/binary>>) ->
    #add_station{radio_id = M_radio_id,
                 mac = M_mac,
                 vlan_name = M_vlan_name};

decode_element(10, <<M_ip_address:4/bytes,
                     M_wtp_count:16/integer>>) ->
    #control_ipv4_address{ip_address = M_ip_address,
                          wtp_count = M_wtp_count};

decode_element(11, <<M_ip_address:16/bytes,
                     M_wtp_count:16/integer>>) ->
    #control_ipv6_address{ip_address = M_ip_address,
                          wtp_count = M_wtp_count};

decode_element(30, <<M_ip_address:4/bytes>>) ->
    #local_ipv4_address{ip_address = M_ip_address};

decode_element(50, <<M_ip_address:16/bytes>>) ->
    #local_ipv6_address{ip_address = M_ip_address};

decode_element(12, <<M_discovery:8/integer,
                     M_echo_request:8/integer>>) ->
    #timers{discovery = M_discovery,
            echo_request = M_echo_request};

decode_element(51, <<M_transport:8/integer>>) ->
    #transport_protocol{transport = enum_transport(M_transport)};

decode_element(13, <<M_data_type:8/integer,
                     M_data_mode:8/integer,
                     M_data_len:16/integer, M_data:M_data_len/bytes>>) ->
    #data_transfer_data{data_type = enum_data_type(M_data_type),
                        data_mode = enum_data_mode(M_data_mode),
                        data = M_data};

decode_element(14, <<M_data_mode:8/integer>>) ->
    #data_transfer_mode{data_mode = enum_data_mode(M_data_mode)};

decode_element(15, <<M_radio_id:8/integer,
                     M_macs/binary>>) ->
    #decryption_error_report{radio_id = M_radio_id,
                             macs = decode_mac_list(M_macs)};

decode_element(16, <<M_radio_id:8/integer,
                     M_report_interval:16/integer>>) ->
    #decryption_error_report_period{radio_id = M_radio_id,
                                    report_interval = M_report_interval};

decode_element(17, <<M_macs/binary>>) ->
    #delete_mac_acl_entry{macs = decode_mac_list(M_macs)};

decode_element(18, <<M_radio_id:8/integer,
                     M_mac_len:8/integer, M_mac:M_mac_len/bytes>>) ->
    #delete_station{radio_id = M_radio_id,
                    mac = M_mac};

decode_element(20, <<M_discovery_type:8/integer>>) ->
    #discovery_type{discovery_type = enum_discovery_type(M_discovery_type)};

decode_element(21, <<M_ip_address:4/bytes,
                     M_status:8/integer,
                     M_mac_len:8/integer, M_mac:M_mac_len/bytes>>) ->
    #duplicate_ipv4_address{ip_address = M_ip_address,
                            status = M_status,
                            mac = M_mac};

decode_element(22, <<M_ip_address:16/bytes,
                     M_status:8/integer,
                     M_mac_len:8/integer, M_mac:M_mac_len/bytes>>) ->
    #duplicate_ipv6_address{ip_address = M_ip_address,
                            status = M_status,
                            mac = M_mac};

decode_element(23, <<M_timeout:32/integer>>) ->
    #idle_timeout{timeout = M_timeout};

decode_element(53, <<M_ecn_support:8/integer>>) ->
    #ecn_support{ecn_support = enum_ecn_support(M_ecn_support)};

decode_element(24, <<M_data_type:8/integer,
                     M_data/binary>>) ->
    #image_data{data_type = enum_data_type(M_data_type),
                data = M_data};

decode_element(25, <<M_vendor:32/integer,
                     M_data/binary>>) ->
    #image_identifier{vendor = M_vendor,
                      data = M_data};

decode_element(26, <<M_file_size:32/integer,
                     M_hash:16/bytes>>) ->
    #image_information{file_size = M_file_size,
                       hash = M_hash};

decode_element(27, <<>>) ->
    #initiate_download{};

decode_element(28, <<M_location/binary>>) ->
    #location_data{location = M_location};

decode_element(29, <<M_maximum_message_length:16/integer>>) ->
    #maximum_message_length{maximum_message_length = M_maximum_message_length};

decode_element(52, <<M_padding/binary>>) ->
    #mtu_discovery_padding{padding = M_padding};

decode_element(31, <<M_radio_id:8/integer,
                     M_admin_state:8/integer>>) ->
    #radio_administrative_state{radio_id = M_radio_id,
                                admin_state = enum_admin_state(M_admin_state)};

decode_element(32, <<M_radio_id:8/integer,
                     M_state:8/integer,
                     M_cause:8/integer>>) ->
    #radio_operational_state{radio_id = M_radio_id,
                             state = enum_state(M_state),
                             cause = enum_cause(M_cause)};

decode_element(33, <<M_result_code:32/integer>>) ->
    #result_code{result_code = M_result_code};

decode_element(34, <<M_reason:8/integer,
                     M_message_element/binary>>) ->
    #returned_message_element{reason = enum_reason(M_reason),
                              message_element = M_message_element};

decode_element(35, <<M_session_id:128/integer>>) ->
    #session_id{session_id = M_session_id};

decode_element(36, <<M_statistics_timer:16/integer>>) ->
    #statistics_timer{statistics_timer = M_statistics_timer};

decode_element(37, <<M_vendor:32/integer,
                     M_element_id:16/integer,
                     M_data/binary>>) ->
    decode_vendor_element({M_vendor, M_element_id}, M_data);

decode_element(38, <<M_vendor:32/integer,
                     M_board_data_sub_elements/binary>>) ->
    #wtp_board_data{vendor = M_vendor,
                    board_data_sub_elements = decode_subelements(M_board_data_sub_elements)};

decode_element(39, <<M_max_radios:8/integer,
                     M_radios_in_use:8/integer,
                     M_encryption_sub_element_len:8/integer, M_Rest/binary>>) ->
    M_encryption_sub_element_size = M_encryption_sub_element_len * 3,
    <<M_encryption_sub_element:M_encryption_sub_element_size/bytes,
      M_sub_elements/binary>> = M_Rest,
    #wtp_descriptor{max_radios = M_max_radios,
                    radios_in_use = M_radios_in_use,
                    encryption_sub_element = [X || <<X:3/bytes>> <= M_encryption_sub_element],
                    sub_elements = decode_vendor_subelements(M_sub_elements)};

decode_element(40, <<M_mode:8/integer>>) ->
    #wtp_fallback{mode = enum_mode(M_mode)};

decode_element(41, <<_:4,
                     M_mode_native:1,
                     M_mode_802_3:1,
                     M_mode_local:1,
                     _:1>>) ->
    #wtp_frame_tunnel_mode{mode = [ 'native' || M_mode_native =/= 0 ] ++ [ '802.3' || M_mode_802_3 =/= 0 ] ++ [ 'local' || M_mode_local =/= 0 ]};

decode_element(44, <<M_mac_type:8/integer>>) ->
    #wtp_mac_type{mac_type = enum_mac_type(M_mac_type)};

decode_element(45, <<M_wtp_name/binary>>) ->
    #wtp_name{wtp_name = M_wtp_name};

decode_element(47, <<M_radio_id:8/integer,
                     M_last_fail_type:8/integer,
                     M_reset_count:16/integer,
                     M_sw_failure_count:16/integer,
                     M_hw_failure_count:16/integer,
                     M_other__failure_count:16/integer,
                     M_unknown_failure_count:16/integer,
                     M_config_update_count:16/integer,
                     M_channel_change_count:16/integer,
                     M_band_change_count:16/integer,
                     M_current_noise_floor:16/integer>>) ->
    #wtp_radio_statistics{radio_id = M_radio_id,
                          last_fail_type = enum_last_fail_type(M_last_fail_type),
                          reset_count = M_reset_count,
                          sw_failure_count = M_sw_failure_count,
                          hw_failure_count = M_hw_failure_count,
                          other__failure_count = M_other__failure_count,
                          unknown_failure_count = M_unknown_failure_count,
                          config_update_count = M_config_update_count,
                          channel_change_count = M_channel_change_count,
                          band_change_count = M_band_change_count,
                          current_noise_floor = M_current_noise_floor};

decode_element(48, <<M_reboot_count_:16/integer,
                     M_ac_initiated_count:16/integer,
                     M_link_failure_count:16/integer,
                     M_sw_failure_count:16/integer,
                     M_hw_failure_count:16/integer,
                     M_other_failure_count:16/integer,
                     M_unknown_failure_count:16/integer,
                     M_last_failure_type:8/integer>>) ->
    #wtp_reboot_statistics{reboot_count_ = M_reboot_count_,
                           ac_initiated_count = M_ac_initiated_count,
                           link_failure_count = M_link_failure_count,
                           sw_failure_count = M_sw_failure_count,
                           hw_failure_count = M_hw_failure_count,
                           other_failure_count = M_other_failure_count,
                           unknown_failure_count = M_unknown_failure_count,
                           last_failure_type = enum_last_failure_type(M_last_failure_type)};

decode_element(49, <<M_ip_address:4/bytes,
                     M_netmask:4/bytes,
                     M_gateway:4/bytes,
                     M_static:8/integer>>) ->
    #wtp_static_ip_address_information{ip_address = M_ip_address,
                                       netmask = M_netmask,
                                       gateway = M_gateway,
                                       static = M_static};

decode_element(1024, <<M_radio_id:8/integer,
                       M_wlan_id:8/integer,
                       M_capability_ess:1,
                       M_capability_ibss:1,
                       M_capability_cf_pollable:1,
                       M_capability_cf_poll_request:1,
                       M_capability_privacy:1,
                       M_capability_short_preamble:1,
                       M_capability_pbcc:1,
                       M_capability_channel_agility:1,
                       M_capability_spectrum_management:1,
                       M_capability_qos:1,
                       M_capability_short_slot_time:1,
                       M_capability_apsd:1,
                       M_capability_reserved:1,
                       M_capability_dsss_ofdm:1,
                       M_capability_delayed_block_ack:1,
                       M_capability_immediate_block_ack:1,
                       M_key_index:8/integer,
                       M_key_status:8/integer,
                       M_key_len:16/integer, M_key:M_key_len/bytes,
                       M_group_tsc:6/bytes,
                       M_qos:8/integer,
                       M_auth_type:8/integer,
                       M_mac_mode:8/integer,
                       M_tunnel_mode:8/integer,
                       M_suppress_ssid:8/integer,
                       M_ssid/binary>>) ->
    #ieee_802_11_add_wlan{radio_id = M_radio_id,
                          wlan_id = M_wlan_id,
                          capability = [ 'ess' || M_capability_ess =/= 0 ] ++ [ 'ibss' || M_capability_ibss =/= 0 ] ++ [ 'cf-pollable' || M_capability_cf_pollable =/= 0 ] ++ [ 'cf-poll-request' || M_capability_cf_poll_request =/= 0 ] ++ [ 'privacy' || M_capability_privacy =/= 0 ] ++ [ 'short_preamble' || M_capability_short_preamble =/= 0 ] ++ [ 'pbcc' || M_capability_pbcc =/= 0 ] ++ [ 'channel_agility' || M_capability_channel_agility =/= 0 ] ++ [ 'spectrum_management' || M_capability_spectrum_management =/= 0 ] ++ [ 'qos' || M_capability_qos =/= 0 ] ++ [ 'short_slot_time' || M_capability_short_slot_time =/= 0 ] ++ [ 'apsd' || M_capability_apsd =/= 0 ] ++ [ 'reserved' || M_capability_reserved =/= 0 ] ++ [ 'dsss_ofdm' || M_capability_dsss_ofdm =/= 0 ] ++ [ 'delayed_block_ack' || M_capability_delayed_block_ack =/= 0 ] ++ [ 'immediate_block_ack' || M_capability_immediate_block_ack =/= 0 ],
                          key_index = M_key_index,
                          key_status = enum_key_status(M_key_status),
                          key = M_key,
                          group_tsc = M_group_tsc,
                          qos = enum_qos(M_qos),
                          auth_type = enum_auth_type(M_auth_type),
                          mac_mode = enum_mac_mode(M_mac_mode),
                          tunnel_mode = enum_tunnel_mode(M_tunnel_mode),
                          suppress_ssid = M_suppress_ssid,
                          ssid = M_ssid};

decode_element(1025, <<M_radio_id:8/integer,
                       M_diversity:8/integer,
                       M_combiner:8/integer,
                       M_antenna_selection_len:8/integer, M_antenna_selection:M_antenna_selection_len/bytes>>) ->
    #ieee_802_11_antenna{radio_id = M_radio_id,
                         diversity = enum_diversity(M_diversity),
                         combiner = enum_combiner(M_combiner),
                         antenna_selection = M_antenna_selection};

decode_element(1026, <<M_radio_id:8/integer,
                       M_wlan_id:8/integer,
                       M_bssid:6/bytes>>) ->
    #ieee_802_11_assigned_wtp_bssid{radio_id = M_radio_id,
                                    wlan_id = M_wlan_id,
                                    bssid = M_bssid};

decode_element(1027, <<M_radio_id:8/integer,
                       M_wlan_id:8/integer>>) ->
    #ieee_802_11_delete_wlan{radio_id = M_radio_id,
                             wlan_id = M_wlan_id};

decode_element(1028, <<M_radio_id:8/integer,
                       _:8,
                       M_current_chan:8/integer,
                       M_current_cca:8/integer,
                       M_energy_detect_threshold:32/integer>>) ->
    #ieee_802_11_direct_sequence_control{radio_id = M_radio_id,
                                         current_chan = M_current_chan,
                                         current_cca = enum_current_cca(M_current_cca),
                                         energy_detect_threshold = M_energy_detect_threshold};

decode_element(1029, <<M_radio_id:8/integer,
                       M_wlan_id:8/integer,
                       M_flags_beacon:1,
                       M_flags_probe_response:1,
                       _:6,
                       M_ie/binary>>) ->
    #ieee_802_11_information_element{radio_id = M_radio_id,
                                     wlan_id = M_wlan_id,
                                     flags = [ 'beacon' || M_flags_beacon =/= 0 ] ++ [ 'probe_response' || M_flags_probe_response =/= 0 ],
                                     ie = M_ie};

decode_element(1030, <<M_radio_id:8/integer,
                       _:8,
                       M_rts_threshold:16/integer,
                       M_short_retry:8/integer,
                       M_long_retry:8/integer,
                       M_fragmentation_threshold:16/integer,
                       M_tx_msdu_lifetime:32/integer,
                       M_rx_msdu_lifetime:32/integer>>) ->
    #ieee_802_11_mac_operation{radio_id = M_radio_id,
                               rts_threshold = M_rts_threshold,
                               short_retry = M_short_retry,
                               long_retry = M_long_retry,
                               fragmentation_threshold = M_fragmentation_threshold,
                               tx_msdu_lifetime = M_tx_msdu_lifetime,
                               rx_msdu_lifetime = M_rx_msdu_lifetime};

decode_element(1031, <<M_radio_id:8/integer,
                       M_wlan_id:8/integer,
                       M_mac:6/bytes>>) ->
    #ieee_802_11_mic_countermeasures{radio_id = M_radio_id,
                                     wlan_id = M_wlan_id,
                                     mac = M_mac};

decode_element(1032, <<M_radio_id:8/integer,
                       _:8,
                       M_first_channel:16/integer,
                       M_number_of_channels_:16/integer,
                       M_max_tx_power_level:16/integer>>) ->
    #ieee_802_11_multi_domain_capability{radio_id = M_radio_id,
                                         first_channel = M_first_channel,
                                         number_of_channels_ = M_number_of_channels_,
                                         max_tx_power_level = M_max_tx_power_level};

decode_element(1033, <<M_radio_id:8/integer,
                       _:8,
                       M_current_chan:8/integer,
                       M_band_support:8/integer,
                       M_ti_threshold:32/integer>>) ->
    #ieee_802_11_ofdm_control{radio_id = M_radio_id,
                              current_chan = M_current_chan,
                              band_support = M_band_support,
                              ti_threshold = M_ti_threshold};

decode_element(1034, <<M_radio_id:8/integer,
                       M_rate_set/binary>>) ->
    #ieee_802_11_rate_set{radio_id = M_radio_id,
                          rate_set = M_rate_set};

decode_element(1035, <<M_client_mac_address:6/bytes,
                       M_bssid:6/bytes,
                       M_radio_id:8/integer,
                       M_wlan_id:8/integer,
                       _:16,
                       M_tkip_icv_errors:32/integer,
                       M_tkip_local_mic_failures:32/integer,
                       M_tkip_remote_mic_failures:32/integer,
                       M_ccmp_replays:32/integer,
                       M_ccmp_decrypt_errors:32/integer,
                       M_tkip_replays:32/integer>>) ->
    #ieee_802_11_rsna_error_report_from_station{client_mac_address = M_client_mac_address,
                                                bssid = M_bssid,
                                                radio_id = M_radio_id,
                                                wlan_id = M_wlan_id,
                                                tkip_icv_errors = M_tkip_icv_errors,
                                                tkip_local_mic_failures = M_tkip_local_mic_failures,
                                                tkip_remote_mic_failures = M_tkip_remote_mic_failures,
                                                ccmp_replays = M_ccmp_replays,
                                                ccmp_decrypt_errors = M_ccmp_decrypt_errors,
                                                tkip_replays = M_tkip_replays};

decode_element(1036, <<M_radio_id:8/integer,
                       M_association_id:16/integer,
                       _:0,
                       M_mac_address:6/bytes,
                       M_capabilities:2/bytes,
                       M_wlan_id:8/integer,
                       M_supported_rate/binary>>) ->
    #ieee_802_11_station{radio_id = M_radio_id,
                         association_id = M_association_id,
                         mac_address = M_mac_address,
                         capabilities = M_capabilities,
                         wlan_id = M_wlan_id,
                         supported_rate = M_supported_rate};

decode_element(1037, <<M_mac_address:6/bytes,
                       _:13,
                       M_p8021p:3/integer>>) ->
    #ieee_802_11_station_qos_profile{mac_address = M_mac_address,
                                     p8021p = M_p8021p};

decode_element(1038, <<M_mac_address:6/bytes,
                       M_flags_akm_only:1,
                       M_flags_ac_crypto:1,
                       _:14,
                       M_pairwise_tsc:6/bytes,
                       M_pairwise_rsc:6/bytes,
                       M_key/binary>>) ->
    #ieee_802_11_station_session_key{mac_address = M_mac_address,
                                     flags = [ 'akm_only' || M_flags_akm_only =/= 0 ] ++ [ 'ac_crypto' || M_flags_ac_crypto =/= 0 ],
                                     pairwise_tsc = M_pairwise_tsc,
                                     pairwise_rsc = M_pairwise_rsc,
                                     key = M_key};

decode_element(1039, <<M_radio_id:8/integer,
                       _:24,
                       M_tx_fragment_count:32/integer,
                       M_multicast_tx_count:32/integer,
                       M_failed_count:32/integer,
                       M_retry_count:32/integer,
                       M_multiple_retry_count:32/integer,
                       M_frame_duplicate_count:32/integer,
                       M_rts_success_count:32/integer,
                       M_rts_failure_count:32/integer,
                       M_ack_failure_count:32/integer,
                       M_rx_fragment_count:32/integer,
                       M_multicast_rx_count:32/integer,
                       M_fcs_error__count:32/integer,
                       M_tx_frame_count:32/integer,
                       M_decryption_errors:32/integer,
                       M_discarded_qos_fragment_count:32/integer,
                       M_associated_station_count:32/integer,
                       M_qos_cf_polls_received_count:32/integer,
                       M_qos_cf_polls_unused_count:32/integer,
                       M_qos_cf_polls_unusable_count:32/integer>>) ->
    #ieee_802_11_statistics{radio_id = M_radio_id,
                            tx_fragment_count = M_tx_fragment_count,
                            multicast_tx_count = M_multicast_tx_count,
                            failed_count = M_failed_count,
                            retry_count = M_retry_count,
                            multiple_retry_count = M_multiple_retry_count,
                            frame_duplicate_count = M_frame_duplicate_count,
                            rts_success_count = M_rts_success_count,
                            rts_failure_count = M_rts_failure_count,
                            ack_failure_count = M_ack_failure_count,
                            rx_fragment_count = M_rx_fragment_count,
                            multicast_rx_count = M_multicast_rx_count,
                            fcs_error__count = M_fcs_error__count,
                            tx_frame_count = M_tx_frame_count,
                            decryption_errors = M_decryption_errors,
                            discarded_qos_fragment_count = M_discarded_qos_fragment_count,
                            associated_station_count = M_associated_station_count,
                            qos_cf_polls_received_count = M_qos_cf_polls_received_count,
                            qos_cf_polls_unused_count = M_qos_cf_polls_unused_count,
                            qos_cf_polls_unusable_count = M_qos_cf_polls_unusable_count};

decode_element(1040, <<M_radio_id:8/integer,
                       M_supported_rates/binary>>) ->
    #ieee_802_11_supported_rates{radio_id = M_radio_id,
                                 supported_rates = M_supported_rates};

decode_element(1041, <<M_radio_id:8/integer,
                       _:8,
                       M_current_tx_power:16/integer>>) ->
    #ieee_802_11_tx_power{radio_id = M_radio_id,
                          current_tx_power = M_current_tx_power};

decode_element(1042, <<M_radio_id:8/integer,
                       M_power_level_len:8/integer, M_Rest/binary>>) ->
    M_power_level_size = M_power_level_len * 2,
    <<M_power_level:M_power_level_size/bytes>> = M_Rest,
    #ieee_802_11_tx_power_level{radio_id = M_radio_id,
                                power_level = [X || <<X:2/bytes>> <= M_power_level]};

decode_element(1043, <<M_radio_id:8/integer,
                       M_mac_address:6/bytes,
                       M_qos_sub_element:8/bytes>>) ->
    #ieee_802_11_update_station_qos{radio_id = M_radio_id,
                                    mac_address = M_mac_address,
                                    qos_sub_element = M_qos_sub_element};

decode_element(1044, <<M_radio_id:8/integer,
                       M_wlan_id:8/integer,
                       M_capability_ess:1,
                       M_capability_ibss:1,
                       M_capability_cf_pollable:1,
                       M_capability_cf_poll_request:1,
                       M_capability_privacy:1,
                       M_capability_short_preamble:1,
                       M_capability_pbcc:1,
                       M_capability_channel_agility:1,
                       M_capability_spectrum_management:1,
                       M_capability_qos:1,
                       M_capability_short_slot_time:1,
                       M_capability_apsd:1,
                       M_capability_reserved:1,
                       M_capability_dsss_ofdm:1,
                       M_capability_delayed_block_ack:1,
                       M_capability_immediate_block_ack:1,
                       M_key_index:8/integer,
                       M_key_status:8/integer,
                       M_key_len:16/integer, M_key:M_key_len/bytes>>) ->
    #ieee_802_11_update_wlan{radio_id = M_radio_id,
                             wlan_id = M_wlan_id,
                             capability = [ 'ess' || M_capability_ess =/= 0 ] ++ [ 'ibss' || M_capability_ibss =/= 0 ] ++ [ 'cf-pollable' || M_capability_cf_pollable =/= 0 ] ++ [ 'cf-poll-request' || M_capability_cf_poll_request =/= 0 ] ++ [ 'privacy' || M_capability_privacy =/= 0 ] ++ [ 'short_preamble' || M_capability_short_preamble =/= 0 ] ++ [ 'pbcc' || M_capability_pbcc =/= 0 ] ++ [ 'channel_agility' || M_capability_channel_agility =/= 0 ] ++ [ 'spectrum_management' || M_capability_spectrum_management =/= 0 ] ++ [ 'qos' || M_capability_qos =/= 0 ] ++ [ 'short_slot_time' || M_capability_short_slot_time =/= 0 ] ++ [ 'apsd' || M_capability_apsd =/= 0 ] ++ [ 'reserved' || M_capability_reserved =/= 0 ] ++ [ 'dsss_ofdm' || M_capability_dsss_ofdm =/= 0 ] ++ [ 'delayed_block_ack' || M_capability_delayed_block_ack =/= 0 ] ++ [ 'immediate_block_ack' || M_capability_immediate_block_ack =/= 0 ],
                             key_index = M_key_index,
                             key_status = enum_key_status(M_key_status),
                             key = M_key};

decode_element(1045, <<M_radio_id:8/integer,
                       _:3,
                       M_tagging_policy:5/bits,
                       M_qos_sub_element:32/bytes>>) ->
    #ieee_802_11_wtp_quality_of_service{radio_id = M_radio_id,
                                        tagging_policy = M_tagging_policy,
                                        qos_sub_element = M_qos_sub_element};

decode_element(1046, <<M_radio_id:8/integer,
                       M_short_preamble:8/integer,
                       M_num_of_bssids:8/integer,
                       M_dtim_period:8/integer,
                       M_bssid:6/bytes,
                       M_beacon_period:16/integer,
                       M_country_string:4/bytes>>) ->
    #ieee_802_11_wtp_radio_configuration{radio_id = M_radio_id,
                                         short_preamble = enum_short_preamble(M_short_preamble),
                                         num_of_bssids = M_num_of_bssids,
                                         dtim_period = M_dtim_period,
                                         bssid = M_bssid,
                                         beacon_period = M_beacon_period,
                                         country_string = M_country_string};

decode_element(1047, <<M_radio_id:8/integer,
                       M_type:8/integer,
                       M_status:8/integer,
                       _:8>>) ->
    #ieee_802_11_wtp_radio_fail_alarm_indication{radio_id = M_radio_id,
                                                 type = enum_type(M_type),
                                                 status = M_status};

decode_element(1048, <<M_radio_id:8/integer,
                       _:28,
                       M_radio_type_802_11n:1,
                       M_radio_type_802_11g:1,
                       M_radio_type_802_11a:1,
                       M_radio_type_802_11b:1>>) ->
    #ieee_802_11_wtp_radio_information{radio_id = M_radio_id,
                                       radio_type = [ '802.11n' || M_radio_type_802_11n =/= 0 ] ++ [ '802.11g' || M_radio_type_802_11g =/= 0 ] ++ [ '802.11a' || M_radio_type_802_11a =/= 0 ] ++ [ '802.11b' || M_radio_type_802_11b =/= 0 ]};

decode_element(Tag, Value) ->
        {Tag, Value}.

decode_vendor_element({18681,1}, <<M_timestamp:32/integer-little,
                                   M_wwan_id:8/integer,
                                   M_rat:8/integer,
                                   M_rssi:8/integer,
                                   _:8,
                                   M_lac:16/integer-little,
                                   _:16,
                                   M_cell_id:32/integer-little>>) ->
    #tp_wtp_wwan_statistics_0_9{timestamp = M_timestamp,
                                wwan_id = M_wwan_id,
                                rat = M_rat,
                                rssi = M_rssi,
                                lac = M_lac,
                                cell_id = M_cell_id};

decode_vendor_element({18681,1}, <<M_timestamp:32/integer,
                                   M_wwan_id:8/integer,
                                   M_rat:8/integer,
                                   M_rssi:8/integer,
                                   M_creg:8/integer,
                                   M_lac:16/integer,
                                   M_latency:16/integer,
                                   M_mcc:8/integer,
                                   M_mnc:8/integer,
                                   _:16,
                                   M_cell_id:32/integer>>) ->
    #tp_wtp_wwan_statistics{timestamp = M_timestamp,
                            wwan_id = M_wwan_id,
                            rat = M_rat,
                            rssi = M_rssi,
                            creg = M_creg,
                            lac = M_lac,
                            latency = M_latency,
                            mcc = M_mcc,
                            mnc = M_mnc,
                            cell_id = M_cell_id};

decode_vendor_element({18681,2}, <<M_second:32/integer,
                                   M_fraction:32/integer>>) ->
    #tp_wtp_timestamp{second = M_second,
                      fraction = M_fraction};

decode_vendor_element({18681,3}, <<M_wwan_id:8/integer,
                                   M_iccid/binary>>) ->
    #tp_wtp_wwan_iccid{wwan_id = M_wwan_id,
                       iccid = M_iccid};

decode_vendor_element({18681,4}, <<M_radio_id:8/integer,
                                   M_wlan_id:8/integer,
                                   M_hold_time:16/integer>>) ->
    #tp_ieee_802_11_wlan_hold_time{radio_id = M_radio_id,
                                   wlan_id = M_wlan_id,
                                   hold_time = M_hold_time};

decode_vendor_element({18681,5}, <<M_data_channel_dead_interval:16/integer>>) ->
    #tp_data_channel_dead_interval{data_channel_dead_interval = M_data_channel_dead_interval};

decode_vendor_element({18681,6}, <<M_ac_join_timeout:16/integer>>) ->
    #tp_ac_join_timeout{ac_join_timeout = M_ac_join_timeout};

decode_vendor_element({18681,7}, <<M_priority:8/integer,
                                   M_type:8/integer,
                                   M_value/binary>>) ->
    #tp_ac_address_with_priority{priority = M_priority,
                                 type = M_type,
                                 value = M_value};

decode_vendor_element({18681,8}, <<M_apn_len:8/integer, M_apn:M_apn_len/bytes,
                                   M_username_len:8/integer, M_username:M_username_len/bytes,
                                   M_password_len:8/integer, M_password:M_password_len/bytes>>) ->
    #wtp_apn_settings{apn = M_apn,
                      username = M_username,
                      password = M_password};

decode_vendor_element({18681,9}, <<M_password/binary>>) ->
    #wtp_administrator_password_settings{password = M_password};

decode_vendor_element({18681,10}, <<M_sha256_image_hash:32/bytes,
                                    M_download_uri/binary>>) ->
    #firmware_download_information{sha256_image_hash = M_sha256_image_hash,
                                   download_uri = M_download_uri};

decode_vendor_element({18681,11}, <<M_status:16/integer,
                                    _:16,
                                    M_bytes_downloaded:32/integer,
                                    M_bytes_remaining:32/integer>>) ->
    #firmware_download_status{status = enum_status(M_status),
                              bytes_downloaded = M_bytes_downloaded,
                              bytes_remaining = M_bytes_remaining};

decode_vendor_element({18681,13}, <<M_radio_id:8/integer,
                                    M_wlan_id:8/integer,
                                    M_capability_ess:1,
                                    M_capability_ibss:1,
                                    M_capability_cf_pollable:1,
                                    M_capability_cf_poll_request:1,
                                    M_capability_privacy:1,
                                    M_capability_short_preamble:1,
                                    M_capability_pbcc:1,
                                    M_capability_channel_agility:1,
                                    M_capability_spectrum_management:1,
                                    M_capability_qos:1,
                                    M_capability_short_slot_time:1,
                                    M_capability_apsd:1,
                                    M_capability_reserved:1,
                                    M_capability_dsss_ofdm:1,
                                    M_capability_delayed_block_ack:1,
                                    M_capability_immediate_block_ack:1,
                                    M_key_index:8/integer,
                                    M_key_status:8/integer,
                                    M_key_len:16/integer, M_key:M_key_len/bytes,
                                    M_group_tsc:6/bytes,
                                    M_qos:8/integer,
                                    M_auth_type:8/integer,
                                    M_mac_mode:8/integer,
                                    M_tunnel_mode:8/integer,
                                    M_suppress_ssid:8/integer,
                                    M_ssid/binary>>) ->
    #ieee_802_11_tp_wlan{radio_id = M_radio_id,
                         wlan_id = M_wlan_id,
                         capability = [ 'ess' || M_capability_ess =/= 0 ] ++ [ 'ibss' || M_capability_ibss =/= 0 ] ++ [ 'cf-pollable' || M_capability_cf_pollable =/= 0 ] ++ [ 'cf-poll-request' || M_capability_cf_poll_request =/= 0 ] ++ [ 'privacy' || M_capability_privacy =/= 0 ] ++ [ 'short_preamble' || M_capability_short_preamble =/= 0 ] ++ [ 'pbcc' || M_capability_pbcc =/= 0 ] ++ [ 'channel_agility' || M_capability_channel_agility =/= 0 ] ++ [ 'spectrum_management' || M_capability_spectrum_management =/= 0 ] ++ [ 'qos' || M_capability_qos =/= 0 ] ++ [ 'short_slot_time' || M_capability_short_slot_time =/= 0 ] ++ [ 'apsd' || M_capability_apsd =/= 0 ] ++ [ 'reserved' || M_capability_reserved =/= 0 ] ++ [ 'dsss_ofdm' || M_capability_dsss_ofdm =/= 0 ] ++ [ 'delayed_block_ack' || M_capability_delayed_block_ack =/= 0 ] ++ [ 'immediate_block_ack' || M_capability_immediate_block_ack =/= 0 ],
                         key_index = M_key_index,
                         key_status = enum_key_status(M_key_status),
                         key = M_key,
                         group_tsc = M_group_tsc,
                         qos = enum_qos(M_qos),
                         auth_type = enum_auth_type(M_auth_type),
                         mac_mode = enum_mac_mode(M_mac_mode),
                         tunnel_mode = enum_tunnel_mode(M_tunnel_mode),
                         suppress_ssid = M_suppress_ssid,
                         ssid = M_ssid};

decode_vendor_element({18681,12}, <<M_apply_confirmation_timeout:16/integer>>) ->
    #apply_confirmation_timeout{apply_confirmation_timeout = M_apply_confirmation_timeout};

decode_vendor_element({18681,14}, <<M_idle_timeout:32/integer,
                                    M_busy_timeout:32/integer>>) ->
    #power_save_mode{idle_timeout = M_idle_timeout,
                     busy_timeout = M_busy_timeout};

decode_vendor_element({18681,15}, <<M_timestamp:32/integer,
                                    M_wwan_id:8/integer,
                                    M_gpsatc/binary>>) ->
    #gps_last_acquired_position{timestamp = M_timestamp,
                                wwan_id = M_wwan_id,
                                gpsatc = M_gpsatc};

decode_vendor_element(Tag, Value) ->
        {Tag, Value}.

encode_element(#ac_descriptor{
                    stations = M_stations,
                    limit = M_limit,
                    active_wtps = M_active_wtps,
                    max_wtps = M_max_wtps,
                    security = M_security,
                    r_mac = M_r_mac,
                    dtls_policy = M_dtls_policy,
                    sub_elements = M_sub_elements}) ->
    encode_element(1, <<M_stations:16,
                        M_limit:16,
                        M_active_wtps:16,
                        M_max_wtps:16,
                        0:5,
                        (encode_flag('pre-shared', M_security)):1,
                        (encode_flag('x509', M_security)):1,
                        0:1,
                        (enum_r_mac(M_r_mac)):8/integer,
                        0:8,
                        0:5,
                        (encode_flag('enc-data', M_dtls_policy)):1,
                        (encode_flag('clear-text', M_dtls_policy)):1,
                        0:1,
                        (encode_vendor_subelements(M_sub_elements))/binary>>);

encode_element(#ac_ipv4_list{
                    ip_address = M_ip_address}) ->
    encode_element(2, <<(encode_ipv4_list(M_ip_address))/binary>>);

encode_element(#ac_ipv6_list{
                    ip_address = M_ip_address}) ->
    encode_element(3, <<(encode_ipv6_list(M_ip_address))/binary>>);

encode_element(#ac_name{
                    name = M_name}) ->
    encode_element(4, <<M_name/binary>>);

encode_element(#ac_name_with_priority{
                    priority = M_priority,
                    name = M_name}) ->
    encode_element(5, <<M_priority:8,
                        M_name/binary>>);

encode_element(#ac_timestamp{
                    timestamp = M_timestamp}) ->
    encode_element(6, <<M_timestamp:32>>);

encode_element(#add_mac_acl{
                    macs = M_macs}) ->
    encode_element(7, <<(encode_mac_list(M_macs))/binary>>);

encode_element(#add_station{
                    radio_id = M_radio_id,
                    mac = M_mac,
                    vlan_name = M_vlan_name}) ->
    encode_element(8, <<M_radio_id:8,
                        (byte_size(M_mac)):8/integer, M_mac/binary,
                        M_vlan_name/binary>>);

encode_element(#control_ipv4_address{
                    ip_address = M_ip_address,
                    wtp_count = M_wtp_count}) ->
    encode_element(10, <<M_ip_address:4/bytes,
                         M_wtp_count:16>>);

encode_element(#control_ipv6_address{
                    ip_address = M_ip_address,
                    wtp_count = M_wtp_count}) ->
    encode_element(11, <<M_ip_address:16/bytes,
                         M_wtp_count:16>>);

encode_element(#local_ipv4_address{
                    ip_address = M_ip_address}) ->
    encode_element(30, <<M_ip_address:4/bytes>>);

encode_element(#local_ipv6_address{
                    ip_address = M_ip_address}) ->
    encode_element(50, <<M_ip_address:16/bytes>>);

encode_element(#timers{
                    discovery = M_discovery,
                    echo_request = M_echo_request}) ->
    encode_element(12, <<M_discovery:8,
                         M_echo_request:8>>);

encode_element(#transport_protocol{
                    transport = M_transport}) ->
    encode_element(51, <<(enum_transport(M_transport)):8/integer>>);

encode_element(#data_transfer_data{
                    data_type = M_data_type,
                    data_mode = M_data_mode,
                    data = M_data}) ->
    encode_element(13, <<(enum_data_type(M_data_type)):8/integer,
                         (enum_data_mode(M_data_mode)):8/integer,
                         (byte_size(M_data)):16/integer, M_data/binary>>);

encode_element(#data_transfer_mode{
                    data_mode = M_data_mode}) ->
    encode_element(14, <<(enum_data_mode(M_data_mode)):8/integer>>);

encode_element(#decryption_error_report{
                    radio_id = M_radio_id,
                    macs = M_macs}) ->
    encode_element(15, <<M_radio_id:8,
                         (encode_mac_list(M_macs))/binary>>);

encode_element(#decryption_error_report_period{
                    radio_id = M_radio_id,
                    report_interval = M_report_interval}) ->
    encode_element(16, <<M_radio_id:8,
                         M_report_interval:16>>);

encode_element(#delete_mac_acl_entry{
                    macs = M_macs}) ->
    encode_element(17, <<(encode_mac_list(M_macs))/binary>>);

encode_element(#delete_station{
                    radio_id = M_radio_id,
                    mac = M_mac}) ->
    encode_element(18, <<M_radio_id:8,
                         (byte_size(M_mac)):8/integer, M_mac/binary>>);

encode_element(#discovery_type{
                    discovery_type = M_discovery_type}) ->
    encode_element(20, <<(enum_discovery_type(M_discovery_type)):8/integer>>);

encode_element(#duplicate_ipv4_address{
                    ip_address = M_ip_address,
                    status = M_status,
                    mac = M_mac}) ->
    encode_element(21, <<M_ip_address:4/bytes,
                         M_status:8,
                         (byte_size(M_mac)):8/integer, M_mac/binary>>);

encode_element(#duplicate_ipv6_address{
                    ip_address = M_ip_address,
                    status = M_status,
                    mac = M_mac}) ->
    encode_element(22, <<M_ip_address:16/bytes,
                         M_status:8,
                         (byte_size(M_mac)):8/integer, M_mac/binary>>);

encode_element(#idle_timeout{
                    timeout = M_timeout}) ->
    encode_element(23, <<M_timeout:32>>);

encode_element(#ecn_support{
                    ecn_support = M_ecn_support}) ->
    encode_element(53, <<(enum_ecn_support(M_ecn_support)):8/integer>>);

encode_element(#image_data{
                    data_type = M_data_type,
                    data = M_data}) ->
    encode_element(24, <<(enum_data_type(M_data_type)):8/integer,
                         M_data/binary>>);

encode_element(#image_identifier{
                    vendor = M_vendor,
                    data = M_data}) ->
    encode_element(25, <<M_vendor:32,
                         M_data/binary>>);

encode_element(#image_information{
                    file_size = M_file_size,
                    hash = M_hash}) ->
    encode_element(26, <<M_file_size:32,
                         M_hash:16/bytes>>);

encode_element(#initiate_download{
                    }) ->
    encode_element(27, <<>>);

encode_element(#location_data{
                    location = M_location}) ->
    encode_element(28, <<M_location/binary>>);

encode_element(#maximum_message_length{
                    maximum_message_length = M_maximum_message_length}) ->
    encode_element(29, <<M_maximum_message_length:16>>);

encode_element(#mtu_discovery_padding{
                    padding = M_padding}) ->
    encode_element(52, <<M_padding/binary>>);

encode_element(#radio_administrative_state{
                    radio_id = M_radio_id,
                    admin_state = M_admin_state}) ->
    encode_element(31, <<M_radio_id:8,
                         (enum_admin_state(M_admin_state)):8/integer>>);

encode_element(#radio_operational_state{
                    radio_id = M_radio_id,
                    state = M_state,
                    cause = M_cause}) ->
    encode_element(32, <<M_radio_id:8,
                         (enum_state(M_state)):8/integer,
                         (enum_cause(M_cause)):8/integer>>);

encode_element(#result_code{
                    result_code = M_result_code}) ->
    encode_element(33, <<M_result_code:32>>);

encode_element(#returned_message_element{
                    reason = M_reason,
                    message_element = M_message_element}) ->
    encode_element(34, <<(enum_reason(M_reason)):8/integer,
                         M_message_element/binary>>);

encode_element(#session_id{
                    session_id = M_session_id}) ->
    encode_element(35, <<M_session_id:128>>);

encode_element(#statistics_timer{
                    statistics_timer = M_statistics_timer}) ->
    encode_element(36, <<M_statistics_timer:16>>);

encode_element(#wtp_board_data{
                    vendor = M_vendor,
                    board_data_sub_elements = M_board_data_sub_elements}) ->
    encode_element(38, <<M_vendor:32,
                         (encode_subelements(M_board_data_sub_elements))/binary>>);

encode_element(#wtp_descriptor{
                    max_radios = M_max_radios,
                    radios_in_use = M_radios_in_use,
                    encryption_sub_element = M_encryption_sub_element,
                    sub_elements = M_sub_elements}) ->
    encode_element(39, <<M_max_radios:8,
                         M_radios_in_use:8,
                         (length(M_encryption_sub_element)):8/integer, (<< <<X/binary>> || X <- M_encryption_sub_element>>)/binary,
                         (encode_vendor_subelements(M_sub_elements))/binary>>);

encode_element(#wtp_fallback{
                    mode = M_mode}) ->
    encode_element(40, <<(enum_mode(M_mode)):8/integer>>);

encode_element(#wtp_frame_tunnel_mode{
                    mode = M_mode}) ->
    encode_element(41, <<0:4,
                         (encode_flag('native', M_mode)):1,
                         (encode_flag('802.3', M_mode)):1,
                         (encode_flag('local', M_mode)):1,
                         0:1>>);

encode_element(#wtp_mac_type{
                    mac_type = M_mac_type}) ->
    encode_element(44, <<(enum_mac_type(M_mac_type)):8/integer>>);

encode_element(#wtp_name{
                    wtp_name = M_wtp_name}) ->
    encode_element(45, <<M_wtp_name/binary>>);

encode_element(#wtp_radio_statistics{
                    radio_id = M_radio_id,
                    last_fail_type = M_last_fail_type,
                    reset_count = M_reset_count,
                    sw_failure_count = M_sw_failure_count,
                    hw_failure_count = M_hw_failure_count,
                    other__failure_count = M_other__failure_count,
                    unknown_failure_count = M_unknown_failure_count,
                    config_update_count = M_config_update_count,
                    channel_change_count = M_channel_change_count,
                    band_change_count = M_band_change_count,
                    current_noise_floor = M_current_noise_floor}) ->
    encode_element(47, <<M_radio_id:8,
                         (enum_last_fail_type(M_last_fail_type)):8/integer,
                         M_reset_count:16,
                         M_sw_failure_count:16,
                         M_hw_failure_count:16,
                         M_other__failure_count:16,
                         M_unknown_failure_count:16,
                         M_config_update_count:16,
                         M_channel_change_count:16,
                         M_band_change_count:16,
                         M_current_noise_floor:16>>);

encode_element(#wtp_reboot_statistics{
                    reboot_count_ = M_reboot_count_,
                    ac_initiated_count = M_ac_initiated_count,
                    link_failure_count = M_link_failure_count,
                    sw_failure_count = M_sw_failure_count,
                    hw_failure_count = M_hw_failure_count,
                    other_failure_count = M_other_failure_count,
                    unknown_failure_count = M_unknown_failure_count,
                    last_failure_type = M_last_failure_type}) ->
    encode_element(48, <<M_reboot_count_:16,
                         M_ac_initiated_count:16,
                         M_link_failure_count:16,
                         M_sw_failure_count:16,
                         M_hw_failure_count:16,
                         M_other_failure_count:16,
                         M_unknown_failure_count:16,
                         (enum_last_failure_type(M_last_failure_type)):8/integer>>);

encode_element(#wtp_static_ip_address_information{
                    ip_address = M_ip_address,
                    netmask = M_netmask,
                    gateway = M_gateway,
                    static = M_static}) ->
    encode_element(49, <<M_ip_address:4/bytes,
                         M_netmask:4/bytes,
                         M_gateway:4/bytes,
                         M_static:8>>);

encode_element(#ieee_802_11_add_wlan{
                    radio_id = M_radio_id,
                    wlan_id = M_wlan_id,
                    capability = M_capability,
                    key_index = M_key_index,
                    key_status = M_key_status,
                    key = M_key,
                    group_tsc = M_group_tsc,
                    qos = M_qos,
                    auth_type = M_auth_type,
                    mac_mode = M_mac_mode,
                    tunnel_mode = M_tunnel_mode,
                    suppress_ssid = M_suppress_ssid,
                    ssid = M_ssid}) ->
    encode_element(1024, <<M_radio_id:8,
                           M_wlan_id:8,
                           (encode_flag('ess', M_capability)):1,
                           (encode_flag('ibss', M_capability)):1,
                           (encode_flag('cf-pollable', M_capability)):1,
                           (encode_flag('cf-poll-request', M_capability)):1,
                           (encode_flag('privacy', M_capability)):1,
                           (encode_flag('short_preamble', M_capability)):1,
                           (encode_flag('pbcc', M_capability)):1,
                           (encode_flag('channel_agility', M_capability)):1,
                           (encode_flag('spectrum_management', M_capability)):1,
                           (encode_flag('qos', M_capability)):1,
                           (encode_flag('short_slot_time', M_capability)):1,
                           (encode_flag('apsd', M_capability)):1,
                           (encode_flag('reserved', M_capability)):1,
                           (encode_flag('dsss_ofdm', M_capability)):1,
                           (encode_flag('delayed_block_ack', M_capability)):1,
                           (encode_flag('immediate_block_ack', M_capability)):1,
                           M_key_index:8,
                           (enum_key_status(M_key_status)):8/integer,
                           (byte_size(M_key)):16/integer, M_key/binary,
                           M_group_tsc:6/bytes,
                           (enum_qos(M_qos)):8/integer,
                           (enum_auth_type(M_auth_type)):8/integer,
                           (enum_mac_mode(M_mac_mode)):8/integer,
                           (enum_tunnel_mode(M_tunnel_mode)):8/integer,
                           M_suppress_ssid:8,
                           M_ssid/binary>>);

encode_element(#ieee_802_11_antenna{
                    radio_id = M_radio_id,
                    diversity = M_diversity,
                    combiner = M_combiner,
                    antenna_selection = M_antenna_selection}) ->
    encode_element(1025, <<M_radio_id:8,
                           (enum_diversity(M_diversity)):8/integer,
                           (enum_combiner(M_combiner)):8/integer,
                           (byte_size(M_antenna_selection)):8/integer, M_antenna_selection/binary>>);

encode_element(#ieee_802_11_assigned_wtp_bssid{
                    radio_id = M_radio_id,
                    wlan_id = M_wlan_id,
                    bssid = M_bssid}) ->
    encode_element(1026, <<M_radio_id:8,
                           M_wlan_id:8,
                           M_bssid:6/bytes>>);

encode_element(#ieee_802_11_delete_wlan{
                    radio_id = M_radio_id,
                    wlan_id = M_wlan_id}) ->
    encode_element(1027, <<M_radio_id:8,
                           M_wlan_id:8>>);

encode_element(#ieee_802_11_direct_sequence_control{
                    radio_id = M_radio_id,
                    current_chan = M_current_chan,
                    current_cca = M_current_cca,
                    energy_detect_threshold = M_energy_detect_threshold}) ->
    encode_element(1028, <<M_radio_id:8,
                           0:8,
                           M_current_chan:8,
                           (enum_current_cca(M_current_cca)):8/integer,
                           M_energy_detect_threshold:32>>);

encode_element(#ieee_802_11_information_element{
                    radio_id = M_radio_id,
                    wlan_id = M_wlan_id,
                    flags = M_flags,
                    ie = M_ie}) ->
    encode_element(1029, <<M_radio_id:8,
                           M_wlan_id:8,
                           (encode_flag('beacon', M_flags)):1,
                           (encode_flag('probe_response', M_flags)):1,
                           0:6,
                           M_ie/binary>>);

encode_element(#ieee_802_11_mac_operation{
                    radio_id = M_radio_id,
                    rts_threshold = M_rts_threshold,
                    short_retry = M_short_retry,
                    long_retry = M_long_retry,
                    fragmentation_threshold = M_fragmentation_threshold,
                    tx_msdu_lifetime = M_tx_msdu_lifetime,
                    rx_msdu_lifetime = M_rx_msdu_lifetime}) ->
    encode_element(1030, <<M_radio_id:8,
                           0:8,
                           M_rts_threshold:16,
                           M_short_retry:8,
                           M_long_retry:8,
                           M_fragmentation_threshold:16,
                           M_tx_msdu_lifetime:32,
                           M_rx_msdu_lifetime:32>>);

encode_element(#ieee_802_11_mic_countermeasures{
                    radio_id = M_radio_id,
                    wlan_id = M_wlan_id,
                    mac = M_mac}) ->
    encode_element(1031, <<M_radio_id:8,
                           M_wlan_id:8,
                           M_mac:6/bytes>>);

encode_element(#ieee_802_11_multi_domain_capability{
                    radio_id = M_radio_id,
                    first_channel = M_first_channel,
                    number_of_channels_ = M_number_of_channels_,
                    max_tx_power_level = M_max_tx_power_level}) ->
    encode_element(1032, <<M_radio_id:8,
                           0:8,
                           M_first_channel:16,
                           M_number_of_channels_:16,
                           M_max_tx_power_level:16>>);

encode_element(#ieee_802_11_ofdm_control{
                    radio_id = M_radio_id,
                    current_chan = M_current_chan,
                    band_support = M_band_support,
                    ti_threshold = M_ti_threshold}) ->
    encode_element(1033, <<M_radio_id:8,
                           0:8,
                           M_current_chan:8,
                           M_band_support:8,
                           M_ti_threshold:32>>);

encode_element(#ieee_802_11_rate_set{
                    radio_id = M_radio_id,
                    rate_set = M_rate_set}) ->
    encode_element(1034, <<M_radio_id:8,
                           M_rate_set/binary>>);

encode_element(#ieee_802_11_rsna_error_report_from_station{
                    client_mac_address = M_client_mac_address,
                    bssid = M_bssid,
                    radio_id = M_radio_id,
                    wlan_id = M_wlan_id,
                    tkip_icv_errors = M_tkip_icv_errors,
                    tkip_local_mic_failures = M_tkip_local_mic_failures,
                    tkip_remote_mic_failures = M_tkip_remote_mic_failures,
                    ccmp_replays = M_ccmp_replays,
                    ccmp_decrypt_errors = M_ccmp_decrypt_errors,
                    tkip_replays = M_tkip_replays}) ->
    encode_element(1035, <<M_client_mac_address:6/bytes,
                           M_bssid:6/bytes,
                           M_radio_id:8,
                           M_wlan_id:8,
                           0:16,
                           M_tkip_icv_errors:32,
                           M_tkip_local_mic_failures:32,
                           M_tkip_remote_mic_failures:32,
                           M_ccmp_replays:32,
                           M_ccmp_decrypt_errors:32,
                           M_tkip_replays:32>>);

encode_element(#ieee_802_11_station{
                    radio_id = M_radio_id,
                    association_id = M_association_id,
                    mac_address = M_mac_address,
                    capabilities = M_capabilities,
                    wlan_id = M_wlan_id,
                    supported_rate = M_supported_rate}) ->
    encode_element(1036, <<M_radio_id:8,
                           M_association_id:16,
                           0:0,
                           M_mac_address:6/bytes,
                           M_capabilities:2/bytes,
                           M_wlan_id:8,
                           M_supported_rate/binary>>);

encode_element(#ieee_802_11_station_qos_profile{
                    mac_address = M_mac_address,
                    p8021p = M_p8021p}) ->
    encode_element(1037, <<M_mac_address:6/bytes,
                           0:13,
                           M_p8021p:3>>);

encode_element(#ieee_802_11_station_session_key{
                    mac_address = M_mac_address,
                    flags = M_flags,
                    pairwise_tsc = M_pairwise_tsc,
                    pairwise_rsc = M_pairwise_rsc,
                    key = M_key}) ->
    encode_element(1038, <<M_mac_address:6/bytes,
                           (encode_flag('akm_only', M_flags)):1,
                           (encode_flag('ac_crypto', M_flags)):1,
                           0:14,
                           M_pairwise_tsc:6/bytes,
                           M_pairwise_rsc:6/bytes,
                           M_key/binary>>);

encode_element(#ieee_802_11_statistics{
                    radio_id = M_radio_id,
                    tx_fragment_count = M_tx_fragment_count,
                    multicast_tx_count = M_multicast_tx_count,
                    failed_count = M_failed_count,
                    retry_count = M_retry_count,
                    multiple_retry_count = M_multiple_retry_count,
                    frame_duplicate_count = M_frame_duplicate_count,
                    rts_success_count = M_rts_success_count,
                    rts_failure_count = M_rts_failure_count,
                    ack_failure_count = M_ack_failure_count,
                    rx_fragment_count = M_rx_fragment_count,
                    multicast_rx_count = M_multicast_rx_count,
                    fcs_error__count = M_fcs_error__count,
                    tx_frame_count = M_tx_frame_count,
                    decryption_errors = M_decryption_errors,
                    discarded_qos_fragment_count = M_discarded_qos_fragment_count,
                    associated_station_count = M_associated_station_count,
                    qos_cf_polls_received_count = M_qos_cf_polls_received_count,
                    qos_cf_polls_unused_count = M_qos_cf_polls_unused_count,
                    qos_cf_polls_unusable_count = M_qos_cf_polls_unusable_count}) ->
    encode_element(1039, <<M_radio_id:8,
                           0:24,
                           M_tx_fragment_count:32,
                           M_multicast_tx_count:32,
                           M_failed_count:32,
                           M_retry_count:32,
                           M_multiple_retry_count:32,
                           M_frame_duplicate_count:32,
                           M_rts_success_count:32,
                           M_rts_failure_count:32,
                           M_ack_failure_count:32,
                           M_rx_fragment_count:32,
                           M_multicast_rx_count:32,
                           M_fcs_error__count:32,
                           M_tx_frame_count:32,
                           M_decryption_errors:32,
                           M_discarded_qos_fragment_count:32,
                           M_associated_station_count:32,
                           M_qos_cf_polls_received_count:32,
                           M_qos_cf_polls_unused_count:32,
                           M_qos_cf_polls_unusable_count:32>>);

encode_element(#ieee_802_11_supported_rates{
                    radio_id = M_radio_id,
                    supported_rates = M_supported_rates}) ->
    encode_element(1040, <<M_radio_id:8,
                           M_supported_rates/binary>>);

encode_element(#ieee_802_11_tx_power{
                    radio_id = M_radio_id,
                    current_tx_power = M_current_tx_power}) ->
    encode_element(1041, <<M_radio_id:8,
                           0:8,
                           M_current_tx_power:16>>);

encode_element(#ieee_802_11_tx_power_level{
                    radio_id = M_radio_id,
                    power_level = M_power_level}) ->
    encode_element(1042, <<M_radio_id:8,
                           (length(M_power_level)):8/integer, (<< <<X/binary>> || X <- M_power_level>>)/binary>>);

encode_element(#ieee_802_11_update_station_qos{
                    radio_id = M_radio_id,
                    mac_address = M_mac_address,
                    qos_sub_element = M_qos_sub_element}) ->
    encode_element(1043, <<M_radio_id:8,
                           M_mac_address:6/bytes,
                           M_qos_sub_element:8/bytes>>);

encode_element(#ieee_802_11_update_wlan{
                    radio_id = M_radio_id,
                    wlan_id = M_wlan_id,
                    capability = M_capability,
                    key_index = M_key_index,
                    key_status = M_key_status,
                    key = M_key}) ->
    encode_element(1044, <<M_radio_id:8,
                           M_wlan_id:8,
                           (encode_flag('ess', M_capability)):1,
                           (encode_flag('ibss', M_capability)):1,
                           (encode_flag('cf-pollable', M_capability)):1,
                           (encode_flag('cf-poll-request', M_capability)):1,
                           (encode_flag('privacy', M_capability)):1,
                           (encode_flag('short_preamble', M_capability)):1,
                           (encode_flag('pbcc', M_capability)):1,
                           (encode_flag('channel_agility', M_capability)):1,
                           (encode_flag('spectrum_management', M_capability)):1,
                           (encode_flag('qos', M_capability)):1,
                           (encode_flag('short_slot_time', M_capability)):1,
                           (encode_flag('apsd', M_capability)):1,
                           (encode_flag('reserved', M_capability)):1,
                           (encode_flag('dsss_ofdm', M_capability)):1,
                           (encode_flag('delayed_block_ack', M_capability)):1,
                           (encode_flag('immediate_block_ack', M_capability)):1,
                           M_key_index:8,
                           (enum_key_status(M_key_status)):8/integer,
                           (byte_size(M_key)):16/integer, M_key/binary>>);

encode_element(#ieee_802_11_wtp_quality_of_service{
                    radio_id = M_radio_id,
                    tagging_policy = M_tagging_policy,
                    qos_sub_element = M_qos_sub_element}) ->
    encode_element(1045, <<M_radio_id:8,
                           0:3,
                           M_tagging_policy:5/bits,
                           M_qos_sub_element:32/bytes>>);

encode_element(#ieee_802_11_wtp_radio_configuration{
                    radio_id = M_radio_id,
                    short_preamble = M_short_preamble,
                    num_of_bssids = M_num_of_bssids,
                    dtim_period = M_dtim_period,
                    bssid = M_bssid,
                    beacon_period = M_beacon_period,
                    country_string = M_country_string}) ->
    encode_element(1046, <<M_radio_id:8,
                           (enum_short_preamble(M_short_preamble)):8/integer,
                           M_num_of_bssids:8,
                           M_dtim_period:8,
                           M_bssid:6/bytes,
                           M_beacon_period:16,
                           M_country_string:4/bytes>>);

encode_element(#ieee_802_11_wtp_radio_fail_alarm_indication{
                    radio_id = M_radio_id,
                    type = M_type,
                    status = M_status}) ->
    encode_element(1047, <<M_radio_id:8,
                           (enum_type(M_type)):8/integer,
                           M_status:8,
                           0:8>>);

encode_element(#ieee_802_11_wtp_radio_information{
                    radio_id = M_radio_id,
                    radio_type = M_radio_type}) ->
    encode_element(1048, <<M_radio_id:8,
                           0:28,
                           (encode_flag('802.11n', M_radio_type)):1,
                           (encode_flag('802.11g', M_radio_type)):1,
                           (encode_flag('802.11a', M_radio_type)):1,
                           (encode_flag('802.11b', M_radio_type)):1>>);

encode_element(#tp_wtp_wwan_statistics_0_9{
                    timestamp = M_timestamp,
                    wwan_id = M_wwan_id,
                    rat = M_rat,
                    rssi = M_rssi,
                    lac = M_lac,
                    cell_id = M_cell_id}) ->
    encode_vendor_element({18681,1}, <<M_timestamp:32,
                                       M_wwan_id:8,
                                       M_rat:8,
                                       M_rssi:8,
                                       0:8,
                                       M_lac:16,
                                       0:16,
                                       M_cell_id:32>>);

encode_element(#tp_wtp_wwan_statistics{
                    timestamp = M_timestamp,
                    wwan_id = M_wwan_id,
                    rat = M_rat,
                    rssi = M_rssi,
                    creg = M_creg,
                    lac = M_lac,
                    latency = M_latency,
                    mcc = M_mcc,
                    mnc = M_mnc,
                    cell_id = M_cell_id}) ->
    encode_vendor_element({18681,1}, <<M_timestamp:32,
                                       M_wwan_id:8,
                                       M_rat:8,
                                       M_rssi:8,
                                       M_creg:8,
                                       M_lac:16,
                                       M_latency:16,
                                       M_mcc:8,
                                       M_mnc:8,
                                       0:16,
                                       M_cell_id:32>>);

encode_element(#tp_wtp_timestamp{
                    second = M_second,
                    fraction = M_fraction}) ->
    encode_vendor_element({18681,2}, <<M_second:32,
                                       M_fraction:32>>);

encode_element(#tp_wtp_wwan_iccid{
                    wwan_id = M_wwan_id,
                    iccid = M_iccid}) ->
    encode_vendor_element({18681,3}, <<M_wwan_id:8,
                                       M_iccid/binary>>);

encode_element(#tp_ieee_802_11_wlan_hold_time{
                    radio_id = M_radio_id,
                    wlan_id = M_wlan_id,
                    hold_time = M_hold_time}) ->
    encode_vendor_element({18681,4}, <<M_radio_id:8,
                                       M_wlan_id:8,
                                       M_hold_time:16>>);

encode_element(#tp_data_channel_dead_interval{
                    data_channel_dead_interval = M_data_channel_dead_interval}) ->
    encode_vendor_element({18681,5}, <<M_data_channel_dead_interval:16>>);

encode_element(#tp_ac_join_timeout{
                    ac_join_timeout = M_ac_join_timeout}) ->
    encode_vendor_element({18681,6}, <<M_ac_join_timeout:16>>);

encode_element(#tp_ac_address_with_priority{
                    priority = M_priority,
                    type = M_type,
                    value = M_value}) ->
    encode_vendor_element({18681,7}, <<M_priority:8,
                                       M_type:8,
                                       M_value/binary>>);

encode_element(#wtp_apn_settings{
                    apn = M_apn,
                    username = M_username,
                    password = M_password}) ->
    encode_vendor_element({18681,8}, <<(byte_size(M_apn)):8/integer, M_apn/binary,
                                       (byte_size(M_username)):8/integer, M_username/binary,
                                       (byte_size(M_password)):8/integer, M_password/binary>>);

encode_element(#wtp_administrator_password_settings{
                    password = M_password}) ->
    encode_vendor_element({18681,9}, <<M_password/binary>>);

encode_element(#firmware_download_information{
                    sha256_image_hash = M_sha256_image_hash,
                    download_uri = M_download_uri}) ->
    encode_vendor_element({18681,10}, <<M_sha256_image_hash:32/bytes,
                                        M_download_uri/binary>>);

encode_element(#firmware_download_status{
                    status = M_status,
                    bytes_downloaded = M_bytes_downloaded,
                    bytes_remaining = M_bytes_remaining}) ->
    encode_vendor_element({18681,11}, <<(enum_status(M_status)):16/integer,
                                        0:16,
                                        M_bytes_downloaded:32,
                                        M_bytes_remaining:32>>);

encode_element(#ieee_802_11_tp_wlan{
                    radio_id = M_radio_id,
                    wlan_id = M_wlan_id,
                    capability = M_capability,
                    key_index = M_key_index,
                    key_status = M_key_status,
                    key = M_key,
                    group_tsc = M_group_tsc,
                    qos = M_qos,
                    auth_type = M_auth_type,
                    mac_mode = M_mac_mode,
                    tunnel_mode = M_tunnel_mode,
                    suppress_ssid = M_suppress_ssid,
                    ssid = M_ssid}) ->
    encode_vendor_element({18681,13}, <<M_radio_id:8,
                                        M_wlan_id:8,
                                        (encode_flag('ess', M_capability)):1,
                                        (encode_flag('ibss', M_capability)):1,
                                        (encode_flag('cf-pollable', M_capability)):1,
                                        (encode_flag('cf-poll-request', M_capability)):1,
                                        (encode_flag('privacy', M_capability)):1,
                                        (encode_flag('short_preamble', M_capability)):1,
                                        (encode_flag('pbcc', M_capability)):1,
                                        (encode_flag('channel_agility', M_capability)):1,
                                        (encode_flag('spectrum_management', M_capability)):1,
                                        (encode_flag('qos', M_capability)):1,
                                        (encode_flag('short_slot_time', M_capability)):1,
                                        (encode_flag('apsd', M_capability)):1,
                                        (encode_flag('reserved', M_capability)):1,
                                        (encode_flag('dsss_ofdm', M_capability)):1,
                                        (encode_flag('delayed_block_ack', M_capability)):1,
                                        (encode_flag('immediate_block_ack', M_capability)):1,
                                        M_key_index:8,
                                        (enum_key_status(M_key_status)):8/integer,
                                        (byte_size(M_key)):16/integer, M_key/binary,
                                        M_group_tsc:6/bytes,
                                        (enum_qos(M_qos)):8/integer,
                                        (enum_auth_type(M_auth_type)):8/integer,
                                        (enum_mac_mode(M_mac_mode)):8/integer,
                                        (enum_tunnel_mode(M_tunnel_mode)):8/integer,
                                        M_suppress_ssid:8,
                                        M_ssid/binary>>);

encode_element(#apply_confirmation_timeout{
                    apply_confirmation_timeout = M_apply_confirmation_timeout}) ->
    encode_vendor_element({18681,12}, <<M_apply_confirmation_timeout:16>>);

encode_element(#power_save_mode{
                    idle_timeout = M_idle_timeout,
                    busy_timeout = M_busy_timeout}) ->
    encode_vendor_element({18681,14}, <<M_idle_timeout:32,
                                        M_busy_timeout:32>>);

encode_element(#gps_last_acquired_position{
                    timestamp = M_timestamp,
                    wwan_id = M_wwan_id,
                    gpsatc = M_gpsatc}) ->
    encode_vendor_element({18681,15}, <<M_timestamp:32,
                                        M_wwan_id:8,
                                        M_gpsatc/binary>>);

encode_element({Tag = {Vendor, Type}, Value}) when is_integer(Vendor), is_integer(Type), is_binary(Value) ->
    encode_vendor_element(Tag, Value);

encode_element({Tag, Value}) when is_integer(Tag), is_binary(Value) ->
    encode_element(Tag, Value).
