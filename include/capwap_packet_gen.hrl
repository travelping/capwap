%% This file is auto-generated. DO NOT EDIT

-record(ac_descriptor, {
        stations = 0,
        limit = 0,
        active_wtps = 0,
        max_wtps = 0,
        security = [],
        r_mac = reserved,
        dtls_policy = [],
        sub_elements
}).

-record(ac_ipv4_list, {
        ip_address
}).

-record(ac_ipv6_list, {
        ip_address
}).

-record(ac_name, {
        name = <<>>
}).

-record(ac_name_with_priority, {
        priority = 0,
        name = <<>>
}).

-record(ac_timestamp, {
        timestamp = 0
}).

-record(add_mac_acl, {
        macs
}).

-record(add_station, {
        radio_id = 0,
        mac = <<>>,
        vlan_name = <<>>
}).

-record(control_ipv4_address, {
        ip_address = <<0,0,0,0>>,
        wtp_count = 0
}).

-record(control_ipv6_address, {
        ip_address = <<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0>>,
        wtp_count = 0
}).

-record(local_ipv4_address, {
        ip_address = <<0,0,0,0>>
}).

-record(local_ipv6_address, {
        ip_address = <<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0>>
}).

-record(timers, {
        discovery = 0,
        echo_request = 0
}).

-record(transport_protocol, {
        transport = udp_lite
}).

-record(data_transfer_data, {
        data_type = included,
        data_mode = reserved,
        data = <<>>
}).

-record(data_transfer_mode, {
        data_mode = reserved
}).

-record(decryption_error_report, {
        radio_id = 0,
        macs
}).

-record(decryption_error_report_period, {
        radio_id = 0,
        report_interval = 0
}).

-record(delete_mac_acl_entry, {
        macs
}).

-record(delete_station, {
        radio_id = 0,
        mac = <<>>
}).

-record(discovery_type, {
        discovery_type = unknown
}).

-record(duplicate_ipv4_address, {
        ip_address = <<0,0,0,0>>,
        status = 0,
        mac = <<>>
}).

-record(duplicate_ipv6_address, {
        ip_address = <<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0>>,
        status = 0,
        mac = <<>>
}).

-record(idle_timeout, {
        timeout = 0
}).

-record(ecn_support, {
        ecn_support = limited
}).

-record(image_data, {
        data_type = included,
        data = <<>>
}).

-record(image_identifier, {
        vendor = 0,
        data = <<>>
}).

-record(image_information, {
        file_size = 0,
        hash = <<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0>>
}).

-record(initiate_download, {
        
}).

-record(location_data, {
        location = <<>>
}).

-record(maximum_message_length, {
        maximum_message_length = 0
}).

-record(mtu_discovery_padding, {
        padding = <<>>
}).

-record(radio_administrative_state, {
        radio_id = 0,
        admin_state = reserved
}).

-record(radio_operational_state, {
        radio_id = 0,
        state = reserved,
        cause = normal
}).

-record(result_code, {
        result_code = 0
}).

-record(returned_message_element, {
        reason = reserved,
        message_element = <<>>
}).

-record(session_id, {
        session_id = 0
}).

-record(statistics_timer, {
        statistics_timer = 0
}).

-record(wtp_board_data, {
        vendor = 0,
        board_data_sub_elements
}).

-record(wtp_descriptor, {
        max_radios = 0,
        radios_in_use = 0,
        encryption_sub_element = [],
        sub_elements
}).

-record(wtp_fallback, {
        mode = reserved
}).

-record(wtp_frame_tunnel_mode, {
        mode = []
}).

-record(wtp_mac_type, {
        mac_type = local
}).

-record(wtp_name, {
        wtp_name = <<>>
}).

-record(wtp_radio_statistics, {
        radio_id = 0,
        last_fail_type = unsuported,
        reset_count = 0,
        sw_failure_count = 0,
        hw_failure_count = 0,
        other__failure_count = 0,
        unknown_failure_count = 0,
        config_update_count = 0,
        channel_change_count = 0,
        band_change_count = 0,
        current_noise_floor = 0
}).

-record(wtp_reboot_statistics, {
        reboot_count_ = 0,
        ac_initiated_count = 0,
        link_failure_count = 0,
        sw_failure_count = 0,
        hw_failure_count = 0,
        other_failure_count = 0,
        unknown_failure_count = 0,
        last_failure_type = unsuported
}).

-record(wtp_static_ip_address_information, {
        ip_address = <<0,0,0,0>>,
        netmask = <<0,0,0,0>>,
        gateway = <<0,0,0,0>>,
        static = 0
}).

-record(ieee_802_11_add_wlan, {
        radio_id = 0,
        wlan_id = 0,
        capability = [],
        key_index = 0,
        key_status = per_station,
        key = <<>>,
        group_tsc = <<0,0,0,0,0,0>>,
        qos = best_effort,
        auth_type = open_system,
        mac_mode = local_mac,
        tunnel_mode = local_bridge,
        suppress_ssid = 0,
        ssid = <<>>
}).

-record(ieee_802_11_antenna, {
        radio_id = 0,
        diversity = disabled,
        combiner = left,
        antenna_selection = <<>>
}).

-record(ieee_802_11_assigned_wtp_bssid, {
        radio_id = 0,
        wlan_id = 0,
        bssid = <<0,0,0,0,0,0>>
}).

-record(ieee_802_11_delete_wlan, {
        radio_id = 0,
        wlan_id = 0
}).

-record(ieee_802_11_direct_sequence_control, {
        radio_id = 0,
        current_chan = 0,
        current_cca = edonly,
        energy_detect_threshold = 0
}).

-record(ieee_802_11_information_element, {
        radio_id = 0,
        wlan_id = 0,
        flags = [],
        ie = <<>>
}).

-record(ieee_802_11_mac_operation, {
        radio_id = 0,
        rts_threshold = 0,
        short_retry = 0,
        long_retry = 0,
        fragmentation_threshold = 0,
        tx_msdu_lifetime = 0,
        rx_msdu_lifetime = 0
}).

-record(ieee_802_11_mic_countermeasures, {
        radio_id = 0,
        wlan_id = 0,
        mac = <<0,0,0,0,0,0>>
}).

-record(ieee_802_11_multi_domain_capability, {
        radio_id = 0,
        first_channel = 0,
        number_of_channels_ = 0,
        max_tx_power_level = 0
}).

-record(ieee_802_11_ofdm_control, {
        radio_id = 0,
        current_chan = 0,
        band_support = 0,
        ti_threshold = 0
}).

-record(ieee_802_11_rate_set, {
        radio_id = 0,
        rate_set = <<>>
}).

-record(ieee_802_11_rsna_error_report_from_station, {
        client_mac_address = <<0,0,0,0,0,0>>,
        bssid = <<0,0,0,0,0,0>>,
        radio_id = 0,
        wlan_id = 0,
        tkip_icv_errors = 0,
        tkip_local_mic_failures = 0,
        tkip_remote_mic_failures = 0,
        ccmp_replays = 0,
        ccmp_decrypt_errors = 0,
        tkip_replays = 0
}).

-record(ieee_802_11_station, {
        radio_id = 0,
        association_id = 0,
        mac_address = <<0,0,0,0,0,0>>,
        capabilities = [],
        wlan_id = 0,
        supported_rate = <<>>
}).

-record(ieee_802_11_station_qos_profile, {
        mac_address = <<0,0,0,0,0,0>>,
        p8021p = 0
}).

-record(ieee_802_11_station_session_key, {
        mac_address = <<0,0,0,0,0,0>>,
        flags = [],
        pairwise_tsc = <<0,0,0,0,0,0>>,
        pairwise_rsc = <<0,0,0,0,0,0>>,
        key = <<>>
}).

-record(ieee_802_11_statistics, {
        radio_id = 0,
        tx_fragment_count = 0,
        multicast_tx_count = 0,
        failed_count = 0,
        retry_count = 0,
        multiple_retry_count = 0,
        frame_duplicate_count = 0,
        rts_success_count = 0,
        rts_failure_count = 0,
        ack_failure_count = 0,
        rx_fragment_count = 0,
        multicast_rx_count = 0,
        fcs_error__count = 0,
        tx_frame_count = 0,
        decryption_errors = 0,
        discarded_qos_fragment_count = 0,
        associated_station_count = 0,
        qos_cf_polls_received_count = 0,
        qos_cf_polls_unused_count = 0,
        qos_cf_polls_unusable_count = 0
}).

-record(ieee_802_11_supported_rates, {
        radio_id = 0,
        supported_rates = <<>>
}).

-record(ieee_802_11_tx_power, {
        radio_id = 0,
        current_tx_power = 0
}).

-record(ieee_802_11_tx_power_level, {
        radio_id = 0,
        power_level = []
}).

-record(ieee_802_11_update_station_qos, {
        radio_id = 0,
        mac_address = <<0,0,0,0,0,0>>,
        qos_sub_element = <<0,0,0,0,0,0,0,0>>
}).

-record(ieee_802_11_update_wlan, {
        radio_id = 0,
        wlan_id = 0,
        capability = [],
        key_index = 0,
        key_status = per_station,
        key = <<>>
}).

-record(ieee_802_11_wtp_quality_of_service, {
        radio_id = 0,
        tagging_policy = <<0:5>>,
        qos_sub_element = <<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0>>
}).

-record(ieee_802_11_wtp_radio_configuration, {
        radio_id = 0,
        short_preamble = unsupported,
        num_of_bssids = 0,
        dtim_period = 0,
        bssid = <<0,0,0,0,0,0>>,
        beacon_period = 0,
        country_string = <<0,0,0,0>>
}).

-record(ieee_802_11_wtp_radio_fail_alarm_indication, {
        radio_id = 0,
        type = receiver,
        status = 0
}).

-record(ieee_802_11_wtp_radio_information, {
        radio_id = 0,
        radio_type = []
}).

-record(tp_wtp_wwan_statistics_0_9, {
        timestamp,
        wwan_id = 0,
        rat = 0,
        rssi = 0,
        lac,
        cell_id
}).

-record(tp_wtp_wwan_statistics, {
        timestamp = 0,
        wwan_id = 0,
        rat = 0,
        rssi = 0,
        creg = 0,
        lac = 0,
        latency = 0,
        mcc = 0,
        mnc = 0,
        cell_id = 0
}).

-record(tp_wtp_timestamp, {
        second = 0,
        fraction = 0
}).

-record(tp_wtp_timestamp_1_1, {
        second = 0
}).

-record(tp_wtp_wwan_iccid, {
        wwan_id = 0,
        iccid = <<>>
}).

-record(tp_ieee_802_11_wlan_hold_time, {
        radio_id = 0,
        wlan_id = 0,
        hold_time = 0
}).

-record(tp_data_channel_dead_interval, {
        data_channel_dead_interval = 0
}).

-record(tp_ac_join_timeout, {
        ac_join_timeout = 0
}).

-record(tp_ac_address_with_priority, {
        priority = 0,
        type = 0,
        value = <<>>
}).

-record(wtp_apn_settings, {
        apn = <<>>,
        username = <<>>,
        password = <<>>
}).

-record(wtp_administrator_password_settings, {
        password = <<>>
}).

-record(firmware_download_information, {
        sha256_image_hash = <<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0>>,
        download_uri = <<>>
}).

-record(firmware_download_status, {
        status = reserved,
        bytes_downloaded = 0,
        bytes_remaining = 0
}).

-record(ieee_802_11_tp_wlan, {
        radio_id = 0,
        wlan_id = 0,
        capability = [],
        key_index = 0,
        key_status = per_station,
        key = <<>>,
        group_tsc = <<0,0,0,0,0,0>>,
        qos = best_effort,
        auth_type = open_system,
        mac_mode = local_mac,
        tunnel_mode = local_bridge,
        suppress_ssid = 0,
        ssid = <<>>
}).

-record(apply_confirmation_timeout, {
        apply_confirmation_timeout = 0
}).

-record(power_save_mode, {
        idle_timeout = 0,
        busy_timeout = 0
}).

-record(gps_last_acquired_position, {
        timestamp = 0,
        wwan_id = 0,
        gpsatc = <<>>
}).

