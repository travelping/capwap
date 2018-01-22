CONFIG PROVIDERS FOR WTPs
=========================

Currently support two config providers:

* capwap_env_config_wtp_provider

    get config from sys.config

* capwap_http_config_wtp_provider

    get config from http server

For setup order and options config provider:

```erlang
[{capwap, [
    {config_providers, [
            {capwap_http_config_wtp_provider, "http://127.0.0.1:8080"},
            capwap_env_config_wtp_provider
    ]}
 ]
}].
```

If config for WTP exists in provider then do not take down provider in
config_providers list. Providers may be duplicated (with different opts).

capwap_env_config_wtp_provider
------------------------------

Specify config in sys.config like in example:

```erlang
[{capwap,
    {wtps, [
		   %% default for ALL WTP's
		   {defaults,
		    [
             {psm_idle_timeout,           30},
		     {psm_busy_timeout,           300},
		     {max_stations,               100},
		     {echo_request_interval,      30},
		     {discovery_interval,         20},
		     {idle_timeout,               300},
		     {data_channel_dead_interval, 70},
		     {ac_join_timeout,            70},
		     {admin_pw,                   undefined},
		     {wlan_hold_time,             15},
		     {radio_settings,
		      [{defaults,  [{beacon_interval, 100}, {wlans, [[{ssid, default}]]}]},
		       {'802.11a', [{operation_mode, '802.11a'}, {channel, 155}]},
		       {'802.11b', [{operation_mode, '802.11b'}, {channel,  11}]},
		       {'802.11g', [{operation_mode, '802.11g'}, {channel,  11}]}
		      ]
		     }
		    ]},
            {<<"wtp-lede">>, [
                {discovery_interval, 40},
                {radio, [
                    {1, [{channel, 36},{wlans, [
                            [{wlan_id, 1}, {ssid, <<"test 1">>}, {suppress_ssid, 0}]
                    ]}]},
                    {2, [{channel, 6},{wlans, [
                        [{wlan_id, 1}, {ssid, <<"test 2">>}, {suppress_ssid, 0}]
                ]}]}

                ]}]}
		  ]}
	  ]}
```

Configs for specific WTP merge with default settings (get option from default
if it not set).


capwap_http_config_wtp_provider
-------------------------------

Specify config in sys.config http servers when capwap get wtp config:

```erlang
[{capwap, [
    {config_providers, [
            {capwap_http_config_wtp_provider, "https://capwap_config.tpip.net"}
    ]}
 ]
}].
```

And capwap will send HTTP GET requests to server:

    ```
    HTTP_ADDRESS/COMMON_NAME
    ```
    like 127.0.0.1/wtp-lede

    Format response:
    ```json
    {
        "type": "wtp-common-config",
        "version": "1.0",
        "config": {
            "psm_idle_timeout":           30,
            "psm_busy_timeout":           300,
            "max_stations":               100,
            "echo_request_interval":      60,
            "discovery_interval":         20,
            "idle_timeout":               300,
            "data_channel_dead_interval": 70,
            "ac_join_timeout":            70,
            "wlan_hold_time":             15,
            "broken_add_wlan_workaround": false,
            "radio": [{
                "radio_id":                1
                "operation_mode":          "802.11g",
                "channel":                 36,
                "beacon_interval":         100,
                "dtim_period":             1,
                "short_preamble":          "supported",
                "rts_threshold":           2347,
                "short_retry":             7,
                "long_retry":              4,
                "fragmentation_threshold": 2346,
                "tx_msdu_lifetime":        512,
                "rx_msdu_lifetime":        512,
                "tx_power":                100,
                "channel_assessment":      "csonly",
                "energy_detect_threshold": 100,
                "band_support":            127,
                "ti_threshold":            1000,
                "diversity":               "disabled",
                "combiner":                "omni",
                "antenna_selection":       [1],
                "report_interval":         300,
                "wlans":                   [
                    {"wlan_id":1, "ssid":"test 1", "suppress_ssid":0}
                ]
        }]
    }
    ```

CAPWAP AC will fill missing options from default.
