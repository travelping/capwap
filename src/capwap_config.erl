-module(capwap_config).

-compile({parse_transform, cut}).
-compile({parse_transform, exprecs}).
-export_records([wtp, wtp_radio]).

-export([validate/0, get/2, get/3, wtp_config/1,
	 wtp_set_radio_infos/3, update_wlan_config/4]).

-include("capwap_packet.hrl").
-include("capwap_config.hrl").

-spec get(Category :: atom(),
	  Key      :: atom(),
	  Default  :: term()) -> term().

-define(APP, capwap).

validate() ->
    lager:info("CAPWAP config validte ok."),
    ok.

get(ac, Key) when is_atom(Key) ->
    application:get_env(?APP, Key).

get(wtp, Keys, Default) ->
    get(ac, [wtps | Keys], Default);

get(ac, Key, Default) when is_atom(Key) ->
    application:get_env(?APP, Key, Default);

get(Category, [Key|Keys], Default) ->
    case application:get_env(?APP, Key) of
	{ok, Val} ->
	    get(Category, Keys, Val, Default);
	_ ->
	    Default
    end.

get(_Category, [], Val, _Default) ->
    Val;

get(Category, [Key|Keys], Val, Default)
  when is_list(Val) ->
    case lists:keyfind(Key, 1, Val) of
	false ->
	    Default;
	{Key, NewVal} ->
	    get(Category, Keys, NewVal, Default)
    end;

get(_Category, _Key, _Val, Default) ->
    Default.

wtp_get(Path, Values)
  when is_list(Values) ->
    Settings = get(wtp, Path, []),
    lager:debug("got Settings for ~p: ~p", [Path, Settings]),
    lists:map(fun({K, V}) ->
		      {K, proplists:get_value(K, Settings, V)}
	      end, Values).

wtp_config(CN) ->
    WTP0 = [{psm_idle_timeout,           30},
	    {psm_busy_timeout,           300},
	    {max_stations,               100},
	    {echo_request_interval,      60},
	    {discovery_interval,         20},
	    {idle_timeout,               300},
	    {data_channel_dead_interval, 70},
	    {ac_join_timeout,            70},
	    {admin_pw,                   undefined},
	    {wlan_hold_time,             15}],
    WTP1 = wtp_get([defaults], WTP0),
    WTP2 = wtp_get([CN], WTP1),
    lager:debug("WTP: ~p", [WTP2]),
    '#new-wtp'(WTP2).

bool_to_int(true) -> 1;
bool_to_int(X) when is_integer(X) andalso X > 0 -> 1;
bool_to_int(_) -> 0.

%% derive WLAN defaults from Radio settings
wtp_init_wlan_radio_defaults(Id, _Radio, WLAN) ->
    WLAN#wtp_wlan{wlan_id = Id,
		  suppress_ssid = bool_to_int(get(ac, suppress_ssid, false))}.

wtp_init_wlan(_CN, _Radio, {ssid, _}, WLAN) ->
    WLAN;
wtp_init_wlan(_CN, _Radio, {suppress_ssid, Value}, WLAN) ->
    WLAN#wtp_wlan{suppress_ssid = bool_to_int(Value)};
wtp_init_wlan(CN, Radio, Setting, WLAN) ->
    lager:debug("ignoring ~p on Radio (~w:~w)", [Setting, CN, Radio#wtp_radio.radio_id]),
    WLAN.

wtp_init_wlan_mf(CN, Radio, Settings, Count) ->
    DefaultSSID = get(ac, default_ssid, <<"CAPWAP">>),
    DynSSIDSuffixLen = get(ac, dynamic_ssid_suffix_len, false),

    SSID = case proplists:get_value(ssid, Settings) of
	       V when is_binary(V) -> V;
	       V when is_list(V)   -> list_to_binary(V);
	       _ when is_integer(DynSSIDSuffixLen),
		      is_binary(CN) ->
		   binary:list_to_bin([DefaultSSID, $-,
				       binary:part(CN,
						   size(CN) - DynSSIDSuffixLen,
						   DynSSIDSuffixLen)]);
	       _ -> DefaultSSID
	   end,
    WLAN0 = wtp_init_wlan_radio_defaults(Count, Radio, #wtp_wlan{ssid = SSID}),
    WLAN = lists:foldl(wtp_init_wlan(CN, Radio, _, _),
		       WLAN0, Settings),
    {WLAN, Count + 1}.

%% apply per RADIO type AC defaults
wtp_init_radio_type_config(CN, RadioType, Radio) ->
    wtp_get([CN, radio_settings, RadioType], Radio).

wtp_init_radio_config(CN, #ieee_802_11_wtp_radio_information{
			     radio_id = RadioId,
			     radio_type = RadioType}) ->
    Radio0 = [{radio_id,		RadioId},
	      {radio_type,		RadioType},
	      {operation_mode,		'802.11g'},
	      {channel,			undefined},
	      {beacon_interval,		100},
	      {dtim_period,		1},
	      {short_preamble,		supported},
	      {rts_threshold,		2347},
	      {short_retry,		7},
	      {long_retry,		4},
	      {fragmentation_threshold,	2346},
	      {tx_msdu_lifetime,	512},
	      {rx_msdu_lifetime,	512},
	      {tx_power,		100},
	      {channel_assessment,	csonly},
	      {energy_detect_threshold,	100},
	      {band_support,		16#7F},
	      {ti_threshold,		1000},
	      {diversity,		disabled},
	      {combiner,		omni},
	      {antenna_selection,	[1]},
	      {report_interval,         300},
	      {wlans,			[]}],

    %% apply per Radio-Type AC defaults
    ConfTypes = [defaults | RadioType],
    Radio1 = lists:foldl(wtp_init_radio_type_config(defaults, _, _), Radio0, ConfTypes),
    Radio2 = lists:foldl(wtp_init_radio_type_config(CN, _, _), Radio1, ConfTypes),

    %% apply per WTP and RadioId settings
    Radio3 = wtp_get([CN, radio, RadioId], Radio2),

    %% turn it into a record
    RadioRec = '#new-wtp_radio'(Radio3),

    %% convert the remaining WLAN tupple list into a record list
    {Wlans, _} = lists:mapfoldl(wtp_init_wlan_mf(CN, RadioRec, _, _), 1, RadioRec#wtp_radio.wlans),
    RadioRec#wtp_radio{wlans = Wlans}.

wtp_set_radio_infos(CN, RadioInfos, Config) ->
    Radios = lists:map(wtp_init_radio_config(CN, _), RadioInfos),
    lager:debug("Radios: ~p", [Radios]),
    Config#wtp{radios = Radios}.

update_wlan_config(RadioId, WlanId, Settings, #wtp{radios = Radios} = Config) ->
    Radio = lists:keyfind(RadioId, #wtp_radio.radio_id, Radios),
    WLAN = lists:keyfind(WlanId, #wtp_wlan.wlan_id, Radio#wtp_radio.wlans),
    Radio1 = Radio#wtp_radio{wlans = lists:keystore(WlanId, #wtp_wlan.wlan_id,
						    Radio#wtp_radio.wlans,
						    '#set-'(Settings, WLAN))},
    Config#wtp{radios = lists:keystore(RadioId, #wtp_radio.radio_id,
				       Radios, Radio1)}.
