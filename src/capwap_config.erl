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

-module(capwap_config).

-compile({parse_transform, cut}).
-compile({parse_transform, exprecs}).
-export_records([wtp, wtp_radio, wtp_wlan_config]).

-export([validate/0, get/2, get/3,
         wtp_config/1, wtp_static_config/1,
         wtp_set_radio_infos/4, update_wlan_config/4, merge/2]).

-include("capwap_packet.hrl").
-include("capwap_config.hrl").
-include("ieee80211.hrl").
-include("eapol.hrl").

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

wtp_static_config(CN) ->
    WTP = capwap_config_wtp_provider:get_config(CN),
    lager:debug("static config for WTP: ~p", [WTP]),
    WTP.

wtp_config(Config) ->
    '#new-wtp'(lists:filter(fun wtp_config_filter/1, Config)).

wtp_config_filter({psm_idle_timeout,           _}) -> true;
wtp_config_filter({psm_busy_timeout,           _}) -> true;
wtp_config_filter({max_stations,               _}) -> true;
wtp_config_filter({echo_request_interval,      _}) -> true;
wtp_config_filter({discovery_interval,         _}) -> true;
wtp_config_filter({idle_timeout,               _}) -> true;
wtp_config_filter({data_channel_dead_interval, _}) -> true;
wtp_config_filter({ac_join_timeout,            _}) -> true;
wtp_config_filter({admin_pw,                   _}) -> true;
wtp_config_filter({wlan_hold_time,             _}) -> true;
wtp_config_filter({broken_add_wlan_workaround, _}) -> true;
wtp_config_filter(_) -> false.

bool_to_int(true) -> 1;
bool_to_int(X) when is_integer(X) andalso X > 0 -> 1;
bool_to_int(_) -> 0.

%% derive WLAN defaults from Radio settings
wtp_init_wlan_radio_defaults(Id, _Radio, WLAN) ->
    RSN = #wtp_wlan_rsn{
	     version = 1,
	     capabilities = 16#000C,
	     group_cipher_suite = ?IEEE_802_1_CIPHER_SUITE_AES,
	     management_frame_protection = false,
	     group_mgmt_cipher_suite = 'AES-CMAC',
	     cipher_suites = [?IEEE_802_1_CIPHER_SUITE_AES],
	     akm_suites = []
	    },
    WLAN#wtp_wlan_config{wlan_id = Id,
			 suppress_ssid = bool_to_int(get(ac, suppress_ssid, false)),
			 mac_mode = local_mac,
			 vlan = 0,
			 privacy = false,
			 rsn = RSN,
			 peer_rekey = 3600,
			 group_rekey = 3600,
			 management_frame_protection = false,
			 fast_transition = false,
			 mobility_domain = 0,
			 strict_group_rekey = false
		 }.

wtp_init_wlan_keymgmt(WLAN = #wtp_wlan_config{
				rsn = #wtp_wlan_rsn{akm_suites = AKM}
				= RSN}, Value) ->
    if Value == psk ->
	    WLAN#wtp_wlan_config{rsn = RSN#wtp_wlan_rsn{akm_suites = ['PSK' | AKM]}};
       Value == 'ft-psk' ->
	    WLAN#wtp_wlan_config{rsn = RSN#wtp_wlan_rsn{akm_suites = ['FT-PSK' | AKM]}};
       Value == wpa ->
	    WLAN#wtp_wlan_config{rsn = RSN#wtp_wlan_rsn{akm_suites = ['802.1x' | AKM]}};
       Value == 'ft-wpa' ->
	    WLAN#wtp_wlan_config{rsn = RSN#wtp_wlan_rsn{akm_suites = ['FT-802.1x' | AKM]}};
       is_list(Value) ->
	    lists:foldl(fun(V, W) -> wtp_init_wlan_keymgmt(W, V) end, WLAN, Value);
       true ->
	    lager:error("WLAN Key Management: ~w is invalid", [Value]),
	    WLAN
    end.

wtp_init_wlan(_CN, _Radio, {ssid, _}, WLAN) ->
    WLAN;
wtp_init_wlan(_CN, _Radio, {suppress_ssid, Value}, WLAN) ->
    WLAN#wtp_wlan_config{suppress_ssid = bool_to_int(Value)};
wtp_init_wlan(_CN, _Radio, {mac_mode, Value}, WLAN)
  when Value == local_mac; Value == split_mac ->
    WLAN#wtp_wlan_config{mac_mode = Value};
wtp_init_wlan(_CN, _Radio, {vlan, Value}, WLAN)
  when is_integer(Value) ->
    WLAN#wtp_wlan_config{vlan = Value};
wtp_init_wlan(_CN, _Radio, {keymgmt, Value}, WLAN) ->
    wtp_init_wlan_keymgmt(WLAN, Value);
wtp_init_wlan(_CN, _Radio, {privacy, Value}, WLAN)
  when is_boolean(Value) ->
    WLAN#wtp_wlan_config{privacy = Value};
wtp_init_wlan(_CN, _Radio, {management_frame_protection, Value}, WLAN)
  when Value == optional; Value == required ->
    WLAN#wtp_wlan_config{management_frame_protection = Value};
wtp_init_wlan(_CN, _Radio, {management_frame_protection, true}, WLAN) ->
    WLAN#wtp_wlan_config{management_frame_protection = required};
wtp_init_wlan(_CN, _Radio, {management_frame_protection, false}, WLAN) ->
    WLAN#wtp_wlan_config{management_frame_protection = false};
wtp_init_wlan(_CN, _Radio, {fast_transition, Value}, WLAN)
  when is_boolean(Value) ->
    WLAN#wtp_wlan_config{fast_transition = Value};
wtp_init_wlan(_CN, _Radio, {mobility_domain, Value}, WLAN)
  when is_integer(Value) ->
    WLAN#wtp_wlan_config{mobility_domain = Value};
wtp_init_wlan(_CN, _Radio, {secret, Value}, WLAN)
  when is_binary(Value) ->
    WLAN#wtp_wlan_config{secret = Value};
wtp_init_wlan(_CN, _Radio, {peer_rekey, Value}, WLAN)
  when is_integer(Value) ->
    WLAN#wtp_wlan_config{peer_rekey = Value};
wtp_init_wlan(_CN, _Radio, {group_rekey, Value}, WLAN)
  when is_integer(Value) ->
    WLAN#wtp_wlan_config{group_rekey = Value};
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
    WLAN0 = wtp_init_wlan_radio_defaults(Count, Radio, #wtp_wlan_config{ssid = SSID}),
    WLAN = lists:foldl(wtp_init_wlan(CN, Radio, _, _),
		       WLAN0, Settings),
    {WLAN, Count + 1}.

wtp_init_radio_config(CN, Config, #ieee_802_11_wtp_radio_information{
			     radio_id = RadioId,
                 radio_type = RadioType}) ->
    Radio0 = ?DEFAULT_RADIO(RadioId, RadioType),

    %% apply per Radio-Type AC defaults
    ConfTypes = [defaults | RadioType],
    Radio1 = lists:foldl(fun(Type, Acc) ->
        DefEnv = capwap_config:get(wtp, [defaults, radio_settings, Type], []),
        merge(DefEnv, Acc)
    end, Radio0, ConfTypes),

    Radio2 = lists:foldl(fun(Type, Acc) ->
        DefEnv = capwap_config:get(wtp, [CN, radio_settings, Type], []),
        merge(DefEnv, Acc)
    end, Radio1, ConfTypes),

    RadiosFromProvider = proplists:get_value(radio, Config, []),
    Radio3 = get_radio_by_id(RadioId, RadiosFromProvider),

    %% turn it into a record
    RadioRec = '#new-wtp_radio'(merge(Radio3, Radio2)),

    %% convert the remaining WLAN tupple list into a record list
    {Wlans, _} = lists:mapfoldl( wtp_init_wlan_mf(CN, RadioRec, _, _), 1, RadioRec#wtp_radio.wlans),
    RadioRec#wtp_radio{wlans = Wlans}.

wtp_set_radio_infos(CN, RadioInfos, Config, StaticConfig) ->
    Radios = lists:map(wtp_init_radio_config(CN, StaticConfig, _), RadioInfos),
    lager:debug("Radios: ~p", [Radios]),
    Config#wtp{radios = Radios}.

update_wlan_config(RadioId, WlanId, Settings, #wtp{radios = Radios} = Config) ->
    Radio = lists:keyfind(RadioId, #wtp_radio.radio_id, Radios),
    WLAN = lists:keyfind(WlanId, #wtp_wlan_config.wlan_id, Radio#wtp_radio.wlans),
    Radio1 = Radio#wtp_radio{wlans = lists:keystore(WlanId, #wtp_wlan_config.wlan_id,
						    Radio#wtp_radio.wlans,
						    '#set-'(Settings, WLAN))},
    Config#wtp{radios = lists:keystore(RadioId, #wtp_radio.radio_id,
				       Radios, Radio1)}.

merge(Settings, DefValues) ->
    lists:map(fun({K, V}) ->
        {K, proplists:get_value(K, Settings, V)}
    end, DefValues).

get_radio_by_id(_, []) -> [];
get_radio_by_id(RadioId, [Radio | Tail]) ->
    case proplists:get_value(radio_id, Radio) of
        RadioId -> Radio;
        _ -> get_radio_by_id(RadioId, Tail)
    end.
