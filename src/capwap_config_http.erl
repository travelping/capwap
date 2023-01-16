%% Copyright (C) 2013-2023, Travelping GmbH <info@travelping.com>

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

-module(capwap_config_http).

%%-behaviour(capwap_config_provider).

-export([wtp_init_config/2, wtp_config/1,
	 wtp_radio_config/3]).
-ifdef(TEST).
-export([transform_values/1]).
-endif.

-include("capwap_config.hrl").

-define(DEFAULT_HTTP, "http://127.0.0.1").

wtp_init_config(CN, Opts) ->
    URL = proplists:get_value(url, Opts, ?DEFAULT_HTTP),
    JSON = request(<<"/", CN/binary>>, URL),
    true = validate_config(JSON),
    Config = maps:get(config, JSON, []),
    Res = transform_values(Config),
    {ok, {CN, capwap_config:'#frommap-wtp'(Res)}}.

wtp_config({_CN, Cfg}) ->
    Cfg#wtp{radios = undefined}.

wtp_radio_config({_CN, #wtp{radios = Radios}}, RadioId, _RadioType) ->
    #wtp_radio{} = lists:keyfind(RadioId, #wtp_radio.radio_id, Radios).

request(Path, Opts) ->
    HttpServer = list_to_binary(Opts),
    Http = <<HttpServer/binary, Path/binary>>,
    case hackney:request(get, Http, []) of
        {ok, 200, _Headers, ClientRef} ->
            {ok, Body} = hackney:body(ClientRef),
            jsx:decode(Body, [return_maps, {labels, existing_atom}]);
        _ ->
            exometer:update([capwap, ac, error_wtp_http_config_count], 1),
            throw({error, get_http_config_wtp})
    end.

validate_config(#{type := <<"wtp-config">>,
		  version := <<"1.0">>}) ->
    true;
validate_config(_) ->
    false.

akm_suite(<<"psk">>)    -> 'PSK';
akm_suite(<<"ft-psk">>) -> 'FT-PSK';
akm_suite(<<"wpa">>)    -> '802.1x';
akm_suite(<<"ft-wpa">>) -> 'FT-802.1x'.

encode_cipher_suite(Suite) ->
    Atom = erlang:binary_to_existing_atom(Suite, utf8),
    <<(capwap_packet:encode_cipher_suite(Atom)):32>>.

transform_values(Values) ->
    maps:fold(
      fun(K0, V0, M) ->
	      {K1, V1} = transform_value(K0, V0),
	      maps:put(K1, V1, M)
      end, #{}, Values).

transform_value(radio_type, V) ->
    {radio_type, [erlang:binary_to_existing_atom(RT, utf8) || RT <- V]};
transform_value(operation_mode, V) ->
    {operation_mode, erlang:binary_to_existing_atom(V, utf8)};
transform_value(short_preamble, V) ->
    {short_preamble, erlang:binary_to_existing_atom(V, utf8)};
transform_value(channel_assessment, V) ->
    {channel_assessment, erlang:binary_to_existing_atom(V, utf8)};
transform_value(diversity, V) ->
    {diversity, erlang:binary_to_existing_atom(V, utf8)};
transform_value(combiner, V) ->
    {combiner, erlang:binary_to_existing_atom(V, utf8)};
transform_value(mac_mode, V) ->
    {mac_mode, erlang:binary_to_existing_atom(V, utf8)};
transform_value(suppress_ssid, true) ->
    {suppress_ssid, 1};
transform_value(suppress_ssid, false) ->
    {suppress_ssid, 0};
transform_value(capabilities, <<"0x", V/binary>>) ->
    {capabilities, binary_to_integer(V,16)};
transform_value(management_frame_protection, V)
  when not is_boolean(V) ->
    {management_frame_protection, erlang:binary_to_existing_atom(V, utf8)};
transform_value(group_cipher_suite, V) ->
    {group_cipher_suite, encode_cipher_suite(V)};
transform_value(cipher_suites, V) ->
    {cipher_suites, [encode_cipher_suite(S) || S <- V]};
transform_value(group_mgmt_cipher_suite, V) ->
    {group_mgmt_cipher_suite, erlang:binary_to_existing_atom(V, utf8)};
transform_value(akm_suites, V) ->
    {akm_suites, [akm_suite(S) || S <- V]};
transform_value(radio, Radios) ->
    {radios, [capwap_config:'#frommap-wtp_radio'(
		transform_values(Radio)) || Radio <- Radios ]};
transform_value(wlans, WLANs) ->
    {wlans, [capwap_config:'#frommap-wtp_wlan_config'(
	       transform_values(WLAN)) || WLAN <- WLANs ]};
transform_value(rsn, RSN) ->
    {rsn, capwap_config:'#frommap-wtp_wlan_rsn'(transform_values(RSN))};

transform_value(K, V) ->
    {K, V}.
