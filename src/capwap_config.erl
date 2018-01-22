%% Copyright (C) 2013-2018, Travelping GmbH <info@travelping.com>

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
	 wtp_init_config_provider/1, wtp_config/1,
	 wtp_radio_config/3]).

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

wtp_init_config_provider(CN) ->
    Default = [capwap_config_env],
    Providers = capwap_config:get(ac, config_providers, Default),
    wtp_init_config_provider(CN, Providers).

wtp_init_config_provider(_CN, []) ->
    {error, unconfigured};
wtp_init_config_provider(CN, [Provider|T])
  when is_atom(Provider) ->
    wtp_init_config_provider(CN, Provider, [], T);
wtp_init_config_provider(CN, [{Provider, Opts}|T])
  when is_atom(Provider), is_list(Opts) ->
    wtp_init_config_provider(CN, Provider, Opts, T).

wtp_init_config_provider(CN, Provider, Opts, Next) ->
    case (catch Provider:wtp_init_config(CN, Opts)) of
	{ok, Settings} ->
	    lager:debug("Eval config provider ~p for ~p", [Provider, CN]),
	    lager:trace("Get wtp config for ~p => ~p", [CN, Settings]),
	    {ok, {Provider, Settings}};
	Error ->
	    lager:debug("Error in provider ~p with reason ~p", [Provider, Error]),
	    wtp_init_config_provider(CN, Next)
    end.

wtp_config({Provider, State}) ->
    Provider:wtp_config(State).

wtp_radio_config({Provider, State}, RadioId, RadioType) ->
    Provider:wtp_radio_config(State, RadioId, RadioType).
