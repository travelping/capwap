%% Copyright 2017-2019 Travelping GmbH <info@travelping.com>
%%
%% This program is free software: you can redistribute it and/or modify
%% it under the terms of the GNU Lesser General Public License as
%% published by the Free Software Foundation, either version 3 of the
%% License, or (at your option) any later version.
%%
%% This program is distributed in the hope that it will be useful,
%% but WITHOUT ANY WARRANTY; without even the implied warranty of
%% MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
%% GNU Lesser General Public License for more details.
%%
%% You should have received a copy of the GNU Lesser General Public License
%% along with this program. If not, see <http://www.gnu.org/licenses/>.

-module(capwap_http_loc).

-compile({parse_transform, cut}).

-behaviour(ergw_aaa).

%% AAA API
-export([validate_handler/1, validate_service/3, validate_procedure/5,
	 initialize_handler/1, initialize_service/2, invoke/6, handle_response/6]).
-export([get_state_atom/1]).

-include_lib("kernel/include/logger.hrl").

-define(GX_APP, 'Gx').
-define(GX_API, gx).

%%===================================================================
%% API
%%===================================================================

initialize_handler(Opts) ->
    ?LOG(debug, "Init'ed handler with Opts: ~p", [Opts]),
    % Returning child specs
    CacheServer = #{id => capwap_tb_cache_server,
                    start => {capwap_tb_cache_server, start_link, [Opts]},
                    restart => permanent,
                    significant => false,
                    shutdown => 500,
                    type => worker},
    ?LOG(debug, "Providing cache spec: ~p", [CacheServer]),
    {ok, [CacheServer]}.

initialize_service(ServiceId, Opts) ->
    ?LOG(debug, "Init'ed service with ServiceId: ~p", [{ServiceId, Opts}]),
    % Returning opts for child specs
    {ok, []}.

validate_handler(Opts) ->
    ?LOG(debug, "Validating handler with Opts: ~p", [Opts]),
    ergw_aaa_config:validate_options(fun validate_option/2, Opts, [], map).

validate_service(Service, HandlerOpts, Opts) ->
    ?LOG(debug, "Validating service with config: ~p", [{Service, HandlerOpts, Opts}]),
    ergw_aaa_config:validate_options(fun validate_option/2, Opts, HandlerOpts, map).

validate_procedure(_Application, _Procedure, _Service, ServiceOpts, Opts) ->
    ?LOG(debug, "Validating procedure with config: ~p", [{_Application, _Procedure, _Service, ServiceOpts, Opts}]),
    ergw_aaa_config:validate_options(fun validate_option/2, Opts, ServiceOpts, map).

validate_option(handler, Value) ->
    Value;
validate_option(service, Value) ->
    Value;
validate_option(uri, Value) when is_binary(Value) ->
    Value;
validate_option(uri, Value) when is_list(Value) ->
    Value;
validate_option(default_location, Value) when is_binary(Value) ->
    Value;
validate_option(timeout, Value) when is_integer(Value) ->
    Value;
validate_option(refresh, Value) when is_integer(Value) ->
    Value;
validate_option(token, Value) when is_binary(Value) ->
    Value;
validate_option(token, Value) when is_list(Value) ->
    Value;
validate_option(keys, Value = #{lat_key := _, long_key := _}) ->
    Value;
validate_option(keys, Value) when is_list(Value) ->
    validate_option(keys, maps:from_list(Value));
validate_option(Opt, Value) ->
    erlang:error(badarg, [Opt, Value]).


invoke(_Service, init, Session, Events, _Opts, _State) ->
    ?LOG(debug, "calling invoke init for capwap_loc_handler: ~p", [{_Service, Session, Events, _Opts, _State}]),
    {ok, Session, Events, #{}};

% Retrieving attributes as per https://thingsboard.io/docs/reference/http-api/
invoke(_Service, Step, Session0 = #{'Location-Id' := undefined}, Events0, _Config, State0) when
        Step == start;
        Step == interim;
        Step == stop ->
    ?LOG(debug, "Undefined 'Location-Id', no action"),
    {ok, Session0, Events0, State0};
invoke(_Service, Step, Session0 = #{'Location-Id' := Name}, Events0, Config = #{default_location := DefLoc}, State0) when
        Step == start;
        Step == interim;
        Step == stop ->
    ?LOG(debug, "Invoking: ~p", [{Step, Session0, Events0, Config, State0}]),
    % Two queries are needed:
    % https://rms.hbw.cennso.com/api/tenant/devices?deviceName=00112B015BA5
    % {"id":{"entityType":"DEVICE","id":"a1ce4f30-b4cc-11e7-9cbf-d33fd42c8630"}
    % https://rms.hbw.cennso.com/api/device/e27a48a0-635b-11ea-aec0-e5764cf599e9
    % curl 'https://rms.hbw.cennso.com/api/plugins/telemetry/DEVICE/a1ce4f30-b4cc-11e7-9cbf-d33fd42c8630/values/timeseries?keys=TB_Telemetry_Latitude,TB_Telemetry_Longitude'
    %'Location-Id' => <<"00112B0159E5">>
    Session = case capwap_tb_cache_server:get_loc(Name) of
        {location, LatVal, LongVal} ->
            ?LOG(debug, "Successful location: ~p", [{LatVal, LongVal}]),
            Session0#{'IM_LI_Location' => iolist_to_binary(io_lib:format("Lat:~s;Lon:~s", [LatVal, LongVal]))};
        error ->
            ?LOG(debug, "Error retrieving location"),
            Session0#{'IM_LI_Location' => iolist_to_binary(DefLoc)}
    end,
    {ok, Session, Events0, State0};

invoke(Service, Procedure, Session, Events, _Opts, State) ->
    ?LOG(error, "calling something else for capwap_loc_handler: ~p", [{Service, Procedure, Session, Events, _Opts, State}]),
    {{error, {Service, Procedure}}, Session, Events, State}.

handle_response(_, _, Session, Events, _, State) ->
    ?LOG(debug, "calling handle_response", []),
    {ok, Session, Events, State}.

get_state_atom(_State) ->
    ?LOG(debug, "capwap_loc_handler: ~p", [_State]),
    undefined.


%%% ============================================================================
%%% Request Logic
%%% ============================================================================

