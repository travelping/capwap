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

-define(VALUE_KEY, <<"value"/utf8>>).

%%===================================================================
%% API
%%===================================================================

initialize_handler(Opts) ->
    ?LOG(debug, "Init'ed handler with Opts: ~p", [Opts]),
    % Returning opts for child specs
    {ok, []}.

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
invoke(_Service, Step, Session0, Events0, Config = #{dev_name := Name, timeout := Timeout,
       uri := URI, keys := #{lat_key := LatKey, long_key := LongKey}, token := Token,
       default_location := DefLoc}, State0) when
        Step == start;
        Step == interim;
        Step == stop ->
    ?LOG(debug, "Invoking: ~p", [{Step, Session0, Events0, Config, State0}]),
    % Beware: not all parts may be present (e.g. port)
    % ergw_sbi_pcf_client needs at least host, port and path
    ParsedURI = case URI of
        _ when is_binary(URI) -> uri_string:parse(URI);
        _ when is_list(URI) -> uri_string:parse(URI)
        % _ when is_list(URI) -> uri_string:parse(unicode:characters_to_binary(URI))
    end,
    % Two queries are needed:
    % https://rms.hbw.cennso.com/api/tenant/devices?deviceName=00112B015BA5
    % {"id":{"entityType":"DEVICE","id":"a1ce4f30-b4cc-11e7-9cbf-d33fd42c8630"}
    % https://rms.hbw.cennso.com/api/device/e27a48a0-635b-11ea-aec0-e5764cf599e9
    % curl 'https://rms.hbw.cennso.com/api/plugins/telemetry/DEVICE/a1ce4f30-b4cc-11e7-9cbf-d33fd42c8630/values/timeseries?keys=TB_Telemetry_Latitude,TB_Telemetry_Longitude'
    %
    #{host := Host} = ParsedURI,
    StringHost = case Host of
        _ when is_binary(Host) -> unicode:characters_to_list(Host);
        _ when is_list(Host) -> Host
    end,
    % Add keys to query
    KeysListVal = <<LatKey/binary, ",", LongKey/binary>>,
    KeysQuery = uri_string:compose_query([{"keys", KeysListVal}]),
    % TODO Check if binary is needed
    LatKeyBin = unicode:characters_to_binary(LatKey),
    LongKeyBin = unicode:characters_to_binary(LongKey),
    Opts = #{timeout => Timeout, uri => ParsedURI#{host => StringHost, query => KeysQuery}, token => Token, dev_name => Name},
    ?LOG(debug, "Passing options: ~p", [Opts]),
    case send_location_req(Opts) of
        {ok, {Response = #{LatKeyBin := [#{?VALUE_KEY := LatVal}], LongKeyBin := [#{?VALUE_KEY := LongVal}]}, LocReqState}} ->
            ?LOG(debug, "Got response: ~p", [{Response, LocReqState}]),
            Session = Session0#{
                'IM_LI_Location' => iolist_to_binary(io_lib:format("Lat:~s;Lon:~s", [LatVal, LongVal]))},
            {ok, Session, Events0, State0};
        {ok, {Response, LocReqState}} ->
            ?LOG(debug, "Got non-matching response: ~p, using default ~p", [{Response, DefLoc}]),
            Session = Session0#{
                'IM_LI_Location' => iolist_to_binary(DefLoc)},
            {ok, Session, Events0, State0};
        {error, Error} ->
            ?LOG(error, "Error retrieving location: ~p, using default ~p", [Error, DefLoc]),
            Session = Session0#{
                'IM_LI_Location' => iolist_to_binary(DefLoc)},
            {ok, Session, Events0, State0}
    end;
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

% The location_req already includes the keys in the path
send_location_req(#{timeout := _Timeout, uri := URI = #{path := UriPath}, token := Token, dev_name := Name}) ->
    JsonHeader = {<<"Content-Type">>, <<"application/json">>},
    AuthHeader = {<<"x-authorization">>, <<"Bearer ", Token/binary>>},

    % ReqOpts = #{start_pool_if_missing => true,
		%% conn_opts => #{protocols => [http2]},
		%% http2_opts => #{keepalive => infinity},
	%	scope => ?MODULE},
    UriPathBin = unicode:characters_to_binary(UriPath),
    DevNamePath = <<UriPathBin/binary, "/tenant/devices">>,
    DevNameQuery = uri_string:compose_query([{"deviceName", Name}]),
    DevNameUri = URI#{path => DevNamePath, query => DevNameQuery},
    % {"id":{"entityType":"DEVICE","id":"a1ce4f30-b4cc-11e7-9cbf-d33fd42c8630"}

    {ok, {#{<<"id">> := #{<<"entityType">> := <<"DEVICE">>, <<"id">> := Id}}, _}} =
        send_get_hackney(uri_string:recompose(DevNameUri), [JsonHeader, AuthHeader], []),
    % {ok, StreamRef} = send_get_gun(Host, Port, Path, Headers, ReqOpts),
    % get_response(#{timeout => Timeout,
	% 	   stream_ref => StreamRef,
	%	   acc => <<>>}).
    % 'https://rms.hbw.cennso.com/api/plugins/telemetry/DEVICE/a1ce4f30-b4cc-11e7-9cbf-d33fd42c8630/values/timeseries?keys=TB_Telemetry_Latitude,TB_Telemetry_Longitude'
    TelemetryPath = <<UriPathBin/binary, "/plugins/telemetry/DEVICE/", Id/binary, "/values/timeseries">>,
    TelemetryUri = URI#{path => TelemetryPath},
    
    send_get_hackney(uri_string:recompose(TelemetryUri), [JsonHeader, AuthHeader], []).

send_get_hackney(Http, Headers, Opts) ->
    case hackney:request(get, Http, Headers, <<>>, Opts) of
        {ok, 200, _RespHeaders, ClientRef} ->
            {ok, Body} = hackney:body(ClientRef),
            {ok, {jsx:decode(Body, [return_maps]), ClientRef}};
        Error ->
            % exometer:update([capwap, ac, error_wtp_http_config_count], 1),
            {error, {invalid_response, Error}}
    end.

send_get_gun(Host, Port, Path, Headers0, ReqOpts) ->
    StartPoolIfMissing = maps:get(start_pool_if_missing, ReqOpts, false),
    Transport = gun:default_transport(Port),
    Authority = gun_http:host_header(Transport, Host, Port),
    Headers = Headers0#{<<"host">> => Authority},

    case gun_pool:get(Path, Headers, ReqOpts) of
    % TODO: Why not leave gun_pool to the lifecycle hooks?
	{async, StreamRef} ->
	    {ok, StreamRef};
	{error, pool_not_found, _} when StartPoolIfMissing =:= true->
	    {ok, ManagerPid} = gun_pool:start_pool(Host, Port, ReqOpts),
	    ok = gun_pool:await_up(ManagerPid),
	    send_get_gun(Host, Port, Path, Headers0, ReqOpts#{start_pool_if_missing => false});
	Other ->
	    Other
    end.

get_response(#{stream_ref := StreamRef, timeout := Timeout, acc := Acc} = Opts) ->
    %% @TODO: fix correct 'Timeout' calculation issue and add time of request finished
    case gun_pool:await(StreamRef, Timeout) of
	{response, fin, Status, Headers} ->
	    handle_response(Opts#{status => Status, headers => Headers}, Acc);
	{response, nofin, Status, Headers} ->
	    get_response(Opts#{status => Status, headers => Headers});
	{data, nofin, Data} ->
	    get_response(Opts#{acc => <<Acc/binary, Data/binary>>});
	{data, fin, Data} ->
	    handle_response(Opts, <<Acc/binary, Data/binary>>);
	{error, _Reason} = Response->
	    Response
    end.

% uri(URI) ->
%     iolist_to_binary([lists:join($/, URI)]).



handle_response(#{status := 200} = Opts, Body) ->
    handle_response_body(Opts, Body);
handle_response(Opts, Body) ->
    ?LOG(error, "Unknown response Opts: ~p / Body: ~p", [Opts, Body]),
    {error, invalid_response}.

handle_response_body(#{headers := Headers, state := State}, Body) ->
    case decode_body(Headers, Body) of
	#{} = Response ->
	    {ok, {Response, State}};
	{error, _} = Error ->
	    Error
    end.

decode_body(Headers, Body) ->
    case lists:keyfind(<<"content-type">>, 1, Headers) of
	{<<"content-type">>, ContentType} ->
	    case cow_http_hd:parse_content_type(ContentType) of
		{<<"application">>, <<"json">>, _Param} ->
		    jsx:decode(Body, [{labels, attempt_atom}, return_maps]);
		_ ->
		    {error, invalid_content_type}
	    end;
	_ ->
	    {error, no_content_type}
    end.

