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

-module(capwap_wtp_fsm_loc_SUITE).

-compile(export_all).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/ms_transform.hrl").
-include_lib("capwap/include/capwap_packet.hrl").

-define(MAC, <<1,2,3,4,5,6>>).

match(MatchSpec, Actual, Expr, File, Line) ->
    CompiledMatchSpec = ets:match_spec_compile(MatchSpec),
    case ets:match_spec_run([Actual], CompiledMatchSpec) of
	[] ->
	    ct:pal("MISMATCH(~s:~b, ~s)~nExpected: ~p~nActual:   ~p~n",
		   [File, Line, Expr, MatchSpec, Actual]),
	    error(badmatch);
	[Result] ->
	    Result
    end.

assert_mbox_match(MatchSpec, File, Line) ->
    CompiledMatchSpec = ets:match_spec_compile(MatchSpec),
    receive
        Actual ->
	    case ets:match_spec_run([Actual], CompiledMatchSpec) of
		[] ->
		    ct:pal("MISMATCH(~s:~b)~nExpected: ~p~nActual:   ~p~n",
			   [File, Line, MatchSpec, Actual]),
		    error(badmatch);
		[Result] ->
		    Result
	    end
    after
        1000 ->
            ct:fail(timeout)
    end.

-define(assert_mbox(Spec), ?assert_mbox_match({Spec,[],[ok]})).
-define(assert_mbox_match(MatchSpec),
        ((fun () -> assert_mbox_match(MatchSpec, ?FILE, ?LINE) end)())).

-define(assert(Spec, Expr), ?match([{Spec,[],[ok]}], Expr)).
-define(match(MatchSpec, Expr),
        ((fun () -> match(MatchSpec, Expr, ??Expr, ?FILE, ?LINE) end)())).

-define(equal(Expected, Actual),
    (fun (Expected@@@, Expected@@@) -> true;
	 (Expected@@@, Actual@@@) ->
	     ct:pal("MISMATCH(~s:~b, ~s)~nExpected: ~p~nActual:   ~p~n",
		    [?FILE, ?LINE, ??Actual, Expected@@@, Actual@@@]),
	     false
     end)(Expected, Actual) orelse error(badmatch)).

suite() ->
    [{timetrap,{seconds,20}}].

init_per_suite(Config0) ->
    Apps = setup_applications(),
    logger:update_primary_config(#{level => all}),
    Dispatch = cowboy_router:compile([
        {'_', [{"/[...]", test_loc_handler, []}]}
    ]),
    {ok, _} = cowboy:start_clear(test_loc_handler,
        [{port, 9999}],
        #{env => #{dispatch => Dispatch}}
    ),
		[ {apps, Apps} | Config0 ].

end_per_suite(Config) ->
		cowboy:stop_listener(test_loc_handler),
    Apps = proplists:get_value(apps, Config),
    [ application:stop(App) || App <- Apps ],
		dp_mockup:unload(),
    ok.

init_per_testcase(_, Config) ->
    meck_init(),
    dp_mockup:clear(),
    capwap_ac_sup:clear(),
    Config.

end_per_testcase(_, Config) ->
    Unloaded = meck_unload(),
		ct:log("Unloaded: ~p~n", [Unloaded]),
    Config.

all() ->
    [wtp_fsm, sta_fsm].

check_auth_session_args(Session) ->
    case maps:get('Username', Session, undefined) of
	V when is_binary(V) ->
	    ok;
	V ->
	    erlang:error(badarg, [{'Username', V}])
    end.

check_session_args({Key, MatchSpec}, Session) ->
    CompiledMatchSpec = ets:match_spec_compile(MatchSpec),
    Value = maps:get(Key, Session, undefined),

    case ets:match_spec_run([Value], CompiledMatchSpec) of
	[ok] ->
	    ok;
	V ->
	    erlang:error(badarg, [{Key, V}])
    end.

wtp_fsm(_Config) ->
    meck:expect(ergw_aaa_session, invoke,
		fun(Session, SessionOpts, authenticate, Opts) ->
			ct:pal("Session: ~p~n", [Session]),
			ct:pal("Opts: ~p~n", [Opts]),
			ct:pal("SessionOpts: ~p~n", [SessionOpts]),
			check_auth_session_args(SessionOpts),
			meck:passthrough([Session, SessionOpts, authenticate, Opts]);
		   (Session, SessionOpts, interim, Opts) ->
			IsIntOrUndefined = ets:fun2ms(fun(X) when is_integer(X) -> ok;
							 (X) when X == undefined -> ok end),
			IsListOrUndefined = ets:fun2ms(fun(X) when is_list(X) -> ok;
							  (X) when X == undefined -> ok end),
			IsList = ets:fun2ms(fun(X) when is_list(X) -> ok end),
			OptValues = [{'TP-CAPWAP-Radio-Id',      IsIntOrUndefined},
				     {'TP-CAPWAP-Timestamp',     IsIntOrUndefined},
				     {'TP-CAPWAP-WWAN-CREG',     IsIntOrUndefined},
				     {'TP-CAPWAP-WWAN-Cell-Id',  IsIntOrUndefined},
				     {'TP-CAPWAP-WWAN-Id',       IsIntOrUndefined},
				     {'TP-CAPWAP-WWAN-LAC',      IsIntOrUndefined},
				     {'TP-CAPWAP-WWAN-Latency',  IsIntOrUndefined},
				     {'TP-CAPWAP-WWAN-MCC',      IsIntOrUndefined},
				     {'TP-CAPWAP-WWAN-MNC',      IsIntOrUndefined},
				     {'TP-CAPWAP-WWAN-RAT',      IsIntOrUndefined},
				     {'TP-CAPWAP-WWAN-RSSi',     IsIntOrUndefined},
				     {'TP-CAPWAP-GPS-Altitude',  IsListOrUndefined},
				     {'TP-CAPWAP-GPS-Hdop',      IsListOrUndefined},
				     {'TP-CAPWAP-GPS-Latitude',  IsListOrUndefined},
				     {'TP-CAPWAP-GPS-Longitude', IsListOrUndefined},
				     {'TP-CAPWAP-GPS-Timestamp', IsListOrUndefined}],
			ct:pal("Session: ~p~n", [Session]),
			ct:pal("Opts: ~p~n", [Opts]),
			ct:pal("SessionOpts: ~p~n", [SessionOpts]),
			lists:foreach(fun(X) ->
					      check_session_args(X, SessionOpts)
				      end, OptValues),
			meck:passthrough([Session, SessionOpts, interim, Opts]);
		   (Session, SessionOpts, Procedure, Opts) ->
			meck:passthrough([Session, SessionOpts, Procedure, Opts])
		end),

    {ok, WTP} = start_local_wtp(),

    Match1 = ets:fun2ms(fun({ok, {Header, Msg}}) when element(1, Header) == capwap_header, element(1, Msg) == discovery_response -> {Header, Msg} end),
    {_Hdr1, _Msg1} = ?match(Match1, wtp_mockup_fsm:send_discovery(WTP)),

    Match2 = ets:fun2ms(fun({ok, {Header, Msg}}) when element(1, Header) == capwap_header, element(1, Msg) == join_response -> {Header, Msg} end),
    {_Hdr2, _Msg2} = ?match(Match2, wtp_mockup_fsm:send_join(WTP)),

    Match3 = ets:fun2ms(fun({ok, {Header, Msg}}) when element(1, Header) == capwap_header, element(1, Msg) == configuration_status_response -> {Header, Msg} end),
    {_Hdr3, _Msg3} = ?match(Match3, wtp_mockup_fsm:send_config_status(WTP)),

    Match4 = ets:fun2ms(fun({ok, {Header, Msg}}) when element(1, Header) == capwap_header, element(1, Msg) == change_state_event_response -> {Header, Msg} end),
    {_Hdr4, _Msg4} = ?match(Match4, wtp_mockup_fsm:send_change_state_event(WTP)),

    Match5 = ets:fun2ms(fun({Header, Msg}) when element(1, Header) == capwap_header, element(1, Msg) == ieee_802_11_wlan_configuration_request -> {Header, Msg} end),
    {_Hdr5, _Msg5} = ?assert_mbox_match(Match5),

    Match6 = ets:fun2ms(fun({ok, {Header, Msg}}) when element(1, Header) == capwap_header, element(1, Msg) == wtp_event_response -> {Header, Msg} end),
    {_Hdr6, _Msg6} = ?match(Match6, wtp_mockup_fsm:send_wwan_statistics(WTP)),

    Match7 = ets:fun2ms(fun({ok, {Header, Msg}}) when element(1, Header) == capwap_header, element(1, Msg) == wtp_event_response -> {Header, Msg} end),
    {_Hdr7, _Msg7} = ?match(Match7, wtp_mockup_fsm:send_wwan_statistics(WTP, 40)),

    %% wait 'Acct-Interim-Interval'
    ct:sleep({seconds, 11}),

    catch stop_local_wtp(WTP),

    ct:sleep(100),

    ?equal(83, meck:num_calls(ergw_aaa_session, invoke, ['_', '_', interim, '_'])),

    meck:validate(ergw_aaa_session),
    meck:validate(capwap_ac),
    ok.

sta_fsm(_Config) ->
    meck:expect(ergw_aaa_session, invoke,
		fun(Session, SessionOpts, authenticate, Opts) ->
			ct:pal("Session: ~p~n", [Session]),
			ct:pal("Opts: ~p~n", [Opts]),
			ct:pal("SessionOpts: ~p~n", [SessionOpts]),
			check_auth_session_args(SessionOpts),
			meck:passthrough([Session, SessionOpts, authenticate, Opts]);
		   (Session, SessionOpts, interim, Opts) ->
			IsIntOrUndefined = ets:fun2ms(fun(X) when is_integer(X) -> ok;
							 (X) when X == undefined -> ok end),
			IsListOrUndefined = ets:fun2ms(fun(X) when is_list(X) -> ok;
							  (X) when X == undefined -> ok end),
			IsList = ets:fun2ms(fun(X) when is_list(X) -> ok end),
			OptValues = [{'TP-CAPWAP-Radio-Id',      IsIntOrUndefined},
				     {'TP-CAPWAP-Timestamp',     IsIntOrUndefined},
				     {'TP-CAPWAP-WWAN-CREG',     IsIntOrUndefined},
				     {'TP-CAPWAP-WWAN-Cell-Id',  IsIntOrUndefined},
				     {'TP-CAPWAP-WWAN-Id',       IsIntOrUndefined},
				     {'TP-CAPWAP-WWAN-LAC',      IsIntOrUndefined},
				     {'TP-CAPWAP-WWAN-Latency',  IsIntOrUndefined},
				     {'TP-CAPWAP-WWAN-MCC',      IsIntOrUndefined},
				     {'TP-CAPWAP-WWAN-MNC',      IsIntOrUndefined},
				     {'TP-CAPWAP-WWAN-RAT',      IsIntOrUndefined},
				     {'TP-CAPWAP-WWAN-RSSi',     IsIntOrUndefined},
				     {'TP-CAPWAP-GPS-Altitude',  IsListOrUndefined},
				     {'TP-CAPWAP-GPS-Hdop',      IsListOrUndefined},
				     {'TP-CAPWAP-GPS-Latitude',  IsListOrUndefined},
				     {'TP-CAPWAP-GPS-Longitude', IsListOrUndefined},
				     {'TP-CAPWAP-GPS-Timestamp', IsListOrUndefined}],
			lists:foreach(fun(X) ->
					      check_session_args(X, SessionOpts)
				      end, OptValues),
			meck:passthrough([Session, SessionOpts, interim, Opts]);
		   (Session, SessionOpts, Procedure, Opts) ->
			meck:passthrough([Session, SessionOpts, Procedure, Opts])
		end),

    {ok, WTP} = start_local_wtp(),

    {ok, _} = wtp_mockup_fsm:send_discovery(WTP),
    {ok, _} = wtp_mockup_fsm:send_join(WTP),
    {ok, _} = wtp_mockup_fsm:send_config_status(WTP),
    {ok, _} = wtp_mockup_fsm:send_change_state_event(WTP),
    receive
	{#capwap_header{}, Msg} when element(1, Msg) == ieee_802_11_wlan_configuration_request ->
	    ok
    after
	1000 ->
	    ct:fail(timeout)
    end,
    {ok, _} = wtp_mockup_fsm:send_wwan_statistics(WTP),

    {ok, _} =  wtp_mockup_fsm:add_station(WTP, ?MAC),

    ?equal(1, length(capwap_station_reg:list_stations())),

    %% wait 2x 'Acct-Interim-Interval'
    ct:sleep({seconds, 21}),

    catch stop_local_wtp(WTP),

    ct:sleep(100),

    ?equal(6, meck:num_calls(ergw_aaa_session, invoke, ['_', '_', interim, '_'])),
    ?equal(2, meck:num_calls(ieee80211_station, handle_event,
			     [info, {timeout, '_', {accounting, 'IP-CAN', periodic}}, connected, '_'])),

    meck:validate(ergw_aaa_session),
    meck:validate(capwap_ac),
    meck:validate(ieee80211_station),
    ok.

%% ------------------------------------------------------------------------------------
%% helper
%% ------------------------------------------------------------------------------------

start_local_wtp() ->
    wtp_mockup_fsm:start_link({{127,0,0,1}, 5246}, {127,0,0,1}, 0,
			      "", "", <<8,8,8,8,8,8>>, false, [{data_keep_alive_timeout, 300}]).

stop_local_wtp(WTP) ->
    wtp_mockup_fsm:stop(WTP).

meck_init() ->
    meck:new(capwap_ac, [passthrough]),
    meck:new(ieee80211_station, [passthrough]),
    meck:new(ergw_aaa_session, [passthrough]).

meck_unload() ->
		lists:foldl(fun(Mod, Acc) ->
			try
					meck:unload(Mod),
					[Mod | Acc]
			catch error:{not_mocked, Mod} ->
					Acc
			end
		end, [], [ergw_aaa_session, ieee80211_station, capwap_ac]).

setup_applications() ->
    {ok, CWD} = file:get_cwd(),
    os:cmd("touch " ++ CWD ++ "/upstream"),
    Apps = [{capwap, [{server_ip, {127, 0, 0, 1}},
		      {enforce_dtls_control, false},
		      {server_socket_opts, [{recbuf, 1048576}, {sndbuf, 1048576}]},
		      {limit, 200},
		      {max_wtp, 100},
		      {security, ['x509']},
		      {versions, [{hardware, <<"SCG">>},
				  {software, <<"SCG">>}]},
		      {ac_name, <<"CAPWAP AC">>},

		      {http_api, [{port, 0}]},

		      {default_ssid, <<"DEV CAPWAP WIFI">>},
		      {default_ssid_suppress, 0},
		      {dynamic_ssid_suffix_len, false},

		      {wtps, [
			      %% default for ALL WTP's
			      {defaults,
			       [{psm_idle_timeout,           30},
				{psm_busy_timeout,           300},
				{max_stations,               100},
				{echo_request_interval,      60},
				{discovery_interval,         20},
				{idle_timeout,               300},
				{data_channel_dead_interval, 70},
				{ac_join_timeout,            70},
				{admin_pw,                   undefined},
				{wlan_hold_time,             15},
				{radio_settings,
				 [{defaults,
				   [{beacon_interval, 200},
				    {dtim_period,     1},
				    {short_preamble,  supported},
				    {wlans, [[]]}
				   ]},
				  {'802.11a',
				   [{operation_mode, '802.11a'},
				    {channel, 155},
				    {wlans, [[]]}
				   ]},
				  {'802.11b',
				   [{operation_mode, '802.11b'},
				    {channel, 11},
				    {wlans, [[]]}
				   ]},
				  {'802.11g',
				   [{operation_mode, '802.11g'},
				    {channel, 11},
				    {beacon_interval, 150},
				    {wlans, [[]]}
				   ]}
				 ]}
			       ]}
			     ]}
		     ]},
	    {ergw_aaa,
	     [
	      {handlers,
	       [{ergw_aaa_static,
		 [{'NAS-Identifier',        <<"NAS-Identifier">>},
		  {'Acct-Interim-Interval', 10}
		 ]},
		       {capwap_http_loc, []}
	       ]},
	      {services,
	       [{'Default',
		 [{handler, 'ergw_aaa_static'},
		  {answers,
		   #{'RADIUS-Auth' =>
			 #{handler => ergw_aaa_radius,
			   'Result-Code' => 2001,
			   'Acct-Interim-Interval' => 10,
			   'TLS-Pre-Shared-Key' => <<"MySecret">>},
		     'RADIUS-Acct' =>
			 #{'Result-Code' => 2001}
		    }
		  }
		 ]},
		       {'Load-Location', [
        {timeout, 5000},
				{token, <<"sometoken">>},
        {uri, "http://127.0.0.1:9999/api/"},
        {keys, [{lat_key, <<"TB_Telemetry_Latitude">>}, {long_key, <<"TB_Telemetry_Longitude">>}]},
				{default_location, <<"Lat:0;Long:0">>},
        {handler, capwap_http_loc}]}
	       ]},
	      {apps,
	       [{capwap_wtp,
		 [{session, ['Default']},
		  {procedures, [{authenticate, [{'Default', [{answer, 'RADIUS-Auth'}]}]},
				{authorize, []},
				{start, ['Load-Location', {'Default', [{answer, 'RADIUS-Acct'}]}]},
				{interim, ['Load-Location', {'Default', [{answer, 'RADIUS-Acct'}]}]},
				{stop, ['Load-Location', {'Default', [{answer, 'RADIUS-Acct'}]}]}
			       ]}
		 ]},
		{capwap_station,
		 [{session, ['Default']},
		  {procedures, [{authenticate, ['Load-Location', {'Default', [{answer, 'RADIUS-Auth'}]}]},
				{authorize, []},
				{start, ['Load-Location', {'Default', [{answer, 'RADIUS-Acct'}]}]},
				{interim, ['Load-Location', {'Default', [{answer, 'RADIUS-Acct'}]}]},
				{stop, ['Load-Location', {'Default', [{answer, 'RADIUS-Acct'}]}]}
			       ]}
		 ]}
	       ]}
	     ]}
	   ],
    [application:load(Name) || {Name, _} <- Apps],
    dp_mockup:new(),
    lists:flatten([setup_application(A) || A <- Apps]).

setup_application({Name, Env}) ->
    application:stop(Name),
    application:unload(Name),
    [application:set_env(Name, Key, Val) || {Key, Val} <- Env],
    {ok, Started} = application:ensure_all_started(Name),
    Started;
setup_application(Name) ->
    {ok, Started} = application:ensure_all_started(Name),
    Started.
