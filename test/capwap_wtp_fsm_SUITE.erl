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

-module(capwap_wtp_fsm_SUITE).

-compile(export_all).
-compile({parse_transform, lager_transform}).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/ms_transform.hrl").

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

suite() ->
    [{timetrap,{minutes,5}}].

init_per_suite(Config) ->
    setup_applications(),
    lager_common_test_backend:bounce(debug),
    Config.

end_per_suite(_Config) ->
    meck_unload(),
    ok.

all() ->
    [wtp_fsm].

check_generic_session_args(Session) ->
    case ergw_aaa_session:attr_get('Username', Session, undefined) of
	V when is_binary(V) ->
	    ok;
	V ->
	    erlang:error(badarg, [{'Username', V}])
    end,

    case ergw_aaa_session:attr_get('Calling-Station', Session, undefined) of
	<<"127.0.0.1">> ->
	    ok;
	CS ->
	    erlang:error(badarg, [{'Calling-Station', CS}])
    end.

check_session_args({Key, MatchSpec}, Session) ->
    CompiledMatchSpec = ets:match_spec_compile(MatchSpec),
    Value = ergw_aaa_session:attr_get(Key, Session, undefined),

    case ets:match_spec_run([Value], CompiledMatchSpec) of
	[ok] ->
	    ok;
	V ->
	    erlang:error(badarg, [{Key, V}])
    end.

wtp_fsm(_Config) ->
    meck:new(ergw_aaa_mock, [passthrough]),
    meck:expect(ergw_aaa_mock, start_authentication,
		fun(From, Session, State) ->
			check_generic_session_args(Session),
			meck:passthrough([From, Session, State])
		end),
    meck:expect(ergw_aaa_mock, start_accounting,
		fun(From, Type = 'Interim', Session, State) ->
			IsIntOrUndefined = ets:fun2ms(fun(X) when is_integer(X) -> ok;
							 (X) when X == undefined -> ok end),
			IsListOrUndefined = ets:fun2ms(fun(X) when is_list(X) -> ok;
							  (X) when X == undefined -> ok end),
			check_generic_session_args(Session),
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
			lists:foreach(fun(X) -> check_session_args(X, Session) end, OptValues),
			meck:passthrough([From, Type, Session, State]);
		   (From, Type, Session, State) ->
			meck:passthrough([From, Type, Session, State])
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

    catch stop_local_wtp(WTP),

    meck:validate(ergw_aaa_mock),
    meck:unload(ergw_aaa_mock),

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
    ok = meck:new(capwap_dp, [non_strict, no_link]),
    ok = meck:expect(capwap_dp, start_link,
		     fun() ->
			     {ok, self()}
		     end),
    ok = meck:expect(capwap_dp, add_wtp,
		     fun(_WTPDataChannelAddress, _MTU) ->
			     ok
		     end),
    ok = meck:expect(capwap_dp, sendto,
		     fun(_WTPDataChannelAddress, _Packet) ->
			     ok
		     end),
    ok.

meck_unload() ->
    meck:unload(capwap_dp).

setup_applications() ->
    {ok, CWD} = file:get_cwd(),
    os:cmd("touch " ++ CWD ++ "/upstream"),
    Apps = [{lager, [{handlers, [{lager_console_backend, info},
				 {lager_file_backend, [{file, "log/error.log"}, {level, error}, {size, 0}, {date, ""}]},
				 {lager_file_backend, [{file, "log/console.log"}, {level, debug}, {size, 0}, {date, ""}]}]}]},
	    {capwap, [{server_ip, {127, 0, 0, 1}},
		      {enforce_dtls_control, false},
		      {server_socket_opts, [{recbuf, 1048576}, {sndbuf, 1048576}]},
		      {limit, 200},
		      {max_wtp, 100},
		      {security, ['x509']},
		      {versions, [{hardware, <<"SCG">>},
				  {software, <<"SCG">>}]},
		      {ac_name, <<"CAPWAP AC">>},

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
	    {ergw_aaa, [{ergw_aaa_provider, {ergw_aaa_mock, [{shared_secret, <<"MySecret">>}]}}]}
	   ],
    [application:load(Name) || {Name, _} <- Apps],
    meck_init(),
    [setup_application(A) || A <- Apps].

setup_application({Name, Env}) ->
    [application:set_env(Name, Key, Val) || {Key, Val} <- Env],
    application:ensure_all_started(Name);
setup_application(Name) ->
    application:ensure_all_started(Name).
