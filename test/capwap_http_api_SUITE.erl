%% Copyright (C) 2013-2023, Travelping GmbH <info@travelping.com>

%% This program is free software; you can redistribute it and/or
%% modify it under the terms of the GNU General Public License
%% as published by the Free Software Foundation; either version
%% 2 of the License, or (at your option) any later version.

-module(capwap_http_api_SUITE).

-compile(export_all).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

all() ->
    [http_api_version_req,
     http_api_list_wtps,
     http_api_list_wtps_with_undefined,
     http_api_get_wtp_info,
     http_api_prometheus_metrics_req,
     http_api_prometheus_metrics_sub_req,
     http_api_metrics_req,
     http_api_metrics_sub_req,
     http_api_bad_command,
     http_api_dp_wtp_list_error,
     http_api_dp_status_error
    ].

init_per_suite(Config0) ->
    logger:update_primary_config(#{level => all}),
    inets:start(),
    Apps = setup_applications(),
    Config = [ {apps, Apps} | Config0 ],

    %% fake exometer entries
    DataPointG = [capwap, dp, "0", 'Error-Fragment-Invalid'],
    DataPointH = [capwap, wtp, <<"wtp-test">>, 'IpPackets'],
    DataPointS = [capwap, dp, "all", 'Error-To-Short'],
    DataPointF = [socket, 'gtp-c', irx, pt, v1, function_test],
    DataPointIP4 = [path, some_metric, {127,0,0,1}, contexts],
    DataPointIP6 = [path, irx, {0,0,0,0,0,0,0,1}, contexts],
    exometer:new(DataPointG, gauge, []),
    exometer:new(DataPointH, histogram, [{time_span, 300 * 1000}]),
    exometer:new(DataPointS, spiral, [{time_span, 300 * 1000}]),
    exometer:new(DataPointF, {function, ?MODULE, exo_function}, []),
    exometer:new(DataPointIP4, gauge, []),
    exometer:new(DataPointIP6, gauge, []),
    lists:foreach(
      fun(_) ->
	      Value = rand:uniform(1000),
	      exometer:update(DataPointG, Value + 0.001),
	      exometer:update(DataPointH, Value),
	      exometer:update(DataPointS, Value)
      end, lists:seq(1, 100)),

    Config.

end_per_suite(Config) ->
    inets:stop(),
    Apps = proplists:get_value(apps, Config),
    [ application:stop(App) || App <- Apps ],
    ok.

http_api_version_req() ->
    [{doc, "Check /api/v1/version API"}].
http_api_version_req(_Config) ->
    URL = get_test_url("/api/v1/version"),
    {ok, {_, _, Body}} = httpc:request(get, {URL, []},
				       [], [{body_format, binary}]),
    Res = jsx:decode(Body, [return_maps]),
    ?assertEqual(#{<<"version">> => <<"none">>}, Res),
    ok.

http_api_list_wtps() ->
    [{doc, "Check /api/v1/wtp API"}].
http_api_list_wtps(_Config) ->
    capwap_wtp_reg:register_args(<<"test-wtp">>, {{127,0,0,1}, 0}),

    URL = get_test_url("/api/v1/wtp"),
    {ok, {_, _, Body}} = httpc:request(get, {URL, []},
				       [], [{body_format, binary}]),
    Res = jsx:decode(Body, [return_maps]),
    ?assertEqual([#{<<"id">> => <<"test-wtp">>,
                    <<"endpoint">> => #{
                      <<"ip">> => <<"127.0.0.1">>,
                      <<"port">> => 0
                    } }], Res),
    capwap_wtp_reg:unregister(),
    {ok, {_, _, Body1}} = httpc:request(get, {URL, []},
				       [], [{body_format, binary}]),
    Res1 = jsx:decode(Body1, [return_maps]),
    ?assertEqual([], Res1),
    ok.

http_api_list_wtps_with_undefined() ->
    [{doc, "Check /api/v1/wtp API with undefined endpoint"}].
http_api_list_wtps_with_undefined(_Config) ->
    capwap_wtp_reg:register_args(<<"test-wtp">>, {{127,0,0,1}, 0}),
    capwap_wtp_reg:register_args(<<"test-wtp-undefined">>, undefined),

    URL = get_test_url("/api/v1/wtp"),
    {ok, {_, _, Body}} = httpc:request(get, {URL, []},
				       [], [{body_format, binary}]),
    Res = jsx:decode(Body, [return_maps]),
    ?assertEqual([#{<<"id">> => <<"test-wtp">>,
                    <<"endpoint">> => #{
                      <<"ip">> => <<"127.0.0.1">>,
                      <<"port">> => 0
                    } }], Res),
    capwap_wtp_reg:unregister(),
    {ok, {_, _, Body1}} = httpc:request(get, {URL, []},
				       [], [{body_format, binary}]),
    Res1 = jsx:decode(Body1, [return_maps]),
    ?assertEqual([], Res1),
    ok.

http_api_get_wtp_info() ->
    [{doc, "Check /api/v1/wtp/{id} API"}].
http_api_get_wtp_info(_Config) ->
    URL = get_test_url("/api/v1/wtp/something"),
    {ok, {_, _, Body}} = httpc:request(get, {URL, []},
				       [], [{body_format, binary}]),
    Response = jsx:decode(Body, [return_maps]),
    ?assertEqual(#{<<"error">> => <<"not_found">>}, Response),
    ok.

http_api_prometheus_metrics_req() ->
    [{doc, "Check Prometheus API Endpoint"}].
http_api_prometheus_metrics_req(_Config) ->
    URL = get_test_url("/metrics"),
    Accept = "application/vnd.google.protobuf;proto=io.prometheus.client.MetricFamily;encoding=delimited;q=0.7,"
             ++ "text/plain;version=0.0.4;q=0.3,*/*;q=0.1",
    {ok, {_, _, Body}} = httpc:request(get, {URL, [{"Accept", Accept}]},
				       [], [{body_format, binary}]),
    Lines = binary:split(Body, <<"\n">>, [global]),
    Result =
        lists:filter(
          fun(<<"capwap_ac_station_count", _/binary>>) -> true;
             (_) -> false
          end, Lines),
    ?assertEqual(1, length(Result)),
    ok.

http_api_prometheus_metrics_sub_req() ->
    [{doc, "Check /metrics/... Prometheus API endpoint"}].
http_api_prometheus_metrics_sub_req(_Config) ->
    Accept = "application/vnd.google.protobuf;proto=io.prometheus.client.MetricFamily;encoding=delimited;q=0.7,"
             ++ "text/plain;version=0.0.4;q=0.3,*/*;q=0.1",
    URL0 = get_test_url("/metrics/capwap/ac/station_count"),
    {ok, {_, _, Body}} = httpc:request(get, {URL0, [{"Accept", Accept}]},
				       [], [{body_format, binary}]),
    Lines = binary:split(Body, <<"\n">>, [global]),
    Result =
        lists:filter(fun(<<"capwap_ac_station_count", _/binary>>) ->
                             true;
                        (_) -> false
                     end, Lines),
    ?assertEqual(1, length(Result)),
    ok.

http_api_metrics_req() ->
    [{doc, "Check /metrics API"}].
http_api_metrics_req(_Config) ->
    URL = get_test_url("/metrics"),
    {ok, {_, _, Body}} = httpc:request(get, {URL, []},
				       [], [{body_format, binary}]),
    Res = jsx:decode(Body, [return_maps]),
    ?assertMatch(#{<<"value">> := 0},
                 maps:get(<<"station_count">>,
                    maps:get(<<"ac">>,
                        maps:get(<<"capwap">>, Res)))
                ),
    ok.

http_api_metrics_sub_req() ->
    [{doc, "Check /metrics/... API"}].
http_api_metrics_sub_req(_Config) ->
    URL0 = get_test_url("/metrics/capwap/ac/station_count"),
    {ok, {_, _, Body0}} = httpc:request(get, {URL0, []},
				       [], [{body_format, binary}]),
    Res0 = jsx:decode(Body0, [return_maps]),
    ?assertMatch(#{<<"value">> := 0}, Res0),
    ok.

http_api_bad_command() ->
    [{doc, "Check unknown commands"}].
http_api_bad_command(_Config) ->
    URL0 = get_test_url("/another_command"),
    {ok, {_, _, Body0}} = httpc:request(get, {URL0, []},
				       [], [{body_format, binary}]),
    ?assertEqual(<<>>, Body0),
    ok.

http_api_dp_wtp_list_error() ->
    [{doc, "Check /api/v1/dp/wtp-list API with capwap-dp node down"}].
http_api_dp_wtp_list_error(_Config) ->
    URL = get_test_url("/api/v1/dp/wtp-list"),
    {ok, {_, _, Body}} = httpc:request(get, {URL, []},
				       [], [{body_format, binary}]),
    Res = jsx:decode(Body, [return_maps]),
    ?assertEqual(<<"error">>, maps:get(<<"type">>, Res)),
    ok.

http_api_dp_status_error() ->
    [{doc, "Check /api/v1/dp/status API with capwap-dp node down"}].
http_api_dp_status_error(_Config) ->
    URL = get_test_url("/api/v1/dp/stats"),
    {ok, {_, _, Body}} = httpc:request(get, {URL, []},
				       [], [{body_format, binary}]),
    Res = jsx:decode(Body, [return_maps]),
    ?assertEqual(<<"error">>, maps:get(<<"type">>, Res)),
    ok.

%%%===================================================================
%%% Internal functions
%%%===================================================================

get_test_url(Path) ->
    Port = ranch:get_port(capwap_http_api),
    lists:flatten(io_lib:format("http://localhost:~w~s", [Port, Path])).

exo_function(_) ->
    [{value, rand:uniform(1000)}].

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
                             ]},
			  {location_provider, #{
			    providers => [
			        {capwap_loc_provider_default, #{default_loc => {location, <<"123">>, <<"456">>}}},
			        {capwap_loc_provider_http, #{uri => "http://127.0.0.1:9999", timeout => 30000}}
		            ],
		            refresh => 1000}
			  }
                     ]},
	    {ergw_aaa,
	     [
	      {handlers,
	       [{ergw_aaa_static,
		 [{'NAS-Identifier',        <<"NAS-Identifier">>},
		  {'Acct-Interim-Interval', 600}
		 ]}
	       ]},
	      {services,
	       [{'Default',
		 [{handler, 'ergw_aaa_static'},
		  {answers,
		   #{'RADIUS-Auth' =>
			 #{'Result-Code' => 2001,
			   'TLS-Pre-Shared-Key' => <<"MySecret">>},
		     'RADIUS-Acct' =>
			 #{'Result-Code' => 2001}
		    }
		  }
		 ]}
	       ]},
	      {apps,
	       [{default,
		 [{session, ['Default']},
		  {procedures, [{authenticate, [{'Default', [{answer, 'RADIUS-Auth'}]}]},
				{authorize, []},
				{start, [{'Default', [{answer, 'RADIUS-Acct'}]}]},
				{interim, [{'Default', [{answer, 'RADIUS-Acct'}]}]},
				{stop, [{'Default', [{answer, 'RADIUS-Acct'}]}]}
			       ]}
		 ]}
	       ]}
	     ]}
	   ],
    [application:load(Name) || {Name, _} <- Apps],
    lists:flatten([setup_application(A) || A <- Apps]).

setup_application({Name, Env}) ->
    application:stop(Name),
    application:unload(Name),
    [application:set_env(Name, Key, Val) || {Key, Val} <- Env],
    {ok, Ret} = application:ensure_all_started(Name),
    Ret;
setup_application(Name) ->
    {ok, Ret} = application:ensure_all_started(Name),
    Ret.
