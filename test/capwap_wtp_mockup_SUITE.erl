
-module(capwap_wtp_mockup_SUITE).

-compile(export_all).

-include_lib("common_test/include/ct.hrl").

suite() ->
    [{timetrap,{seconds,30}}].

init_per_suite(Config) ->
    setup_applications(),
    Config.

end_per_suite(_Config) ->
    ok.

init_per_group(_GroupName, Config) ->
    Config.

end_per_group(_GroupName, _Config) ->
    ok.

init_per_testcase(_TestCase, Config) ->
    {ok, CS} = wtp_mockup_fsm:start_link(),
    [{control_socket, CS} | Config].

end_per_testcase(_TestCase, _Config) ->
    ok.

groups() ->
    [].

all() -> 
    [discovery].

discovery() -> 
    [].

discovery(Config) -> 
    CS = proplists:get_value(control_socket, Config),
    ok = wtp_mockup_fsm:send_discovery(CS),
    ok = wtp_mockup_fsm:send_join(CS),
    ok = wtp_mockup_fsm:send_config_status(CS),
    ok = wtp_mockup_fsm:send_change_state_event(CS),
    ok = wtp_mockup_fsm:send_wwan_statistics(CS),
    ok = wtp_mockup_fsm:add_station(CS, <<144,39,228,64,185,19>>),
    timer:sleep(5000).

setup_applications() ->
    {ok, CWD} = file:get_cwd(),
    os:cmd("touch " ++ CWD ++ "/upstream"),
    Apps = [{lager, [{handlers, [
				 {lager_console_backend, info},
				 {lager_file_backend, [
						       {file, "log/error.log"}, {level, error}, {size, 10485760}, {date, "$D0"}, {count, 5}]},
				 {lager_file_backend, [
						       {file, "log/console.log"}, {level, debug}, {size, 10485760}, {date, "$D0"}, {count, 5}]}]}
		    ]},
	    asn1,
	    crypto,
	    public_key,
	    ssl,
	    sasl,
	    jobs,
	    eradius,
	    regine,
	    ctld,
	    {capwap, [{server_ip, {127, 0, 0, 1}},
		      {enforce_dtls_control, false},
		      {ctld_provider, {ctld_mock, [{secret, <<"MySecret">>}]}},
		      {server_socket_opts, [{netns, CWD ++ "/upstream"}, {recbuf, 1048576}, {sndbuf, 1048576}]}
		     ]}
	   ],
    [setup_application(A) || A <- Apps].

setup_application({Name, Env}) ->
    application:load(Name),
    [application:set_env(Name, Key, Val) || {Key, Val} <- Env],
    application:start(Name);

setup_application(Name) ->
    setup_application({Name, []}).
