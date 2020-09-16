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

-module(capwap_wtp_mockup_SUITE).

-compile(export_all).

-include_lib("kernel/include/logger.hrl").
-include_lib("common_test/include/ct.hrl").

suite() ->
    [{timetrap,{minutes,5}}].

init_per_suite(Config) ->
    case proplists:get_bool(run_mockup, Config) of
	true ->
	    setup_applications(),
	    Config;
	_ ->
	    {skip, "disabled"}
    end.

all() ->
    [load_local].

load_local(Config) ->
    [WaitFor, KeepRunningFor, WtpCount, KeepAliveTimeout] =
	get_config([{wait_for, 0},
                {keep_running_for, 2000},
                {multi_wtp_count, 10},
                {keep_alive_timeout, 1}]),
    CertDir = "",
    RootCert = "",

    StartTimeouts = [Index * 100 || Index <- lists:seq(1, WtpCount)],
    IPs = generate_ip_addresses({127,0,0,1}, WtpCount),
    TimeoutsAndIPs = lists:zip(StartTimeouts, IPs),
    Helper = fun({StartTimeout, IP}) ->
                     timer:sleep(StartTimeout),
                     start_wtp({{127,0,0,1}, 5246}, CertDir, RootCert, WaitFor, IP, false, [{data_keep_alive_timeout, KeepAliveTimeout}])
             end,
    WTPs = pmap(Helper, TimeoutsAndIPs),

    WTPsAndIPs = lists:zip(WTPs, IPs),
    pmap(fun({WTP, {A, B, C, D}}) ->
                 ok = wtp_mockup_fsm:add_station(WTP, <<144, 39, A, B, C, D>>)
         end,
         WTPsAndIPs),
    timer:sleep(KeepRunningFor),
    WTPs.

setup_applications() ->
    {ok, CWD} = file:get_cwd(),
    os:cmd("touch " ++ CWD ++ "/upstream"),
    Apps = [asn1,
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
		      {http_api, [{port, 0}]},
		      {server_socket_opts, [{recbuf, 1048576}, {sndbuf, 1048576}]}
		     ]}
	   ],
    [setup_application(A) || A <- Apps].

setup_application({Name, Env}) ->
    application:load(Name),
    [application:set_env(Name, Key, Val) || {Key, Val} <- Env],
    application:start(Name);

setup_application(Name) ->
    setup_application({Name, []}).

start_wtp(SCG, CertDir, RootCert, WaitFor, IP, UseDtls) ->
    start_wtp(SCG, CertDir, RootCert, WaitFor, IP, UseDtls, []).

start_wtp(SCG, CertDir, RootCert, WaitFor, IP, UseDtls, Options) ->
    {ok, CS} = wtp_mockup_fsm:start_link(SCG, IP, 5248, CertDir, RootCert, <<8,8,8,8,8,8>>, UseDtls, Options),
    {ok, _} = wtp_mockup_fsm:send_discovery(CS),
    timer:sleep(WaitFor),
    {ok, _} = wtp_mockup_fsm:send_join(CS),
    timer:sleep(WaitFor),
    {ok, _} = wtp_mockup_fsm:send_config_status(CS),
    timer:sleep(WaitFor),
    {ok, _} = wtp_mockup_fsm:send_change_state_event(CS),
    timer:sleep(WaitFor),
    {ok, _} = wtp_mockup_fsm:send_wwan_statistics(CS),
    CS.


tuple_to_integer_ip({A, B, C, D}) ->
    <<IP:32/integer>> = <<A:8, B:8, C:8, D:8>>,
    IP;
tuple_to_integer_ip({A, B, C, D, E, F, G, H}) ->
    <<IP:128/integer>> = <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>,
    IP.

integer_ip_to_tuple(IP)
  when IP < 16#100000000 ->
    <<A:8, B:8, C:8, D:8>> = <<IP:32>>,
    {A, B, C, D};
integer_ip_to_tuple(IP) ->
    <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>> = <<IP:128>>,
    {A, B, C, D, E, F, G, H}.

%% generates the next Num ip-addresses, starting with FromIp
generate_ip_addresses(Start, Count) ->
    generate_ip_addresses(tuple_to_integer_ip(Start), Count, []).

generate_ip_addresses(_, 0, Acc) ->
    lists:reverse(Acc);
generate_ip_addresses(IP, N, Acc) ->
    generate_ip_addresses(IP + 1, N - 1, [integer_ip_to_tuple(IP)|Acc]).

pmap(F, L) ->
    pmap(F, L, infinity).

pmap(F, L, Timeout) ->
    Parent = self(),
    Pids = [proc_lib:spawn(fun() -> Parent ! {self(), F(X)} end) || X <- L],
    lists:map(
        fun(Pid) ->
            receive {Pid, Result} ->
	            Result
            after Timeout ->
                      {error, timeout}
            end
        end, Pids).

get_multi_cert_paths(undefined) ->
    [];

get_multi_cert_paths(MultiCertDir) ->
    {ok, Filenames} = file:list_dir(MultiCertDir),
    [filename:join(MultiCertDir, FN) || FN <- Filenames].

get_config(KeyDefaults) when is_list(KeyDefaults) ->
    Conf = [application:get_env(capwap, Key, Default) || {Key, Default} <- KeyDefaults],
    ?LOG(debug, "reading config from fake application capwap_wtp_mockup : ~p", [Conf]),
    Conf.
