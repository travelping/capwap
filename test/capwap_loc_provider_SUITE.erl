%% Copyright (C) 2023, Travelping GmbH <info@travelping.com>

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

-module(capwap_loc_provider_SUITE).

-compile(export_all).

-include_lib("common_test/include/ct.hrl").
-include("capwap_config.hrl").

-define(equal(Expected, Actual),
    (fun (Expected@@@, Expected@@@) -> true;
	 (Expected@@@, Actual@@@) ->
	     ct:pal("MISMATCH(~s:~b, ~s)~nExpected: ~p~nActual:   ~p~n",
		    [?FILE, ?LINE, ??Actual, Expected@@@, Actual@@@]),
	     false
     end)(Expected, Actual) orelse error(badmatch)).


-define(match(Guard, Expr),
	((fun () ->
		  case (Expr) of
		      Guard -> ok;
		      V -> ct:pal("MISMATCH(~s:~b, ~s)~nExpected: ~p~nActual:   ~s~n",
				   [?FILE, ?LINE, ??Expr, ??Guard, pretty_print(V)]),
			    error(badmatch)
		  end
	  end)())).

suite() ->
	[{timetrap,{seconds,30}}].

all() ->
    [test_cache,
     test_config_chain,
     test_reconfig,
     test_error].

capwap_app(LocConfig) ->
    {application,
     capwap,
     [{vsn, dummy},
      {id, dummy},
      {env, [{location_provider, #{}}]},
      {mod, {capwap_dummy_app, LocConfig}}]}.

init_per_suite(Config) ->
    logger:update_primary_config(#{level => all}),
    logger:update_formatter_config(default, template, [time," ",pid," ",level," ",mfa,": ",msg,"\n"]),
    logger:update_formatter_config(default, level, all),
    logger:update_formatter_config(cth_log_redirect, template, [time," ",pid," ",level," ",mfa,": ",msg,"\n"]),
    logger:update_formatter_config(cth_log_redirect, level, all),
    % Dummy app to allow 
    ct:pal("--> Apps: ~p", [application:which_applications()]),
    ct:pal("--> My app: ~p", [application:get_application()]),
    ct:pal("Env for capwap: ~p", [application:get_all_env(capwap)]),
    ct:log("Suite config: ~p~n", [Config]),
    meck:new(test_loc_handler, [no_link, passthrough]),
    RefreshTime = 5000,
    LocConfig = #{providers => [
	{capwap_loc_provider_http, #{uri => "http://127.0.0.1:9990", timeout => 30000}},
	{capwap_loc_provider_default, #{default_loc => {location, <<"123.123">>, <<"456.456">>}}}
      ],
      refresh => RefreshTime},
    %% NOTICE
    %% Due to the dependency on checking the env of the application the caller
    %% belongs to, this test suite sets up a dummy application called "capwap"
    %% that includes both the location user and the location provider. Otherwise,
    %% the caller function calls would fail when trying to find the appropriate
    %% env config key (config woul be undefined since ct does not run within an
    %% application).
    %% So all calls on capwap_loc_provider are done on loc_provider_proxy instead,
    %% which basically proxies the calls to capwap_loc_provider, but is also
    %% under the capwap application, so the right env is chosen.
    %% This is only needed for tests.
    % capwap is stopped but loaded....
    application:unload(capwap),
    LoadedCapwap = application:load(capwap_app(LocConfig)),
    StartedCapwap = application:start(capwap),
    ct:pal("Loaded & Started? ~p", [{LoadedCapwap, StartedCapwap}]),
    application:ensure_all_started(ranch),
    application:ensure_all_started(hackney),
    
    Dispatch = cowboy_router:compile([
        {'_', [{"/[...]", test_loc_handler, []}]}
    ]),
    {ok, _} = cowboy:start_clear(test_loc_handler,
        [{port, 9990}],
        #{env => #{dispatch => Dispatch}}
    ),
    LocSuiteCfg = #{test_loc_name => test_loc_handler, refresh_time => RefreshTime},
    [{loc_suite_cfg, LocSuiteCfg} | Config].


end_per_suite(Config) ->
    {value, {loc_suite_cfg, #{test_loc_name := TestLocName}}} =
        lists:keysearch(loc_suite_cfg, 1, Config),
    application:stop(capwap),
    application:unload(capwap),
    meck:unload(test_loc_handler),
    cowboy:stop_listener(TestLocName),
    ok.

init_per_testcase(_, Config) ->
    loc_provider_proxy:flush_loc_cache(),
    Config.

end_per_testcase(TC, _) when 
   TC == test_reconfig orelse 
   TC == test_error orelse 
   TC == test_existing_server_no_cache ->
    RefreshTime = 5000,
    LocConfig = #{providers => [
	{capwap_loc_provider_http, #{uri => "http://127.0.0.1:9999", timeout => 30000}},
	{capwap_loc_provider_default, #{default_loc => {location, <<"123.123">>, <<"456.456">>}}}
      ],
      refresh => RefreshTime},
    loc_provider_proxy:load_config(LocConfig),
    meck:expect(test_loc_handler, content, fun() ->  meck:passthrough([]) end),
    ok;
end_per_testcase(_, _) ->
    meck:expect(test_loc_handler, content, fun() ->  meck:passthrough([]) end),
    ok.

%% ==============================================
%% Tests
%% ==============================================

test_cache() ->
    [{doc, "Test that the cache is used and refreshed appropriately"}].
test_cache(_) ->
    ct:pal("Env for capwap: ~p", [application:get_all_env(capwap)]),
    V1 = #{<<"latitude">> => <<"001.1">>,  <<"longitude">> => <<"002.2">>},
    V2 = #{<<"latitude">> => <<"100.0">>,  <<"longitude">> => <<"200.0">>},
    meck:expect(test_loc_handler, content, fun() -> jsx:encode(V1) end),
    {location, <<"001.1">>, <<"002.2">>} = loc_provider_proxy:get_loc(<<"device">>),
    meck:expect(test_loc_handler, content, fun() -> jsx:encode(V2) end),
    %% Note we change the value right now to catch errors in caching
    timer:sleep(1000),
    %% Cache hasn't expired
    {location, <<"001.1">>, <<"002.2">>} = loc_provider_proxy:get_loc(<<"device">>),
    timer:sleep(10000),
    %% Cache has expired now
    {location, <<"100.0">>, <<"200.0">>} = loc_provider_proxy:get_loc(<<"device">>),
    ok.

test_config_chain() ->
    [{doc, "Test that the next provider is used in case of error"}].
test_config_chain(_) ->
    NonConformant = #{<<"error">> => <<"errorMsg">>},
    meck:expect(test_loc_handler, content, fun() -> jsx:encode(NonConformant) end),
    {location, <<"123.123">>, <<"456.456">>} = loc_provider_proxy:get_loc(<<"device">>).

test_reconfig() ->
    [{doc, "Test that config can be modified at runtime"}].
test_reconfig(Config) ->
    RefreshTime = 5000,
    LocConfig = #{providers => [
	{capwap_loc_provider_default, #{default_loc => {location, Lat = <<"123.123">>, Long = <<"456.456">>}}}
      ],
      refresh => RefreshTime},
    loc_provider_proxy:load_config(LocConfig),
    {location, <<"123.123">>, <<"456.456">>} = loc_provider_proxy:get_loc(<<"device">>).

test_error() ->
    [{doc, "Test that an error is returned in case of no valid providers"}].
test_error(Config) ->
    RefreshTime = 5000,
    LocConfig = #{providers => [
      ],
      refresh => RefreshTime},
    loc_provider_proxy:load_config(LocConfig),
    {error, no_more_providers} = loc_provider_proxy:get_loc(<<"device">>).
