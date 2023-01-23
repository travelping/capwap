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

%% The `capwap_loc_provider` functionality retrieves location information
%% using a pluggable architecture. A plugin supplying location
%% information to CAPWAP needs to provide a module conforming to
%% the `capwap_loc_provider` using the callbacks defined below.

%% This functionality expects a configuration term with the following
%% format:

%% ```
%% {location_provider, #{
%%     providers => [
%%         {<plugin module>, <configuration term>}
%%     ],
%%     refresh => <refresh time>}
%% }
%% ```

%% This module includes a cache that stores already retrieved locations
%% for a configurable time. After the timer expires, the entry is removed from
%% the cache, and resolved again when a new request comes in.

-module(capwap_loc_provider).

-behavior(gen_server).

%% API
-export([start/1, start_link/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

%% user api
-export([flush_loc_cache/0, get_loc/1, get_loc/2, load_config/1]).

-include_lib("kernel/include/logger.hrl").

-define(CACHE_LOC, capwap_loc_provider_cache).

-record(loc_cache, {loc_tab, config_tab, refresh, providers, provider_chain = undefined}).

%% callbacks

-callback config_fun(any()) -> fun((<<>>) -> {error, any()} | {location, <<>>, <<>>}).
%% A separate callback returning an opaque ref would be
%% useful in the case of stateful providers.
%% This option is not covered yet.

%% API

start_link(Config) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, Config, []).

start(Config) ->
    gen_server:start({local, ?MODULE}, ?MODULE, Config, []).

%% validation

validate(#{refresh := RefreshTime, providers := Providers})
  when is_integer(RefreshTime) andalso RefreshTime>0 ->
    validate_providers(Providers),
    ok.

validate_providers(Providers) when is_list(Providers) ->
    lists:map(fun validate_provider/1, Providers),
    ok.

validate_provider({Mod, Config}) ->
    Mod:validate_provider(Config).

%% gen_server callbacks

init(Config = #{refresh := RefreshTime, providers := Providers}) ->
    validate(Config),
    ?LOG(debug, "Table ref: ~p", [ets:whereis(?CACHE_LOC)]),
    TabOpts = [set, protected, named_table, {read_concurrency, true}],
    %% Not needed since it will return the table name
    LocTab = ets:new(?CACHE_LOC, TabOpts),
    ?LOG(debug, "cache started: ~p", [LocTab]),
    ?LOG(debug, "table ref: ~p", [ets:whereis(?CACHE_LOC)]),
    %% TODO Handle exceptions in chain?
    {ok, #loc_cache{
	loc_tab = LocTab, refresh = RefreshTime, providers = Providers, provider_chain = chain(Providers)}}.

handle_call(flush_loc_cache, _, State = #loc_cache{loc_tab = LocTab}) ->
    ?LOG(debug, "Flush location cache, tableref: ~p", [ets:whereis(LocTab)]),
    ets:delete_all_objects(LocTab),
    {reply, ok, State};
handle_call({get_loc, true, Name}, _, State = #loc_cache{
	     loc_tab = LocTab, refresh = RefreshTime, provider_chain = Chain}) ->
    ?LOG(debug, "get location for device name (with cache): ~p", [Name]),
    Result = case ets:lookup(LocTab, Name) of
	[{Name, Loc = {location, _, _}}] -> Loc;
	[] -> refresh_loc(Name, Chain, LocTab, RefreshTime)
    end,
    {reply, Result, State};
handle_call({get_loc, false, Name}, _, State = #loc_cache{
	     provider_chain = Chain}) ->
    ?LOG(debug, "get location for device name (without cache): ~p", [Name]),
    Result = Chain(Name),
    {reply, Result, State};
handle_call({load_config, #{refresh := RefreshTime, providers := Providers}}, _, OldState) ->
    NewState = OldState#loc_cache{refresh = RefreshTime, providers = Providers, provider_chain = chain(Providers)},
    ?LOG(debug, "reloading config: from ~p to ~p", [OldState#loc_cache{provider_chain = undefined}, NewState]),
    {reply, OldState, NewState}.

handle_cast(_, State) ->
    ?LOG(error, "Unexpected cast"),
    {noreply, State}.

handle_info({evict, Name}, State = #loc_cache{loc_tab = LocTab}) ->
    ?LOG(debug, "refresh location expired for device name: ~p", [Name]),
    ets:delete(LocTab, Name),
    {noreply, State}.

terminate(Reason, _) ->
    ?LOG(debug, "terminating: ~p", [Reason]),
    ok.

%% user api

is_enabled() ->
    case application:get_env(capwap, location_provider) of
	undefined -> false;
	{ok, _} -> true
    end.

flush_loc_cache() ->
    case is_enabled() of
	true -> gen_server:call(?MODULE, flush_loc_cache);
	false -> {error, "Location not enabled"}
    end.

load_config(Config) ->
    case is_enabled() of
	true -> gen_server:call(?MODULE, {load_config, Config});
	false -> {error, "Location not enabled"}
    end.
    

%% Uses exceptions and error (for the provider itself)
get_loc(Name) ->
    get_loc(Name, true).

get_loc(Name, true) ->
    case is_enabled() of
	true -> 
	    ?LOG(debug, "table ref: ~p", [ets:whereis(?CACHE_LOC)]),
	    case ets:lookup(?CACHE_LOC, Name) of
		[{Name, Loc = {location, _, _}}] -> Loc;
		[] -> gen_server:call(?MODULE, {get_loc, true, Name}, 20000)
	    end;
	false -> {error, "Location not enabled"}
    end;
get_loc(Name, false) ->
    case is_enabled() of
	true ->
	    ?LOG(debug, "Bypassing cache"),
	    gen_server:call(?MODULE, {get_loc, false, Name}, 20000);
	false -> {error, "Location not enabled"}
    end.

%% Internal functions

refresh_loc(Name, Chain, LocTab, RefreshTime) ->
    case Chain(Name) of
	E = {error, _} -> E;
	L = {location, _, _} -> 
	    ets:insert(LocTab, {Name, L}),
	    erlang:send_after(RefreshTime, ?MODULE, {evict, Name}),
	    L
    end.

% Should cause be logged? Or maybe passed on to the next item?
prov_fun(ModFun, Next) ->
    fun(Name) -> case ModFun(Name) of {error, _Cause} -> Next(Name); L = {location, _, _} -> L end end.

error_fun(_) ->
    {error, no_more_providers}.

chain(Providers) ->
    lists:foldl(fun({Mod, Config}, Next) -> prov_fun(Mod:config_fun(Config), Next) end, fun error_fun/1, lists:reverse(Providers)).
