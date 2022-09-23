-module(capwap_loc_provider).

-behavior(gen_server).

%% API
-export([start/1, start_link/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

%% user api
-export([flush_loc_cache/0, get_loc/1, get_loc/2, load_config/1]).

-include_lib("kernel/include/logger.hrl").

-define(CACHE_LOC, capwap_loc_provider_cache).
-define(CACHE_CONFIG, capwap_loc_config_cache).
-define(TIMER_WAIT, 2000).

-record(loc_cache, {loc_tab, config_tab, refresh, providers, provider_chain = undefined}).

%% callbacks

-callback config_fun(any()) -> fun((<<>>) -> {error, any()} | {location, <<>>, <<>>}).
%% A separate callback returning an opaque ref would be
%% useful in the case of stateful providers.
%% This option is not covered yet.

%% user api

start_link(Config) ->
  gen_server:start_link({local, ?MODULE}, ?MODULE, Config, []).

start(Config) ->
  gen_server:start({local, ?MODULE}, ?MODULE, Config, []).

flush_loc_cache() ->
  gen_server:call(?MODULE, flush_loc_cache).

load_config(Config) ->
  gen_server:call(?MODULE, {load_config, Config}).

%% Uses exceptions and error (for the provider itself)
get_loc(Name) ->
  get_loc(Name, true).

get_loc(Name, true) ->
  ?LOG(debug, "table ref: ~p", [ets:whereis(?CACHE_LOC)]),
  case ets:lookup(?CACHE_LOC, Name) of
    [{Name, Loc = {location, _, _}}] -> Loc;
    [] -> gen_server:call(?MODULE, {get_loc, true, Name}, 20000)
  end;
get_loc(Name, false) ->
  ?LOG(debug, "bypassing cache"),
  gen_server:call(?MODULE, {get_loc, false, Name}, 20000).

%% gen_server impl

init(#{refresh := RefreshTime, providers := Providers}) ->
  ?LOG(debug, "table ref: ~p", [ets:whereis(?CACHE_LOC)]),
  TabOpts = [set, protected, named_table, {read_concurrency, true}],
  %% Not needed since it will return the table name
  LocTab = ets:new(?CACHE_LOC, TabOpts),
  ?LOG(debug, "cache started: ~p", [LocTab]),
  ?LOG(debug, "table ref: ~p", [ets:whereis(?CACHE_LOC)]),
  %% TODO Handle exceptions in chain?
  {ok, #loc_cache{
    loc_tab = LocTab, refresh = RefreshTime, providers = Providers, provider_chain = chain(Providers)}}.

handle_call(flush_loc_cache, _, State = #loc_cache{loc_tab = LocTab}) ->
  ?LOG(debug, "whoami: ~p", [self()]),	
  ?LOG(debug, "tableref: ~p", [ets:whereis(LocTab)]),	
  ?LOG(debug, "Flush location cache"),
  ets:delete_all_objects(LocTab),
  {reply,ok,State};
handle_call({get_loc, UseCache = true, Name}, _, State = #loc_cache{
    loc_tab = LocTab, refresh = RefreshTime, provider_chain = Chain}) ->
  ?LOG(debug, "get location for device name (with cache): ~p", [Name]),
  Result = case ets:lookup(LocTab, Name) of
    [{Name, Loc = {location, _, _}}] -> Loc;
    [] -> refresh_loc(Name, Chain, LocTab, RefreshTime)
  end,
  {reply, Result, State};
handle_call({get_loc, UseCache = false, Name}, _, State = #loc_cache{
    loc_tab = LocTab, refresh = RefreshTime, provider_chain = Chain}) ->
  ?LOG(debug, "get location for device name (without cache): ~p", [Name]),
  Result = Chain(Name),
  {reply, Result, State};
handle_call({load_config, #{refresh := RefreshTime, providers := Providers}}, _, OldState) ->
  NewState = OldState#loc_cache{refresh = RefreshTime, providers = Providers, provider_chain = chain(Providers)},
  ?LOG(debug, "reloading config: from ~p to ~p", [OldState#loc_cache{provider_chain = undefined}, NewState]),
  {reply,OldState,NewState}.

handle_cast(_, State) ->
  ?LOG(error, "Unexpected cast"),
  {noreply,State}.

handle_info({evict, Name}, State = #loc_cache{loc_tab = LocTab}) ->
  ?LOG(debug, "refresh location expired for device name: ~p", [Name]),
  ets:delete(LocTab, Name),
  {noreply,State}.

%% Should cause be logged? Or maybe passed on to the next item?
prov_fun(ModFun, Next) ->
  fun(Name) -> case ModFun(Name) of {error, _Cause} -> Next(Name); L = {location, _, _} -> L end end.
error_fun(_) ->
  {error, no_more_providers}.

chain(Providers) ->
  lists:foldl(fun({Mod, Config}, Next) -> prov_fun(Mod:config_fun(Config), Next) end, fun error_fun/1, lists:reverse(Providers)).

terminate(Reason, _) ->
  ?LOG(debug, "terminating: ~p", [Reason]),
  ok.

%% Internal functions

refresh_loc(Name, Chain, LocTab, RefreshTime) ->
  case Chain(Name) of
    E = {error, _} -> E;
    L = {location, _, _} -> 
      ets:insert(LocTab, {Name, L}),
      erlang:send_after(RefreshTime, ?MODULE, {evict, Name}),
      L
  end.

%% get_millis() ->
%%   {Mega, Sec, Micro} = os:timestamp(),
%%   (Mega*1000000 + Sec)*1000 + round(Micro/1000).