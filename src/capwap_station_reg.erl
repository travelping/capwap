-module(capwap_station_reg).

-behaviour(regine_server).

%% API
-export([start_link/0]).
-export([register/2, unregister/2, lookup/2, register/1, unregister/1, lookup/1]).

%% regine_server callbacks
-export([init/1, handle_register/4, handle_unregister/3, handle_pid_remove/3, handle_death/3, terminate/2]).

-define(SERVER, ?MODULE).

-record(state, {
         }).

%%%===================================================================
%%% API
%%%===================================================================

start_link() ->
    regine_server:start_link({local, ?SERVER}, ?MODULE, []).

register(ClientMAC) ->
    regine_server:register(?SERVER, self(), ClientMAC, undefined).

register(AC, Station) ->
    regine_server:register(?SERVER, self(), {AC, Station}, undefined).

unregister(ClientMAC) ->
    regine_server:unregister(?SERVER, ClientMAC, undefined).

unregister(AC, Station) ->
    regine_server:unregister(?SERVER, {AC, Station}, undefined).

lookup(ClientMAC) ->
    case ets:lookup(?SERVER, ClientMAC) of
	[] -> not_found;
	[{_, RadioMAC}] -> {ok, RadioMAC}
    end.

lookup(AC, Station) ->
    case ets:lookup(?SERVER, {AC, Station}) of
	[] -> not_found;
	[{_, Pid}] -> {ok, Pid}
    end.

%%%===================================================================
%%% regine_server functions
%%%===================================================================

init([]) ->
    process_flag(trap_exit, true),
    ets:new(?SERVER, [bag, protected, named_table, {keypos, 1}, {read_concurrency, true}]),
    {ok, #state{}}.

handle_register(Pid, StationId, undefined, State) ->
    ets:insert(?SERVER, {StationId, Pid}),
    {ok, [StationId], State}.

handle_unregister(StationId, _Args, State) ->
    Pids = ets:lookup(?SERVER, StationId),
    ets:delete(?SERVER, StationId),
    {Pids, State}.

handle_death(_Pid, _Reason, State) ->
    State.

handle_pid_remove(_Pid, StationIds, State) ->
    lists:foreach(fun (StationId) ->
                          ets:delete(?SERVER, StationId)
                  end, StationIds),
    State.

terminate(_Reason, _State) ->
    ok.
