-module(capwap_wtp_reg).

-behaviour(regine_server).

%% API
-export([start_link/0]).
-export([register/1, unregister/0, lookup/1, register_sessionid/2, lookup_sessionid/2]).

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

register(PeerId) ->
    regine_server:register(?SERVER, self(), PeerId, undefined).

register_sessionid(PeerId, SessionId) ->
    regine_server:register(?SERVER, self(), {PeerId, SessionId}, undefined).

unregister() ->
    regine_server:unregister_pid(?SERVER, self()).

lookup(PeerId) ->
    case ets:lookup(?SERVER, PeerId) of
	[] -> not_found;
	[{_, Pid}] -> {ok, Pid}
    end.

lookup_sessionid(PeerId, SessionId) ->
    case ets:lookup(?SERVER, {PeerId, SessionId}) of
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

handle_register(Pid, PeerId, _Args, State) ->
    ets:insert(?SERVER, {PeerId, Pid}),
    {ok, [PeerId], State}.

handle_unregister(PeerId, _Args, State) ->
    Pids = ets:lookup(?SERVER, PeerId),
    ets:delete(?SERVER, PeerId),
    {Pids, State}.

handle_death(_Pid, _Reason, State) ->
    State.

handle_pid_remove(Pid, PeerIds, State) ->
    lists:foreach(fun (PeerId) ->
                          ets:delete_object(?SERVER, {PeerId, Pid})
                  end, PeerIds),
    State.

terminate(_Reason, _State) ->
    ok.
