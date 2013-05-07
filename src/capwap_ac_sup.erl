-module(capwap_ac_sup).

-behaviour(supervisor).

%% API
-export([start_link/0, new_wtp/4]).

%% Supervisor callbacks
-export([init/1]).

-define(SERVER, ?MODULE).

%%%===================================================================
%%% API functions
%%%===================================================================

start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

new_wtp(Socket, IP, InPortNo, Packet) ->
    io:format("Stating new WTP: ~p, ~p, ~p, ~p~n", [Socket, IP, InPortNo, Packet]),
    R = supervisor:start_child(?SERVER, [Socket, IP, InPortNo, Packet]),
    io:format("Result: ~p~n", [R]),
    R.

%%%===================================================================
%%% Supervisor callbacks
%%%===================================================================

init([]) ->
    {ok, {{simple_one_for_one, 1000, 1000},
	  [{capwap_ac, {capwap_ac, start_link, []}, temporary, 1000, worker, [capwap_ac]}]}}.
