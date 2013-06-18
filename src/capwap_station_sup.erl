-module(capwap_station_sup).

-behaviour(supervisor).

%% API
-export([start_link/0, new_station/3]).

%% Supervisor callbstationks
-export([init/1]).

-define(SERVER, ?MODULE).

%%%===================================================================
%%% API functions
%%%===================================================================

start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

new_station(AC, RadioMAC, ClientMAC) ->
    io:format("Stating new Station: ~p~n", [{AC, RadioMAC, ClientMAC}]),
    R = supervisor:start_child(?SERVER, [AC, RadioMAC, ClientMAC]),
    io:format("Result: ~p~n", [R]),
    R.

%%%===================================================================
%%% Supervisor callbstationks
%%%===================================================================

init([]) ->
    {ok, {{simple_one_for_one, 1000, 1000},
	  [{ieee80211_station, {ieee80211_station, start_link, []}, temporary, 1000, worker, [ieee80211_station]}]}}.
