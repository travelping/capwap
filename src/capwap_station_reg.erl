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

-module(capwap_station_reg).

-behaviour(regine_server).

%% API
-export([start_link/0]).
-export([register/3, unregister/3, lookup/3, register/1, unregister/1, lookup/1]).
-export([list_stations/0]).

%% regine_server callbacks
-export([init/1, handle_register/4, handle_unregister/3, handle_pid_remove/3, handle_death/3, terminate/2]).

-include_lib("stdlib/include/ms_transform.hrl").

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

register(AC, BSS, Station) ->
    regine_server:register(?SERVER, self(), {AC, BSS, Station}, undefined).

unregister(ClientMAC) ->
    regine_server:unregister(?SERVER, ClientMAC, undefined).

unregister(AC, BSS, Station) ->
    regine_server:unregister(?SERVER, {AC, BSS, Station}, undefined).

lookup(ClientMAC) ->
    case ets:lookup(?SERVER, ClientMAC) of
	[] -> not_found;
	[{_, RadioMAC}] -> {ok, RadioMAC}
    end.

lookup(AC, BSS, Station) ->
    case ets:lookup(?SERVER, {AC, BSS, Station}) of
	[] -> not_found;
	[{_, Pid}] -> {ok, Pid}
    end.

list_stations() ->
    ets:select(?SERVER, ets:fun2ms(fun({{AC, _BSS, MAC}, _}) when is_binary(MAC) -> {AC, MAC} end)).

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
