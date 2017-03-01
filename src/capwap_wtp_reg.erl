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

-module(capwap_wtp_reg).

-behaviour(regine_server).

%% API
-export([start_link/0]).
-export([register/1, register_args/2, unregister/0, unregister/1,
	 lookup/1, register_sessionid/2, lookup_sessionid/2]).
-export([list_commonnames/0, get_commonname/1]).

%% regine_server callbacks
-export([init/1, handle_register/4, handle_unregister/3, handle_pid_remove/3, handle_death/3, terminate/2]).

-include_lib("stdlib/include/ms_transform.hrl").

-define(SERVER, ?MODULE).
-define(SELECT_COMMONNAMES_ADDRESS, [{{'$1','_','$2'},[{is_binary,'$1'}],[{{'$1','$2'}}]}]).
-define(SELECT_BY_PID (Pid), [{{'$1',Pid,'$2'},[],[true]}]).

-record(state, {
         }).

%%%===================================================================
%%% API
%%%===================================================================

start_link() ->
    regine_server:start_link({local, ?SERVER}, ?MODULE, []).

register(PeerId) -> register_args(PeerId, undefined).
register_args(PeerId, Args) ->
    regine_server:register(?SERVER, self(), PeerId, Args).

register_sessionid(PeerId, SessionId) ->
    regine_server:register(?SERVER, self(), {PeerId, SessionId}, undefined).

unregister() ->
    regine_server:unregister_pid(?SERVER, self()).

unregister(Key) ->
    regine_server:unregister_pid(?SERVER, self(), Key).

lookup(PeerId) ->
    case ets:lookup(?SERVER, PeerId) of
	[] -> not_found;
	[{_, Pid, _}] -> {ok, Pid}
    end.

lookup_sessionid(PeerId, SessionId) ->
    case ets:lookup(?SERVER, {PeerId, SessionId}) of
	[] -> not_found;
	[{_, Pid, _}] -> {ok, Pid}
    end.

get_commonname(GetPid) ->
    ets:select(?SERVER, ets:fun2ms(fun({PeerId, Pid, Args}) when Pid == GetPid, is_binary(PeerId) -> {PeerId, Args} end)).

list_commonnames() ->
    ets:select(?SERVER, ?SELECT_COMMONNAMES_ADDRESS).

%%%===================================================================
%%% regine_server functions
%%%===================================================================

init([]) ->
    process_flag(trap_exit, true),
    ets:new(?SERVER, [bag, protected, named_table, {keypos, 1}, {read_concurrency, true}]),
    {ok, #state{}}.

handle_register(Pid, PeerId, Args, State) ->
    ets:insert(?SERVER, {PeerId, Pid, Args}),
    {ok, [PeerId], State}.

handle_unregister(PeerId, _Args, State) ->
    Pids = ets:lookup(?SERVER, PeerId),
    ets:delete(?SERVER, PeerId),
    {Pids, State}.

handle_death(_Pid, _Reason, State) ->
    State.

handle_pid_remove(Pid, _PeerIds, State) ->
    ets:select_delete(?SERVER, ?SELECT_BY_PID(Pid)),
    State.

terminate(_Reason, _State) ->
    ok.
