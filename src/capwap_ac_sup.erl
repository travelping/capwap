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

-module(capwap_ac_sup).

-behaviour(supervisor).

%% API
-export([start_link/0, new_wtp/1]).

%% Supervisor callbacks
-export([init/1]).

-ifdef(TEST).
-export([clear/0]).
-endif.

-include_lib("kernel/include/logger.hrl").

-define(SERVER, ?MODULE).

%%%===================================================================
%%% API functions
%%%===================================================================

start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

new_wtp(Peer) ->
    ?LOG(debug, "Stating new WTP: ~p", [Peer]),
    R = supervisor:start_child(?SERVER, [Peer]),
    ?LOG(debug, "Result: ~p", [R]),
    R.

-ifdef(TEST).
clear() ->
    [exit(Pid, shutdown) || {_, Pid, _, _} <- supervisor:which_children(?SERVER)].
-endif.

%%%===================================================================
%%% Supervisor callbacks
%%%===================================================================

init([]) ->
    {ok, {{simple_one_for_one, 1000, 1000},
          [{capwap_ac, {capwap_ac, start_link, []}, temporary, 1000, worker, [capwap_ac]}]}}.
