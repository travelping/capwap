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

-module(capwap_sup).

-behaviour(supervisor).

%% API
-export([start_link/0, start_listener/2, start_tracer/1]).

%% Supervisor callbacks
-export([init/1]).

%% Helper macro for declaring children of supervisor
-define(CHILD(I, Type, Args), {I, {I, start_link, Args}, permanent, 5000, Type, [I]}).

%% ===================================================================
%% API functions
%% ===================================================================

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

%% start a listener process for the given transport module with arguments
start_listener(TransportMod, Arguments) ->
    Spec = TransportMod:listener_spec(Arguments),
    supervisor:start_child(?MODULE, Spec).

start_tracer(File) ->
    Spec = ?CHILD(capwap_trace, worker, []),
    case supervisor:start_child(?MODULE, Spec) of
	{ok, _} ->
	    capwap_trace:add_handler(File);
	Other ->
	    Other
    end.

%% ===================================================================
%% Supervisor callbacks
%% ===================================================================

init([]) ->
    {ok, {{one_for_one, 30, 60}, [
				  ?CHILD(capwap_wtp_reg, worker, []),
				  ?CHILD(capwap_ac_sup, supervisor, []),
				  ?CHILD(capwap_station_reg, worker, []),
				  ?CHILD(capwap_station_sup, supervisor, []),
				  ?CHILD(capwap_dp, worker, []),
				  ?CHILD(capwap_dhcp_relay, worker, []),
                  ?CHILD(capwap_http_api, supervisor, [])
    ]} }.
