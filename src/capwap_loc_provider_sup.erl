%% Copyright (C) 2013-2023, Travelping GmbH <info@travelping.com>

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

-module(capwap_loc_provider_sup).

-behaviour(supervisor).

%% API
-export([start_link/1, location_children/0]).

%% Supervisor callbacks
-export([init/1]).

%% Helper macro for declaring children of supervisor
-define(CHILD(I, Type, Args), {I, {I, start_link, Args}, permanent, 5000, Type, [I]}).

-include_lib("kernel/include/logger.hrl").

%% API functions

start_link(Config) ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, [Config]).

location_children() ->
    case application:get_env(location_provider) of
	undefined ->
	    ?LOG(warning, "Location provider disabled, no config found"),
	    [];
	{ok, LocProviderConfig} ->
	    ?LOG(info, "Location provider enabled"),
	    [?CHILD(capwap_loc_provider_sup, supervisor, [LocProviderConfig])]
    end.

%% Supervisor callbacks

init([Config]) ->
    ?LOG(debug, "Init'ed supervisor with config: ~p", [Config]),
    ProviderServer = #{id => capwap_loc_provider,
		       start => {capwap_loc_provider, start_link, [Config]},
		       restart => permanent,
		       significant => false,
		       shutdown => 500,
		       type => worker},

    {ok, {#{strategy => one_for_one, intensity => 30, period => 60}, [
	    ProviderServer
    ]}}.
