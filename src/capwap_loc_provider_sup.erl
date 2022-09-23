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

-module(capwap_loc_provider_sup).

-behaviour(supervisor).

%% API
-export([start_link/1]).

%% Supervisor callbacks
-export([init/1]).

%% Helper macro for declaring children of supervisor
-define(CHILD(I, Type, Args), {I, {I, start_link, Args}, permanent, 5000, Type, [I]}).

-include_lib("kernel/include/logger.hrl").

%% ===================================================================
%% API functions
%% ===================================================================

start_link(Config) ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, [Config]).

%% ===================================================================
%% Supervisor callbacks
%% ===================================================================

%%===================================================================
%% API
%%===================================================================

validate_option(handler, Value) ->
    Value;
validate_option(service, Value) ->
    Value;
validate_option(uri, Value) when is_binary(Value) ->
    Value;
validate_option(uri, Value) when is_list(Value) ->
    Value;
validate_option(default_location, Value) when is_binary(Value) ->
    Value;
validate_option(timeout, Value) when is_integer(Value) ->
    Value;
validate_option(refresh, Value) when is_integer(Value) ->
    Value;
validate_option(token, Value) when is_binary(Value) ->
    Value;
validate_option(token, Value) when is_list(Value) ->
    Value;
validate_option(keys, Value = #{lat_key := _, long_key := _}) ->
    Value;
validate_option(keys, Value) when is_list(Value) ->
    validate_option(keys, maps:from_list(Value));
validate_option(Opt, Value) ->
    erlang:error(badarg, [Opt, Value]).




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
    ]} }.
