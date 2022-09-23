%% Copyright 2017-2019 Travelping GmbH <info@travelping.com>
%%
%% This program is free software: you can redistribute it and/or modify
%% it under the terms of the GNU Lesser General Public License as
%% published by the Free Software Foundation, either version 3 of the
%% License, or (at your option) any later version.
%%
%% This program is distributed in the hope that it will be useful,
%% but WITHOUT ANY WARRANTY; without even the implied warranty of
%% MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
%% GNU Lesser General Public License for more details.
%%
%% You should have received a copy of the GNU Lesser General Public License
%% along with this program. If not, see <http://www.gnu.org/licenses/>.

-module(capwap_loc_provider_default).

-compile({parse_transform, cut}).

-behaviour(capwap_loc_provider).

-include_lib("kernel/include/logger.hrl").

%% AAA API
-export([config_fun/1]).

%%===================================================================
%% API
%%===================================================================

config_fun(#{default_loc := L = {location, <<_/binary>>, <<_/binary>>}}) ->
  fun(_) -> ?LOG(debug, "Default provider returning: ~p", [L]), L end.