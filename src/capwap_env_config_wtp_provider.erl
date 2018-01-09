%% Copyright (C) 2013-2018, Travelping GmbH <info@travelping.com>

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

-module(capwap_env_config_wtp_provider).
-behaviour(capwap_config_wtp_provider).

-export([
   get_config/2
]).

get_config(CN, _Opts) ->
    Settings = capwap_config:get(wtp, [CN], []),
    {ok, lists:map(fun transform/1, Settings)}.

transform({radio, RList}) ->
    NewR = [ [{radio_id, RadioId} | Property] || {RadioId, Property} <- RList],
    {radio, NewR};
transform(Other) -> Other.

