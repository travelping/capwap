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
    DefaultEnv = capwap_config:get(wtp, [defaults], []),
    Defaults = [
        {psm_idle_timeout,           30},
        {psm_busy_timeout,           300},
        {max_stations,               100},
        {echo_request_interval,      60},
        {discovery_interval,         20},
        {idle_timeout,               300},
        {data_channel_dead_interval, 70},
        {ac_join_timeout,            70},
        {admin_pw,                   undefined},
        {wlan_hold_time,             15},
        {broken_add_wlan_workaround, false},
        {radio, []} ],
    DefaultCommon = capwap_config:merge(DefaultEnv, Defaults),
    Settings1 = lists:map(fun transform/1, Settings),
    WTP = capwap_config:merge(Settings1, DefaultCommon),
    {ok, WTP}.

transform({radio, RList}) ->
    NewR = [ [{radio_id, RadioId} | Property] || {RadioId, Property} <- RList],
    {radio, NewR};
transform(Other) -> Other.
