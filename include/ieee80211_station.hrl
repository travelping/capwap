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

-record(sta_cap, {
                  aid = 16#C001      :: integer(),
                  wmm = false        :: boolean(),
                  sgi_20mhz = 0      :: boolean(),
                  sgi_40mhz = 0      :: boolean(),
                  smps = disabled    :: atom(),
                  back_delay = false :: boolean(),
                  ampdu_density = 0  :: integer(),
                  ampdu_factor = 0   :: integer(),
                  rx_mask = <<0,0,0,0,0,0,0,0,0,0>> :: binary(),
                  rx_highest = 0     :: integer(),

                  last_rsne          :: undefined | binary(),
                  rsn                :: undefiend | #wtp_wlan_rsn{}
                 }).

-record(station_config, {
                         data_path,
                         wtp_data_channel_address,
                         wtp_id,
                         wtp_session_id,
                         mac_mode,
                         tunnel_mode,

                         bss,
                         bss_ies,
                         wpa_config,
                         gtk,
                         igtk
                        }).
