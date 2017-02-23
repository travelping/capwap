%% Copyright (C) 2017, Travelping GmbH <info@travelping.com>

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

-define(CAPWAP_BINDING_802_11, 1).

-record(wpa_config, {
	  ssid,
	  privacy,
	  rsn,
	  secret,
	  peer_rekey,
	  group_rekey,
	  strict_group_rekey
	 }).

-record(wlan, {
	  wlan_identifier,

	  bss,
	  ssid,
	  suppress_ssid,
	  mode,
	  mac_mode,
	  tunnel_mode,
	  rate_set,
	  privacy,
	  wpa_config,
	  information_elements,

	  state,

	  group_tsc,
	  gtk,
	  igtk,

	  group_rekey_state,
	  group_rekey_timer
         }).

-record(ieee80211_key, {cipher, index, key}).
