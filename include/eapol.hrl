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

-define(LLC_DSAP_SNAP, 16#aa).
-define(LLC_SSAP_SNAP, 16#aa).
-define(LLC_CNTL_SNAP, 3).
-define(SNAP_ORG_ETHERNET, 0,0,0).

-define(ETH_P_PAE, 16#888e).          %% Port Access Entity (IEEE 802.1X)

-record(ccmp, {rsn,
	       akm_algo,
	       mic_algo,
	       group_mgmt_cipher_suite,
	       replay_counter,
	       master_session_key,
	       pre_master_key,
	       nonce,
	       kck,
	       kek,
	       tk}).
