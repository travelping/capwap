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

-define('id-kp-capwapAC', {1,3,6,1,5,5,7,3,18}).
-define('id-kp-capwapWTP', {1,3,6,1,5,5,7,3,19}).

-record(capwap_header, {
	  radio_id,
	  wb_id,
	  flags              = [],
	  radio_mac          = undefined,
	  wireless_spec_info = undefined
}).

-record(fragment, {type, keepalive, fragmentid, fstart, fend, last, header, payload}).

-include("capwap_packet_gen.hrl").
