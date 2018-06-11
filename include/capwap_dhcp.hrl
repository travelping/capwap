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

-record (dhcp_packet, {
  msg_type,
  requested_ip = {0, 0, 0, 0},
  op = 0,
  htype = 0,
  hlen = 0,
  hops = 0,
  xid = 0,
  secs = 0,
  flags = 0,
  %% Client address
  ciaddr = {0, 0, 0, 0},
  %% Your (client) address
  yiaddr = {0, 0, 0, 0},
  %% Next server address
  siaddr = {0, 0, 0, 0},
  %% Relay
  giaddr = {0, 0, 0, 0},
  %% Client mac address
  chaddr = {0, 0, 0, 0, 0, 0},
  %% Server hostname
  sname = 0,
  %% Boot file name
  file = 0,
  options = []}).
