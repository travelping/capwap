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

-module(capwap_http_api).

-export([start_link/0]).

-define(DEFAULT_PORT,	8000).
-define(DEFAULT_IP,     {127, 0, 0, 1}).
-define(ACCEPTORS_NUM,  100).

start_link() ->
    HttpConfig = application:get_env(capwap, http_api, []),
    Port = proplists:get_value(port, HttpConfig, ?DEFAULT_PORT),
    IP = proplists:get_value(ip, HttpConfig, ?DEFAULT_IP),
    INet = get_inet(IP),
    AcceptorsNum = proplists:get_value(acceptors_num, HttpConfig, ?ACCEPTORS_NUM),
    Dispatch = cowboy_router:compile([
		{'_', [
            {"/metrics",        capwap_http_api_handler, []},
			{"/api/v1/version", capwap_http_api_handler, []},

            {"/api/v1/wtp",                           capwap_http_api_handler, []},
            {"/api/v1/wtp/:id",                       capwap_http_api_handler, []},
            {"/api/v1/wtp/:id/update/:link/:hash",    capwap_http_api_handler, []},
            {"/api/v1/wtp/:id/set-ssid/:ssid[/:rid]", capwap_http_api_handler, []},
            {"/api/v1/wtp/:id/stop-radio/:rid",       capwap_http_api_handler, []},

            {"/api/v1/station",     capwap_http_api_handler, []},
            {"/api/v1/station/:id", capwap_http_api_handler, []},

            {"/api/v1/dp/wtp-list", capwap_http_api_handler, []},
            {"/api/v1/dp/stats",    capwap_http_api_handler, []},

            {"/api/v1/spec/ui",       capwap_swagger_ui_handler, []},
            {"/api/v1/spec/ui/[...]", cowboy_static, {priv_dir, capwap, "static"}}
		]}
	]),
    TransOpts = [{port, Port}, {ip, IP}, INet, {num_acceptors, AcceptorsNum}],
    ProtoOpts = #{env => #{dispatch => Dispatch}},
    cowboy:start_clear(capwap_http_api, TransOpts, ProtoOpts).

get_inet({_, _, _, _}) ->
    inet;
get_inet({_, _, _, _, _, _, _, _}) ->
    inet6.

