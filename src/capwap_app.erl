%% Copyright (C) 2013-2023, Travelping GmbH <info@travelping.com>

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

-module(capwap_app).

-behaviour(application).

%% Application callbacks
-export([start/2, stop/1, config_change/3]).

%% ===================================================================
%% Application callbacks
%% ===================================================================

start(_StartType, _StartArgs) ->
    ok = capwap_config:validate(),

    lists:foreach(
      fun(MetricName) ->
              exometer:new(MetricName, counter, [])
      end, [
            [capwap, ac, wtp_count],
            [capwap, ac, station_count],
            [capwap, ac, ssl_expired_certs_count],
            [capwap, ac, error_wtp_http_config_count]
           ]),

    case capwap_sup:start_link() of
	{ok, _} = Ret ->
	    capwap_trace:start_tracer(),
	    Opts = case application:get_env(server_ip) of
		       {ok, IP} -> [{ip, IP}];
		       _        -> []
		   end,
	    SOpts = case application:get_env(server_socket_opts) of
			{ok, SOpts0} when is_list(SOpts0) ->
			    SOpts0;
		       _ -> []
		   end,
	    {ok, _} = capwap_sup:start_listener(capwap_udp, {5246, Opts ++ SOpts}),
	    Ret;
	Error ->
	    Error
    end.

stop(_State) ->
    ok.

config_change(_Changed, _New, _Removed) ->
    capwap_config:validate().
