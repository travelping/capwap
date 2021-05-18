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

-module(capwap_app).

-behaviour(application).

%% Application callbacks
-export([start/2, stop/1, config_change/3]).

%% ===================================================================
%% Application callbacks
%% ===================================================================

start(_StartType, _StartArgs) ->
    ok = capwap_config:validate(),
    declare_metrics(),

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

declare_metrics() ->
    prometheus_gauge:declare([{name, capwap_ac_wtps},
			      {help, "Total number of connected WTPs"}]),
    prometheus_counter:declare([{name, capwap_ac_ssl_expired_certs_total},
				{help, "Total number of TLS expired certificate errors"}]),
    prometheus_gauge:declare([{name, capwap_wtp_stations}, {labels, [wtp]},
			      {help, "Total number of connected Stations"}]),

    %% DP counters
    prometheus_counter:declare([{name, capwap_dp_in_packets_total}, {labels, [thread]},
				{help, "Total number of in packets"}]),
    prometheus_counter:declare([{name, capwap_dp_out_packets_total}, {labels, [thread]},
				{help, "Total number of out packets"}]),
    prometheus_counter:declare([{name, capwap_dp_in_octets_total}, {labels, [thread]},
				{help, "Total number of in octets"}]),
    prometheus_counter:declare([{name, capwap_dp_out_octets_total}, {labels, [thread]},
				{help, "Total number of out octets"}]),
    prometheus_counter:declare([{name, capwap_dp_received_fragments_total}, {labels, [thread]},
				{help, "Total number of received fragments"}]),
    prometheus_counter:declare([{name, capwap_dp_send_fragments_total}, {labels, [thread]},
				{help, "Total number of send fragments"}]),
    prometheus_counter:declare([{name, capwap_dp_error_invalid_stations_total}, {labels, [thread]},
				{help, "Total number of invalid station errors"}]),
    prometheus_counter:declare([{name, capwap_dp_error_fragment_invalid_total}, {labels, [thread]},
				{help, "Total number of invalid fragments error"}]),
    prometheus_counter:declare([{name, capwap_dp_error_fragment_too_old_total}, {labels, [thread]},
				{help, "Total number of fragment tool old errors"}]),
    prometheus_counter:declare([{name, capwap_dp_error_invalid_wtp}, {labels, [thread]},
				{help, "Total number of invalid WTP errors"}]),
    prometheus_counter:declare([{name, capwap_dp_error_header_length_invalid}, {labels, [thread]},
				{help, "Total number of header length invalid errors"}]),
    prometheus_counter:declare([{name, capwap_dp_error_too_short}, {labels, [thread]},
				{help, "Total number of too short errors"}]),
    prometheus_counter:declare([{name, capwap_dp_rate_limit_unknown_wtp}, {labels, [thread]},
				{help, "Total number of rate limites unknown WTPs"}]),

    %% WTP counters
    prometheus_counter:declare([{name, capwap_wtp_in_packets_total}, {labels, [thread]},
				{help, "Total number of in packets"}]),
    prometheus_counter:declare([{name, capwap_wtp_out_packets_total}, {labels, [thread]},
				{help, "Total number of out packets"}]),
    prometheus_counter:declare([{name, capwap_wtp_in_octets_total}, {labels, [thread]},
				{help, "Total number of in octets"}]),
    prometheus_counter:declare([{name, capwap_wtp_out_octets_total}, {labels, [thread]},
				{help, "Total number of out octets"}]),
    prometheus_counter:declare([{name, capwap_wtp_received_fragments_total}, {labels, [thread]},
				{help, "Total number of received fragments"}]),
    prometheus_counter:declare([{name, capwap_wtp_send_fragments_total}, {labels, [thread]},
				{help, "Total number of send fragments"}]),
    prometheus_counter:declare([{name, capwap_wtp_error_invalid_stations_total}, {labels, [thread]},
				{help, "Total number of invalid station errors"}]),
    prometheus_counter:declare([{name, capwap_wtp_error_fragment_invalid_total}, {labels, [thread]},
				{help, "Total number of invalid fragments error"}]),
    prometheus_counter:declare([{name, capwap_wtp_error_fragment_too_old_total}, {labels, [thread]},
				{help, "Total number of fragment tool old errors"}]),

    ok.
