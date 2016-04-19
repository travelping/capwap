-module(capwap_app).

-behaviour(application).

%% Application callbacks
-export([start/2, stop/1, config_change/3]).

%% ===================================================================
%% Application callbacks
%% ===================================================================

start(_StartType, _StartArgs) ->
    ok = capwap_config:validate(),

    exometer:new([capwap, ac, wtp_count], counter, []),
    exometer:new([capwap, ac, station_count], counter, []),

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
