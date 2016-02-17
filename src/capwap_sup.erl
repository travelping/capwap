-module(capwap_sup).

-behaviour(supervisor).

%% API
-export([start_link/0, start_listener/2, start_tracer/1]).

%% Supervisor callbacks
-export([init/1]).

%% Helper macro for declaring children of supervisor
-define(CHILD(I, Type, Args), {I, {I, start_link, Args}, permanent, 5000, Type, [I]}).

%% ===================================================================
%% API functions
%% ===================================================================

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

%% start a listener process for the given transport module with arguments
start_listener(TransportMod, Arguments) ->
    Spec = TransportMod:listener_spec(Arguments),
    supervisor:start_child(?MODULE, Spec).

start_tracer(File) ->
    Spec = ?CHILD(capwap_trace, worker, []),
    case supervisor:start_child(?MODULE, Spec) of
	{ok, _} ->
	    capwap_trace:add_handler(File);
	Other ->
	    Other
    end.

%% ===================================================================
%% Supervisor callbacks
%% ===================================================================

init([]) ->
    {ok, {{one_for_one, 30, 60}, [
				  ?CHILD(capwap_wtp_reg, worker, []),
				  ?CHILD(capwap_ac_sup, supervisor, []),
				  ?CHILD(capwap_station_reg, worker, []),
				  ?CHILD(capwap_station_sup, supervisor, []),
				  ?CHILD(capwap_dp, worker, [])
                                ]} }.
