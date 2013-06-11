-module(capwap_sup).

-behaviour(supervisor).

%% API
-export([start_link/0, start_listener/2]).

%% Supervisor callbacks
-export([init/1]).

%% Helper macro for declaring children of supervisor
-define(CHILD(I, Type), {I, {I, start_link, []}, permanent, 5000, Type, [I]}).

%% ===================================================================
%% API functions
%% ===================================================================

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

%% start a listener process for the given transport module with arguments
start_listener(TransportMod, Arguments) ->
    Spec = TransportMod:listener_spec(Arguments),
    supervisor:start_child(?MODULE, Spec).

%% ===================================================================
%% Supervisor callbacks
%% ===================================================================

init([]) ->
    {ok, {{one_for_one, 5, 10}, [
                                 ?CHILD(capwap_wtp_reg, worker),
                                 ?CHILD(capwap_ac_sup, supervisor),
                                 ?CHILD(capwap_station_reg, worker),
                                 ?CHILD(capwap_station_sup, supervisor)
                                ]} }.
