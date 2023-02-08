-module(capwap_dummy_app).

-include_lib("kernel/include/logger.hrl").

-behaviour(application).

%% Application callbacks
-export([start/2, stop/1]).

start(StartType, StartArgs) ->
    ?LOG(debug, "Starting with terms: ~p", [{StartType, StartArgs}]),
    capwap_dummy_sup:start_link(StartArgs).

stop(State) ->
    ?LOG(debug, "Stopping: ~p", [State]).
