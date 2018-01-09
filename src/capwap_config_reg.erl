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

-module(capwap_config_reg).

-behaviour(gen_server).

%% API
-export([
         start_link/0,
         common_config/1,
         radio_config/3
        ]).

%% gen_server callbacks
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).

-define(SERVER, ?MODULE).

-record(state, {
    configs  = #{} :: #{},
    monitors = #{} :: #{}
}).

%%%===================================================================
%%% API
%%%===================================================================

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

common_config(CN) ->
    io:format("Get common config~n~n"),
    gen_server:call(?SERVER, {common_config, CN}).

radio_config(CN, RadioId, RadioType) ->
    io:format("Get radio config ~p~n~n", [RadioId]),
    gen_server:call(?SERVER, {radio_config, CN, RadioId, RadioType}).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([]) ->
    {ok, #state{}}.

handle_call({common_config, CN}, {From, _},
            State = #state{configs = Configs, monitors = Mons}) ->
    case maps:find(CN, Configs) of
        error ->
            Ref = erlang:monitor(process, From),
            Config = capwap_config:wtp_static_config(CN),
            io:format("Get config ~p~n", [Config]),
            ResConfig = capwap_config:wtp_config(Config),
            NewState = State#state{
                configs = Configs#{CN => Config},
                monitors = Mons#{Ref => CN}
            },
            {reply, ResConfig, NewState};
        {ok, Config} ->
            ResConfig = capwap_config:wtp_config(Config),
            {reply, ResConfig, State}
    end;
handle_call({radio_config, CN, RadioId, RadioType}, {From, _},
            State = #state{configs = Configs, monitors = Mons}) ->
    case maps:find(CN, Configs) of
        error ->
            Ref = erlang:monitor(process, From),
            Config = capwap_config:wtp_static_config(CN),
            Res = capwap_config:wtp_set_radio_infos(CN, RadioId, RadioType, Config),
            NewState = State#state{
                configs = Configs#{CN => Config},
                monitors = Mons#{Ref => CN}
            },
            {reply, Res, NewState};
        {ok, Config} ->
            Res = capwap_config:wtp_set_radio_infos(CN, RadioId, RadioType, Config),
            {reply, Res, State}
    end;

handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({'DOWN', Ref, process, _, _},
            State = #state{configs = Configs, monitors = Mons}) ->
    {CN, NewMons} = maps:take(Ref, Mons),
    {noreply, State#state{configs = maps:remove(CN, Configs),
                          monitors = NewMons}};
handle_info(_, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.
