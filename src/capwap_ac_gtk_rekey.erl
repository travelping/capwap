-module(capwap_ac_gtk_rekey).

-behaviour(gen_server).

%% API
-export([start_link/3, gtk_rekey_done/2]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-define(SERVER, ?MODULE).

-record(state, {acref, stations, timer}).

%%%===================================================================
%%% API
%%%===================================================================

start_link(ACRef, GTK, Stations) ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [ACRef, GTK, Stations], []).

gtk_rekey_done(Controller, Station) ->
    gen_server:cast(Controller, {gtk_rekey_done, Station}).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([ACRef, GTK, Stations]) ->
    lists:foreach(fun(Sta) ->
			  monitor(process, Sta),
			  ieee80211_station:start_gtk_rekey(Sta, self(), GTK)
		  end, Stations),
    erlang:send_after(5000, self(), group_rekey_timeout),
    {ok, #state{acref = ACRef, stations = Stations}}.

handle_call(_Request, _From, State) ->
    {reply, ok, State}.

handle_cast({gtk_rekey_done, Sta}, State) ->
    lager:debug("Group Rekey Station DONE: ~p", [Sta]),
    handle_sta_done(Sta, State);

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({'DOWN', _MonitorRef, process, Sta, _Info}, State) ->
    lager:debug("Group Rekey Station Down: ~p", [Sta]),
    handle_sta_done(Sta, State);

handle_info(group_rekey_timeout, State) ->
    lager:debug("Group Rekey Timeout"),
    gtk_rekey_done(State);

handle_info(Info, State) ->
    lager:debug("GTP ReKey handler, unexpected Info: ~p", [Info]),
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
gtk_rekey_done(#state{acref = ACRef} = State) ->
    capwap_ac:gtk_rekey_done(ACRef),
    {stop, normal, State}.

handle_sta_done(Sta, #state{stations = Stations0} = State) ->
    case lists:delete(Sta, Stations0) of
	[] ->
	    gtk_rekey_done(State);
	Stations ->
	    {noreply, State#state{stations = Stations}}
    end.
