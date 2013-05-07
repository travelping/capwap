-module(capwap_udp).

-behaviour(gen_server).

%% API
-export([start_link/2]).

%% Transport Modules Callbacks
-export([listener_spec/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-define(SERVER, ?MODULE).
-define(SOCKTAB, ?MODULE).

-record(state, {socket}).

%%%===================================================================
%%% API
%%%===================================================================

start_link(Port, Options) ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [Port, Options], [{debug, [trace]}]).

%%%===================================================================
%%% Transport Module Callbacks
%%%===================================================================

%% return a supervisor spec to start a listener
listener_spec({Port, Options}) ->
    {{?MODULE, f, Port},
     {?MODULE, start_link, [Port, Options]},
     permanent, 5000, worker, [?MODULE]}.

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([Port, Options]) ->
    case gen_udp:open(Port, Options ++ [binary, {reuseaddr, true}]) of
	{ok, Socket} ->
	    inet:setopts(Socket, [{active, once}]),
	    {ok, #state{socket = Socket}};
	Error ->
	    {stop, Error}
    end.

handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({udp, Socket, IP, InPortNo, Packet}, State = #state{socket = Socket}) ->
    case capwap_wtp_reg:lookup({IP, InPortNo}) of
	{ok, PeerPid} ->
	    io:format("PeerPid: ~p~n", [PeerPid]),
	    capwap_ac:packet_in(PeerPid, Packet);
	not_found ->
	    capwap_ac_sup:new_wtp(Socket, IP, InPortNo, Packet)
    end,
    inet:setopts(Socket, [{active, once}]),
    {noreply, State};

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
