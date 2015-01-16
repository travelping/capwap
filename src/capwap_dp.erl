-module(capwap_dp).

-behavior(gen_server).

%% API
-export([start_link/0]).

%% C-Node wrapper
-export([bind/1, clear/0, get_stats/0]).
-export([add_wtp/2, del_wtp/1, get_wtp/1, list_wtp/0]).
-export([attach_station/2, detach_station/1]).
-export([sendto/2]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

%% dev API
-export([run/1]).

-include("include/capwap_packet.hrl").

-record(state, {tref, timeout}).

-define(SERVER, ?MODULE).

%%===================================================================
%% API
%%===================================================================
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).


%%===================================================================
%% C-Node API Wrapper
%%===================================================================


bind(Owner) ->
    call({bind, Owner}).

clear() ->
    call({clear}).

add_wtp(WTP, MTU) ->
    call({add_wtp, WTP, MTU}).

del_wtp(WTP) ->
    call({del_wtp, WTP}).

get_wtp(WTP) ->
    call({get_wtp, WTP}).

list_wtp() ->
    call({list_wtp}).

attach_station(WTP, STA) ->
    call({attach_station, WTP, STA}).

detach_station(STA) ->
    call({detach_station, STA}).

sendto(WTP, Msg) when is_binary(Msg) ->
    call({sendto, WTP, Msg}).

get_stats() ->
    call({get_stats}).

call(Args) ->
    call(Args, infinity).

call(Args, Timeout) ->
    Node = get_node(),
    gen_server:call({capwap, Node}, Args, Timeout).

%%===================================================================
%% gen_server callbacks
%%===================================================================
init([]) ->
    State = connect(#state{tref = undefined, timeout = 10}),
    {ok, State}.

handle_call(_Request, _From, State) ->
    {reply, ok, State}.

handle_cast(_Request, State) ->
    {noreply, State}.

handle_info({nodedown, Node}, State0) ->
    lager:warning("node down: ~p", [Node]),

    State1 = handle_nodedown(State0),
    State2 = start_nodedown_timeout(State1),
    {noreply, State2};

handle_info(reconnect, State0) ->
    lager:warning("trying to reconnect"),
    State1 = connect(State0#state{tref = undefined}),
    {noreply, State1};

handle_info({packet_in,tap, Packet}, State) ->
    lager:debug("TAP: ~p", [Packet]),
    <<MAC:6/bytes, _/binary>> = Packet,
    case flower_mac_learning:is_broadcast(MAC) of
	true ->
	    lager:warning("need to handle broadcast to ~s", [flower_tools:format_mac(MAC)]),
	    ok;

	_ ->
	    lager:warning("packet for invalid STA ~s", [flower_tools:format_mac(MAC)]),
	    ok
    end,
    {noreply, State};

handle_info({capwap_in, WTPDataChannelAddress, Msg}, State) ->
    lager:warning("CAPWAP from ~p: ~p", [WTPDataChannelAddress, Msg]),
    case capwap_ac:handle_data(self(), none, WTPDataChannelAddress, Msg) of
	{reply, Reply} ->
	    %% send Reply to WTP
	    lager:debug("sendto(~p, ~p)", [WTPDataChannelAddress, Reply]),
	    sendto(WTPDataChannelAddress, Reply),
	    ok;

	{add_flow, Sw, _Owner, _WTPDataChannelAddress, RadioMAC, MAC, _MacMode, TunnelMode, Forward} ->
	    %% add STA to WTP
	    lager:debug("attach_station(~p, ~p)", [WTPDataChannelAddress, MAC]),
	    attach_station(WTPDataChannelAddress, MAC),
	    ok;

	{del_flow, _Sw, _Owner, _WTPDataChannelAddress, _RadioMAC, MAC, _MacMode, TunnelMode} ->
	    %% remove STA from WTP
	    lager:debug("detach_station(~p, ~p)", [WTPDataChannelAddress, MAC]),
	    detach_station(MAC),
	    ok;

	_Other ->
	    lager:warning("handle_info reply: ~p", [_Other]),
	    ok
    end,
    {noreply, State};

handle_info({wtp_down, WTP}, State) ->
    lager:warning("WTP DOWN: ~p", [WTP]),
    del_wtp(WTP),
    {noreply, State};

handle_info(Info, State) ->
    lager:warning("Unhandled info message: ~p", [Info]),
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

get_node() ->
    DP = application:get_env(capwap, 'capwap-dp', "capwap-dp"),
    list_to_atom(DP ++ "@" ++ net_adm:localhost()).

start_nodedown_timeout(State = #state{tref = undefined, timeout = Timeout}) ->
    NewTimeout = if Timeout < 3000 -> Timeout * 2;
		    true           -> Timeout
		 end,
    TRef = erlang:send_after(Timeout, self(), reconnect),
    State#state{tref = TRef, timeout = NewTimeout};

start_nodedown_timeout(State) ->
    State.

connect(State) ->
    Node = get_node(),
    case net_adm:ping(Node) of
	pong ->
	    lager:warning("Node ~p is up", [Node]),
	    erlang:monitor_node(Node, true),
	    clear(),
	    bind(self()),
	    State#state{timeout = 10};
	pang ->
	    lager:warning("Node ~p is down", [Node]),
	    start_nodedown_timeout(State)
    end.

handle_nodedown(State) ->
    State.

%%%===================================================================
%%% Development helper
%%%===================================================================

run(WTP) ->
    bind(self()),
    add_wtp(WTP, 1400),
    run_loop(WTP).

run_loop(WTP) ->
    receive
	{packet_in, tap, Packet} ->
	    io:format("Packet-In: ~p~n", [Packet]),
	    <<MAC:6/bytes, _/binary>> = Packet,
	    case {flower_mac_learning:eth_addr_is_reserved(MAC), flower_mac_learning:may_learn(MAC)} of
		{false, true} ->
		    io:format("install STA: ~p~n", [MAC]),
		    attach_station(WTP, MAC);

		_ ->
		    ok
	    end,
	    Data = capwap_packet:encode(data, {#capwap_header{radio_id = 1, wb_id = 2, flags = [{frame, '802.3'}]}, Packet}),
	    [sendto(WTP, X) || X <- Data],
	    ok;

	{capwap_in, WTPDataChannelAddress, Msg} ->
	    io:format("CAPWAP From ~p: ~p~n", [WTPDataChannelAddress, Msg]),
	    ok;

	Other ->
	    io:format("Other: ~p~n", [Other]),
	    ok
    end,
    run_loop(WTP).
