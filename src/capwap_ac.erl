-module(capwap_ac).

-behaviour(gen_fsm).

%% API
-export([start_link/1, accept/3]).

%% gen_fsm callbacks
-export([init/1, listen/2, idle/2, join/2, configure/2, run/2,
	 handle_event/3,
	 handle_sync_event/4, handle_info/3, terminate/3, code_change/4]).


-export([handle_packet/3]).

-include("capwap_debug.hrl").
-include("capwap_packet.hrl").

-define(SERVER, ?MODULE).

%% TODO: convert constants into configuration values
-define(IDLE_TIMEOUT, 30 * 1000).
-define(RetransmitInterval, 3 * 1000).
-define(MaxRetransmit, 5).

-record(state, {
	  peer,
	  socket,
	  last_response,
	  last_request,
	  retransmit_timer,
	  retransmit_counter,
	  seqno = 0}).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Creates a gen_fsm process which calls Module:init/1 to
%% initialize. To ensure a synchronized start-up procedure, this
%% function does not return until Module:init/1 has returned.
%%
%% @spec start_link() -> {ok, Pid} | ignore | {error, Error}
%% @end
%%--------------------------------------------------------------------
start_link(Peer) ->
    gen_fsm:start_link({local, ?SERVER}, ?MODULE, [Peer], [{debug, [trace]}]).

handle_packet(_Address, _Port, Packet) ->
    try	capwap_packet:decode(control, Packet) of
	{Header, {discovery_request, 1, Seq, Elements}} ->
	    Answer = answer_discover(Seq, Elements, Header),
	    {reply, Answer};
	{_Header, {join_request, 1, _Seq, _Elements}} ->
	    accept;
	_ ->
	    {error, not_capwap}
    catch
	_:_ ->
	    {error, not_capwap}
    end.

accept(WTP, Type, Socket) ->
    gen_fsm:send_event(WTP, {accept, Type, Socket}).

%%%===================================================================
%%% gen_fsm callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Whenever a gen_fsm is started using gen_fsm:start/[3,4] or
%% gen_fsm:start_link/[3,4], this function is called by the new
%% process to initialize.
%%
%% @spec init(Args) -> {ok, StateName, State} |
%%                     {ok, StateName, State, Timeout} |
%%                     ignore |
%%                     {stop, StopReason}
%% @end
%%--------------------------------------------------------------------
init([Peer]) ->
    capwap_wtp_reg:register(Peer),
    {ok, listen, #state{peer = Peer}, 5000}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% There should be one instance of this function for each possible
%% state name. Whenever a gen_fsm receives an event sent using
%% gen_fsm:send_event/2, the instance of this function with the same
%% name as the current state name StateName is called to handle
%% the event. It is also called if a timeout occurs.
%%
%% @spec state_name(Event, State) ->
%%                   {next_state, NextStateName, NextState} |
%%                   {next_state, NextStateName, NextState, Timeout} |
%%                   {stop, Reason, NewState}
%% @end
%%--------------------------------------------------------------------
listen({accept, udp, Socket}, State) ->
    capwap_udp:setopts(Socket, [{active, true}, {mode, binary}]),
    ?DEBUG(?GREEN "udp_accept: ~p~n", [Socket]),
    {next_state, idle, State#state{socket = {udp, Socket}}};

listen({accept, dtls, Socket}, State) ->
    ?DEBUG(?GREEN "ssl_accept on: ~p~n", [Socket]),
    case ssl:ssl_accept(Socket, mk_ssl_opts()) of
	{ok, SslSocket} ->
	    ?DEBUG(?GREEN "ssl_accept: ~p~n", [SslSocket]),
	    ssl:setopts(SslSocket, [{active, true}, {mode, binary}]),
	    {next_state, idle, State#state{socket = {dtls, SslSocket}}};
	Other ->
	    ?DEBUG(?RED "ssl_accept failed: ~p~n", [Other]),
	    {stop, normal, State}
    end;

listen(timeout, State) ->
    {stop, normal, State}.

idle(timeout, State) ->
    {stop, normal, State};

idle({discovery_request, Seq, _Elements, #capwap_header{
				radio_id = RadioId, wb_id = WBID, flags = Flags}},
     State) ->
    RespElements = ac_info(),
    Header = #capwap_header{radio_id = RadioId, wb_id = WBID, flags = Flags},
    State1 = send_response(Header, discovery_response, Seq, RespElements, State),
    {next_state, idle, State1, ?IDLE_TIMEOUT};

idle({join_request, Seq, _Elements, #capwap_header{
			   radio_id = RadioId, wb_id = WBID, flags = Flags}},
     State) ->
    RespElements = ac_info() ++ [#result_code{result_code = 0}],
    Header = #capwap_header{radio_id = RadioId, wb_id = WBID, flags = Flags},
    State1 = send_response(Header, join_response, Seq, RespElements, State),
    {next_state, join, State1, ?IDLE_TIMEOUT};

idle({Msg, Seq, Elements, Header}, State) ->
    io:format("in idle got: ~p~n", [{Msg, Seq, Elements, Header}]),
    {next_state, idle, State, ?IDLE_TIMEOUT}.

join({configuration_status_request, Seq, _Elements, #capwap_header{
					   radio_id = RadioId, wb_id = WBID, flags = Flags}},
     State) ->
    RespElements = [%%#ac_ipv4_list{ip_address = [<<0,0,0,0>>]},
		    #timers{discovery = 20,
			    echo_request = 2},
		    #decryption_error_report_period{
			     radio_id = RadioId,
			     report_interval = 15},
		    #idle_timeout{timeout = 10}],
    Header = #capwap_header{radio_id = RadioId, wb_id = WBID, flags = Flags},
    State1 = send_response(Header, configuration_status_response, Seq, RespElements, State),
    {next_state, configure, State1, ?IDLE_TIMEOUT};

join({Msg, Seq, Elements, Header}, State) ->
    io:format("in join got: ~p~n", [{Msg, Seq, Elements, Header}]),
    {next_state, join, State, ?IDLE_TIMEOUT}.

configure({change_state_event_request, Seq, _Elements, #capwap_header{
					      radio_id = RadioId, wb_id = WBID, flags = Flags}},
	  State) ->
    Header = #capwap_header{radio_id = RadioId, wb_id = WBID, flags = Flags},
    State1 = send_response(Header, change_state_event_response, Seq, [], State),

    ReqElements = [#ieee_802_11_add_wlan{
		      radio_id      = RadioId,
		      wlan_id       = 1,
		      capability    = [ess, short_slot_time],
		      auth_type     = open_system,
		      mac_mode      = split_mac,
		      tunnel_mode   = '802_11_tunnel',
		      suppress_ssid = 1,
		      ssid          = <<"CAPWAP Test">>
		     }],
    Header1 = #capwap_header{radio_id = RadioId, wb_id = WBID, flags = Flags},
    State2 = send_request(Header1, ieee_802_11_wlan_configuration_request, ReqElements, State1),

    {next_state, run, State2, ?IDLE_TIMEOUT};

configure({Msg, Seq, Elements, Header}, State) ->
    io:format("in configure got: ~p~n", [{Msg, Seq, Elements, Header}]),
    {next_state, configure, State, ?IDLE_TIMEOUT}.

run(timeout, State) ->
    io:format("IdleTimeout in Run~n"),
    Header = #capwap_header{radio_id = 0, wb_id = 1, flags = []},
    Elements = [],
    State1 = send_request(Header, echo_request, Elements, State),
    {next_state, run, State1, ?IDLE_TIMEOUT};

run({echo_request, Seq, Elements, #capwap_header{
			  radio_id = RadioId, wb_id = WBID, flags = Flags}},
    State) ->
    io:format("EchoReq in Run got: ~p~n", [{Seq, Elements}]),
    Header = #capwap_header{radio_id = RadioId, wb_id = WBID, flags = Flags},
    State1 = send_response(Header, echo_response, Seq, Elements, State),
    {next_state, run, State1, ?IDLE_TIMEOUT};

run({Msg, Seq, Elements, Header}, State) ->
    io:format("in run got: ~p~n", [{Msg, Seq, Elements, Header}]),
    {next_state, run, State, ?IDLE_TIMEOUT}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% There should be one instance of this function for each possible
%% state name. Whenever a gen_fsm receives an event sent using
%% gen_fsm:sync_send_event/[2,3], the instance of this function with
%% the same name as the current state name StateName is called to
%% handle the event.
%%
%% @spec state_name(Event, From, State) ->
%%                   {next_state, NextStateName, NextState} |
%%                   {next_state, NextStateName, NextState, Timeout} |
%%                   {reply, Reply, NextStateName, NextState} |
%%                   {reply, Reply, NextStateName, NextState, Timeout} |
%%                   {stop, Reason, NewState} |
%%                   {stop, Reason, Reply, NewState}
%% @end
%%--------------------------------------------------------------------
%% start(_Event, _From, State) ->
%%     Reply = ok,
%%     {reply, Reply, state_name, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Whenever a gen_fsm receives an event sent using
%% gen_fsm:send_all_state_event/2, this function is called to handle
%% the event.
%%
%% @spec handle_event(Event, StateName, State) ->
%%                   {next_state, NextStateName, NextState} |
%%                   {next_state, NextStateName, NextState, Timeout} |
%%                   {stop, Reason, NewState}
%% @end
%%--------------------------------------------------------------------
handle_event(_Event, StateName, State) ->
    {next_state, StateName, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Whenever a gen_fsm receives an event sent using
%% gen_fsm:sync_send_all_state_event/[2,3], this function is called
%% to handle the event.
%%
%% @spec handle_sync_event(Event, From, StateName, State) ->
%%                   {next_state, NextStateName, NextState} |
%%                   {next_state, NextStateName, NextState, Timeout} |
%%                   {reply, Reply, NextStateName, NextState} |
%%                   {reply, Reply, NextStateName, NextState, Timeout} |
%%                   {stop, Reason, NewState} |
%%                   {stop, Reason, Reply, NewState}
%% @end
%%--------------------------------------------------------------------
handle_sync_event(_Event, _From, StateName, State) ->
    Reply = ok,
    {reply, Reply, StateName, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called by a gen_fsm when it receives any
%% message other than a synchronous or asynchronous event
%% (or a system message).
%%
%% @spec handle_info(Info,StateName,State)->
%%                   {next_state, NextStateName, NextState} |
%%                   {next_state, NextStateName, NextState, Timeout} |
%%                   {stop, Reason, NewState}
%% @end
%%--------------------------------------------------------------------
-define(SEQ_LE(S1, S2), (S1 < S2 andalso (S2-S1) < 128) orelse (S1>S2 andalso (S1-S2) > 128)).

handle_info({capwap_udp, Socket, Packet}, StateName, State = #state{socket = {_, Socket}}) ->
    ?DEBUG(?GREEN "in State ~p got UDP: ~p~n", [StateName, Packet]),
    handle_capwap_packet(Packet, StateName, State);

handle_info({ssl, Socket, Packet}, StateName, State = #state{socket = {_, Socket}}) ->
    ?DEBUG(?GREEN "in State ~p got DTLS: ~p~n", [StateName, Packet]),
    handle_capwap_packet(Packet, StateName, State);

handle_info({timeout, _, retransmit}, StateName, State) ->
    resend_request(StateName, State);
handle_info(Info, StateName, State) ->
    ?DEBUG(?RED "in State ~p unexpected Info: ~p~n", [StateName, Info]),
    {next_state, StateName, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called by a gen_fsm when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any
%% necessary cleaning up. When it returns, the gen_fsm terminates with
%% Reason. The return value is ignored.
%%
%% @spec terminate(Reason, StateName, State) -> void()
%% @end
%%--------------------------------------------------------------------
terminate(_Reason, _StateName, #state{socket = Socket}) ->
    socket_close(Socket),
    ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Convert process state when code is changed
%%
%% @spec code_change(OldVsn, StateName, State, Extra) ->
%%                   {ok, StateName, NewState}
%% @end
%%--------------------------------------------------------------------
code_change(_OldVsn, StateName, State, _Extra) ->
    {ok, StateName, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

handle_capwap_packet(Packet, StateName, State = #state{
					  last_response = LastResponse,
					  last_request = LastRequest}) ->
    try	capwap_packet:decode(control, Packet) of
	{Header, {Msg, 1, Seq, Elements}} ->
	    %% Request
	    ?DEBUG(?BLUE "got capwap request: ~w~n", [Msg]),
	    case LastResponse of
		{Seq, _} ->
		    resend_response(State),
		    {next_state, StateName, State};
		{LastSeq, _} when ?SEQ_LE(Seq, LastSeq) ->
		    %% old request, silently ignore
		    {next_state, StateName, State};
		_ ->
		    ?MODULE:StateName({Msg, Seq, Elements, Header}, State)
	    end;
	{Header, {Msg, 0, Seq, Elements}} ->
	    %% Response
	    ?DEBUG(?BLUE "got capwap response: ~w~n", [Msg]),
	    case LastRequest of
		{Seq, _} ->
		    State1 = ack_request(State),
		    ?MODULE:StateName({Msg, Seq, Elements, Header}, State1);
		_ ->
		    %% invalid Seq, out-of-order packet, silently ignore,
		    {next_state, StateName, State}
	    end
    catch
	Class:Error ->
	    error_logger:error_report([{capwap_packet, decode}, {class, Class}, {error, Error}]),
	    {next_state, StateName, State, ?IDLE_TIMEOUT}
    end.

ac_info() ->
    [#ac_descriptor{stations    = 0,
		    limit       = 200,
		    active_wtps = 0,
		    max_wtps    = 2,
%%		    security    = ['pre-shared'],
		    security    = ['x509'],
		    r_mac       = supported,
		    dtls_policy = ['clear-text'],
		    sub_elements = [{{0,4},<<"Hardware Ver. 1.0">>},
				    {{0,5},<<"Software Ver. 1.0">>}]},
     #ac_name{name = <<"My AC Name">>}
    ] ++ control_addresses().

send_info_after(Time, Event) ->
    erlang:start_timer(Time, self(), Event).

bump_seqno(State = #state{seqno = SeqNo}) ->
    State#state{seqno = (SeqNo + 1) rem 256}.

send_response(Header, MsgType, Seq, MsgElems,
	   State = #state{socket = Socket}) ->
    ?DEBUG(?BLUE "send capwap response(~w): ~w~n", [Seq, MsgType]),
    BinMsg = capwap_packet:encode(control, {Header, {MsgType, Seq, MsgElems}}),
    ok = socket_send(Socket, BinMsg),
    State#state{last_response = {Seq, BinMsg}}.

resend_response(#state{socket = Socket, last_response = {_, BinMsg}}) ->
    ?DEBUG(?RED "resend capwap response~n", []),
    ok = socket_send(Socket, BinMsg).

send_request(Header, MsgType, ReqElements,
	     State = #state{socket = Socket, seqno = SeqNo}) ->
    ?DEBUG(?BLUE "send capwap request(~w): ~w~n", [SeqNo, MsgType]),
    BinMsg = capwap_packet:encode(control, {Header, {MsgType, SeqNo, ReqElements}}),
    ok = socket_send(Socket, BinMsg),
    State1 = State#state{last_request = {SeqNo, BinMsg},
			 retransmit_timer = send_info_after(?RetransmitInterval, retransmit),
			 retransmit_counter = ?MaxRetransmit
		   },
    bump_seqno(State1).

resend_request(StateName, State = #state{retransmit_counter = 0}) ->
    io:format("Finial Timeout in ~w, STOPPING~n", [StateName]),
    {stop, normal, State};
resend_request(StateName,
	       State = #state{socket = Socket,
			      last_request = {_, BinMsg},
			      retransmit_counter = MaxRetransmit}) ->
    ?DEBUG(?RED "resend capwap request~n", []),
    ok = socket_send(Socket, BinMsg),
    State1 = State#state{retransmit_timer = send_info_after(?RetransmitInterval, retransmit),
			 retransmit_counter = MaxRetransmit - 1
			},
    {next_state, StateName, State1}.


%% Stop Timer, clear LastRequest
ack_request(State0) ->
    State1 = State0#state{last_request = undefined},
    cancel_retransmit(State1).

cancel_retransmit(State = #state{retransmit_timer = undefined}) ->
    State;
cancel_retransmit(State = #state{retransmit_timer = Timer}) ->
    gen_fsm:cancel_timer(Timer),
    State#state{retransmit_timer = undefined}.

control_addresses() ->
    case application:get_env(server_ip) of
	{ok, IP} ->
	    [control_address(IP)];
	_ ->
	    all_local_control_addresses()
    end.

control_address({A,B,C,D}) ->
    #control_ipv4_address{ip_address = <<A,B,C,D>>,
			  wtp_count = 0};
control_address({A,B,C,D,E,F,G,H}) ->
    #control_ipv6_address{ip_address = <<A:16,B:16,C:16,D:16,E:16,F:16,G:16,H:16>>,
			  wtp_count = 0}.

all_local_control_addresses() ->
    case inet:getifaddrs() of
	{ok, IfList} ->
	    process_iflist(IfList, []);
	_ ->
	    []
    end.

process_iflist([], Acc) ->
    Acc;
process_iflist([{_Ifname, Ifopt}|Rest], Acc) ->
    Acc1 = process_ifopt(Ifopt, Acc),
    process_iflist(Rest, Acc1).

process_ifopt([], Acc) ->
    Acc;
process_ifopt([{addr,IP}|Rest], Acc) ->
    IE = control_address(IP),
    process_ifopt(Rest, [IE|Acc]);
process_ifopt([_|Rest], Acc) ->
    process_ifopt(Rest, Acc).

answer_discover(Seq, _Elements, #capwap_header{
		       radio_id = RadioId, wb_id = WBID, flags = Flags}) ->
    RespElems = ac_info(),
    Header = #capwap_header{radio_id = RadioId, wb_id = WBID, flags = Flags},
    capwap_packet:encode(control, {Header, {discovery_response, Seq, RespElems}}).

user_lookup(srp, Username, _UserState) ->
    ?DEBUG(?GREEN "srp: ~p~n", [Username]),
    Salt = ssl:random_bytes(16),
    UserPassHash = crypto:hash(sha, [Salt, crypto:hash(sha, [Username, <<$:>>, <<"secret">>])]),
    {ok, {srp_1024, Salt, UserPassHash}};

user_lookup(psk, Username, UserState) ->
    ?DEBUG(?GREEN "psk: ~p~n", [Username]),
    {ok, UserState}.

socket_send({udp, Socket}, Data) ->
    capwap_udp:send(Socket, Data);
socket_send({dtls, Socket}, Data) ->
    ssl:send(Socket, Data).

socket_close({udp, Socket}) ->
    capwap_udp:close(Socket);
socket_close({dtls, Socket}) ->
    ssl:close(Socket).

mk_ssl_opts() ->
    Dir = filename:join([code:lib_dir(capwap), "priv", "certs"]),
    [{active, false},
     {verify, 0},
     {mode, binary},
     {reuseaddr, true},

     {versions, ['dtlsv1.2', dtlsv1]},
     %%{cb_info, {ssl_udp_test, ssl_udp_test, udp_closed, udp_error}},
     {cb_info, capwap_udp},
     {verify_client_hello, true},

     {ciphers,[{ecdhe_rsa, aes_128_cbc, sha},
	       {dhe_rsa, aes_128_cbc, sha},
	       {rsa, aes_128_cbc, sha},
	       {ecdhe_rsa, aes_256_cbc, sha},
	       {dhe_rsa, aes_256_cbc, sha},
	       {rsa, aes_256_cbc, sha},
	       {dhe_psk, aes_128_cbc,sha},
	       {psk, aes_128_cbc,sha},
	       {dhe_psk, aes_256_cbc,sha},
	       {psk, aes_256_cbc,sha}]},

     {psk_identity, "CAPWAP"},
     {user_lookup_fun, {fun user_lookup/3, <<16#11>>}},
     %% {ciphers,[{srp_dss, aes_256_cbc, sha}]},
     %% {ciphers, [{srp_anon, aes_256_cbc, sha}]},

     {cacertfile, filename:join([Dir, "cacerts.pem"])},
     {certfile, filename:join([Dir, "server.pem"])},
     {keyfile, filename:join([Dir, "server.key"])}
    ].

