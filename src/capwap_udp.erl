%%----------------------------------------------------------------------
%% Purpose : UDP API Wrapper
%%----------------------------------------------------------------------

-module(capwap_udp).

-behavior(gen_server).

-include("capwap_debug.hrl").

%% API
-export([start_link/2]).

%% DTLS Transport callbacks
-export([connect/3, connect/4, accept/2, listen/2, shutdown/2, close/1, controlling_process/2]).
-export([send/2, recv/2, recv/3, handle_ssl_info/2]).
-export([getopts/2, setopts/2, port/1, peername/1, sockname/1]).
-export([connection_type/1, callback_info/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

%% Transport Modules Callbacks
-export([listener_spec/1]).

-define(SERVER, ?MODULE).
-define(PROTOCOL, ?MODULE).

-define(ECLOSED, {error, closed}).
-define(ENOTCONN, {error, enotconn}).

-ifdef(debug).
-define(SERVER_OPTS, [{debug, [trace]}]).
-else.
-define(SERVER_OPTS, []).
-endif.

%%===================================================================
%% API
%%===================================================================
start_link(Port, Options) ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [self(), Port, Options], ?SERVER_OPTS).

%%===================================================================
%% Transport Module Callbacks
%%===================================================================

%% return a supervisor spec to start a listener
listener_spec({Port, Options}) ->
    {{?MODULE, f, Port},
     {?MODULE, start_link, [Port, Options]},
     permanent, 5000, worker, [?MODULE]}.

%%===================================================================
%% DTLS Transport API
%%===================================================================

connect(Address, Port, Options, _Timeout) ->
    connect(Address, Port, Options).

connect(Address, Port, Opts0) ->
    Options = lists:filter(fun({packet, _}) -> false;
                              ({packet_size, _}) -> false;
                              (_) -> true end, Opts0),
    case open_socket(0, Options) of
        {ok, Socket} ->
            case gen_udp:connect(Socket, Address, Port) of
                ok ->
                    {ok, Socket};
                Error = {error, _Reason} ->
                    Error
            end;
        Error = {error, _Reason} ->
            lager:error("Error ~p opening socket on port port 0 with opts ~p", [Error, Options]),
            Error
    end.

accept(ListenSocket, Timeout) ->
    call(ListenSocket, accept, Timeout, infinity).

listen(Port, Options) ->
%%    gen_server:start_link(?MODULE, [Port, Options], [{debug, [trace]}]).
    gen_server:start_link(?MODULE, [self(), Port, Options], []).

controlling_process(Socket, Pid) when is_port(Socket) ->
    gen_udp:controlling_process(Socket, Pid);
controlling_process(Socket, Pid) ->
    call(Socket, controlling_process, {self(), Pid}).

close(Socket) when is_port(Socket) ->
    gen_udp:close(Socket);
close(Socket) ->
    call(Socket, close, undefined).

send(Socket, Data) when is_port(Socket) ->
    send(Socket, dtls, Data);
send(Socket, Data) ->
    call(Socket, send, Data).

recv(Socket, Length) ->
    recv(Socket, Length, infinity).

recv(Socket, Length, Timeout) when is_port(Socket) ->
    case gen_udp:recv(Socket, Length, Timeout) of
	{ok, {_Address, _Port, Packet}} ->
	    {ok, Packet};
	Error ->
	    Error
    end;
recv(Socket, Length, Timeout) ->
    call(Socket, recv, {Length, Timeout}).

shutdown(Socket, _How) when is_port(Socket) ->
    ok;
shutdown(Socket, How) ->
    call(Socket, shutdown, How).

%% map UDP port info's to three-tupple format
handle_ssl_info(Socket, {udp, Socket, _Address, _Port, Packet}) ->
    {next, {?PROTOCOL, Socket, Packet}};
handle_ssl_info(_, Info) ->
    Info.

getopts(Socket, Options) when is_port(Socket) ->
    inet:getopts(Socket, Options);
getopts(Socket, Options) ->
    call(Socket, getopts, Options).

setopts(Socket, Options) when is_port(Socket) ->
    inet:setopts(Socket, Options);
setopts(Socket, Options) ->
    call(Socket, setopts, Options).

peername(Socket) when is_port(Socket) ->
    inet:peername(Socket);
peername(Socket) ->
    call(Socket, peername, undefined).

sockname(Socket) when is_port(Socket) ->
    inet:sockname(Socket);
sockname(Socket) ->
    call(Socket, sockname, undefined).

port(Socket) when is_port(Socket) ->
    inet:port(Socket);
port(Socket) ->
    call(Socket, port, undefined).

connection_type(_Socket) ->
    datagram.

callback_info() ->
    {?MODULE, ?PROTOCOL, udp_closed, udp_error}.

%%----------------------------------
%% Port Logic
%%----------------------------------

call(Socket, Request, Args) ->
    ?DEBUG(?GREEN "call: ~p ~p~n", [Socket, Request]),
    call(Socket, Request, Args, 5000).

call(Socket, Request, Args, Timeout) when is_pid(Socket) ->
    call_socket(Socket, {Request, undefined, Args}, Timeout);
call({Socket, SslSocket}, Request, Args, Timeout) when is_pid(Socket) ->
    call_socket(Socket, {Request, SslSocket, Args}, Timeout).

call_socket(Socket, Request, Timeout) ->
    try
	gen_server:call(Socket, Request, Timeout)
    catch
	exit:{noproc,_} -> ?ECLOSED
    end.

capwap_socket(SslSocketId) ->
    {self(), SslSocketId}.

%%===================================================================
%% gen_server callbacks
%%===================================================================

-record(state, {socket, owner, mode, state = init, accepting, connections, virtual_sockets}).
-record(capwap_socket, {id, type, peer, owner, mode, queue}).

init([Owner, Port, Options0]) ->
    process_flag(trap_exit, true),
    Options = proplists:expand([{binary, [{mode, binary}]},
				{list, [{mode, list}]}], Options0),
    Opts1 = lists:keystore(recbuf, 1, Options, {recbuf, 20*1024}),
    Opts0 = lists:keystore(active, 1, Opts1, {active, true}),
    Opts = lists:keystore(mode, 1, Opts0, {mode, binary}),
    case open_socket(Port, Opts) of
        {ok, Socket} ->
            {ok, #state{socket = Socket,
                        owner = Owner,
                        mode = proplists:get_value(mode, Options, list),
                        state = listen,
                        connections = gb_trees:empty(),
                        virtual_sockets = gb_trees:empty()}};
        Error ->
            lager:error("Error ~p opening socket on port port ~p with opts ~p", [Error, Port, Opts]),
            Error
    end.

%%--------------------------------------------------------------------
%% -spec terminate(reason(), #state{}) -> ok.
%%
%% Description: This function is called by a gen_server when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any necessary
%% cleaning up. When it returns, the gen_server terminates with Reason.
%% The return value is ignored.
%%--------------------------------------------------------------------
terminate(_Reason, _State) ->
    ok.

%%--------------------------------------------------------------------
-spec code_change(term(), #state{}, list()) -> {ok, #state{}}.
%%
%% Description: Convert process state when code is changed
%%--------------------------------------------------------------------
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% ---------------------------------------------------------------------------
%% universal Socket operations
%% ---------------------------------------------------------------------------

handle_call({sockname, _, _}, _From, State = #state{socket = Socket}) ->
    Reply = inet:sockname(Socket),
    {reply, Reply, State};

handle_call({port, _, _}, _From, State = #state{socket = Socket}) ->
    Reply = inet:port(Socket),
    {reply, Reply, State};

%% ---------------------------------------------------------------------------
%% Listening Socket operations
%% ---------------------------------------------------------------------------

handle_call({accept, undefined, Timeout}, From, State = #state{state = listen}) ->
    {noreply, State#state{state = accepting, accepting = From}, Timeout};
handle_call({accept, undefined, _Timeout}, _From, State) ->
    {reply, {error, already_listening}, State};

handle_call({getopts, undefined, Options}, _From, State = #state{socket = Socket, mode = Mode}) ->
    case inet:getopts(Socket, Options) of
	{ok, SocketOptions} ->
	    Reply = {ok, lists:keystore(mode, 1, SocketOptions, {mode, Mode})};
	Reply ->
	    ok
    end,
    {reply, Reply, State};

handle_call({setopts, undefined, Options}, _From, State = #state{socket = Socket, mode = Mode}) ->
    Opts0 = lists:keystore(active, 1, Options, {active, true}),
    Opts = lists:keydelete(mode, 1, Opts0),
    Reply = inet:setopts(Socket, Opts),
    {reply, Reply, State#state{mode = proplists:get_value(mode, Options, Mode)}};

handle_call({controlling_process, undefined, {Old, New}}, _From, State = #state{owner = Old}) ->
    {reply, ok, State#state{owner = New}};
handle_call({controlling_process, undefined, _}, _From, State) ->
    {reply, {error, not_owner}, State};

handle_call({close, undefined, _Args}, _From, State0 = #state{socket = Socket}) ->
    Reply = gen_udp:close(Socket),
    State = reply_accept(?ECLOSED, State0),
    {reply, Reply, State#state{state = closed}};

handle_call({_, undefined, _Args}, _From, State = #state{state = closed}) ->
    {reply, ?ECLOSED, State};

handle_call({_, undefined, _Args}, _From, State) ->
    {reply, ?ENOTCONN, State};

%% ---------------------------------------------------------------------------
%% Connected Socket operations
%% ---------------------------------------------------------------------------

handle_call({close, CSocketId, Args}, From, State) ->
    with_socket(CSocketId, Args, From, ok, fun socket_close/4, State);

handle_call({shutdown, CSocketId, How}, From, State) ->
    with_socket(CSocketId, How, From, ?ECLOSED, fun socket_shutdown/4, State);

handle_call({recv, CSocketId, Args}, From, State) ->
    with_socket(CSocketId, Args, From, ?ECLOSED, fun socket_recv/4, State);

handle_call({send, CSocketId, Packet}, From, State) ->
    with_socket(CSocketId, Packet, From, ?ENOTCONN, fun socket_send/4, State);

handle_call({setopts, CSocketId, Options}, From, State) ->
    with_socket(CSocketId, Options, From, ?ENOTCONN, fun socket_setopts/4, State);

handle_call({getopts, CSocketId, Options}, From, State) ->
    with_socket(CSocketId, Options, From, ?ENOTCONN, fun socket_getopts/4, State);

handle_call({peername, CSocketId, Args}, From, State) ->
    with_socket(CSocketId, Args, From, ?ENOTCONN, fun socket_peername/4, State);

handle_call({controlling_process, CSocketId, Args}, From, State) ->
    with_socket(CSocketId, Args, From, ?ENOTCONN, fun socket_controlling_process/4, State);

handle_call(_Request, _From, State) ->
    {reply, ok, State}.

%handle_call(Request, From, State = #state{socket = Socket, connections = Cons}) ->
handle_cast(_Request, State) ->
    {noreply, State}.

handle_info(timeout, State0 = #state{state = accepting}) ->
    State = reply_accept({error, timeout}, State0),
    {noreply, State};

handle_info({udp, Socket, IP, InPortNo, Packet},
	    State0 = #state{socket = Socket}) ->
    State = handle_packet({IP, InPortNo}, Packet, State0),
    inet:setopts(Socket, [{active, once}]),
    {noreply, State};

%% TODO handle SSL decoded packet!
%% handle_info({udp, Socket, IP, InPortNo, Packet},
%% 	    State0 = #state{socket = Socket, ip_conns = IpConns}) ->
%%     Peer = {IP, InPortNo},
%%     State1 = case gb_trees:lookup(Peer, IpConns) of
%% 		 none ->
%% 		     handle_accept(Peer, Packet, State0);
%% 		 {value, SslSocket} ->
%% 		     handle_packet(Peer, SslSocket, Packet, State0)
%% 	     end,
%%     inet:setopts(Socket, [{active, once}]),
%%     {noreply, State1};

handle_info(Info, State) ->
    lager:warning("Unhandled info message: ~p", [Info]),
    {noreply, State}.

handle_packet(Peer, <<0:4, 0:4, _/binary>> = Packet, State) ->
    handle_packet(Peer, udp, Packet, State);
handle_packet(Peer, <<0:4, 1:4, _:3/bytes, Packet/binary>>, State) ->
    handle_packet(Peer, dtls, Packet, State).

handle_packet(Peer, Type, Packet, State) ->
    CSocket = get_csocket(Peer, Type, State),
    handle_packet(Peer, Type, CSocket, Packet, State).

handle_packet(Peer, Type, undefined, Packet,
	      State0 = #state{socket = Socket}) ->
    ?DEBUG("handle_packet #4~n"),
    case handle_first_packet(Peer, Type, Packet, State0) of
	{reply, Data} ->
	    ?DEBUG("handle_packet #4-1~n"),
	    send(Socket, Peer, Type, [Data]),
	    State0;

	accept ->
	    ?DEBUG("handle_packet #4-2~n"),
	    %% NOTE: the first request is decode twice, should this be changed?
	    {ok, Owner} = get_wtp(Peer, State0),

	    {CSocketId, State} = new_csocket(Peer, Type, Owner, Packet, State0),
	    capwap_ac:accept(Owner, Type, capwap_socket(CSocketId)),
	    State;

	Other ->
	    ?DEBUG(?RED "handle_packet #4-3: ~p~n", [Other]),
	    %% silently ignore
	    State0
    end;

handle_packet(_Peer, _Type, CSocket0 = #capwap_socket{mode = passive, queue = Queue}, Packet, State) ->
    ?DEBUG("handle_packet #5~n"),
    CSocket = CSocket0#capwap_socket{queue = queue:in(Packet, Queue)},
    update_csocket(CSocket, State);

handle_packet(_Peer, _Type, #capwap_socket{id = CSocketId, mode = _Mode, owner = Owner}, Packet, State) ->
    ?DEBUG("handle_packet #6~n"),
    Owner ! {?PROTOCOL, capwap_socket(CSocketId), Packet},
    State.

handle_first_packet({Address, Port}, udp, Packet, _State) ->
    ?DEBUG("handle_first_packet: plain CAPWAP~n~p~n", [Packet]),
    %% TODO: keep AC configuration in State and pass it to AC
    capwap_ac:handle_packet(Address, Port, Packet);
handle_first_packet({Address, Port}, dtls, Packet, _State) ->
    ?DEBUG(?BLUE "handle_first_packet: DTLS CAPWAP~n"),
    ssl_datagram:handle_packet(Address, Port, Packet).

send(Socket, Type, Data) when is_binary(Data) ->
    do_send(Socket, Type, Data);
send(_, _, []) ->
    ok;
send(Socket, Type, [H|T]) ->
    case do_send(Socket, Type, H) of
	ok ->
	    send(Socket, Type, T);
	Other ->
	    Other
    end.

send(Socket, Peer, Type, Data) when is_binary(Data) ->
    do_send(Socket, Peer, Type, Data);
send(_, _, _, []) ->
    ok;
send(Socket, Peer, Type, [H|T]) ->
    case do_send(Socket, Peer, Type, H) of
	ok ->
	    send(Socket, Peer, Type, T);
	Other ->
	    Other
    end.

do_send(Socket, udp, Data) ->
    gen_udp:send(Socket, Data);
do_send(Socket, dtls, Data) ->
    gen_udp:send(Socket, [<<0:4, 1:4, 0:24>>, Data]).

do_send(Socket, {Address, Port}, udp, Data) ->
    gen_udp:send(Socket, Address, Port, Data);
do_send(Socket, {Address, Port}, dtls, Data) ->
    gen_udp:send(Socket, Address, Port, [<<0:4, 1:4, 0:24>>, Data]).

reply_accept(Reply, State = #state{state = accepting, accepting = Accepting}) ->
    gen_server:reply(Accepting, Reply),
    State#state{state = listen, accepting = undefined};
reply_accept(_Reply, State) ->
    State.

%% ---------------------------------------------------------------------------
%% Socket Handling functions
%% ---------------------------------------------------------------------------
with_socket(CSocketId, Args, From, Error, Fun, State =
		#state{virtual_sockets = VSockets}) ->
    case gb_trees:lookup(CSocketId, VSockets) of
	none ->
	    {reply, Error, State};
	{value, CSocket} ->
	    Fun(CSocket, Args, From, State)
    end.

socket_close(CSocket, _, _From, State0) ->
    State = delete_csocket(CSocket, State0),
    {reply, ok, State}.

socket_shutdown(_CSocket, _Args, _From, State) ->
    {reply, ok, State}.

socket_recv(CSocket = #capwap_socket{queue = Queue},
	    {_Length = 0, _Timeout = 0}, _From, State0) ->
    State = update_csocket(CSocket#capwap_socket{queue = queue:new()}, State0),
    {reply, {ok, binary:list_to_bin(Queue)}, State}.

socket_send(#capwap_socket{type = Type, peer = Peer},
	    Packet, _From,
	    State = #state{socket = Socket}) ->
    Reply = send(Socket, Peer, Type, Packet),
    {reply, Reply, State}.

socket_setopts(CSocket = #capwap_socket{id = CSocketId, owner = Owner, queue = Queue},
	       Options, _From, State0) ->
    case proplists:get_value(active, Options) of
	Active when Active /= false ->
	    [Owner ! {?PROTOCOL, capwap_socket(CSocketId), Packet} || Packet <- queue:to_list(Queue)],
	    State = update_csocket(CSocket#capwap_socket{mode = active, queue = queue:new()}, State0),
	    {reply, ok, State};
	_ ->
	    {reply, ok, State0}
    end.

socket_getopts(_CSocket, _Args, _From, State) ->
    Reply = {ok, [{active, false}, list, {packet, 0}]},
    {reply, Reply, State}.

socket_peername(#capwap_socket{peer = Peer}, _, _From, State) ->
    {reply, {ok, Peer}, State}.

socket_controlling_process(CSocket = #capwap_socket{owner = Old}, {Old, Pid}, _From, State0) ->
    State = update_csocket(CSocket#capwap_socket{owner = Pid}, State0),
    {reply, ok, State};
socket_controlling_process(_, _, _From, State) ->
    {reply, {error, not_owner}, State}.


%% =====================================================================================

get_wtp(Peer, _State) ->
    %% TODO: keep AC configuration in State and pass it to new AC
    case capwap_wtp_reg:lookup(Peer) of
	not_found ->
	    capwap_ac_sup:new_wtp(Peer);
	Reply ->
	    Reply
    end.

new_csocket(Peer, Type, Owner, Packet, State0 =
	       #state{connections = Connections, virtual_sockets = VSockets}) ->
    CSocketId = make_ref(),
    CSocket = #capwap_socket{id = CSocketId, type = Type, peer = Peer, owner = Owner,
			     mode = passive, queue = queue:from_list([Packet])},

    State = State0#state{connections     = gb_trees:insert({Peer, Type}, CSocketId, Connections),
			 virtual_sockets = gb_trees:insert(CSocketId, CSocket, VSockets)},
    {CSocketId, State}.

get_csocket(Peer, Type,
		#state{connections = Connections, virtual_sockets = VSockets}) ->
    case gb_trees:lookup({Peer, Type}, Connections) of
	none ->
	    undefined;
	{value, CSocketId} ->
	    gb_trees:get(CSocketId, VSockets)
    end.

update_csocket(CSocket = #capwap_socket{id = CSocketId},
	        State = #state{virtual_sockets = VSockets}) ->
    State#state{virtual_sockets = gb_trees:update(CSocketId, CSocket, VSockets)}.

delete_csocket(#capwap_socket{id = CSocketId, type = Type, peer = Peer},
	       State =
		   #state{connections = Connections, virtual_sockets = VSockets}) ->
    State#state{
      connections = gb_trees:delete_any({Peer, Type}, Connections),
      virtual_sockets = gb_trees:delete_any(CSocketId, VSockets)}.

open_socket(Port, Options) ->
    case lists:keytake(netns, 1, Options) of
        {value, {_, NetNs}, Opts} ->
            case gen_socket:raw_socketat(NetNs, inet, dgram, udp) of
                {ok, Fd} ->
                    Ret = case lists:keytake(ip, 1, Opts) of
                              {value, {_, IP}, _} ->
                                  gen_socket:bind(Fd, {inet4, IP, Port});
                              _ ->
                                  ok
                          end,
                    case Ret of
                        ok ->
                            gen_udp:open(Port, [{reuseaddr, true}, {fd, Fd}|Opts]);
                        _ ->
                            Ret
                    end;
                Other ->
                    Other
            end;
        _ ->
            gen_udp:open(Port, [{reuseaddr, true} | Options])
    end.
