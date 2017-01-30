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

-define(DEBUG_OPTS,[{install, {fun lager_sys_debug:lager_gen_fsm_trace/3, ?MODULE}}]).

%%===================================================================
%% API
%%===================================================================
start_link(Port, Options) ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [self(), Port, Options],
                          [{debug, ?DEBUG_OPTS}]).

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
                    lager:error("Error ~p connecting socket on port ~p : ~p", [Error, Port, Address]),
                    Error
            end;
        Error = {error, _Reason} ->
            lager:error("Error ~p opening socket on port 0 with opts ~p", [Error, Options]),
            Error
    end.

accept(ListenSocket, Timeout) ->
    call(ListenSocket, accept, Timeout, infinity).

listen(Port, Options) ->
    gen_server:start_link(?MODULE, [self(), Port, Options], [{debug, ?DEBUG_OPTS}]).

controlling_process(Socket, Pid) when is_port(Socket) ->
    gen_udp:controlling_process(Socket, Pid);
controlling_process(Socket, Pid) ->
    call(Socket, controlling_process, {self(), Pid}).

close(Socket) when is_port(Socket) ->
    lager:debug("Closing socket ~p", [Socket]),
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
handle_ssl_info(Socket, {udp, Socket, _Address, _Port, <<0:4, 1:4, _:3/bytes, Packet/binary>>}) ->
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
    lager:debug(?GREEN "call: ~p ~p" ?WHITE, [Socket, Request]),
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
-record(capwap_socket, {id, type, peer, owner, monitor, mode, queue}).

init([Owner, Port, Options0]) ->
    process_flag(trap_exit, true),
    Options = proplists:expand([{binary, [{mode, binary}]},
				{list, [{mode, list}]}], Options0),
    Opts0 = lists:keystore(active, 1, Options, {active, true}),
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
terminate(Reason, State) ->
    error_logger:info_msg("Terminating UDP process with reason ~p : ~p~n", [Reason, State]),
    gen_udp:close(State#state.socket),
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
    unlink(Old),
    link(New),
    {reply, ok, State#state{owner = New}};
handle_call({controlling_process, undefined, _}, _From, State) ->
    {reply, {error, not_owner}, State};

handle_call({close, undefined, _Args}, _From, State0 = #state{socket = Socket}) ->
    lager:info("Closing socket, requested from ~p", [_From]),
    Reply = gen_udp:close(Socket),
    State = reply_accept(?ECLOSED, State0),
    {reply, Reply, State#state{state = closed}};

handle_call({_, undefined, _Args}, _From, State = #state{state = closed}) ->
    lager:debug("Socket already closed", []),
    {reply, ?ECLOSED, State};

handle_call({_, undefined, _Args}, _From, State) ->
    lager:debug("Socket not connected", []),
    {reply, ?ENOTCONN, State};

%% ---------------------------------------------------------------------------
%% Connected Socket operations
%% ---------------------------------------------------------------------------

handle_call({close, CSocketId, Args}, From, State) ->
    lager:info("Closing socket, requested from ~p", [From]),
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

handle_info({'EXIT', Owner, _}, State = #state{owner = Owner}) ->
    lager:info("owner process ~p exited", [Owner]),
    {stop, normal, State#state{owner = undefined}};

handle_info({'DOWN', _MonitorRef, _Type, Pid, _Info}, State0 = #state{virtual_sockets = VSockets}) ->
    State = socket_owner_down(Pid, gb_trees:next(gb_trees:iterator(VSockets)), State0),
    {noreply, State};

handle_info(Info, State) ->
    lager:warning("Unhandled info message: ~p", [Info]),
    {noreply, State}.

handle_packet(Peer, <<0:4, 0:4, _/binary>> = Packet, State) ->
    handle_packet(Peer, udp, Packet, State);
handle_packet(Peer, <<0:4, 1:4, _:3/bytes, Packet/binary>>, State) ->
    handle_packet(Peer, dtls, Packet, State);
handle_packet(Peer, Packet, State) ->
    lager:debug(?RED "invalid CAPWAP header from ~p: ~p" ?WHITE, [Peer, Packet]),
    %% silently ignore
    State.

handle_packet(Peer, Type, Packet, State) ->
    CSocket = get_csocket(Peer, Type, State),
    handle_packet(Peer, Type, CSocket, Packet, State).

handle_packet(Peer, Type, undefined, Packet,
	      State0 = #state{socket = Socket}) ->
    lager:debug("handle_packet #4"),
    case handle_first_packet(Peer, Type, Packet, State0) of
        {reply, Data} ->
            lager:debug("handle_packet #4-1"),
            send(Socket, Peer, Type, [Data]),
            State0;

        accept ->
            lager:debug("handle_packet #4-2"),
            %% NOTE: the first request is decode twice, should this be changed?
            {ok, Owner} = get_wtp(Peer, State0),

            {CSocketId, State} = new_csocket(Peer, Type, Owner, Packet, State0),
            capwap_ac:accept(Owner, Type, capwap_socket(CSocketId)),
            State;

        Other ->
            lager:debug(?RED "handle_packet #4-3: ~p" ?WHITE, [Other]),
            %% silently ignore
            State0
    end;

handle_packet(_Peer, _Type, CSocket0 = #capwap_socket{mode = passive, queue = Queue}, Packet, State) ->
    lager:debug("handle_packet #5"),
    CSocket = CSocket0#capwap_socket{queue = queue:in(Packet, Queue)},
    update_csocket(CSocket, State);

handle_packet(_Peer, _Type, #capwap_socket{id = CSocketId, mode = _Mode, owner = Owner}, Packet, State) ->
    lager:debug("handle_packet #6"),
    Owner ! {?PROTOCOL, capwap_socket(CSocketId), Packet},
    State.

handle_first_packet(WTPControlChannelAddress, udp, Packet, _State) ->
    lager:debug("handle_first_packet: plain CAPWAP~n~p", [Packet]),
    %% TODO: keep AC configuration in State and pass it to AC
    capwap_ac:handle_packet(WTPControlChannelAddress, Packet);
handle_first_packet({Address, Port}, dtls, Packet, _State) ->
    lager:debug(?BLUE "handle_first_packet: DTLS CAPWAP" ?WHITE),
    try
        dtlsex_datagram:handle_packet(Address, Port, Packet)
    catch
        E:C ->
            lager:error("Error ~p:~p handling DTLS packet ~p", [E, C, Packet]),
            ignore
    end.

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

socket_controlling_process(CSocket = #capwap_socket{owner = Old, monitor = OldMonRef}, {Old, Pid}, _From, State0) ->
    catch(demonitor(process, OldMonRef)),
    MonRef = monitor(process, Pid),
    State = update_csocket(CSocket#capwap_socket{owner = Pid, monitor = MonRef}, State0),
    {reply, ok, State};
socket_controlling_process(_, _, _From, State) ->
    {reply, {error, not_owner}, State}.

socket_owner_down(_Pid, none, State) ->
    State;
socket_owner_down(Pid, {_Key, VSocket = #capwap_socket{owner = Pid}, _Iter}, State) ->
    delete_csocket(VSocket, State);
socket_owner_down(Pid, {_Key, _Value, Iter}, State) ->
    socket_owner_down(Pid, gb_trees:next(Iter), State).

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
    MonRef = monitor(process, Owner),
    CSocket = #capwap_socket{id = CSocketId, type = Type, peer = Peer,
			     owner = Owner, monitor = MonRef,
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

delete_csocket(#capwap_socket{id = CSocketId, type = Type, peer = Peer, monitor = MonRef},
	       State =
		   #state{connections = Connections, virtual_sockets = VSockets}) ->
    catch(demonitor(MonRef)),
    State#state{
      connections = gb_trees:delete_any({Peer, Type}, Connections),
      virtual_sockets = gb_trees:delete_any(CSocketId, VSockets)}.

open_socket(Port, Options) ->
    Opts1 = [{reuseaddr, true}|Options],
    Res = gen_udp:open(Port, Opts1),
    lager:debug("Opening udp connecting on port ~p : ~p : ~p ", [Port, Res, Opts1]),
    Res.
