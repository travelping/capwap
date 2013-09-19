-module(capwap_ac).

-behaviour(gen_fsm).

%% API
-export([start_link/1, accept/3, get_peer_data/1, take_over/1, new_station/3]).

%% gen_fsm callbacks
-export([init/1, listen/2, idle/2, join/2, configure/2, data_check/2, run/2,
	 idle/3, join/3, configure/3, data_check/3, run/3,
	 handle_event/3,
	 handle_sync_event/4, handle_info/3, terminate/3, code_change/4]).

-export([handle_packet/3, handle_data/5]).

-include_lib("public_key/include/OTP-PUB-KEY.hrl").
-include("capwap_debug.hrl").
-include("capwap_packet.hrl").

-define(SERVER, ?MODULE).

%% TODO: convert constants into configuration values
-define(IDLE_TIMEOUT, 30 * 1000).
-define(SSL_ACCEPT_TIMEOUT, 30 * 1000).
-define(RetransmitInterval, 3 * 1000).
-define(MaxRetransmit, 5).

-record(state, {
	  id,
	  peer,
	  peer_data,
	  flow_switch,
	  socket,
	  session,
	  mac_types,
	  tunnel_modes,
	  mac_mode,
	  tunnel_mode,
	  last_response,
	  last_request,
	  retransmit_timer,
	  retransmit_counter,
	  seqno = 0,
	  version,
	  event_log
}).

-ifdef(debug).
-define(SERVER_OPTS, [{debug, [trace]}]).
-else.
-define(SERVER_OPTS, []).
-endif.

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
    gen_fsm:start_link(?MODULE, [Peer], ?SERVER_OPTS).

handle_packet(_Address, _Port, Packet) ->
    try	capwap_packet:decode(control, Packet) of
	{Header, {discovery_request, 1, Seq, Elements}} ->
	    Answer = answer_discover(Seq, Elements, Header),
	    {reply, Answer};
	{Header, {join_request, 1, Seq, Elements}} ->
	    handle_plain_join(Seq, Elements, Header);
	Pkt ->
	    lager:warning("unexpected CAPWAP packet: ~p", [Pkt]),
	    {error, not_capwap}
    catch
	Class:Error ->
	    lager:error("failure: ~p:~p", [Class, Error]),
	    {error, not_capwap}
    end.

handle_data(FlowSwitch, Sw, Address, Port, Packet) ->
    lager:debug("capwap_data: ~p, ~p, ~p~n", [Address, Port, Packet]),
    try	capwap_packet:decode(data, Packet) of
	{Header, PayLoad} ->
	    KeepAlive = proplists:get_bool('keep-alive', Header#capwap_header.flags),
	    handle_capwap_data(FlowSwitch, Sw, Address, Port, Header, KeepAlive, PayLoad);
	_ ->
	    {error, not_capwap}
    catch
	_:_ ->
	    {error, not_capwap}
    end.

accept(WTP, Type, Socket) ->
    gen_fsm:send_event(WTP, {accept, Type, Socket}).

get_peer_data(WTP) ->
    gen_fsm:sync_send_all_state_event(WTP, get_peer_data).

take_over(WTP) ->
    gen_fsm:sync_send_all_state_event(WTP, {take_over, self()}).

new_station(WTP, BSS, SA) ->
    gen_fsm:sync_send_event(WTP, {new_station, BSS, SA}).

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
    process_flag(trap_exit, true),
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
    lager:info("udp_accept: ~p~n", [Socket]),
    next_state(idle, State#state{socket = {udp, Socket}, id = undefined});

listen({accept, dtls, Socket}, State) ->
    lager:info("ssl_accept on: ~p~n", [Socket]),

    {ok, Session} = start_session(Socket, State),
    case ssl:ssl_accept(Socket, mk_ssl_opts(Session), ?SSL_ACCEPT_TIMEOUT) of
        {ok, SslSocket} ->
            lager:info("ssl_accept: ~p~n", [SslSocket]),
            ssl:setopts(SslSocket, [{active, true}, {mode, binary}]),

            {ok, Cert} = ssl:peercert(SslSocket),
            #'OTPCertificate'{
               tbsCertificate =
               #'OTPTBSCertificate'{
                  subject = {rdnSequence, SubjectList}
                 }} = public_key:pkix_decode_cert(Cert, otp),
            Subject = [erlang:hd(S)|| S <- SubjectList],
            {value, #'AttributeTypeAndValue'{value = {utf8String, CommonName}}} =
            lists:keysearch(?'id-at-commonName', #'AttributeTypeAndValue'.type, Subject),
            lager:debug("ssl_cert: ~p~n", [CommonName]),

            case capwap_wtp_reg:lookup(CommonName) of
                {ok, OldPid} ->
                    lager:info("take_over: ~p", [OldPid]),
                    capwap_ac:take_over(OldPid),
                    ok;
                _ ->
                    ok
            end,
            capwap_wtp_reg:register(CommonName),

            EventLogBasePath = application:get_env(capwap, event_log_base_path, "."),
            EventLogPath = filename:join([EventLogBasePath, ["events-", erlang:binary_to_list(CommonName), ".log"]]),
            lager:info("EventLogP: ~w", [EventLogPath]),

            ok = filelib:ensure_dir(EventLogPath),
            {ok, EventLog} = file:open(EventLogPath, [append]),
            State1 = State#state{event_log=EventLog, socket = {dtls, SslSocket}, session = Session, id = CommonName},
            %% TODO: find old connection instance, take over their StationState and stop them
            next_state(idle, State1);
        Other ->
            lager:error("ssl_accept failed: ~p~n", [Other]),
            {stop, normal, State#state{session=Session}}
    end;

listen(timeout, State) ->
    {stop, normal, State}.

idle({keep_alive, _FlowSwitch, _Sw, _PeerId, Header, PayLoad}, _From, State) ->
    lager:warning("in IDLE got unexpected keep_alive: ~p~n", [{Header, PayLoad}]),
    reply({error, unexpected}, idle, State).

idle(timeout, State) ->
    lager:info("timeout in IDLE -> stop~n"),
    {stop, normal, State};

idle({discovery_request, Seq, Elements, #capwap_header{
				radio_id = RadioId, wb_id = WBID, flags = Flags}},
     State) ->
    lager:debug("discover_request: ~p~n", [[lager:pr(E, ?MODULE) || E <- Elements]]),
    RespElements = ac_info(Elements),
    Header = #capwap_header{radio_id = RadioId, wb_id = WBID, flags = Flags},
    State1 = send_response(Header, discovery_response, Seq, RespElements, State),
    next_state(idle, State1);

idle({join_request, Seq, Elements, #capwap_header{
			   radio_id = RadioId, wb_id = WBID, flags = Flags}},
     State0 = #state{peer = {Address, _}, session = Session}) ->
    lager:info("Join-Request: ~p~n", [[lager:pr(E, ?MODULE) || E <- Elements]]),

    Version = get_wtp_version(Elements),
    SessionId = proplists:get_value(session_id, Elements),
    capwap_wtp_reg:register_sessionid(Address, SessionId),

    MacTypes = ie(wtp_mac_type, Elements),
    TunnelModes = ie(wtp_frame_tunnel_mode, Elements),
    State1 = State0#state{mac_types = MacTypes, tunnel_modes = TunnelModes, version = Version},

    RespElements = ac_info_version(Version) ++ [#result_code{result_code = 0}],
    Header = #capwap_header{radio_id = RadioId, wb_id = WBID, flags = Flags},
    State = send_response(Header, join_response, Seq, RespElements, State1),
    SessionOpts = wtp_accounting_infos(Elements, [{'TP-CAPWAP-Radio-Id', RadioId}]),
    lager:info("WTP Session Start Opts: ~p", [SessionOpts]),
    ctld_session:start(Session, SessionOpts),
    next_state(join, State);

idle({Msg, Seq, Elements, Header}, State) ->
    lager:warning("in IDLE got unexpexted: ~p~n", [{Msg, Seq, Elements, Header}]),
    next_state(idle, State).

join({keep_alive, _FlowSwitch, _Sw, _PeerId, Header, PayLoad}, _From, State) ->
    lager:warning("in JOIN got unexpected keep_alive: ~p~n", [{Header, PayLoad}]),
    reply({error, unexpected}, join, State).

join(timeout, State) ->
    lager:info("timeout in JOIN -> stop~n"),
    {stop, normal, State};

join({configuration_status_request, Seq, _Elements, #capwap_header{
					   radio_id = RadioId, wb_id = WBID, flags = Flags}},
     State) ->
    App = capwap,
    EchoRequestInterval = application:get_env(App, echo_request_interval, 10),
    DiscoveryInterval = application:get_env(App, discovery_interval, 20),
    IdleTimeout = application:get_env(App, idle_timeout, 300),
    DataChannelDeadInterval = application:get_env(App, data_channel_dead_interval, 70),
    ACJoinTimeout = application:get_env(App, ac_join_timeout, 60),

    RespElements = [%%#ac_ipv4_list{ip_address = [<<0,0,0,0>>]},
		    #timers{discovery = DiscoveryInterval,
			    echo_request = EchoRequestInterval},
		    #tp_data_channel_dead_interval{data_channel_dead_interval = DataChannelDeadInterval},
		    #tp_ac_join_timeout{ac_join_timeout = ACJoinTimeout},
		    #decryption_error_report_period{
			     radio_id = RadioId,
			     report_interval = 15},
		    #idle_timeout{timeout = IdleTimeout}],
    Header = #capwap_header{radio_id = RadioId, wb_id = WBID, flags = Flags},
    State1 = send_response(Header, configuration_status_response, Seq, RespElements, State),
    next_state(configure, State1);

join({Msg, Seq, Elements, Header}, State) ->
    lager:warning("in JOIN got unexpexted: ~p~n", [{Msg, Seq, Elements, Header}]),
    next_state(join, State).

configure({keep_alive, _FlowSwitch, _Sw, _PeerId, Header, PayLoad}, _From, State) ->
    lager:warning("in CONFIGURE got unexpected keep_alive: ~p~n", [{Header, PayLoad}]),
    reply({error, unexpected}, configure, State).

configure(timeout, State) ->
    lager:info("timeout in CONFIGURE -> stop~n"),
    {stop, normal, State};

configure({change_state_event_request, Seq, _Elements, #capwap_header{
					      radio_id = RadioId, wb_id = WBID, flags = Flags}},
	  State) ->
    Header = #capwap_header{radio_id = RadioId, wb_id = WBID, flags = Flags},
    State1 = send_response(Header, change_state_event_response, Seq, [], State),
    next_state(data_check, State1);

configure({Msg, Seq, Elements, Header}, State) ->
    lager:debug("in configure got: ~p~n", [{Msg, Seq, Elements, Header}]),
    next_state(configure, State).

data_check({keep_alive, FlowSwitch, Sw, PeerId, Header, PayLoad}, _From, State) ->
    lager:debug("in DATA_CHECK got expected keep_alive: ~p~n", [{Sw, Header, PayLoad}]),
    capwap_wtp_reg:register(PeerId),
    gen_fsm:send_event(self(), configure),
    reply({reply, {Header, PayLoad}}, run, State#state{peer_data = PeerId, flow_switch = FlowSwitch}).

data_check(timeout, State) ->
    lager:info("timeout in DATA_CHECK -> stop~n"),
    {stop, normal, State};

data_check({Msg, Seq, Elements, Header}, State) ->
    lager:warning("in DATA_CHECK got unexpexted: ~p~n", [{Msg, Seq, Elements, Header}]),
    next_state(data_check, State).

run({new_station, BSS, SA}, _From, State = #state{peer_data = PeerId, flow_switch = FlowSwitch,
                                                  mac_mode = MacMode, tunnel_mode = TunnelMode}) ->
    lager:info("in RUN got new_station: ~p", [SA]),

    lager:debug("search for station ~p", [{self(), SA}]),
    %% we have to repeat the search again to avoid a race
    Reply = case capwap_station_reg:lookup(self(), SA) of
		not_found ->
		    lager:debug("station not found: ~p", [{self(), SA}]),
		    case capwap_station_reg:lookup(SA) of
			not_found ->
			    capwap_station_sup:new_station(self(), FlowSwitch, PeerId, BSS, SA, MacMode, TunnelMode);
			{ok, Station0} ->
			    lager:debug("TAKE-OVER: station ~p found as ~p", [{self(), SA}, Station0]),
			    ieee80211_station:take_over(Station0, self(), FlowSwitch, PeerId, BSS, MacMode, TunnelMode)
		    end;
		Ok = {ok, Station0} ->
		    lager:debug("station ~p found as ~p", [{self(), SA}, Station0]),
		    Ok
	    end,
    reply(Reply, run, State);

run({keep_alive, _FlowSwitch, Sw, _PeerId, Header, PayLoad}, _From, State) ->
    lager:debug("in RUN got expected keep_alive: ~p~n", [{Sw, Header, PayLoad}]),
    reply({reply, {Header, PayLoad}}, run, State).

run(timeout, State) ->
    lager:info("IdleTimeout in Run~n"),
    next_state(run, State);

run({echo_request, Seq, Elements, #capwap_header{
			  radio_id = RadioId, wb_id = WBID, flags = Flags}},
    State) ->
    lager:debug("EchoReq in Run got: ~p~n", [{Seq, Elements}]),
    Header = #capwap_header{radio_id = RadioId, wb_id = WBID, flags = Flags},
    State1 = send_response(Header, echo_response, Seq, Elements, State),
    next_state(run, State1);

run({ieee_802_11_wlan_configuration_response, _Seq,
	   Elements, _Header}, State) ->
    case proplists:get_value(result_code, Elements) of
	0 ->
	    lager:debug("IEEE 802.11 WLAN Configuration ok"),
	    ok;
	Code ->
	    lager:warning("IEEE 802.11 WLAN Configuration failed with ~w~n", [Code]),
	    ok
    end,
    next_state(run, State);

run({station_configuration_response, _Seq,
     Elements, _Header}, State) ->
    %% TODO: timeout and Error handling, e.g. shut the station process down when the Add Station failed
    case proplists:get_value(result_code, Elements) of
	0 ->
	    lager:debug("Station Configuration ok"),
	    ok;
	Code ->
	    lager:warning("Station Configuration failed with ~w~n", [Code]),
	    ok
    end,
    next_state(run, State);

run(configure, State = #state{id = WtpId}) ->
    lager:debug("configure WTP: ~p", [WtpId]),
    RadioId = 1,
    App = capwap,
    DefaultSSID = application:get_env(App, default_ssid, <<"CAPWAP">>),
    SSIDs = application:get_env(App, ssids, []),
    DynSSIDSuffixLen = application:get_env(App, dynamic_ssid_suffix_len, false),
    SSID = case proplists:get_value({WtpId, RadioId}, SSIDs) of
	       undefined
		 when is_integer(DynSSIDSuffixLen), is_binary(WtpId) ->
                   binary:list_to_bin([DefaultSSID, $-, binary:part(WtpId, size(WtpId) - DynSSIDSuffixLen, DynSSIDSuffixLen)]);
               WtpSSID
		 when is_binary(WtpSSID) ->
                   WtpSSID;
	       _ ->
                   DefaultSSID
           end,
    WBID = 1,
    Flags = [{frame,'802.3'}],
    MacMode = select_mac_mode(State#state.mac_types),
    TunnelMode = select_tunnel_mode(State#state.tunnel_modes, MacMode),
    ReqElements = [#ieee_802_11_add_wlan{
    		      radio_id      = RadioId,
    		      wlan_id       = 1,
    		      capability    = [ess, short_slot_time],
    		      auth_type     = open_system,
    		      mac_mode      = MacMode,
    		      tunnel_mode   = TunnelMode,
    		      suppress_ssid = 1,
		      ssid          = SSID
    		     }],
    Header1 = #capwap_header{radio_id = RadioId, wb_id = WBID, flags = Flags},
    State1 = State#state{mac_mode = MacMode, tunnel_mode = TunnelMode},
    State2 = send_request(Header1, ieee_802_11_wlan_configuration_request, ReqElements, State1),
    next_state(run, State2);

run({add_station, #capwap_header{radio_id = RadioId, wb_id = WBID}, MAC}, State) ->
    Flags = [{frame,'802.3'}],
    ReqElements = [#add_station{
    		      radio_id  = RadioId,
		      mac       = MAC,
		      vlan_name = <<>>
		     }],
    Header1 = #capwap_header{radio_id = RadioId, wb_id = WBID, flags = Flags},
    State1 = send_request(Header1, station_configuration_request, ReqElements, State),
    next_state(run, State1);

run({del_station, #capwap_header{radio_id = RadioId, wb_id = WBID}, MAC}, State) ->
    Flags = [{frame,'802.3'}],
    ReqElements = [#delete_station{
    		      radio_id  = RadioId,
		      mac       = MAC
		     }],
    Header1 = #capwap_header{radio_id = RadioId, wb_id = WBID, flags = Flags},
    State1 = send_request(Header1, station_configuration_request, ReqElements, State),
    next_state(run, State1);

run({wtp_event_request, Seq, Elements, RequestHeader =
	 #capwap_header{radio_id = RadioId, wb_id = WBID, flags = Flags}}, State) ->
    ResponseHeader = #capwap_header{radio_id = RadioId, wb_id = WBID, flags = Flags},
    State1 = send_response(ResponseHeader, wtp_event_response, Seq, [], State),
    State2 = handle_wtp_event(Elements, RequestHeader, State1),
    Now = calendar:now_to_universal_time(erlang:now()),
    {FormatString, FormatVars} = lists:foldl(
                                   fun
                                       ({Key, Value}, {FStr, FVars}) ->
                                           {FStr ++ "~p(~p), ", FVars ++ [Key, Value]};
                                       (Record, {FStr, FVars}) ->
                                           {FStr ++ "~p, ", FVars ++ [Record]}
                                   end, {"~p@~p: ", [State#state.id, Now]}, Elements),
    EventData = io_lib:format(FormatString ++ "~n", FormatVars),
    ok = file:write(State#state.event_log, EventData),
    next_state(run, State2);

run(Event, State) ->
    lager:warning("in RUN got unexpexted: ~p~n", [Event]),
    next_state(run, State).

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
    next_state(StateName, State).

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
handle_sync_event(get_peer_data, _From, run, State) ->
    Reply = {ok, State#state.peer_data},
    reply(Reply, run, State);
handle_sync_event(get_peer_data, _From, StateName, State) ->
    Reply = {error, not_connected},
    reply(Reply, StateName, State);
handle_sync_event({take_over, NewWtp}, _From, _StateName, State) ->
    %% TODO: move Stations to new wtp
    lager:debug("take_over: old: ~p, new: ~p", [self(), NewWtp]),
    capwap_wtp_reg:unregister(),
    Reply = ok,
    {stop, normal, Reply, State};
handle_sync_event(_Event, _From, StateName, State) ->
    Reply = ok,
    reply(Reply, StateName, State).

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
    lager:debug("in State ~p got UDP: ~p~n", [StateName, Packet]),
    handle_capwap_packet(Packet, StateName, State);

handle_info({ssl, Socket, Packet}, StateName, State = #state{socket = {_, Socket}}) ->
    lager:debug("in State ~p got DTLS: ~p~n", [StateName, Packet]),
    handle_capwap_packet(Packet, StateName, State);

handle_info({timeout, _, retransmit}, StateName, State) ->
    resend_request(StateName, State);
handle_info(Info, StateName, State) ->
    lager:warning("in State ~p unexpected Info: ~p~n", [StateName, Info]),
    next_state(StateName, State).

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
terminate(Reason, StateName,
	  State = #state{peer_data = PeerId, event_log=EventLog,
			 flow_switch = FlowSwitch, socket = Socket,
			 session = Session}) ->
    error_logger:info_msg("AC session terminating in state ~p with state ~p with reason ~p~n", [StateName, State, Reason]),
    case StateName of
        run ->
            FlowSwitch ! {wtp_down, PeerId},
            ok;
        _ ->
            ok
    end,
    if Session /= undefined -> ctld_session:stop(Session, []);
       true -> ok
    end,
    socket_close(Socket),
    stop_trace(EventLog),
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

next_state(NextStateName, State)
  when NextStateName == idle ->
    {next_state, NextStateName, State};
next_state(NextStateName, State) ->
     {next_state, NextStateName, State, ?IDLE_TIMEOUT}.

reply(Reply, NextStateName, State)
  when NextStateName == idle ->
    {reply, Reply, NextStateName, State};
reply(Reply, NextStateName, State) ->
    {reply, Reply, NextStateName, State, ?IDLE_TIMEOUT}.

%% non-DTLS join-reqeust, check app config
handle_plain_join(Seq, _Elements, #capwap_header{
			 radio_id = RadioId, wb_id = WBID, flags = Flags}) ->
    case application:get_env(capwap, enforce_dtls_control, true) of
	false ->
	    lager:warning("Accepting JOIN with DTLS"),
	    accept;
	_ ->
	    lager:warning("Rejecting JOIN without DTLS"),
	    RespElems = [#result_code{result_code = 18}],
	    Header = #capwap_header{radio_id = RadioId, wb_id = WBID, flags = Flags},
	    Answer = capwap_packet:encode(control, {Header, {join_response, Seq, RespElems}}),
	    {reply, Answer}
    end.

handle_capwap_data(FlowSwitch, Sw, Address, Port, Header, true, PayLoad) ->
    lager:debug("CAPWAP Data KeepAlive: ~p~n", [PayLoad]),

    SessionId = proplists:get_value(session_id, PayLoad),
    case capwap_wtp_reg:lookup_sessionid(Address, SessionId) of
	not_found ->
	    {error, not_found};
	{ok, AC} ->
	    PeerId = {Address, Port},
	    case gen_fsm:sync_send_event(AC, {keep_alive, FlowSwitch, Sw, PeerId, Header, PayLoad}) of
		{reply, {RHeader, RPayLoad}} ->
		    Data = capwap_packet:encode(data, {RHeader, RPayLoad}),
		    {reply, Data};
		Other ->
		    Other
	    end
    end;

handle_capwap_data(_FlowSwitch, Sw, Address, Port,
		   Header = #capwap_header{
		     flags = Flags,
		     radio_id = RadioId, wb_id = WBID},
		   false, Frame) ->
    lager:debug("CAPWAP Data PayLoad:~n~p~n~p~n", [Header, Frame]),
    PeerId = {Address, Port},
    case capwap_wtp_reg:lookup(PeerId) of
	not_found ->
	    lager:warning("AC for data session no found: ~p~n", [PeerId]),
	    {error, not_found};
	{ok, AC} ->
	    %% TODO: multiple highly redundant case to follow, find a way to simplify
	    case proplists:get_value(frame, Flags) of
		'802.3' ->
		    lager:warning("got 802.3 payload Frame, what TODO with it???"),
		    case ieee80211_station:handle_ieee802_3_frame(AC, Frame) of
			{add, RadioMAC, MAC, MacMode, TunnelMode} ->
			    gen_fsm:send_event(AC, {add_station, Header, MAC}),
			    lager:debug("MacMode: ~w, TunnelMode ~w~n", [MacMode, TunnelMode]),
			    {add_flow, Sw, self(), Address, Port, RadioMAC, MAC, MacMode, TunnelMode};

			{flow, RadioMAC, MAC, MacMode, TunnelMode} ->
			    {add_flow, Sw, self(), Address, Port, RadioMAC, MAC, MacMode, TunnelMode};

			Other ->
			    Other
		    end;

		native ->
		    case ieee80211_station:handle_ieee80211_frame(AC, Frame) of
			{reply, Reply} ->
			    %% build capwap packet....
			    RHeader = #capwap_header{
			      radio_id = RadioId,
			      wb_id = WBID,
			      flags = [{frame, 'native'}]},
			    Data = capwap_packet:encode(data, {RHeader, Reply}),
			    {reply, Data};

			{add, RadioMAC, MAC, MacMode, TunnelMode} ->
			    gen_fsm:send_event(AC, {add_station, Header, MAC}),
			    lager:debug("MacMode: ~w, TunnelMode ~w~n", [MacMode, TunnelMode]),
			    {add_flow, Sw, self(), Address, Port, RadioMAC, MAC, MacMode, TunnelMode};

			{flow, RadioMAC, MAC, MacMode, TunnelMode} ->
			    {add_flow, Sw, self(), Address, Port, RadioMAC, MAC, MacMode, TunnelMode};

			{del, RadioMAC, MAC, MacMode, TunnelMode} ->
			    gen_fsm:send_event(AC, {del_station, Header, MAC}),
			    {del_flow, Sw, self(), Address, Port, RadioMAC, MAC, MacMode, TunnelMode};

			Other ->
			    Other
		    end;

		_ ->
		    {error, unknown_frame_format}
	    end
    end.

handle_capwap_packet(Packet, StateName, State = #state{
					  last_response = LastResponse,
					  last_request = LastRequest}) ->
    try	capwap_packet:decode(control, Packet) of
	{Header, {Msg, 1, Seq, Elements}} ->
	    %% Request
	    lager:debug("got capwap request: ~w~n", [Msg]),
	    case LastResponse of
		{Seq, _} ->
		    resend_response(State),
		    {next_state, StateName, State, ?IDLE_TIMEOUT};
		{LastSeq, _} when ?SEQ_LE(Seq, LastSeq) ->
		    %% old request, silently ignore
		    {next_state, StateName, State, ?IDLE_TIMEOUT};
		_ ->
		    ?MODULE:StateName({Msg, Seq, Elements, Header}, State)
	    end;
	{Header, {Msg, 0, Seq, Elements}} ->
	    %% Response
	    lager:debug("got capwap response: ~w~n", [Msg]),
	    case LastRequest of
		{Seq, _} ->
		    State1 = ack_request(State),
		    ?MODULE:StateName({Msg, Seq, Elements, Header}, State1);
		_ ->
		    %% invalid Seq, out-of-order packet, silently ignore,
		    {next_state, StateName, State, ?IDLE_TIMEOUT}
	    end
    catch
	Class:Error ->
	    lager:error([{capwap_packet, decode}, {class, Class}, {error, Error}], "Decode error ~p:~p", [Class, Error]),
	    {next_state, StateName, State, ?IDLE_TIMEOUT}
    end.

handle_wtp_event(Elements, Header, State = #state{session = Session}) ->
    SessionOptsList = lists:foldl(fun(Ev, SOptsList) -> handle_wtp_stats_event(Ev, Header, SOptsList) end, [], Elements),
    if length(SessionOptsList) /= 0 ->
	    ctld_session:interim_batch(Session, SessionOptsList);
       true -> ok
    end,
    State.

handle_wtp_stats_event(#tp_wtp_wwan_statistics_0_9{timestamp = Timestamp, wwan_id = WWanId, rat = RAT,
					     rssi = RSSi, lac = LAC, cell_id = CellId},
		 _Header, SOptsList) ->
    Opts = orddict:from_list([{'TP-CAPWAP-Timestamp', Timestamp},
			      {'TP-CAPWAP-WWAN-Id',   WWanId},
			      {'TP-CAPWAP-WWAN-RAT',       RAT},
			      {'TP-CAPWAP-WWAN-RSSi',      RSSi},
			      {'TP-CAPWAP-WWAN-LAC',       LAC},
			      {'TP-CAPWAP-WWAN-Cell-Id',   CellId}]),
    lager:debug("WTP Event Opts: ~p", [Opts]),
    [Opts|SOptsList];
handle_wtp_stats_event(#tp_wtp_wwan_statistics{timestamp = Timestamp, wwan_id = WWanId, rat = RAT,
					 rssi = RSSi, creg = CREG, lac = LAC, latency = Latency,
					 mcc = MCC, mnc = MNC, cell_id = CellId},
		 _Header, SOptsList) ->
    Opts = orddict:from_list([{'TP-CAPWAP-Timestamp', Timestamp},
			      {'TP-CAPWAP-WWAN-Id',   WWanId},
			      {'TP-CAPWAP-WWAN-RAT',       RAT},
			      {'TP-CAPWAP-WWAN-RSSi',      RSSi},
			      {'TP-CAPWAP-WWAN-CREG',      CREG},
			      {'TP-CAPWAP-WWAN-LAC',       LAC},
			      {'TP-CAPWAP-WWAN-Latency',   Latency},
			      {'TP-CAPWAP-WWAN-MCC',       MCC},
			      {'TP-CAPWAP-WWAN-MNC',       MNC},
			      {'TP-CAPWAP-WWAN-Cell-Id',   CellId}]),
    lager:debug("WTP Event Opts: ~p", [Opts]),
    [Opts|SOptsList];
handle_wtp_stats_event(_Event, _Header, SOptsList) ->
    SOptsList.

map_aalwp({Priority, Name}) when is_binary(Name) ->
    #tp_ac_address_with_priority{
	   priority = Priority,
	   type = 0,
	   value = Name
	  };
map_aalwp({Priority, IPv4 = {_,_,_,_}}) ->
    #tp_ac_address_with_priority{
	   priority = Priority,
	   type = 1,
	   value = tuple_to_ip(IPv4)
	  };
map_aalwp({Priority, IPv6 = {_,_,_,_,_,_,_,_}}) ->
    #tp_ac_address_with_priority{
	   priority = Priority,
	   type = 2,
	   value = tuple_to_ip(IPv6)
	  }.

s2i(V) ->
    case string:to_integer(V) of
	{Int, []} -> Int;
	_         -> V
    end.

split_version(Value) ->
    [s2i(V) || V <- string:tokens(binary_to_list(Value), ".-")].

get_wtp_version(Elements) ->
    case lists:keyfind(wtp_descriptor, 1, Elements) of
	#wtp_descriptor{sub_elements=SubElements} ->
	    case lists:keyfind({18681,0}, 1, SubElements) of
		{_, Value} ->
		    [Major, Minor, Patch|AddOn] = split_version(Value),
		    {Major * 65536 + Minor * 256 + Patch, AddOn};
		_ ->
		    {0, undefined}
	    end;
	_ ->
	    {0, undefined}
    end.

wtp_accounting_infos([], Acc) ->
    Acc;
wtp_accounting_infos([#wtp_descriptor{sub_elements = SubElements}|Elements], Acc) ->
    Acc1 = wtp_accounting_descriptor_infos(SubElements, Acc),
    wtp_accounting_infos(Elements, Acc1);
wtp_accounting_infos([{session_id, Value}|Elements], Acc)
  when is_integer(Value) ->
    Acc1 = [{'TP-CAPWAP-Session-Id', <<Value:128>>}|Acc],
    wtp_accounting_infos(Elements, Acc1);
wtp_accounting_infos([_|Elements], Acc) ->
    wtp_accounting_infos(Elements, Acc).

wtp_accounting_descriptor_infos([], Acc) ->
    Acc;
wtp_accounting_descriptor_infos([{{18681,0}, Version}|Elements], Acc)
  when is_binary(Version) ->
    Acc1 = [{'TP-CAPWAP-WTP-Version', Version}|Acc],
    wtp_accounting_descriptor_infos(Elements, Acc1);
wtp_accounting_descriptor_infos([_|Elements], Acc) ->
    wtp_accounting_descriptor_infos(Elements, Acc).

ac_info(Elements) ->
    Version = get_wtp_version(Elements),
    lager:debug("ac_info version: ~p", [Version]),
    ac_info_version(Version).

ac_info_version({Version, _AddOn}) ->
    App = capwap,
    Versions = application:get_env(App, versions, []),
    AcList = if Version > 16#010104 ->
		     [map_aalwp(I) || I <- application:get_env(App, ac_address_list_with_prio, [])];

		true -> []
	     end,
    [#ac_descriptor{stations    = 0,
		    limit       = application:get_env(App, limit, 200),
		    active_wtps = 0,
		    max_wtps    = application:get_env(App, max_wtps, 200),
%%		    security    = ['pre-shared'],
		    security    = application:get_env(App, security, ['x509']),
		    r_mac       = supported,
		    dtls_policy = ['clear-text'],
		    sub_elements = [{{0,4}, proplists:get_value(hardware, Versions, <<"Hardware Ver. 1.0">>)},
				    {{0,5}, proplists:get_value(software, Versions, <<"Software Ver. 1.0">>)}]},
     #ac_name{name = application:get_env(App, ac_name, <<"My AC Name">>)}
    ] ++ control_addresses(App) ++ AcList.

send_info_after(Time, Event) ->
    erlang:start_timer(Time, self(), Event).

bump_seqno(State = #state{seqno = SeqNo}) ->
    State#state{seqno = (SeqNo + 1) rem 256}.

send_response(Header, MsgType, Seq, MsgElems,
	   State = #state{socket = Socket}) ->
    lager:debug("send capwap response(~w): ~w~n", [Seq, MsgType]),
    BinMsg = capwap_packet:encode(control, {Header, {MsgType, Seq, MsgElems}}),
    ok = socket_send(Socket, BinMsg),
    State#state{last_response = {Seq, BinMsg}}.

resend_response(#state{socket = Socket, last_response = {_, BinMsg}}) ->
    lager:warning("resend capwap response~n", []),
    ok = socket_send(Socket, BinMsg).

send_request(Header, MsgType, ReqElements,
	     State = #state{socket = Socket, seqno = SeqNo}) ->
    lager:debug("send capwap request(~w): ~w~n", [SeqNo, MsgType]),
    BinMsg = capwap_packet:encode(control, {Header, {MsgType, SeqNo, ReqElements}}),
    ok = socket_send(Socket, BinMsg),
    State1 = State#state{last_request = {SeqNo, BinMsg},
			 retransmit_timer = send_info_after(?RetransmitInterval, retransmit),
			 retransmit_counter = ?MaxRetransmit
		   },
    bump_seqno(State1).

resend_request(StateName, State = #state{retransmit_counter = 0}) ->
    lager:debug("Final Timeout in ~w, STOPPING~n", [StateName]),
    {stop, normal, State};
resend_request(StateName,
	       State = #state{socket = Socket,
			      last_request = {_, BinMsg},
			      retransmit_counter = MaxRetransmit}) ->
    lager:warning("resend capwap request~n", []),
    ok = socket_send(Socket, BinMsg),
    State1 = State#state{retransmit_timer = send_info_after(?RetransmitInterval, retransmit),
			 retransmit_counter = MaxRetransmit - 1
			},
    {next_state, StateName, State1, ?IDLE_TIMEOUT}.


%% Stop Timer, clear LastRequest
ack_request(State0) ->
    State1 = State0#state{last_request = undefined},
    cancel_retransmit(State1).

cancel_retransmit(State = #state{retransmit_timer = undefined}) ->
    State;
cancel_retransmit(State = #state{retransmit_timer = Timer}) ->
    gen_fsm:cancel_timer(Timer),
    State#state{retransmit_timer = undefined}.

control_addresses(App) ->
    case application:get_env(App, control_ips) of
	{ok, IPs} when is_list(IPs) ->
	    [control_address(IP) || IP <- IPs];
	_ ->
	    case application:get_env(App, server_ip) of
		{ok, IP} ->
		    [control_address(IP)];
		_ ->
		    all_local_control_addresses()
	    end
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

answer_discover(Seq, Elements, #capwap_header{
		       radio_id = RadioId, wb_id = WBID, flags = Flags}) ->
    lager:debug("discover_request: ~p~n", [[lager:pr(E, ?MODULE) || E <- Elements]]),
    RespElems = ac_info(Elements),
    Header = #capwap_header{radio_id = RadioId, wb_id = WBID, flags = Flags},
    capwap_packet:encode(control, {Header, {discovery_response, Seq, RespElems}}).

socket_send({udp, Socket}, Data) ->
    capwap_udp:send(Socket, Data);
socket_send({dtls, Socket}, Data) ->
    ssl:send(Socket, Data).

stop_trace(undefined) ->
    ok;
stop_trace(Trace) ->
    ok = file:close(Trace).

socket_close({udp, Socket}) ->
    capwap_udp:close(Socket);
socket_close({dtls, Socket}) ->
    ssl:close(Socket);
socket_close(undefined) ->
    ok;
socket_close(Socket) ->
    lager:warning("Got Close on: ~p~n", [Socket]),
    ok.

user_lookup(srp, Username, _UserState) ->
    lager:debug("srp: ~p~n", [Username]),
    Salt = ssl:random_bytes(16),
    UserPassHash = crypto:hash(sha, [Salt, crypto:hash(sha, [Username, <<$:>>, <<"secret">>])]),
    {ok, {srp_1024, Salt, UserPassHash}};

user_lookup(psk, Username, Session) ->
    lager:debug("user_lookup: Username: ~p~n", [Username]),
    Opts = [{'Username', Username},
	    {'Authentication-Method', {'TLS', 'Pre-Shared-Key'}}],
    case ctld_session:authenticate(Session, Opts) of
	success ->
	    lager:info("AuthResult: success~n"),
	    case ctld_session:get(Session, 'TLS-Pre-Shared-Key') of
		{ok, PSK} ->
		    lager:info("AuthResult: PSK: ~p~n", [PSK]),
		    {ok, PSK};
		_ ->
		    lager:info("AuthResult: NO PSK~n"),
		    {error, "no PSK"}
	    end;
	Other ->
	    lager:info("AuthResult: ~p~n", [Other]),
	    {error, Other}
    end.

verify_cert(_,{bad_cert, _} = Reason, _) ->
    {fail, Reason};
verify_cert(_,{extension, _}, UserState) ->
    {unknown, UserState};
verify_cert(_, valid, UserState) ->
    {valid, UserState};
verify_cert(#'OTPCertificate'{
	       tbsCertificate =
		   #'OTPTBSCertificate'{
		 subject = {rdnSequence, SubjectList},
		 extensions = Extensions
		}}, valid_peer, UserState) ->
    Subject = [erlang:hd(S)|| S <- SubjectList],
    {value, #'AttributeTypeAndValue'{value = {utf8String, CommonName}}} =
	lists:keysearch(?'id-at-commonName', #'AttributeTypeAndValue'.type, Subject),
    #'Extension'{extnValue = ExtnValue} =
	lists:keyfind(?'id-ce-extKeyUsage', #'Extension'.extnID, Extensions),

    case lists:member(?'id-kp-capwapWTP', ExtnValue) of
	true -> verify_cert_auth_cn(CommonName, UserState);
	_    -> {fail, "not a valid WTP certificate"}
    end.

verify_cert_auth_cn(CommonName, Session) ->
    Opts = [{'Username', CommonName},
	    {'Authentication-Method', {'TLS', 'X509-Subject-CN'}}],
    case ctld_session:authenticate(Session, Opts) of
        success ->
            lager:info("AuthResult: success for ~p", [CommonName]),
            {valid, Session};
        {fail, Reason} ->
            lager:info("AuthResult: fail, ~p for ~p", [Reason, CommonName]),
            {fail, Reason};
        Other ->
            lager:info("AuthResult: ~p for ~p", [Other, CommonName]),
            {fail, Other}
    end.

mk_ssl_opts(Session) ->
    App = capwap,
    Dir = case application:get_env(App, certs) of
	      {ok, Path} ->
		  Path;
	      _ ->
		  filename:join([code:lib_dir(App), "priv", "certs"])
	  end,

    [{active, false},
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
	       {ecdhe_psk, aes_128_cbc, sha},
	       {dhe_psk, aes_128_cbc,sha},
	       {psk, aes_128_cbc,sha},
	       {ecdhe_psk, aes_256_cbc, sha},
	       {dhe_psk, aes_256_cbc,sha},
	       {psk, aes_256_cbc,sha}]},

     {verify, verify_peer},
     {verify_fun, {fun verify_cert/3, Session}},
     {fail_if_no_peer_cert, true},

     {psk_identity, "CAPWAP"},
     {user_lookup_fun, {fun user_lookup/3, Session}},
     %% {ciphers,[{srp_dss, aes_256_cbc, sha}]},
     %% {ciphers, [{srp_anon, aes_256_cbc, sha}]},

     {cacertfile, filename:join([Dir, "cacerts.pem"])},
     {certfile, filename:join([Dir, "server.pem"])},
     {keyfile, filename:join([Dir, "server.key"])}
    ].

ip2str(IP) ->
    inet_parse:ntoa(IP).

tunnel_medium({_,_,_,_}) ->
    'IPv4';
tunnel_medium({_,_,_,_,_,_,_,_}) ->
    'IPv6'.

start_session(Socket, _State) ->
    SessionData = session_info(Socket),
    {ok, {Provider, ProviderOpts}} = application:get_env(ctld_provider),
    ctld_session_sup:new_session(?MODULE, self(), Provider, ProviderOpts, SessionData).

session_info(Socket) ->
    {ok, {Address, _Port}} = capwap_udp:peername(Socket),
    [{'Calling-Station', ip2str(Address)},
     {'Tunnel-Type', 'CAPWAP'},
     {'Tunnel-Medium-Type', tunnel_medium(Address)},
     {'Tunnel-Client-Endpoint', ip2str(Address)}].

ie(Key, Elements) ->
    proplists:get_value(Key, Elements).

select_mac_mode(local) ->
    local_mac;
select_mac_mode(split) ->
    split_mac;
select_mac_mode(both) ->
    local_mac.

select_tunnel_mode(Modes, local_mac) ->
    case proplists:get_bool('802.3', Modes) of
	true -> '802_3_tunnel';
	_    -> '802_11_tunnel'
    end;
select_tunnel_mode(_Modes, split_mac) ->
    '802_11_tunnel'.

tuple_to_ip({A, B, C, D}) ->
    <<A:8, B:8, C:8, D:8>>;
tuple_to_ip({A, B, C, D, E, F, G, H}) ->
    <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>.
