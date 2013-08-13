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
    case ssl:ssl_accept(Socket, mk_ssl_opts(Session)) of
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

            {ok, EventLog} = lager:trace_file(EventLogPath, [{class, wtp_statistics}], debug),
            State1 = State#state{event_log=EventLog, socket = {dtls, SslSocket}, session = Session, id = CommonName},
            %% TODO: find old connection instance, take over their StationState and stop them
            next_state(idle, State1);
        Other ->
            lager:error("ssl_accept failed: ~p~n", [Other]),
            {stop, normal, State}
    end;

listen(timeout, State) ->
    {stop, normal, State}.

idle({keep_alive, _FlowSwitch, _Sw, _PeerId, Header, PayLoad}, _From, State) ->
    lager:warning("in IDLE got unexpected keep_alive: ~p~n", [{Header, PayLoad}]),
    reply({error, unexpected}, idle, State).

idle(timeout, State) ->
    lager:info("timeout in IDLE -> stop~n"),
    {stop, normal, State};

idle({discovery_request, Seq, _Elements, #capwap_header{
				radio_id = RadioId, wb_id = WBID, flags = Flags}},
     State) ->
    RespElements = ac_info(),
    Header = #capwap_header{radio_id = RadioId, wb_id = WBID, flags = Flags},
    State1 = send_response(Header, discovery_response, Seq, RespElements, State),
    next_state(idle, State1);

idle({join_request, Seq, Elements, #capwap_header{
			   radio_id = RadioId, wb_id = WBID, flags = Flags}},
     State0 = #state{peer = {Address, _}}) ->
    lager:info("Join-Request: ~p~n", [Elements]),

    SessionId = proplists:get_value(session_id, Elements),
    capwap_wtp_reg:register_sessionid(Address, SessionId),

    MacTypes = ie(wtp_mac_type, Elements),
    TunnelModes = ie(wtp_frame_tunnel_mode, Elements),
    State1 = State0#state{mac_types = MacTypes, tunnel_modes = TunnelModes},

    RespElements = ac_info() ++ [#result_code{result_code = 0}],
    Header = #capwap_header{radio_id = RadioId, wb_id = WBID, flags = Flags},
    State = send_response(Header, join_response, Seq, RespElements, State1),
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

    RespElements = [%%#ac_ipv4_list{ip_address = [<<0,0,0,0>>]},
		    #timers{discovery = DiscoveryInterval,
			    echo_request = EchoRequestInterval},
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
    lager:warning("in RUN got new_station: ~p~n", [SA]),

    lager:debug("search Station ~p~n", [{self(), SA}]),
    %% we have to repeat the search again to avoid a race
    Reply = case capwap_station_reg:lookup(self(), SA) of
		not_found ->
		    lager:debug("not found~n"),
		    capwap_station_sup:new_station(self(), FlowSwitch, PeerId, BSS, SA, MacMode, TunnelMode);
		Ok = {ok, Station0} ->
		    lager:debug("found as ~p~n", [Station0]),
		    Ok
	    end,
    reply(Reply, run, State);

run({keep_alive, _FlowSwitch, Sw, _PeerId, Header, PayLoad}, _From, State) ->
    lager:debug("in RUN got expected keep_alive: ~p~n", [{Sw, Header, PayLoad}]),
    reply({reply, {Header, PayLoad}}, run, State).

run(timeout, State) ->
    lager:info("IdleTimeout in Run~n"),
    Header = #capwap_header{radio_id = 0, wb_id = 1, flags = []},
    Elements = [],
    State1 = send_request(Header, echo_request, Elements, State),
    next_state(run, State1);

run({echo_request, Seq, Elements, #capwap_header{
			  radio_id = RadioId, wb_id = WBID, flags = Flags}},
    State) ->
    lager:debug("EchoReq in Run got: ~p~n", [{Seq, Elements}]),
    Header = #capwap_header{radio_id = RadioId, wb_id = WBID, flags = Flags},
    State1 = send_response(Header, echo_response, Seq, Elements, State),
    next_state(run, State1);

run(configure, State = #state{id = WtpId}) ->
    lager:debug("configure WTP: ~p", [WtpId]),
    {TStamp, _} = now_to_sntp_time(erlang:now()),
    RadioId = 1,
    WBID = 1,
    Flags = [{frame,'802.3'}],
    ReqElements = [#ac_timestamp{timestamp = TStamp}],
    Header1 = #capwap_header{radio_id = RadioId, wb_id = WBID, flags = Flags},
    State1 = send_request(Header1, configuration_update_request, ReqElements, State),
    next_state(run, State1);

run({configuration_update_response, _Seq, Elements, _Header}, State) ->
    case proplists:get_value(result_code, Elements) of
	0 ->
	    lager:debug("Configuration Update ok"),
	    ok;
	Code ->
	    lager:warning("Configuration Update with ~w~n", [Code]),
	    %% ignore failures
	    ok
    end,
    run(configure_wlan, State);

run(configure_wlan, State = #state{id = WtpId}) ->
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

run({ieee_802_11_wlan_configuration_response, _Seq, Elements, _Header}, State) ->
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

run({wtp_event_request, Seq, Elements, #capwap_header{radio_id = RadioId, wb_id = WBID, 
                                                       flags = Flags}}, State) ->
    Header = #capwap_header{radio_id = RadioId, wb_id = WBID, flags = Flags},
    State1 = send_response(Header, wtp_event_response, Seq, [], State),
    Now = calendar:now_to_universal_time(erlang:now()),
    {FormatString, FormatVars} = lists:foldl(
                                   fun({Key, Value}, {FStr, FVars}) ->
                                           {FStr ++ "~p(~p), ", FVars ++ [Key, Value]}
                                   end, {"~p@~p: ", [State#state.id, Now]}, Elements),
    lager:debug([{class, wtp_statistics}], FormatString, FormatVars),
    next_state(run, State1);

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
terminate(Reason, StateName, #state{peer_data = PeerId, event_log=EventLog, session=Session,
                                    flow_switch = FlowSwitch, socket = Socket}=State) ->
    error_logger:info_msg("AC session terminating in state ~p with state ~p with reason ~p~n", [StateName, State, Reason]),
    % FIXME: why does lager crash at this point?
    % lager:debug("CAPWAP WTP Session ~p terminating in state ~p with reason ~p", [PeerId, StateName, Reason]),
    case StateName of
        run ->
            FlowSwitch ! {wtp_down, PeerId},
            ok;
        _ ->
            ok
    end,
    %ctld_session:stop(Session, []),
    ctld_session:terminate(Session),
    %socket_close(Socket),
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

ac_info() ->
    App = capwap,
    Versions = application:get_env(App, versions, []),
    AcList = case application:get_env(App, ac_ipv4_list, []) of
                 [] ->
                     [];
                 AcIps when is_list(AcIps) ->
                     [#ac_ipv4_list{ip_address=AcIps}];
                 _ ->
                     []
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
    lager:debug("Finial Timeout in ~w, STOPPING~n", [StateName]),
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

answer_discover(Seq, _Elements, #capwap_header{
		       radio_id = RadioId, wb_id = WBID, flags = Flags}) ->
    RespElems = ac_info(),
    Header = #capwap_header{radio_id = RadioId, wb_id = WBID, flags = Flags},
    capwap_packet:encode(control, {Header, {discovery_response, Seq, RespElems}}).

socket_send({udp, Socket}, Data) ->
    capwap_udp:send(Socket, Data);
socket_send({dtls, Socket}, Data) ->
    ssl:send(Socket, Data).

stop_trace(undefined) ->
    ok;
stop_trace(Trace) ->
    lager:stop_trace(Trace).

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

%% sntp_time_to_now({Sec, USec}) ->
%%     case Sec band 16#80000000 of
%% 	0 -> Time = Sec + 2085978496; % use base: 7-Feb-2036 @ 06:28:16 UTC
%% 	_ -> Time = Sec - 2208988800  % use base: 1-Jan-1900 @ 01:00:00 UTC
%%     end,
%%     {Time div 1000000, Time rem 1000000, round((USec * 1000000) / (1 bsl 32))}.

now_to_sntp_time({_,_,USec} = Now) ->
    %% calendar:datetime_to_gregorian_seconds({{1900,1,1}, {0,0,0}})   == 59958230400
    %% calendar:datetime_to_gregorian_seconds({{2036,2,7}, {6,28,16}}) == 64253197696
    Seconds =
	case calendar:datetime_to_gregorian_seconds(calendar:now_to_universal_time(Now)) of
	    SecsSinceFeb2036 when SecsSinceFeb2036 >= 64253197696 ->
		SecsSinceFeb2036 - 64253197696;
	    SecsSinceJan1900 ->
		16#80000000 bor SecsSinceJan1900 - 59958230400
	end,
    {Seconds, round(USec * (1 bsl 32) / 1000000)}.
