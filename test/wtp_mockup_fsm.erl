-module(wtp_mockup_fsm).
-compile([{parse_transform, lager_transform}]).

-behaviour(gen_fsm).

-include("../include/capwap_packet.hrl").

%% API
-export([start_link/0,
	 start_link/8,
	 stop/1,
	 send_discovery/1,
	 send_join/1,
	 send_config_status/1,
	 send_change_state_event/1,
	 send_wwan_statistics/1,
	 send_wwan_statistics/2,
	 add_station/2,
	 send_keep_alive/1
	]).

%% gen_fsm callbacks
-export([init/1,
	 idle/2, idle/3,
	 discovery/2, discovery/3,
	 configure/2, configure/3,
	 join/2, join/3,
	 run/2, run/3,
	 handle_event/3, handle_sync_event/4, handle_info/3, terminate/3, code_change/4]).

-define(SERVER, ?MODULE).
-define(Default_WTP_MAC, <<8,8,8,8,8,8>>).
-define(Default_Local_Control_Port, 5248).
-define(Default_SCG, {{127,0,0,1}, 5246}).

-record(state, {control_socket,
		data_socket,
		ctrl_stream,
		owner,
		seqno,
		stations,
		remote_mode,
		cert_dir,
		root_cert,
		ip,
		mac,
		scg,
		simulated_data_port,
		next_resp,
		echo_request_timer,
		echo_request_timeout,
		flow_switches,
		capwap_wtp_session_id,
		wifi_up,
		request_pending,
		keep_alive_timer,
		keep_alive_timeout,
        options
	       }).

%%%===================================================================
%%% API
%%%===================================================================
%% Params: (SCG, LocalIpAddress, LocalControlPort, CertDir, LocalMacAddresss, RemoteMode)
start_link() ->
    start_link(?Default_SCG, {127,0,0,1}, ?Default_Local_Control_Port, "./", "./root.pem", ?Default_WTP_MAC, false, []).

start_link(SCG, IP, Port, CertDir, RootCert, Mac, RemoteMode, Options) ->
    gen_fsm:start_link(?MODULE, [SCG, IP, Port, CertDir, RootCert, Mac, RemoteMode, self(), Options], []).

stop(WTP) ->
    MonitorRef = monitor(process, WTP),
    gen_fsm:sync_send_all_state_event(WTP, stop),
    receive
	{'DOWN', MonitorRef, _, _, _} ->
	    ok
    end.

send_discovery(WTP_FSM) ->
    gen_fsm:sync_send_event(WTP_FSM, send_discovery).

send_join(WTP_FSM) ->
    gen_fsm:sync_send_event(WTP_FSM, send_join).

send_config_status(WTP_FSM) ->
    gen_fsm:sync_send_event(WTP_FSM, send_config_status).

send_change_state_event(WTP_FSM) ->
    gen_fsm:sync_send_event(WTP_FSM, send_change_state_event).

send_keep_alive(WTP_FSM) ->
    gen_fsm:sync_send_event(WTP_FSM, send_keep_alive).

send_wwan_statistics(WTP_FSM) ->
    gen_fsm:sync_send_event(WTP_FSM, send_wwan_statistics).

send_wwan_statistics(WTP_FSM, NoIEs) ->
    gen_fsm:sync_send_event(WTP_FSM, {send_wwan_statistics, NoIEs}).

add_station(WTP_FSM, Mac) ->
    case gen_fsm:sync_send_event(WTP_FSM, {add_station, Mac}) of
	wait_for_wifi ->
	    timer:sleep(100),
	    add_station(WTP_FSM, Mac);
	ok ->
	    ok
    end.

%%%===================================================================
%%% gen_fsm callbacks
%%%===================================================================

init([SCG = {SCGIP, SCGControlPort}, IP, Port, CertDir, RootCert, Mac, RemoteMode, Owner, Options]) ->
    {ok, ControlSocket} = capwap_udp:connect(SCGIP, SCGControlPort, [{active, false}, {mode, binary}, {ip, IP}]),

    DataSocket = case RemoteMode of
		     true ->
			 {ok, UdpDataSocket} = capwap_udp:connect(SCGIP, SCGControlPort + 1, [{active, false}, {mode, binary}, {ip, IP}]),
			 ok = capwap_udp:setopts(UdpDataSocket, [{active, true}]),
			 UdpDataSocket;
		     false ->
			 undefined
		 end,

    {ok, idle, #state{control_socket = ControlSocket,
		      data_socket = DataSocket,
		      ctrl_stream = capwap_stream:init(1500),
		      owner = Owner,
		      seqno = 0,
		      stations = [],
		      remote_mode = RemoteMode,
		      cert_dir = CertDir,
		      root_cert = RootCert,
		      ip = IP,
		      mac = Mac,
		      scg = SCG,
		      simulated_data_port = Port,
		      next_resp = undefined,
		      flow_switches = {spawn(fun()-> ok end),
				       spawn(fun()-> ok end)},
		      echo_request_timeout = 0,
		      keep_alive_timeout = 0,
		      capwap_wtp_session_id = random:uniform(329785637896618622174542098706248598340),
		      wifi_up = false,
		      request_pending = undefined,
              options = Options
		     }}.

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
idle(_Event, State) ->
    {next_state, idle, State}.

idle(send_discovery, _From, State) ->
    IEs = [#discovery_type{discovery_type = static}
	  ] ++ create_default_ies(),
    {resp, Resp, State0} = do_transition(State, control, discovery, {discovery_request, IEs}, udp_sync, req, undefined),
    lager:debug("got discovery response:  ~p", [Resp]),
    {reply, {ok, Resp}, discovery, State0};

idle(_Event, _From, State) ->
    {reply, {error, bad_event}, idle, State}.

discovery(_Event, State) ->
    {next_state, discovery, State}.

discovery(send_join, From, State=#state{control_socket = CS, ip = IP,
					 capwap_wtp_session_id = CapwapWtpSessionId}) ->
    S1 = case State#state.remote_mode of
	     true ->
		 lager:debug("connecting ssl socket with options ~p", [make_ssl_options(State)]),
		 ok = capwap_udp:setopts(CS, [{active, true}]),
		 {ok, SSLSocket} = ssl:connect(CS, make_ssl_options(State)),
		 ok = ssl:setopts(SSLSocket, [{active, true}]),
		 lager:debug("successfully connected ssl socket", []),
		 State#state{control_socket = SSLSocket};
	     _ ->
		 ok = capwap_udp:setopts(CS, [{active, true}]),
		 State
	 end,

    IEs = [#location_data{location = <<"  Next to Fridge">>},
	   #local_ipv4_address{ip_address = tuple_to_ip(IP)},
	   #wtp_name{wtp_name = <<"My WTP 1">>},
	   #session_id{session_id = CapwapWtpSessionId}
	  ] ++ create_default_ies(),
    do_transition(S1, control, discovery, {join_request, IEs}, async, req, {join_response, From});

discovery(_Event, _From, State) ->
    {reply, {error, bad_event}, discovery, State}.

join(_Event, State) ->
    {next_state, join, State}.

join(send_config_status, From, State) ->
    IEs = [#ac_name{name = <<" My AC">>},
	   #ac_name_with_priority{priority = 0, name = <<"ACPrimary">>},
	   #ac_name_with_priority{priority = 1, name = <<"ACSecondary">>},
	   #radio_administrative_state{radio_id = 0, admin_state = enabled},
	   #statistics_timer{statistics_timer = 120},
	   #wtp_reboot_statistics{},
	   #ieee_802_11_wtp_radio_information{radio_type = ['802.11g','802.11b']},
	   #ieee_802_11_supported_rates{supported_rates = <<130,132,139,150,12,18,24,36>>},
	   #ieee_802_11_multi_domain_capability{first_channel = 1,
						number_of_channels_ = 14,
						max_tx_power_level = 27}
	  ],
    do_transition(State, control, join, {configuration_status_request, IEs}, async, req, {configuration_status_response, From});

join(_Event, _From, State) ->
    {reply, {error, bad_event}, join, State}.

configure(_Event, State) ->
    {next_state, configure, State}.

configure(send_change_state_event, From, State) ->
    IEs =[#radio_operational_state{state = enabled},
	  #result_code{}
	 ],
    do_transition(State, control, configure,
		  {change_state_event_request, IEs},
		  async, req, {change_state_event_response, From});

configure(_Event, _From, State) ->
    {reply, {error, bad_event}, configure, State}.

run(echo_timeout, State) ->
    lager:debug("Echo Timeout in Run"),
    do_transition(State, control, run, {echo_request, []});

run(keep_alive_timeout, State = #state{capwap_wtp_session_id = CapwapWtpSessionId}) ->
    lager:debug("keep-alive Timeout in Run"),
    Flags = ['keep-alive', {frame,'802.3'}],
    KeepAliveIEs=[#session_id{session_id = CapwapWtpSessionId}],
    do_transition(State, data, run, {Flags, KeepAliveIEs});

run(_Event, State) ->
    {next_state, run, State}.

run(send_wwan_statistics, From, State) ->
    TimeStamp = timestamp(),
    IEs = [#tp_wtp_wwan_statistics{
	      latency = 5,
	      timestamp = TimeStamp},
	   #gps_last_acquired_position{
	      timestamp = TimeStamp,
	      gpsatc = <<"$GPSACP: 154750.000,5207.6688N,01137.8028E,0.7,62.4,2,196.4,45.7,24.7,030914,09">>}],
    do_transition(State, control, run, {wtp_event_request, IEs}, async, req, {wtp_event_response, From});

run({send_wwan_statistics, NoIEs}, From, State) ->
    TimeStamp = timestamp(),
    IE = [#tp_wtp_wwan_statistics{
	      latency = 5,
	      timestamp = TimeStamp},
	   #gps_last_acquired_position{
	      timestamp = TimeStamp,
	      gpsatc = <<"$GPSACP: 154750.000,5207.6688N,01137.8028E,0.7,62.4,2,196.4,45.7,24.7,030914,09">>}],
    IEs = lists:flatten(lists:duplicate(NoIEs, IE)),
    do_transition(State, control, run, {wtp_event_request, IEs}, async, req, {wtp_event_response, From});

run({add_station, _}, _From, State = #state{wifi_up = false}) ->
    {reply, wait_for_wifi, run, State};

run({add_station, Mac}, From, State = #state{mac = WTPMac,
					      wifi_up = true}) ->
    Unknown = 0,
    FromDS = 0,
    ToDS=0,
    {Type, SubType} = ieee80211_station:frame_type('Association Request'),
    FrameControl = <<SubType:4, Type:2, 0:2, Unknown:6, FromDS:1, ToDS:1>>,
    Duration = 0,
    DA = <<1:48>>,
    SA = Mac,
    BSS = WTPMac,
    SequenceControl = get_seqno(State),
    Frame = <<0:8>>,
    Payload = <<FrameControl:2/bytes,
		Duration:16, DA:6/bytes, SA:6/bytes, BSS:6/bytes,
		SequenceControl:16/little-integer, Frame/binary>>,
    Flags=[{frame, native}],
    lager:info("in state run adding station: ~p", [Mac]),
    do_transition(State, data, run, {Flags, Payload}, async, req, {add_station_resp, From});

    %% this transition provokes an error which occured before request queue was introduce into capwap_ac
    %% {TypeDis, SubTypeDis} = ieee80211_station:frame_type('Disassociation'),
    %% FrameControlDis = <<SubTypeDis:4, TypeDis:2, 0:2, Unknown:6, FromDS:1, ToDS:1>>,
    %% SequenceControlDis = SequenceControl + 1,
    %% PayloadDis = <<FrameControlDis:2/bytes,
    %% 		   Duration:16, DA:6/bytes, SA:6/bytes, BSS:6/bytes,
    %% 		   SequenceControlDis:16/little-integer, Frame/binary>>,
    %% do_transition(State, data, run, {Flags, PayloadDis}, async);



run(_Event, _From, State) ->
    {reply, {error, bad_event}, run, State}.


handle_event(_Event, StateName, State) ->
    {next_state, StateName, State}.

handle_sync_event(stop, _From, _StateName, State) ->
    {stop, normal, ok, State};
handle_sync_event(_Event, _From, StateName, State) ->
    {reply, ok, StateName, State}.

handle_info({ssl, Socket, Packet}, StateName, State = #state{control_socket = Socket}) ->
    DecRequest = capwap_packet:decode(control, Packet),
    lager:debug("in state ~p got control DTLS: ~p", [StateName, DecRequest]),
    handle_incoming(DecRequest, StateName, control, State);

handle_info({udp, CS, _IP, _InPort, Packet}, StateName, State=#state{control_socket = CS}) ->
    DecRequest = capwap_packet:decode(control, Packet),
    lager:debug("in state ~p got control udp: ~p", [StateName, DecRequest]),
    handle_incoming(DecRequest, StateName, control, State);

handle_info({udp, DS, _IP, _InPort, Packet}, StateName, State=#state{data_socket = DS}) ->
    DecRequest = capwap_packet:decode(data, Packet),
    lager:debug("in state ~p got data udp: ~p", [StateName, DecRequest]),
    handle_incoming(DecRequest, StateName, data, State);

handle_info({ssl, DS, _IP, _InPort, Packet}, StateName, State=#state{data_socket = DS}) ->
    DecRequest = capwap_packet:decode(data, Packet),
    lager:debug("in state ~p got data DTLS: ~p", [StateName, DecRequest]),
    handle_incoming(DecRequest, StateName, data, State);

handle_info(Info, StateName, State) ->
    lager:warning("in state ~p received unhandled info: ~p", [StateName, Info]),
    {next_state, StateName, State}.

terminate(_Reason, _StateName, _State) ->
    ok.

code_change(_OldVsn, StateName, State, _Extra) ->
    {ok, StateName, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

bump_seqno(State = #state{seqno = SeqNo}) ->
    State#state{seqno = (SeqNo + 1) rem 256}.

get_seqno(#state{seqno=SQNO}) ->
    SQNO.

send_capwap(State = #state{data_socket=DS, remote_mode=true}, data, Packet) ->
    ct:pal("send data capwap: ~p", [Packet]),
    gen_udp:send(DS, Packet),
    reset_keep_alive_timer(State);

send_capwap(#state{remote_mode=false} = State, data, []) ->
    reset_keep_alive_timer(State);
send_capwap(#state{data_socket=DS, remote_mode=false,
		   simulated_data_port = Port,
		   scg = {SCGIP, _}, ip = IP,
		  flow_switches = {SW1, SW2}
		  } = State,
	    data, [Packet|Rest]) ->
    ct:pal("send simulated data capwap: ~p", [Packet]),
    case capwap_ac:handle_data(SW1, SW2, IP, Port, Packet) of
	{reply, Resp}  ->
	    {udp, DS, SCGIP, Port + 1, Resp};
	_ ->
	    ok
    end,
    send_capwap(State, data, Rest);

send_capwap(State = #state{control_socket=CS, remote_mode=true}, control, Packet) ->
    ct:pal("send control ssl capwap: ~p", [Packet]),
    if is_list(Packet) ->
	    lists:foreach(fun(P) -> ok = ssl:send(CS, P) end, Packet);
       true ->
	    ok = ssl:send(CS, Packet)
    end,
    reset_echo_request_timer(State);

send_capwap(State = #state{control_socket=CS, remote_mode=false}, control, Packet) ->
    ct:pal("send control udp capwap: ~p", [Packet]),
    if is_list(Packet) ->
	    lists:foreach(fun(P) -> ok = gen_udp:send(CS, P) end, Packet);
       true ->
	    ok = gen_udp:send(CS, Packet)
    end,
    reset_echo_request_timer(State).

recv_capwap(#state{control_socket=CS, remote_mode=true}) ->
    {ok, Resp} = ssl:recv(CS, 1500, 2000),
    Resp;

recv_capwap(#state{control_socket=CS, remote_mode=false}) ->
    {ok, Resp} = capwap_udp:recv(CS, 1000, 1000),
    Resp.


create_header(#state{mac = MAC}) ->
    #capwap_header{radio_id = 0,
		   wb_id = 1,
		   flags = [{frame,'802.3'}],
		   radio_mac = MAC,
		   wireless_spec_info = undefined}.

do_transition(State, Type, NextState, Packet) ->
    do_transition(State, Type, NextState, Packet, async, req, undefined).

%% Format packet for data channel
do_transition(State, data, NextState, {Flags, IEs}, Mode, RespSeq, UserCallback)  when Flags =/= packet  ->
    Header = create_header(State),
    Header1 = Header#capwap_header{flags=Flags},
    ct:pal("do data encode: ~p", [{Header1, IEs}]),
    Packet = capwap_packet:encode(data,
				  {Header1, IEs}),
    do_transition(State, data, NextState, {packet, Packet}, Mode, RespSeq, UserCallback);

%% Format packet for control channel
do_transition(State = #state{ctrl_stream = CtrlStreamState0, seqno = SeqNum},
	      control, NextState, {ReqType, IEs},
	      Mode, RespSeq, UserCallback) when ReqType =/= packet ->
    Header = create_header(State),
    SeqNumToUse = case RespSeq of
		      {resp, RespSeqNum} ->
			  RespSeqNum;
		      req ->
			  SeqNum
		  end,

    Msg = {Header, {ReqType, SeqNumToUse, IEs}},
    {Packet, CtrlStreamState1} = capwap_stream:encode(control, Msg, CtrlStreamState0),
    lager:debug("in do_transition, ~p to send: ~p", [ReqType, Packet]),

    do_transition(State#state{ctrl_stream = CtrlStreamState1}, control,
		  NextState, {packet, Packet}, Mode, RespSeq, UserCallback);

%% send packet and make state transition
%% mode = async | udp_sync
%% udp_sync: forces udp usage when otherwise capwapa-dtls would be used
do_transition(State=#state{remote_mode = RemoteMode,
			   request_pending=undefined},
	      Type, NextState, {packet, Packet},
	      Mode, RespSeq, UserCallback) ->
    State0 = case Mode of
		 udp_sync ->
		     S1 = send_capwap(State#state{remote_mode = false}, Type, Packet),
		     S1#state{remote_mode = RemoteMode};
		 _ ->
		     send_capwap(State, Type, Packet)
	     end,
    State1 = case UserCallback of
		 undefined ->
		     State0;
		 {RespType, From} ->
		     State0#state{request_pending={RespType,From}}
	     end,
    case {Type, Mode, RespSeq} of
	{control, udp_sync, _} ->
	    Resp = recv_capwap(State1#state{remote_mode = false}),
	    DecResp = capwap_packet:decode(control, Resp),
	    {resp, DecResp, bump_seqno(State1)};
	{_, _, {resp, _}} ->
	    {next_state, NextState, State1};
	{control, _, req} ->
	    {next_state, NextState, bump_seqno(State1)};
	{data, _, req} ->
	    {next_state, NextState, State1}
    end.

create_default_ies() ->
    [#ieee_802_11_wtp_radio_information{radio_type = ['802.11g','802.11b']},
     #wtp_mac_type{mac_type = local},
     #wtp_frame_tunnel_mode{mode = [native]},
     #wtp_board_data{vendor = 23456,
		     board_data_sub_elements = [{0,<<0,1,226,64>>},
						{1,<<0,1,226,64>>}]},
     #wtp_descriptor{max_radios = 1,
		     radios_in_use = 1,
		     encryption_sub_element = [<<1,10,9>>],
		     sub_elements = [{{23456,0},<<0,1,226,64>>},
				     {{23456,1},<<0,0,48,59>>},
				     {{23456,2},<<0,18,214,136>>}]}
    ].

timestamp() ->
    {Mega, Secs, _} = now(),
    Mega*1000000 + Secs.

handle_incoming(Response = {#capwap_header{},
			    {wtp_event_response, _, _RemoteSeq, _IEs}},
		run, control,
		State = #state{request_pending={wtp_event_response, From}}) ->
    reply_test(State, From, {ok, Response}, run);

handle_incoming(Response = {#capwap_header{},
			    {join_response, _, _RemoteSeq, _IEs}},
		discovery, control,
		State = #state{request_pending={join_response, From}}) ->
    reply_test(State, From, {ok, Response}, join);

handle_incoming(Response = {#capwap_header{},
			    {configuration_status_response, _, _RemoteSeq, IEs}},
                join,
                control,
                State = #state{request_pending={configuration_status_response, From}}) ->
    #timers{echo_request = EchoTimer} = lists:keyfind(timers, 1, IEs),
    reply_test(State#state{echo_request_timeout = EchoTimer}, From, {ok, Response}, configure);

handle_incoming(Request = {#capwap_header{},
			   {ieee_802_11_wlan_configuration_request, _, RemoteSeq, _WlanConfigIEs}} = Req,
		StateName,
		control,
		State = #state{owner = Owner, request_pending = RP}) ->
    lager:debug("Got expected wlan_config_request in ~p: ~p", [StateName, Req]),
    Owner ! Request,
    State0 = State#state{wifi_up = true},
    {next_state, StateName, State1} = do_transition(State0#state{request_pending = undefined},
						    control, StateName,
						    {ieee_802_11_wlan_configuration_response,[#result_code{}]},
						    async, {resp, RemoteSeq}, undefined),
    {next_state, StateName, State1#state{request_pending = RP}};

handle_incoming(Request = {#capwap_header{},
			   {station_configuration_request, _, RemoteSeq, _StationConfigIEs}} = Req,
		run,
		control,
		State = #state{request_pending = {add_station_resp, From}}) ->
    lager:debug("got expected station_config_request: ~p", [Req]),
    {next_state, run, State0} = reply_test(State, From, {ok, Request}, run),
    do_transition(State0, control, run,
		  {station_configuration_response, [#result_code{}]},
		  async, {resp, RemoteSeq}, undefined);

handle_incoming(Response = {_Header, {change_state_event_response, _, _, []}},
		configure, control,
		State= #state{capwap_wtp_session_id = CapwapWtpSessionId,
                      request_pending = {change_state_event_response, From},
                      options=Options})  ->
    %% establish dtls on data socket if remote_mode = true
    %% currently not in use (TODO add option for dtls usage on data socket)
    %% State0 = case State#state.remote_mode of
    %% 		 true ->
    %% 		     %% {ok, DataSocket} = ssl:connect(UdpDataSocket, make_ssl_options(State1)),
    %% 		     %% lager:info("successfull ssl handshake done for data socket", []),
    %% 		     %% ok = ssl:setopts(DataSocket, [{active, true}]),
    %% 		     State#state{data_socket = UdpDataSocket};
    %% 		 false ->
    %% 		     State
    %% 	     end,
    {next_state, run, State1} = reply_test(State, From, {ok, Response}, run),

    Flags = ['keep-alive', {frame,'802.3'}],
    KeepAliveIEs=[#session_id{session_id = CapwapWtpSessionId}],
    KeepAliveTimeout = proplists:get_value(data_keep_alive_timeout, Options, 30),
    do_transition(State1#state{keep_alive_timeout = KeepAliveTimeout}, data, run, {Flags, KeepAliveIEs});

handle_incoming({Header, _} = Req, run, data, State) ->
    KeepAlive = proplists:get_bool('keep-alive', Header#capwap_header.flags),
    case KeepAlive of
	true ->
	    lager:debug("WTP ~p received keep-alive in RUN state! ~p", [State#state.ip, State#state.keep_alive_timeout]),
	    {next_state, run, State};
	false ->
	    lager:warning("in ~p received a data response not expected: ~p", [run, Req]),
	    {next_state, run, State}
    end;

handle_incoming(Req,
		StateName,
		Type,
		State) ->
    lager:warning("handle_incoming: in ~p received a ~p response not expected: ~p", [StateName, Type, Req]),
    {next_state, StateName, State}.

make_ssl_options(#state{cert_dir = CertDir,
			root_cert = RootCert}) ->
    [{active, once},
     {mode, binary},
     {reuseaddr, true},

     {versions, [dtlsv1]},
     {cb_info, capwap_udp},
     {ciphers,[{ecdhe_rsa, aes_128_cbc, sha},
	       {dhe_rsa, aes_128_cbc, sha},
	       {rsa, aes_128_cbc, sha},
	       {ecdhe_rsa, aes_256_cbc, sha},
	       {dhe_rsa, aes_256_cbc, sha},
	       {rsa, aes_256_cbc, sha}
	      ]},
     {verify, verify_none},

     {cacertfile, case RootCert of
		      undefined ->
			  filename:join([CertDir, "root.pem"]);
		      Val ->
			  Val
		  end},
     {certfile, filename:join([CertDir, "client.pem"])},
     {keyfile, filename:join([CertDir, "client.key"])}
    ].

tuple_to_ip({A, B, C, D}) ->
    <<A:8, B:8, C:8, D:8>>;
tuple_to_ip({A, B, C, D, E, F, G, H}) ->
    <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>.


reset_echo_request_timer(State = #state{echo_request_timeout = 0}) ->
    State;

reset_echo_request_timer(State = #state{echo_request_timer = Timer, echo_request_timeout = Timeout}) ->
    if is_reference(Timer) -> gen_fsm:cancel_timer(Timer);
       true -> ok
    end,
    State#state{echo_request_timer = gen_fsm:send_event_after(Timeout * 1000, echo_timeout)}.

reset_keep_alive_timer(State = #state{keep_alive_timeout = 0}) ->
    State;

reset_keep_alive_timer(State = #state{keep_alive_timer = Timer, keep_alive_timeout = Timeout}) ->
    if is_reference(Timer) -> gen_fsm:cancel_timer(Timer);
       true -> ok
    end,
    State#state{keep_alive_timer = gen_fsm:send_event_after(Timeout * 1000, keep_alive_timeout)}.

remove_rp(State=#state{}) ->
    State#state{request_pending = undefined}.

reply_test(State, From, Resp, NextState) ->
    gen_fsm:reply(From, Resp),
    {next_state, NextState, remove_rp(State)}.
