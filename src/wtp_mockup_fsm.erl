
%%%-------------------------------------------------------------------
%%% @author olerixmanntp <olerixmanntp@kiiiiste>
%%% @copyright (C) 2014, olerixmanntp
%%% @doc
%%%
%%% @end
%%% Created :  3 Mar 2014 by olerixmanntp <olerixmanntp@kiiiiste>
%%%-------------------------------------------------------------------
-module(wtp_mockup_fsm).

-behaviour(gen_fsm).

-include("capwap_packet.hrl").
%-include("capwap_packet_gen.hrl").

%% API
-export([start_link/0,
	 start_link/1,
	 send_discovery/1,
	 send_join/1,
	 send_config_status/1,
	 send_change_state_event/1,
	 send_wwan_statistics/1,
	 add_station/2
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

-record(state, {control_socket, 
		seqno,
		stations}).

%%%===================================================================
%%% API
%%%===================================================================
start_link() ->
    start_link(5248).

start_link(Port) ->
    gen_fsm:start_link(?MODULE, [Port], []).


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

add_station(WTP_FSM, Mac) ->
    gen_fsm:sync_send_event(WTP_FSM, {add_station, Mac}).

%%%===================================================================
%%% gen_fsm callbacks
%%%===================================================================

init([Port]) ->
    {ok, ControlSocket} = gen_udp:open(Port, [{active, false}, {mode, binary}]),
    {ok, idle, #state{control_socket = ControlSocket,
		      seqno = 0,
		      stations = []}}.
 
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

idle(send_discovery, _From, State=#state{seqno = SeqNum}) ->
    IEs = [#discovery_type{discovery_type = static}
	  ] ++ create_default_ies(),
    do_transition(State, discovery_request, discovery, IEs);

idle(_Event, _From, State) ->
    {reply, {error, bad_event}, idle, State}.

discovery(_Event, State) ->
    {next_state, discovery, State}.

discovery(send_join, _From, State=#state{seqno = SeqNum}) ->
    IEs = [#location_data{location = <<"  Next to Fridge">>},
	   #local_ipv4_address{ip_address = <<192,168,1,1>>},
	   #wtp_name{wtp_name = <<"My WTP 1">>},
	   #session_id{session_id = 329785637896618622174542098706248598340}
	  ] ++ create_default_ies(),
    do_transition(State, join_request, join, IEs);

discovery(_Event, _From, State) ->
    {reply, {error, bad_event}, discovery, State}.

join(_Event, State) ->
    {next_state, join, State}.

    
join(send_config_status, _From, State=#state{seqno = SeqNum}) ->
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
    do_transition(State, configuration_status_request, configure, IEs);

join(_Event, _From, State) ->
    {reply, {error, bad_event}, join, State}.

configure(_Event, State) ->
    {next_state, configure, State}.

configure(send_change_state_event, _From, State=#state{control_socket = CS}) ->
    IEs =[#radio_operational_state{state = enabled},
	  #result_code{}
	 ],
    {reply, ok, data_check, State1} = do_transition(State, 
						    change_state_event_request, 
						    data_check, 
						    IEs),
    %% make control channel socket active    
    inet:setopts(CS, [{active, true}]),
    
    %% mock data socket through flsc
    Header = create_header(),
    Header1 = Header#capwap_header{flags=['keep-alive', {frame,'802.3'}]},
    KeepAliveIEs=[#session_id{session_id = 329785637896618622174542098706248598340}
	],
    Packet = capwap_packet:encode(data,
				  {Header1, KeepAliveIEs}),
    
    {reply, KeepAliveResp} = capwap_ac:handle_data(sw1, sw2, {127, 0, 0, 1}, 12345, Packet),
    DecKeepAliveResp = capwap_packet:decode(data, KeepAliveResp),
    lager:debug("got keep_alive response: ~p", [DecKeepAliveResp]),    
    {reply, ok, run, bump_seqno(State)};

configure(_Event, _From, State) ->
    {reply, {error, bad_event}, configure, State}.

run(_Event, State) ->
    {next_state, run, State}.

run(send_wwan_statistics, _From, State) ->
    IEs = [#tp_wtp_wwan_statistics{latency = 5,
				   timestamp = timestamp()}
	  ],
    do_transition(State, wtp_event_request, run, IEs, async);

run({add_station, Mac}, _From, State = #state{stations=Stations}) ->
    Unknown = 0,
    FromDS = 0,
    ToDS=0,
    {Type, SubType} = ieee80211_station:frame_type('Association Request'),
    FrameControl = <<SubType:4, Type:2, 0:2, Unknown:6, FromDS:1, ToDS:1>>,
    Duration = 0,
    DA = <<0:48>>,
    SA = <<1:48>>,
    BSS = <<0:48>>,
    SequenceControl = 0,
    Frame = <<0:8>>,
    Payload = <<FrameControl:2/bytes,
		Duration:16, DA:6/bytes, SA:6/bytes, BSS:6/bytes,
		SequenceControl:16/little-integer, Frame/binary>>,
    
    Flags=[{frame, native}],
    capwap_send_data(State, Flags, Payload),

    {TypeDis, SubTypeDis} = ieee80211_station:frame_type('Disassociation'),
    FrameControlDis = <<SubTypeDis:4, TypeDis:2, 0:2, Unknown:6, FromDS:1, ToDS:1>>,
    SequenceControlDis = SequenceControl + 1,
    PayloadDis = <<FrameControlDis:2/bytes,
		   Duration:16, DA:6/bytes, SA:6/bytes, BSS:6/bytes,
		   SequenceControlDis:16/little-integer, Frame/binary>>,
    capwap_send_data(State, Flags, PayloadDis),
    {reply, ok, run, State};

run(_Event, _From, State) ->
    {reply, {error, bad_event}, run, State}.


handle_event(_Event, StateName, State) ->
    {next_state, StateName, State}.

handle_sync_event(_Event, _From, StateName, State) ->
    {reply, ok, StateName, State}.

handle_info({udp, CS, _IP, _InPort, Packet}, run, State=#state{control_socket = CSS}) ->
    
    DecRequest = capwap_packet:decode(control, Packet),
    handle_udp_run(DecRequest, State);

handle_info(Info, StateName, State) ->
    lager:debug("in state ~p received unhandled info: ~p", [StateName, Info]),    
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

send_capwap(#state{control_socket=CS}, Packet) ->
    gen_udp:send(CS, {127, 0, 0, 1}, 5246, Packet).

recv_capwap(#state{control_socket=CS}) ->
    {ok, {_IP, _Port, Resp}} = gen_udp:recv(CS, 1000, 1000),
    Resp.

capwap_send_data(State, Flags, IEs) ->
    Header = create_header(),
    Header1 = Header#capwap_header{flags=Flags},
    Packet = capwap_packet:encode(data,
				  {Header1, IEs}),
    
    capwap_ac:handle_data(sw1, sw2, {127, 0, 0, 1}, 12345, Packet).

create_header() ->
    #capwap_header{radio_id = 0,
		   wb_id = 1,
		   flags = [{frame,'802.3'}],
		   radio_mac = <<8,8,8,8,8,8>>,
		   wireless_spec_info = undefined}.

do_transition(State, ReqType, NextState, IEs) ->
    do_transition(State, ReqType, NextState, IEs, sync).

do_transition(State=#state{seqno = SeqNum}, ReqType, NextState, IEs, Mode) ->
    Header = create_header(),
    Packet = capwap_packet:encode(control,
				  {Header,
				   {ReqType, SeqNum, IEs}}),
    lager:info("~p to send: ~p", [ReqType, Packet]),
    send_capwap(State, Packet),
    case Mode of
	sync ->
	    Resp = recv_capwap(State),
	    DecResp = capwap_packet:decode(control, Resp),
	    lager:info("got ~p response: ~p", [ReqType, DecResp]),
	    {reply, ok, NextState, bump_seqno(State)};
	async ->
	    {reply, ok, NextState, bump_seqno(State)}
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
    Timestamp = Mega*1000000 + Secs.

handle_udp_run({#capwap_header{},  
		{ieee_802_11_wlan_configuration_request, _, RemoteSeq, _WlanConfigIEs}} = Req, 
	       State) ->
    lager:debug("got expected wlan_config_request: ~p", [Req]),
    CRespPacket = capwap_packet:encode(control,
				       {create_header(),
					{ieee_802_11_wlan_configuration_response, RemoteSeq, []}}),
    send_capwap(State, CRespPacket),
    {next_state, run, State};

handle_udp_run({#capwap_header{},  
		{station_configuration_request, _, RemoteSeq, _StationConfigIEs}} = Req, 
	       State) ->
    lager:debug("got expected station_config_request: ~p", [Req]),
    CRespPacket = capwap_packet:encode(control,
				       {create_header(),
					{station_configuration_response, RemoteSeq, [#result_code{}]}}),
    send_capwap(State, CRespPacket),
    {next_state, run, State};

handle_udp_run({#capwap_header{},  
		{wtp_event_response, _, _, _}} = Req, 
	       State) ->
    {next_state, run, State};
handle_udp_run(PKT, State) ->
    lager:debug("got unhandled CAPWAP request in run: ~p", [PKT]),
    {next_state, run, State}.
