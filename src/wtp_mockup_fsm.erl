
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
	 send_change_state_event/1
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
		seqno}).

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

%%%===================================================================
%%% gen_fsm callbacks
%%%===================================================================

init([Port]) ->
    {ok, ControlSocket} = gen_udp:open(Port, [{active, false}, {mode, binary}]),
    {ok, idle, #state{control_socket = ControlSocket,
		      seqno = 0}}.

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

configure(send_change_state_event, _From, State) ->
    IEs =[#radio_operational_state{state = enabled},
	  #result_code{}
	 ],
    {reply, ok, data_check, State1} = do_transition(State, 
						    change_state_event_request, 
						    data_check, 
						    IEs),
    % mock data socket through flsc
    SeqNum = State1#state.seqno,
    Header = create_header(),
    Header1 = Header#capwap_header{flags=['keep-alive', {frame,'802.3'}]},
    KeepAliveIEs=[#session_id{session_id = 329785637896618622174542098706248598340}
	],
    Packet = capwap_packet:encode(data,
				  {Header1, KeepAliveIEs}),
    {reply, KeepAliveResp} = capwap_ac:handle_data(sw1, sw2, {127, 0, 0, 1}, 12345, Packet),
    DecKeepAliveResp = capwap_packet:decode(data, KeepAliveResp),
    lager:info("got keep_alive response: ~p", [DecKeepAliveResp]),
    
    WlanConfigRequest = recv_capwap(State),
    
    DecWlanConfigRequest = capwap_packet:decode(control, WlanConfigRequest),
    {#capwap_header{},  
     {ieee_802_11_wlan_configuration_request, _, _, WlanConfigIEs}} = DecWlanConfigRequest,
    lager:info("got expected wlan_config_request: ~p", [DecWlanConfigRequest]),
    {reply, ok, run, State1};

configure(_Event, _From, State) ->
    {reply, {error, bad_event}, configure, State}.

run(_Event, State) ->
    {next_state, run, State}.

run(_Event, _From, State) ->
    {reply, {error, bad_event}, run, State}.


handle_event(_Event, StateName, State) ->
    {next_state, StateName, State}.

handle_sync_event(_Event, _From, StateName, State) ->
    Reply = ok,
    {reply, Reply, StateName, State}.

handle_info(_Info, StateName, State) ->
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

send_capwap(#state{control_socket=CS}, Packet) ->
    gen_udp:send(CS, {127, 0, 0, 1}, 5246, Packet).

recv_capwap(#state{control_socket=CS}) ->
    {ok, {_IP, _Port, Resp}} = gen_udp:recv(CS, 1000, 1000),
    Resp.

create_header() ->
    #capwap_header{radio_id = 0,
		   wb_id = 1,
		   flags = [{frame,'802.3'}],
		   radio_mac = <<8,8,8,8,8,8>>,
		   wireless_spec_info = undefined}.

do_transition(State=#state{seqno = SeqNum}, ReqType, NextState, IEs) ->
    Header = create_header(),
    Packet = capwap_packet:encode(control,
				  {Header,
				   {ReqType, SeqNum, IEs}}),
    lager:info("~p to send: ~p", [ReqType, Packet]),
    send_capwap(State, Packet),
    Resp = recv_capwap(State),
    DecResp = capwap_packet:decode(control, Resp),
    lager:info("got ~p response: ~p", [ReqType, DecResp]),
    
    {reply, ok, NextState, bump_seqno(State)}.


create_default_ies() ->
    [#ieee_802_11_wtp_radio_information{radio_type = ['802.11g','802.11b']},
     #wtp_mac_type{mac_type = split},
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
