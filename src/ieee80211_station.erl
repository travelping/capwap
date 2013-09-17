-module(ieee80211_station).

-behavior(gen_fsm).

%% API
-export([start_link/7, handle_ieee80211_frame/2, handle_ieee802_3_frame/2,
         set_out_action/3, get_out_action/2, take_over/7]).

%% gen_fsm callbacks
-export([init/1,
	 init_auth/2, init_auth/3,
	 init_assoc/2, init_assoc/3,
	 init_start/2, init_start/3,
	 connected/2, connected/3,
	 shutdown/2, shutdown/3,
	 handle_event/3, handle_sync_event/4,
	 handle_info/3, terminate/3, code_change/4]).

-include("capwap_debug.hrl").

-define(SERVER, ?MODULE).
-define(IDLE_TIMEOUT, 30 * 1000).
-define(SHUTDOWN_TIMEOUT, 1 * 1000).

-define(OPEN_SYSTEM, 0).
-define(SUCCESS, 0).
-define(REFUSED, 1).

-record(state, {
          ac,
          ac_monitor,
          flow_switch,
          peer_data,
          radio_mac,
          mac,
          mac_mode,
          tunnel_mode,
          out_action
         }).

-record(auth_frame, {algo, seq_no, status, params}).

-ifdef(debug).
-define(SERVER_OPTS, [{debug, [trace]}]).
-else.
-define(SERVER_OPTS, []).
-endif.

%%%===================================================================
%%% API
%%%===================================================================
start_link(AC, FlowSwitch, PeerId, RadioMAC, ClientMAC, MacMode, TunnelMode) ->
    gen_fsm:start_link(?MODULE, [AC, FlowSwitch, PeerId, RadioMAC, ClientMAC, MacMode, TunnelMode], ?SERVER_OPTS).

handle_ieee80211_frame(AC, <<FrameControl:2/bytes,
			      _Duration:16, DA:6/bytes, SA:6/bytes, BSS:6/bytes,
			      _SequenceControl:16/little-integer, Frame/binary>>) ->
    %% FragmentNumber = SequenceControl band 16#0f,
    %% SequenceNumber = SequenceControl bsr 4,

    <<SubType:4, Type:2, 0:2, _:6, FromDS:1, ToDS:1>> = FrameControl,
    FrameType = frame_type(Type, SubType),
    ieee80211_request(AC, FrameType, DA, SA, BSS, FromDS, ToDS, Frame);

handle_ieee80211_frame(_, Frame) ->
    lager:warning("unhandled IEEE802.11 Frame:~n~s", [flower_tools:hexdump(Frame)]),
    {error, unhandled}.

handle_ieee802_3_frame(AC, <<_EthDst:6/bytes, EthSrc:6/bytes, _/binary>> = Frame) ->
    case capwap_station_reg:lookup(AC, EthSrc) of
	not_found ->
	    lager:warning("got 802.3 from unknown Ethern station"),
	    {error, invalid_station};
	{ok, Station} ->
	    gen_fsm:sync_send_event(Station, {'802.3', Frame})
    end;
handle_ieee802_3_frame(_, _Frame) ->
    {error, unhandled}.

get_wtp_for_client_mac(Sw, ClientMAC) ->
    case capwap_station_reg:lookup(ClientMAC) of
	{ok, Pid} ->
	    gen_fsm:sync_send_all_state_event(Pid, {get_wtp_for_client_mac, Sw});
	_ ->
	    not_found
    end.

set_out_action(Sw, ClientMAC, Action) ->
    case capwap_station_reg:lookup(ClientMAC) of
	{ok, Pid} ->
	    gen_fsm:sync_send_all_state_event(Pid, {set_out_action, Sw, Action});
	_ ->
	    not_found
    end.

get_out_action(Sw, ClientMAC) ->
    case capwap_station_reg:lookup(ClientMAC) of
	{ok, Pid} ->
	    gen_fsm:sync_send_all_state_event(Pid, {get_out_action, Sw});
	_ ->
	    not_found
    end.

take_over(Pid, AC, FlowSwitch, PeerId, RadioMAC, MacMode, TunnelMode) ->
    gen_fsm:sync_send_event(Pid, {take_over, AC, FlowSwitch, PeerId, RadioMAC, MacMode, TunnelMode}).

%%%===================================================================
%%% gen_fsm callbacks
%%%===================================================================
init([AC, FlowSwitch, PeerId, RadioMAC, ClientMAC, MacMode, TunnelMode]) ->
    lager:debug("Register station ~p as ~w", [{AC, RadioMAC, ClientMAC}, self()]),
    capwap_station_reg:register(ClientMAC),
    capwap_station_reg:register(AC, ClientMAC),
    ACMonitor = erlang:monitor(process, AC),
    State = #state{ac = AC, ac_monitor = ACMonitor, flow_switch = FlowSwitch, peer_data = PeerId,
                   radio_mac = RadioMAC, mac = ClientMAC, mac_mode = MacMode, tunnel_mode = TunnelMode},
    {ok, initial_state(MacMode), State}.

%%
%% State transitions follow IEEE 802.11-2012, Section 10.3.2
%%

%%
%% State 1
%%
init_auth(timeout, State) ->
    lager:warning("idle timeout in INIT_AUTH"),
    next_state(init_auth, State).

init_auth(Event = {'Authentication', DA, SA, BSS, 0, 0, Frame}, _From, State) ->
    lager:debug("in INIT_AUTH got Authentication Request: ~p", [Event]),
    AuthFrame = decode_auth_frame(Frame),
    case AuthFrame of
	#auth_frame{algo   = ?OPEN_SYSTEM,
		    status = ?SUCCESS} ->
	    %% send Auth OK
	    Reply = gen_auth_ok(DA, SA, BSS, Frame),
	    reply({reply, Reply}, init_assoc, State);
	_ ->
	    %% send Auth Fail
	    Reply = gen_auth_fail(DA, SA, BSS, Frame),
	    reply({reply, Reply}, init_auth, State)
    end;

init_auth(Event, From, State)
  when element(1, Event) == take_over ->
    lager:debug("in INIT_AUTH got TAKE-OVER: ~p", [Event]),
    handle_take_over(Event, From, State);

init_auth(Event, _From, State) ->
    lager:warning("in INIT_AUTH got unexpexted: ~p", [Event]),
    reply({error, unexpected}, init_auth, State).

%%
%% State 2
%%
init_assoc(timeout, State) ->
    lager:warning("idle timeout in INIT_ASSOC"),
    next_state(init_assoc, State).

init_assoc(Event = {'Authentication', _DA, _SA, _BSS, 0, 0, _Frame}, _From, State)
  when State#state.mac_mode == local_mac ->
    lager:debug("in INIT_ASSOC Local-MAC Mode got Authentication Request: ~p", [Event]),
    reply({ok, ignore}, init_assoc, State);

init_assoc(Event = {FrameType, _DA, _SA, BSS, 0, 0, _Frame}, _From,
	   State = #state{radio_mac = BSS, mac = MAC, mac_mode = MacMode, 
                      peer_data = {WtpIp, _}, tunnel_mode = TunnelMode})
  when MacMode == local_mac andalso
       (FrameType == 'Association Request' orelse FrameType == 'Reassociation Request') ->
    lager:debug("in INIT_ASSOC Local-MAC Mode got Association Request: ~p", [Event]),

    %% MAC blocks would go here!

    %% RFC 5416, Sect. 2.2.2:
    %%
    %%   While the MAC is terminated on the WTP, it is necessary for the AC to
    %%   be aware of mobility events within the WTPs.  Thus, the WTP MUST
    %%   forward the IEEE 802.11 Association Request frames to the AC.  The AC
    %%   MAY reply with a failed Association Response frame if it deems it
    %%   necessary, and upon receipt of a failed Association Response frame
    %%   from the AC, the WTP MUST send a Disassociation frame to the station.

    {ok, {_, ProviderOpts}} = application:get_env(ctld_provider),
    ctld_station_session:association(format_mac(MAC), WtpIp, ProviderOpts),

    reply({add, BSS, MAC, MacMode, TunnelMode}, connected, State);

init_assoc(Event = {'Authentication', _DA, _SA, _BSS, 0, 0, _Frame}, From, State) ->
    lager:debug("in INIT_ASSOC got Authentication Request: ~p", [Event]),
    %% fall-back to init_auth....
    init_auth(Event, From, State);

init_assoc(Event = {FrameType, DA, SA, BSS, 0, 0, _Frame}, _From, State)
  when (FrameType == 'Association Request' orelse FrameType == 'Reassociation Request') ->
    lager:debug("in INIT_ASSOC got Association Request: ~p", [Event]),
    %% Fake Assoc Details
    %% we should at the very least match the Rates.....

    Frame = <<16#01, 16#00, 16#00, 16#00, 16#01, 16#c0, 16#01, 16#08,
	      16#82, 16#84, 16#0b, 16#16, 16#0c, 16#12, 16#18, 16#24,
	      16#dd, 16#18, 16#00, 16#50, 16#f2, 16#02, 16#01, 16#01,
	      16#00, 16#00, 16#03, 16#a4, 16#00, 16#00, 16#27, 16#a4,
	      16#00, 16#00, 16#42, 16#43, 16#5e, 16#00, 16#62, 16#32,
	      16#2f, 16#00>>,

    {Type, SubType} = frame_type('Association Response'),
    FrameControl = <<SubType:4, Type:2, 0:2, 0:6, 0:1, 0:1>>,
    Duration = 0,
    SequenceControl = 0,
    Reply = <<FrameControl/binary,
	      Duration:16/integer-little,
	      SA:6/bytes, DA:6/bytes, BSS:6/bytes,
	      SequenceControl:16,
	      Frame/binary>>,
    reply({reply, Reply}, init_start, State);

init_assoc(Event, From, State)
  when element(1, Event) == take_over ->
    lager:debug("in INIT_ASSOC got TAKE-OVER: ~p", [Event]),
    handle_take_over(Event, From, State);

init_assoc(Event, _From, State) ->
    lager:warning("in INIT_ASSOC got unexpexted: ~p", [Event]),
    reply({error, unexpected}, init_assoc, State).

%%
%% State 3
%%
init_start(timeout, State) ->
    lager:warning("idle timeout in INIT_START"),
    next_state(init_start, State).

init_start(Event = {'Null', _DA, _SA, BSS, 0, 1, <<>>}, _From,
	   State = #state{radio_mac = BSS, mac = MAC, mac_mode = MacMode, tunnel_mode = TunnelMode}) ->
    lager:debug("in INIT_START got Null: ~p", [Event]),
    reply({add, BSS, MAC, MacMode, TunnelMode}, connected, State);

init_start(Event, From, State)
  when element(1, Event) == take_over ->
    lager:debug("in INIT_START got TAKE-OVER: ~p", [Event]),
    handle_take_over(Event, From, State);

init_start(Event, _From, State) ->
    lager:warning("in INIT_START got unexpexted: ~p", [Event]),
    reply({error, unexpected}, init_start, State).

%%
%% State 4
%%
connected(timeout, State) ->
    lager:warning("idle timeout in CONNECTED"),
    next_state(connected, State).

connected({'802.3', Data}, _From,
	  State = #state{radio_mac = BSS, mac = MAC, mac_mode = MacMode, tunnel_mode = TunnelMode}) ->
    lager:debug("in CONNECTED got 802.3 Data:~n~s", [flower_tools:hexdump(Data)]),
    reply({flow, BSS, MAC, MacMode, TunnelMode}, connected, State);

connected(Event = {'Deauthentication', _DA, _SA, BSS, 0, 0, _Frame}, _From,
	   State = #state{radio_mac = BSS, mac = MAC, mac_mode = MacMode, 
                      peer_data = {WtpIp, _}, tunnel_mode = TunnelMode}) ->
    lager:debug("in CONNECTED got Deauthentication: ~p", [Event]),
    {ok, {_, ProviderOpts}} = application:get_env(ctld_provider),
    ctld_station_session:disassociation(format_mac(MAC), WtpIp, ProviderOpts),
    reply({del, BSS, MAC, MacMode, TunnelMode}, shutdown, State);

connected(Event = {'Disassociation', _DA, _SA, BSS, 0, 0, _Frame}, _From,
	   State = #state{radio_mac = BSS, mac = MAC, mac_mode = MacMode, 
                      peer_data = {WtpIp, _}, tunnel_mode = TunnelMode}) ->
    lager:debug("in CONNECTED got Disassociation: ~p", [Event]),
    {ok, {_, ProviderOpts}} = application:get_env(ctld_provider),
    ctld_station_session:disassociation(format_mac(MAC), WtpIp, ProviderOpts),
    reply({del, BSS, MAC, MacMode, TunnelMode}, init_assoc, State);

connected(Event, From, State = #state{mac = MAC, peer_data = {WtpIp, _}})
  when element(1, Event) == take_over ->
    lager:debug("in CONNECTED got TAKE-OVER: ~p", [Event]),
    {ok, {_, ProviderOpts}} = application:get_env(ctld_provider),
    ctld_station_session:disassociation(format_mac(MAC), WtpIp, ProviderOpts),
    handle_take_over(Event, From, State);

connected(Event, _From, State) ->
    lager:warning("in CONNECTED got unexpexted: ~p", [Event]),
    reply({error, unexpected}, connected, State).

%%
%% keep process arround for a few seconds to deal with reorderd, pending frames (should not happen!)
%%
shutdown(timeout, State) ->
    lager:debug("idle timeout in SHUTDOWN"),
    {stop, normal, State}.

shutdown(Event, _From, State) ->
    lager:warning("in SHUTDOWN got unexpexted: ~p", [Event]),
    reply({error, unexpected}, shutdown, State).

handle_event(_Event, StateName, State) ->
    next_state(StateName, State).

handle_sync_event({get_wtp_for_client_mac, _Sw}, _From, StateName,
                  State = #state{ac = AC, radio_mac = RadioMAC}) ->
    case capwap_ac:get_peer_data(AC) of
        {ok, {Address, Port}} ->
            Reply = {ok, Address, Port, RadioMAC},
            reply(Reply, StateName, State);
        Other ->
            reply(Other, StateName, State)
    end;

handle_sync_event({set_out_action, _Sw, Action}, _From, StateName, State) ->
    reply(ok, StateName, State#state{out_action = Action});

handle_sync_event({get_out_action, _Sw}, _From, StateName, State) ->
    reply(State#state.out_action, StateName, State);

handle_sync_event(_Event, _From, StateName, State) ->
    Reply = ok,
    reply(Reply, StateName, State).

handle_info({'DOWN', ACMonitor, process, AC, _Info}, StateName,
            State = #state{ac = AC, ac_monitor = ACMonitor,
			   flow_switch = FlowSwitch, peer_data = PeerId,
                           radio_mac = BSS, mac = MAC,
                           mac_mode = MacMode, tunnel_mode = TunnelMode}) ->
    lager:warning("AC died ~w", [AC]),

    if
        StateName == connected; StateName == shutdown ->
            %% if the AC dies in connected whe have to the Switch directly,
            %% to avoid a race do it in shutdown as well
            FlowSwitch ! {station_down, PeerId, BSS, MAC, MacMode, TunnelMode};
        true ->
            ok
    end,

    {stop, normal, State};

handle_info(Info, StateName, State) ->
    lager:warning("in State ~p unexpected Info: ~p", [StateName, Info]),
    next_state(StateName, State).

terminate(_Reason, StateName, #state{mac = MAC}) ->
    lager:warning("Station ~s terminated in State ~w", [flower_tools:format_mac(MAC), StateName]),
    ok.

code_change(_OldVsn, StateName, State, _Extra) ->
    {ok, StateName, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

gen_auth_ok(DA, SA, BSS, _InFrame) ->
    Frame = encode_auth_frame(#auth_frame{algo   = ?OPEN_SYSTEM, seq_no = 2,
					  status = ?SUCCESS, params = <<>>}),

    {Type, SubType} = frame_type('Authentication'),
    FrameControl = <<SubType:4, Type:2, 0:2, 0:6, 0:1, 0:1>>,
    Duration = 0,
    SequenceControl = 0,
    <<FrameControl/binary,
      Duration:16/integer-little,
      SA:6/bytes, DA:6/bytes, BSS:6/bytes,
      SequenceControl:16,
      Frame/binary>>.

gen_auth_fail(DA, SA, BSS, _InFrame) ->
    Frame = encode_auth_frame(#auth_frame{algo   = ?OPEN_SYSTEM, seq_no = 2,
					  status = ?REFUSED, params = <<>>}),

    {Type, SubType} = frame_type('Authentication'),
    FrameControl = <<SubType:4, Type:2, 0:2, 0:6, 0:1, 0:1>>,
    Duration = 0,
    SequenceControl = 0,
    <<FrameControl/binary,
      Duration:16/integer-little,
      SA:6/bytes, DA:6/bytes, BSS:6/bytes,
      SequenceControl:16,
      Frame/binary>>.

next_state(NextStateName, State)
  when NextStateName == shutdown ->
     {next_state, NextStateName, State, ?SHUTDOWN_TIMEOUT};
next_state(NextStateName, State) ->
     {next_state, NextStateName, State, ?IDLE_TIMEOUT}.

reply(Reply, NextStateName, State)
  when NextStateName == shutdown ->
    {reply, Reply, NextStateName, State, ?SHUTDOWN_TIMEOUT};
reply(Reply, NextStateName, State) ->
    {reply, Reply, NextStateName, State, ?IDLE_TIMEOUT}.

ieee80211_request(_AC, _FrameType, _DA, SA, BSS, _FromDS, _ToDS, _Frame)
  when SA == BSS ->
    %% OpenCAPWAP is stupid, it mirrors our own Frame back to us....
    {ok, ignore};

ieee80211_request(AC, FrameType, DA, SA, BSS, FromDS, ToDS, Frame)
  when FrameType == 'Authentication';
       FrameType == 'Association Request';
       FrameType == 'Reassociation Request';
       FrameType == 'Null' ->
    lager:debug("search Station ~p", [{AC, SA}]),
    Found = case capwap_station_reg:lookup(AC, SA) of
		not_found ->
		    lager:debug("not found"),
		    capwap_ac:new_station(AC, BSS, SA);
		Ok = {ok, Station0} ->
		    lager:debug("found as ~p", [Station0]),
		    Ok
	    end,
    case Found of
	{ok, Station} ->
	    gen_fsm:sync_send_event(Station, {FrameType, DA, SA, BSS, FromDS, ToDS, Frame});
	Other ->
	    Other
    end;

ieee80211_request(AC, FrameType, DA, SA, BSS, FromDS, ToDS, Frame)
  when FrameType == 'Deauthentication';
       FrameType == 'Disassociation' ->
    lager:warning("got IEEE 802.11 Frame: ~p", [{FrameType, DA, SA, BSS, FromDS, ToDS, Frame}]),

    lager:debug("search Station ~p", [{AC, SA}]),
    case capwap_station_reg:lookup(AC, SA) of
        not_found ->
            lager:debug("not found"),
            {ok, ignore};

        {ok, Station} ->
            lager:debug("found as ~p", [Station]),
            gen_fsm:sync_send_event(Station, {FrameType, DA, SA, BSS, FromDS, ToDS, Frame})
    end;

ieee80211_request(_AC, FrameType, _DA, _SA, _BSS, _FromDS, _ToDS, _Frame)
  when FrameType == 'Probe Request' ->
    {ok, ignore};

ieee80211_request(_AC, FrameType, DA, SA, BSS, FromDS, ToDS, Frame) ->
    lager:warning("unhandled IEEE 802.11 Frame: ~p", [{FrameType, DA, SA, BSS, FromDS, ToDS, Frame}]),
    {error, unhandled}.

handle_take_over({take_over, AC, FlowSwitch, PeerId, RadioMAC, MacMode, TunnelMode}, _From,
		 State0 = #state{ac = OldAC, ac_monitor = OldACMonitor,
				 flow_switch = _OldFlowSwitch,
				 radio_mac = OldRadioMAC, mac = ClientMAC,
				 mac_mode = _OldMacMode, tunnel_mode = _OldTunnelMode}) ->
    %% NOTE: we could build a real WIFI switch when we could build OF rules that sends
    %%       the traffic to all WTP's this client is still valid on!
    %%
    %%       with the current MacMode, the new flow entry will simply overwrite the old one,
    %%       so no further action is required here, but other Mac/TunnelModes might

    lager:debug("Takeover station ~p as ~w", [{OldAC, OldRadioMAC, ClientMAC}, self()]),
    lager:debug("Register station ~p as ~w", [{AC, RadioMAC, ClientMAC}, self()]),

    capwap_station_reg:unregister(OldAC, ClientMAC),
    capwap_station_reg:register(AC, ClientMAC),

    erlang:demonitor(OldACMonitor, [flush]),
    ACMonitor = erlang:monitor(process, AC),

    State = State0#state{ac = AC, ac_monitor = ACMonitor,
			 flow_switch = FlowSwitch, peer_data = PeerId,
			 radio_mac = RadioMAC, mac_mode = MacMode,
			 tunnel_mode = TunnelMode},
    reply({ok, self()}, initial_state(MacMode), State).

%% partially en/decode Authentication Frames
decode_auth_frame(<<Algo:16/little-integer, SeqNo:16/little-integer,
		    Status:16/little-integer, Params/binary>>) ->
    #auth_frame{algo   = Algo,
		seq_no = SeqNo,
		status = Status,
		params = Params};
decode_auth_frame(_) ->
    invalid.

encode_auth_frame(#auth_frame{algo   = Algo, seq_no = SeqNo,
			      status = Status, params = Params}) ->
    <<Algo:16/little-integer, SeqNo:16/little-integer,
      Status:16/little-integer, Params/binary>>.

%% Management
frame_type(2#00, 2#0000) -> 'Association Request';
frame_type(2#00, 2#0001) -> 'Association Response';
frame_type(2#00, 2#0010) -> 'Reassociation Request';
frame_type(2#00, 2#0011) -> 'Reassociation Response';
frame_type(2#00, 2#0100) -> 'Probe Request';
frame_type(2#00, 2#0101) -> 'Probe Response';
frame_type(2#00, 2#0110) -> 'Timing Advertisement';
frame_type(2#00, 2#0111) -> 'Reserved';
frame_type(2#00, 2#1000) -> 'Beacon';
frame_type(2#00, 2#1001) -> 'ATIM';
frame_type(2#00, 2#1010) -> 'Disassociation';
frame_type(2#00, 2#1011) -> 'Authentication';
frame_type(2#00, 2#1100) -> 'Deauthentication';
frame_type(2#00, 2#1101) -> 'Action';
frame_type(2#00, 2#1110) -> 'Action No Ack';
frame_type(2#00, 2#1111) -> 'Reserved';

%% Controll
frame_type(2#01, 2#0111) -> 'Control Wrapper';
frame_type(2#01, 2#1000) -> 'Block Ack Request';
frame_type(2#01, 2#1001) -> 'Block Ack';
frame_type(2#01, 2#1010) -> 'PS-Poll';
frame_type(2#01, 2#1011) -> 'RTS';
frame_type(2#01, 2#1100) -> 'CTS';
frame_type(2#01, 2#1101) -> 'ACK';
frame_type(2#01, 2#1110) -> 'CF-End';
frame_type(2#01, 2#1111) -> 'CF-End + CF-Ack';

%% Data
frame_type(2#10, 2#0000) -> 'Data';
frame_type(2#10, 2#0001) -> 'Data + CF-Ack';
frame_type(2#10, 2#0010) -> 'Data + CF-Poll';
frame_type(2#10, 2#0011) -> 'Data + CF-Ack + CF-Poll';
frame_type(2#10, 2#0100) -> 'Null';
frame_type(2#10, 2#0101) -> 'CF-Ack';
frame_type(2#10, 2#0110) -> 'CF-Poll';
frame_type(2#10, 2#0111) -> 'CF-Ack + CF-Poll';
frame_type(2#10, 2#1000) -> 'QoS Data';
frame_type(2#10, 2#1001) -> 'QoS Data + CF-Ack';
frame_type(2#10, 2#1010) -> 'QoS Data + CF-Poll';
frame_type(2#10, 2#1011) -> 'QoS Data + CF-Ack + CF-Poll';
frame_type(2#10, 2#1100) -> 'QoS Null';
frame_type(2#10, 2#1101) -> 'Reserved';
frame_type(2#10, 2#1110) -> 'QoS CF-Poll';
frame_type(2#10, 2#1111) -> 'QoS CF-Ack + CF-Poll';

frame_type(_,_)           -> 'Reserved'.

%% Management
frame_type('Association Request')         -> {2#00, 2#0000};
frame_type('Association Response')        -> {2#00, 2#0001};
frame_type('Reassociation Request')       -> {2#00, 2#0010};
frame_type('Reassociation Response')      -> {2#00, 2#0011};
frame_type('Probe Request')               -> {2#00, 2#0100};
frame_type('Probe Response')              -> {2#00, 2#0101};
frame_type('Timing Advertisement')        -> {2#00, 2#0110};
frame_type('Beacon')                      -> {2#00, 2#1000};
frame_type('ATIM')                        -> {2#00, 2#1001};
frame_type('Disassociation')              -> {2#00, 2#1010};
frame_type('Authentication')              -> {2#00, 2#1011};
frame_type('Deauthentication')            -> {2#00, 2#1100};
frame_type('Action')                      -> {2#00, 2#1101};
frame_type('Action No Ack')               -> {2#00, 2#1110};

%% Controll
frame_type('Control Wrapper')             -> {2#01, 2#0111};
frame_type('Block Ack Request')           -> {2#01, 2#1000};
frame_type('Block Ack')                   -> {2#01, 2#1001};
frame_type('PS-Poll')                     -> {2#01, 2#1010};
frame_type('RTS')                         -> {2#01, 2#1011};
frame_type('CTS')                         -> {2#01, 2#1100};
frame_type('ACK')                         -> {2#01, 2#1101};
frame_type('CF-End')                      -> {2#01, 2#1110};
frame_type('CF-End + CF-Ack')             -> {2#01, 2#1111};

%% Data
frame_type('Data')                        -> {2#10, 2#0000};
frame_type('Data + CF-Ack')               -> {2#10, 2#0001};
frame_type('Data + CF-Poll')              -> {2#10, 2#0010};
frame_type('Data + CF-Ack + CF-Poll')     -> {2#10, 2#0011};
frame_type('Null')                        -> {2#10, 2#0100};
frame_type('CF-Ack')                      -> {2#10, 2#0101};
frame_type('CF-Poll')                     -> {2#10, 2#0110};
frame_type('CF-Ack + CF-Poll')            -> {2#10, 2#0111};
frame_type('QoS Data')                    -> {2#10, 2#1000};
frame_type('QoS Data + CF-Ack')           -> {2#10, 2#1001};
frame_type('QoS Data + CF-Poll')          -> {2#10, 2#1010};
frame_type('QoS Data + CF-Ack + CF-Poll') -> {2#10, 2#1011};
frame_type('QoS Null')                    -> {2#10, 2#1100};
frame_type('Reserved')                    -> {2#10, 2#1101};
frame_type('QoS CF-Poll')                 -> {2#10, 2#1110};
frame_type('QoS CF-Ack + CF-Poll')        -> {2#10, 2#1111};

frame_type(_) ->
    {0, 0}.

format_mac(<<A:8, B:8, C:8, D:8, E:8, F:8>>) ->
    flat_format("~2.16.0b:~2.16.0b:~2.16.0b:~2.16.0b:~2.16.0b:~2.16.0b", [A, B, C, D, E, F]);
format_mac(MAC) ->
    flat_format("~w", MAC).

flat_format(Format, Data) ->
    lists:flatten(io_lib:format(Format, Data)).

initial_state(local_mac) ->
    init_assoc;
initial_state(split_mac) ->
    init_auth.
