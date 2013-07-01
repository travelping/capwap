-module(ieee80211_station).

-behavior(gen_fsm).

%% API
-export([start_link/3, handle_ieee80211_frame/2, handle_ieee802_3_frame/2]).

%% gen_fsm callbacks
-export([init/1,
	 init_auth/2, init_auth/3,
	 init_assoc/2, init_assoc/3,
	 init_start/2, init_start/3,
	 connected/2, connected/3,
	 handle_event/3, handle_sync_event/4,
	 handle_info/3, terminate/3, code_change/4]).

-include("capwap_debug.hrl").

-define(SERVER, ?MODULE).
-define(IDLE_TIMEOUT, 30 * 1000).

-define(OPEN_SYSTEM, 0).
-define(SUCCESS, 0).
-define(REFUSED, 1).

-record(state, {ac, radio_mac, mac, mac_mode, tunnel_mode}).

-record(auth_frame, {algo, seq_no, status, params}).

%%%===================================================================
%%% API
%%%===================================================================
start_link(AC, RadioMAC, ClientMAC) ->
    gen_fsm:start_link(?MODULE, [AC, RadioMAC, ClientMAC], [{debug, [trace]}]).

handle_ieee80211_frame(AC, <<FrameControl:2/bytes,
			      _Duration:16, DA:6/bytes, SA:6/bytes, BSS:6/bytes,
			      _SequenceControl:16/little-integer, Frame/binary>>) ->
    %% FragmentNumber = SequenceControl band 16#0f,
    %% SequenceNumber = SequenceControl bsr 4,

    <<SubType:4, Type:2, 0:2, _:6, FromDS:1, ToDS:1>> = FrameControl,
    FrameType = frame_type(Type, SubType),
    ieee80211_request(AC, FrameType, DA, SA, BSS, FromDS, ToDS, Frame);

handle_ieee80211_frame(_, Frame) ->
    ?DEBUG(?RED "unhandled IEEE802.11 Frame:~n~s~n", [flower_tools:hexdump(Frame)]),
    {error, unhandled}.

handle_ieee802_3_frame(AC, <<_EthDst:6/bytes, EthSrc:6/bytes, _/binary>> = Frame) ->
    case capwap_station_reg:lookup(AC, EthSrc) of
	not_found ->
	    ?DEBUG(?RED "got 802.3 from unknown Ethern station~n"),
	    {error, invalid_station};
	{ok, Station} ->
	    gen_fsm:sync_send_event(Station, {'802.3', Frame})
    end;
handle_ieee802_3_frame(_, _Frame) ->
    {error, unhandled}.

get_wtp_for_client_mac(_Sw, ClientMAC) ->
    case capwap_station_reg:lookup(ClientMAC) of
	{ok, Pid} ->
	    gen_fsm:sync_send_all_state_event(Pid, {get_wtp_for_client_mac, _Sw});
	_ ->
	    not_found
    end.

%%%===================================================================
%%% gen_fsm callbacks
%%%===================================================================
init([AC, RadioMAC, ClientMAC]) ->
    ?DEBUG(?BLUE "register Station ~p as ~w~n", [{AC, RadioMAC, ClientMAC}, self()]),
    capwap_station_reg:register(ClientMAC),
    capwap_station_reg:register(AC, ClientMAC),
    erlang:monitor(process, AC),
    {ok, MacMode, TunnelMode} = capwap_ac:get_peer_mode(AC),
    State = #state{ac = AC, radio_mac = RadioMAC, mac = ClientMAC, mac_mode = MacMode, tunnel_mode = TunnelMode},
    case MacMode of
	local_mac ->
	    {ok, init_assoc, State};
	split_mac ->
	    {ok, init_auth, State}
    end.

init_auth(timeout, State) ->
    ?DEBUG(?RED "idle timeout in INIT_AUTH~n"),
    next_state(init_auth, State).

init_auth(Event = {'Authentication', DA, SA, BSS, 0, 0, Frame}, _From, State) ->
    ?DEBUG(?GREEN "in INIT_AUTH got Authentication Request: ~p~n", [Event]),
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

init_auth(Event, _From, State) ->
    ?DEBUG(?RED "in INIT_AUTH got unexpexted: ~p~n", [Event]),
    reply({error, unexpected}, init_auth, State).

init_assoc(timeout, State) ->
    ?DEBUG(?RED "idle timeout in INIT_ASSOC~n"),
    next_state(init_assoc, State).

init_assoc(Event = {'Authentication', _DA, _SA, _BSS, 0, 0, _Frame}, _From, State)
  when State#state.mac_mode == local_mac ->
    ?DEBUG(?GREEN "in INIT_ASSOC Local-MAC Mode got Authentication Request: ~p~n", [Event]),
    reply({ok, ignore}, init_assoc, State);

init_assoc(Event = {'Association Request', _DA, _SA, BSS, 0, 0, _Frame}, _From,
	   State = #state{radio_mac = BSS, mac = MAC, mac_mode = MacMode, tunnel_mode = TunnelMode})
  when MacMode == local_mac ->
    ?DEBUG(?GREEN "in INIT_ASSOC Local-MAC Mode got Association Request: ~p~n", [Event]),

    %% MAC blocks would go here!

    %% RFC 5416, Sect. 2.2.2:
    %%
    %%   While the MAC is terminated on the WTP, it is necessary for the AC to
    %%   be aware of mobility events within the WTPs.  Thus, the WTP MUST
    %%   forward the IEEE 802.11 Association Request frames to the AC.  The AC
    %%   MAY reply with a failed Association Response frame if it deems it
    %%   necessary, and upon receipt of a failed Association Response frame
    %%   from the AC, the WTP MUST send a Disassociation frame to the station.

    reply({add, BSS, MAC, MacMode, TunnelMode}, connected, State);

init_assoc(Event = {'Authentication', _DA, _SA, _BSS, 0, 0, _Frame}, From, State) ->
    ?DEBUG(?GREEN "in INIT_ASSOC got Authentication Request: ~p~n", [Event]),
    %% fall-back to init_auth....
    init_auth(Event, From, State);

init_assoc(Event = {'Association Request', DA, SA, BSS, 0, 0, _Frame}, _From, State) ->
    ?DEBUG(?GREEN "in INIT_ASSOC got Association Request: ~p~n", [Event]),
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

init_assoc(Event, _From, State) ->
    ?DEBUG(?RED "in INIT_ASSOC got unexpexted: ~p~n", [Event]),
    reply({error, unexpected}, init_assoc, State).

init_start(timeout, State) ->
    ?DEBUG(?RED "idle timeout in INIT_START~n"),
    next_state(init_start, State).

init_start(Event = {'Null', _DA, _SA, BSS, 0, 1, <<>>}, _From,
	   State = #state{radio_mac = BSS, mac = MAC, mac_mode = MacMode, tunnel_mode = TunnelMode}) ->
    ?DEBUG(?GREEN "in INIT_START got Null: ~p~n", [Event]),
    reply({add, BSS, MAC, MacMode, TunnelMode}, connected, State);

init_start(Event, _From, State) ->
    ?DEBUG(?RED "in INIT_START got unexpexted: ~p~n", [Event]),
    reply({error, unexpected}, init_start, State).

connected(timeout, State) ->
    ?DEBUG(?RED "idle timeout in CONNECTED~n"),
    next_state(connected, State).

connected({'802.3', Data}, _From,
	  State = #state{radio_mac = BSS, mac = MAC, mac_mode = MacMode, tunnel_mode = TunnelMode}) ->
    ?DEBUG(?GREEN "in CONNECTED got 802.3 Data:~n~s~n", [flower_tools:hexdump(Data)]),
    reply({flow, BSS, MAC, MacMode, TunnelMode}, connected, State);

connected(Event, _From, State) ->
    ?DEBUG(?RED "in CONNECTED got unexpexted: ~p~n", [Event]),
    reply({error, unexpected}, connected, State).

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

handle_sync_event(_Event, _From, StateName, State) ->
    Reply = ok,
    reply(Reply, StateName, State).

handle_info({'DOWN', _MonitorRef, process, AC, _Info}, _StateName, State = #state{ac = AC}) ->
    ?DEBUG(?RED "AC died~n"),
    {stop, normal, State};

handle_info(Info, StateName, State) ->
    ?DEBUG(?RED "in State ~p unexpected Info: ~p~n", [StateName, Info]),
    next_state(StateName, State).

terminate(_Reason, StateName, #state{mac = MAC}) ->
    ?DEBUG(?RED "Station ~p terminated in State ~w~n", [MAC, StateName]),
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

next_state(NextStateName, State) ->
     {next_state, NextStateName, State, ?IDLE_TIMEOUT}.

reply(Reply, NextStateName, State) ->
    {reply, Reply, NextStateName, State, ?IDLE_TIMEOUT}.

ieee80211_request(_AC, _FrameType, _DA, SA, BSS, _FromDS, _ToDS, _Frame)
  when SA == BSS ->
    %% OpenCAPWAP is stupid, it mirrors our own Frame back to us....
    {ok, ignore};

ieee80211_request(AC, FrameType, DA, SA, BSS, FromDS, ToDS, Frame)
  when FrameType == 'Authentication';
       FrameType == 'Association Request';
       FrameType == 'Null' ->
    ?DEBUG(?BLUE "search Station ~p~n", [{AC, SA}]),
    Found = case capwap_station_reg:lookup(AC, SA) of
		not_found ->
		    ?DEBUG(?BLUE "not found~n"),
		    capwap_station_sup:new_station(AC, BSS, SA);
		Ok = {ok, Station0} ->
		    ?DEBUG(?BLUE "found as ~p~n", [Station0]),
		    Ok
	    end,
    case Found of
	{ok, Station} ->
	    gen_fsm:sync_send_event(Station, {FrameType, DA, SA, BSS, FromDS, ToDS, Frame});
	Other ->
	    Other
    end;

ieee80211_request(_AC, FrameType, _DA, _SA, _BSS, _FromDS, _ToDS, _Frame)
  when FrameType == 'Probe Request' ->
    {ok, ignore};

ieee80211_request(_AC, FrameType, DA, SA, BSS, FromDS, ToDS, Frame) ->
    ?DEBUG(?RED "unhandled IEEE 802.11 Frame: ~p~n", [{FrameType, DA, SA, BSS, FromDS, ToDS, Frame}]),
    {error, unhandled}.

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
