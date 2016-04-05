-module(ieee80211_station).

-behavior(gen_fsm).

%% API
-export([start_link/9, handle_ieee80211_frame/2, handle_ieee802_3_frame/2,
         take_over/9, detach/1, delete/1]).
%% Helpers
-export([format_mac/1]).

%% For testing
-export([frame_type/1]).

%% gen_fsm callbacks
-export([init/1,
	 init_auth/2, init_auth/3,
	 init_assoc/2, init_assoc/3,
	 init_start/2, init_start/3,
	 connected/2, connected/3,
	 handle_event/3, handle_sync_event/4,
	 handle_info/3, terminate/3, code_change/4]).

-include("capwap_debug.hrl").
-include("capwap_packet.hrl").
-include("ieee80211.hrl").
-include("ieee80211_station.hrl").

-import(ctld_session, [to_session/1, attr_get/2]).

-define(SERVER, ?MODULE).
-define(IDLE_TIMEOUT, 30 * 1000).
-define(SHUTDOWN_TIMEOUT, 1 * 1000).

-define(OPEN_SYSTEM, 0).
-define(SUCCESS, 0).
-define(REFUSED, 1).

-record(state, {
          ac,
          ac_monitor,
	  ctld_session,
          data_path,
          data_channel_address,
	  wtp_id,
	  wtp_session_id,
          radio_mac,
          mac,
          mac_mode,
          tunnel_mode,
          out_action,
	  capabilities
         }).

-record(auth_frame, {algo, seq_no, status, params}).

-define(DEBUG_OPTS,[{install, {fun lager_sys_debug:lager_gen_fsm_trace/3, ?MODULE}}]).

%%%===================================================================
%%% API
%%%===================================================================
start_link(AC, DataPath, WTPDataChannelAddress, WtpId, SessionId, RadioMAC, ClientMAC, MacMode, TunnelMode) ->
    gen_fsm:start_link(?MODULE, [AC, DataPath, WTPDataChannelAddress, WtpId, SessionId, RadioMAC, ClientMAC, MacMode, TunnelMode], [{debug, ?DEBUG_OPTS}]).

handle_ieee80211_frame(AC, <<FrameControl:2/bytes,
			      _Duration:16, DA:6/bytes, SA:6/bytes, BSS:6/bytes,
			      _SequenceControl:16/little-integer, FrameRest/binary>>) ->
    %% FragmentNumber = SequenceControl band 16#0f,
    %% SequenceNumber = SequenceControl bsr 4,

    <<SubType:4, Type:2, 0:2, Order:1, _:5, FromDS:1, ToDS:1>> = FrameControl,
    FrameType = frame_type(Type, SubType),
    Frame = strip_ht_control(Order, FrameRest),
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

take_over(Pid, AC, DataPath, WTPDataChannelAddress, WtpId, SessionId, RadioMAC, MacMode, TunnelMode) ->
    gen_fsm:sync_send_event(Pid, {take_over, AC, DataPath, WTPDataChannelAddress, WtpId, SessionId, RadioMAC, MacMode, TunnelMode}).

detach(ClientMAC) ->
    case capwap_station_reg:lookup(ClientMAC) of
	{ok, Pid} ->
	    gen_fsm:sync_send_event(Pid, detach);
	_ ->
	    not_found
    end.

delete(Pid) when is_pid(Pid) ->
    gen_fsm:sync_send_event(Pid, delete).

%%%===================================================================
%%% gen_fsm callbacks
%%%===================================================================
init([AC, DataPath, WTPDataChannelAddress, WtpId, SessionId, RadioMAC, ClientMAC, MacMode, TunnelMode]) ->
    lager:debug("Register station ~p as ~w", [{AC, RadioMAC, ClientMAC}, self()]),
    capwap_station_reg:register(ClientMAC),
    capwap_station_reg:register(AC, ClientMAC),
    ACMonitor = erlang:monitor(process, AC),
    State = #state{ac = AC, ac_monitor = ACMonitor, data_path = DataPath,
		   data_channel_address = WTPDataChannelAddress, wtp_id = WtpId, wtp_session_id = SessionId,
                   radio_mac = RadioMAC, mac = ClientMAC, mac_mode = MacMode, tunnel_mode = TunnelMode,
		  capabilities = #sta_cap{}},
    {ok, initial_state(MacMode), State}.

%%
%% State transitions follow IEEE 802.11-2012, Section 10.3.2
%%

%%
%% State 1
%%
init_auth(timeout, State) ->
    lager:warning("idle timeout in INIT_AUTH"),
    {stop, normal, State}.

init_auth(Event = {'Authentication', DA, SA, BSS, 0, 0, Frame}, _From, State) ->
    lager:debug("in INIT_AUTH got Authentication Request: ~p", [Event]),
    AuthFrame = decode_auth_frame(Frame),
    case AuthFrame of
	#auth_frame{algo   = ?OPEN_SYSTEM,
		    status = ?SUCCESS} ->
	    %% send Auth OK
	    Reply = gen_auth_ok(DA, SA, BSS, Frame),
	    {reply, {reply, Reply}, init_assoc, State, ?IDLE_TIMEOUT};
	_ ->
	    %% send Auth Fail
	    Reply = gen_auth_fail(DA, SA, BSS, Frame),
	    {reply, {reply, Reply}, init_auth, State, ?IDLE_TIMEOUT}
    end;

init_auth(Event, From, State)
  when element(1, Event) == take_over ->
    lager:debug("in INIT_AUTH got TAKE-OVER: ~p", [Event]),
    handle_take_over(Event, From, State);

init_auth(Event, _From, State) when Event == detach; Event == delete ->
    {reply, {error, not_attached}, init_auth, State, ?IDLE_TIMEOUT};

init_auth(Event, _From, State) ->
    lager:warning("in INIT_AUTH got unexpexted: ~p", [Event]),
    {reply, {error, unexpected}, init_auth, State, ?IDLE_TIMEOUT}.

%%
%% State 2
%%
init_assoc(timeout, State) ->
    lager:warning("idle timeout in INIT_ASSOC"),
    {stop, normal, State}.

init_assoc(Event = {'Authentication', _DA, _SA, _BSS, 0, 0, _Frame}, _From, State)
  when State#state.mac_mode == local_mac ->
    lager:debug("in INIT_ASSOC Local-MAC Mode got Authentication Request: ~p", [Event]),
    {reply, {ok, ignore}, init_assoc, State, ?IDLE_TIMEOUT};

init_assoc(Event = {FrameType, _DA, _SA, BSS, 0, 0, Frame}, _From,
	   State0 = #state{radio_mac = BSS, mac = MAC, mac_mode = MacMode,
			   tunnel_mode = TunnelMode})
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

    State1 = update_sta_from_mgmt_frame(FrameType, Frame, State0),
    State = ctld_association(State1),

    Reply = {add, BSS, MAC, State#state.capabilities, MacMode, TunnelMode},
    {reply, Reply, connected, State, ?IDLE_TIMEOUT};

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
    {reply, {reply, Reply}, init_start, State, ?IDLE_TIMEOUT};

init_assoc(Event, From, State)
  when element(1, Event) == take_over ->
    lager:debug("in INIT_ASSOC got TAKE-OVER: ~p", [Event]),
    handle_take_over(Event, From, State);

init_assoc(Event, _From, State) when Event == detach; Event == delete ->
    {reply, {error, not_attached}, init_assoc, State, ?IDLE_TIMEOUT};

init_assoc(Event, _From, State) ->
    lager:warning("in INIT_ASSOC got unexpexted: ~p", [Event]),
    {reply, {error, unexpected}, init_assoc, State, ?IDLE_TIMEOUT}.

%%
%% State 3
%%
init_start(timeout, State) ->
    lager:warning("idle timeout in INIT_START"),
    {stop, normal, State}.

init_start(Event = {'Null', _DA, _SA, BSS, 0, 1, <<>>}, _From,
	   State = #state{radio_mac = BSS, mac = MAC, mac_mode = MacMode,
			  tunnel_mode = TunnelMode, capabilities = StaCaps}) ->
    lager:debug("in INIT_START got Null: ~p", [Event]),
    Reply = {add, BSS, MAC, StaCaps, MacMode, TunnelMode},
    {reply, Reply, connected, State, ?IDLE_TIMEOUT};

init_start(Event, From, State)
  when element(1, Event) == take_over ->
    lager:debug("in INIT_START got TAKE-OVER: ~p", [Event]),
    handle_take_over(Event, From, State);

init_start(Event, _From, State) when Event == detach; Event == delete ->
    {reply, {error, not_attached}, init_start, State, ?IDLE_TIMEOUT};

init_start(Event, _From, State) ->
    lager:warning("in INIT_START got unexpexted: ~p", [Event]),
    {reply, {error, unexpected}, init_start, State, ?IDLE_TIMEOUT}.

%%
%% State 4
%%
connected(timeout, State) ->
    lager:warning("idle timeout in CONNECTED"),
    {next_state, connected, State, ?IDLE_TIMEOUT}.

connected({'802.3', Data}, _From,
	  State = #state{radio_mac = BSS, mac = MAC, mac_mode = MacMode, tunnel_mode = TunnelMode}) ->
    lager:debug("in CONNECTED got 802.3 Data:~n~s", [flower_tools:hexdump(Data)]),
    {reply, {flow, BSS, MAC, MacMode, TunnelMode}, connected, State, ?IDLE_TIMEOUT};

connected(Event = {FrameType, _DA, _SA, BSS, 0, 0, Frame}, _From,
	   State0 = #state{radio_mac = BSS, mac = MAC, mac_mode = MacMode,
			   tunnel_mode = TunnelMode})
  when MacMode == local_mac andalso
       (FrameType == 'Association Request' orelse FrameType == 'Reassociation Request') ->
    lager:debug("in CONNECTED Local-MAC Mode got Association Request: ~p", [Event]),

    %% Mobility Event!!! The station Reattached to the SAME AP and the AP had not yet
    %% deleted the Station

    %% MAC blocks would go here!

    %% RFC 5416, Sect. 2.2.2:
    %%
    %%   While the MAC is terminated on the WTP, it is necessary for the AC to
    %%   be aware of mobility events within the WTPs.  Thus, the WTP MUST
    %%   forward the IEEE 802.11 Association Request frames to the AC.  The AC
    %%   MAY reply with a failed Association Response frame if it deems it
    %%   necessary, and upon receipt of a failed Association Response frame
    %%   from the AC, the WTP MUST send a Disassociation frame to the station.

    State = update_sta_from_mgmt_frame(FrameType, Frame, State0),

    Reply = {add, BSS, MAC, State#state.capabilities, MacMode, TunnelMode},
    {reply, Reply, connected, State, ?IDLE_TIMEOUT};

connected(Event = {'Deauthentication', _DA, _SA, BSS, 0, 0, _Frame}, _From,
	   State = #state{radio_mac = BSS, mac = MAC, mac_mode = MacMode,
			  tunnel_mode = TunnelMode}) ->
    lager:debug("in CONNECTED got Deauthentication: ~p", [Event]),
    ctld_disassociation(State),
    {reply, {del, BSS, MAC, MacMode, TunnelMode}, initial_state(MacMode), State, ?SHUTDOWN_TIMEOUT};

connected(Event = {'Disassociation', _DA, _SA, BSS, 0, 0, _Frame}, _From,
	   State = #state{radio_mac = BSS, mac = MAC, mac_mode = MacMode,
			  tunnel_mode = TunnelMode}) ->
    lager:debug("in CONNECTED got Disassociation: ~p", [Event]),
    ctld_disassociation(State),
    {reply, {del, BSS, MAC, MacMode, TunnelMode}, init_assoc, State, ?SHUTDOWN_TIMEOUT};

connected(Event, From, State)
  when element(1, Event) == take_over ->
    lager:debug("in CONNECTED got TAKE-OVER: ~p", [Event]),
    ctld_disassociation(State),
    handle_take_over(Event, From, State);

connected(delete, _From, State = #state{ac = AC, radio_mac = RadioMAC,
						mac = MAC, mac_mode = MacMode,
						tunnel_mode = TunnelMode}) ->
    gen_fsm:send_event(AC, {delete_station, 1, 1, RadioMAC, MAC, MacMode, TunnelMode}),
    ctld_disassociation(State),
    {reply, ok, initial_state(MacMode), State, ?SHUTDOWN_TIMEOUT};

connected(detach, _From, State = #state{ac = AC, radio_mac = RadioMAC,
					mac = MAC, mac_mode = MacMode,
					tunnel_mode = TunnelMode}) ->
    gen_fsm:send_event(AC, {detach_station, 1, 1, RadioMAC, MAC, MacMode, TunnelMode}),
    ctld_disassociation(State),
    {reply, ok, initial_state(MacMode), State, ?SHUTDOWN_TIMEOUT};

connected(Event, _From, State) ->
    lager:warning("in CONNECTED got unexpexted: ~p", [Event]),
    {reply, {error, unexpected}, connected, State, ?IDLE_TIMEOUT}.

handle_event(_Event, StateName, State) ->
    {next_state, StateName, State, ?IDLE_TIMEOUT}.

handle_sync_event(_Event, _From, StateName, State) ->
    Reply = ok,
    {reply, Reply, StateName, State, ?IDLE_TIMEOUT}.

handle_info({'DOWN', _ACMonitor, process, AC, _Info}, _StateName,
            State = #state{ac = AC}) ->
    lager:warning("AC died ~w", [AC]),
    {stop, normal, State};

handle_info(Info, StateName, State) ->
    lager:warning("in State ~p unexpected Info: ~p", [StateName, Info]),
    {next_state, StateName, State, ?IDLE_TIMEOUT}.

terminate(_Reason, StateName, State = #state{ac = AC, radio_mac = RadioMAC,
					     mac = MAC, mac_mode = MacMode,
					     tunnel_mode = TunnelMode}) ->
    if StateName == connected ->
	    gen_fsm:send_event(AC, {detach_station, 1, 1, RadioMAC, MAC, MacMode, TunnelMode}),
	    ctld_disassociation(State);
       true ->
	    ok
    end,
    capwap_ac:station_terminating(AC),
    lager:warning("Station ~s terminated in State ~w", [format_mac(MAC), StateName]),
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

handle_take_over({take_over, AC, DataPath, WTPDataChannelAddress, WtpId, SessionId, RadioMAC, MacMode, TunnelMode}, _From,
		 State0 = #state{ac = OldAC, ac_monitor = OldACMonitor,
				 data_path = _OldDataPath,
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
			 data_path = DataPath, data_channel_address = WTPDataChannelAddress,
			 wtp_id = WtpId, wtp_session_id = SessionId,
			 radio_mac = RadioMAC, mac_mode = MacMode,
			 tunnel_mode = TunnelMode},
    {reply, {ok, self()}, initial_state(MacMode), State, ?IDLE_TIMEOUT}.

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

update_sta_from_mgmt_frame(FrameType, Frame, State)
  when (FrameType == 'Association Request') ->
    <<_Capability:16, _ListenInterval:16,
      IEs/binary>> = Frame,
    update_sta_from_mgmt_frame_ies(IEs, State);
update_sta_from_mgmt_frame(FrameType, Frame, State)
  when (FrameType == 'Reassociation Request') ->
    <<_Capability:16, _ListenInterval:16,
      _CurrentAP:6/bytes, IEs/binary>> = Frame,
    update_sta_from_mgmt_frame_ies(IEs, State);
update_sta_from_mgmt_frame(_FrameType, _Frame, State) ->
    State.

update_sta_from_mgmt_frame_ies(IEs, #state{capabilities = Cap0} = State) ->
    ListIE = [ {Id, Data} || <<Id:8, Len:8, Data:Len/bytes>> <= IEs ],
    Cap = lists:foldl(fun update_sta_cap_from_mgmt_frame_ie/2, Cap0, ListIE),
    lager:debug("New Station Caps: ~p", [lager:pr(Cap, ?MODULE)]),
    State#state{capabilities = Cap}.

smps2atom(0) -> static;
smps2atom(1) -> dynamic;
smps2atom(2) -> reserved;
smps2atom(3) -> disabled.

update_sta_cap_from_mgmt_frame_ie(IE = {?WLAN_EID_HT_CAP, HtCap}, Cap) ->
    lager:debug("Mgmt IE HT CAP: ~p", [IE]),
    <<CapInfo:2/bytes, AMPDU_ParamsInfo:8/bits, MCSinfo:16/bytes,
      ExtHtCapInfo:2/bytes, TxBFinfo:4/bytes, ASelCap:8/bits>> = HtCap,
    lager:debug("CapInfo: ~p, AMPDU: ~p, MCS: ~p, ExtHt: ~p, TXBf: ~p, ASEL: ~p",
		[CapInfo, AMPDU_ParamsInfo, MCSinfo, ExtHtCapInfo, TxBFinfo, ASelCap]),
    <<_TxSTBC:1, SGI40Mhz:1, SGI20Mhz:1, _GFPreamble:1, SMPS:2, _Only20Mhz:1, _LDPC:1,
      _TXOP:1, _FortyMHzIntol:1, _PSMPSup:1, _DSSSMode:1, _MaxAMSDULen:1, BAckDelay:1, _RxSTBC:2>>
	= CapInfo,
    <<_:3, AMPDU_Density:3, AMPDU_Factor:2>> = AMPDU_ParamsInfo,
    <<RxMask:10/bytes, RxHighest:16/integer-little, _TxParms:8, _:3/bytes>> = MCSinfo,

    Cap#sta_cap{sgi_20mhz = (SGI20Mhz == 1), sgi_40mhz = (SGI40Mhz == 1),
		smps = smps2atom(SMPS), back_delay = (BAckDelay == 1),
		ampdu_density = AMPDU_Density, ampdu_factor = AMPDU_Factor,
		rx_mask = RxMask, rx_highest = RxHighest
	       };

%% Vendor Specific:
%%  OUI:  00-50-F2 - Microsoft
%%  Type: 2        - WMM/WME
%%  WME Subtype: 0 - IE
%%  WME Version: 1
update_sta_cap_from_mgmt_frame_ie(IE = {?WLAN_EID_VENDOR_SPECIFIC,
				    <<16#00, 16#50, 16#F2, 2, 0, 1, _/binary>>}, Cap) ->
    lager:debug("Mgmt IE WMM: ~p", [IE]),
    Cap#sta_cap{wmm = true};
update_sta_cap_from_mgmt_frame_ie(IE = {_Id, _Value}, Cap) ->
    lager:debug("Mgmt IE: ~p", [IE]),
    Cap.

strip_ht_control(0, Frame) ->
    Frame;
strip_ht_control(1, <<_HT:4/bytes, Frame/binary>>) ->
    Frame.

%% Accounting Support
ip2str(IP) ->
    iolist_to_binary(inet_parse:ntoa(IP)).

tunnel_medium({_,_,_,_}) ->
    'IPv4';
tunnel_medium({_,_,_,_,_,_,_,_}) ->
    'IPv6'.

add_tunnel_info({Address, _Port}, SessionData) ->
    [{'Tunnel-Type', 'CAPWAP'},
     {'Tunnel-Medium-Type', tunnel_medium(Address)},
     {'Tunnel-Client-Endpoint', ip2str(Address)}
     |SessionData].

accounting_update(STA, SessionOpts) ->
    lager:debug("accounting_update: ~p, ~p", [STA, attr_get('MAC', SessionOpts)]),
    case attr_get('MAC', SessionOpts) of
	{ok, MAC} ->
	    STAStats = capwap_dp:get_station(MAC),
	    lager:debug("STA Stats: ~p", [STAStats]),
	    {_MAC, {RcvdPkts, SendPkts, RcvdBytes, SendBytes}} = STAStats,
	    Acc = [{'InPackets',  RcvdPkts},
		    {'OutPackets', SendPkts},
		    {'InOctets',   RcvdBytes},
		    {'OutOctets',  SendBytes}],
	    ctld_session:merge(SessionOpts, to_session(Acc));
	_ ->
	    SessionOpts
    end.

ctld_association(State = #state{mac = MAC, data_channel_address = WTPDataChannelAddress,
				wtp_id = WtpId, wtp_session_id = WtpSessionId}) ->
    MACStr = format_mac(MAC),
    SessionData0 = [{'Accouting-Update-Fun', fun accounting_update/2},
		    {'Service-Type', 'TP-CAPWAP-STA'},
		    {'Framed-Protocol', 'TP-CAPWAP'},
		    {'MAC', MAC},
		    {'Username', MACStr},
		    {'Calling-Station', MACStr},
		    {'Location-Id', WtpId},
		    {'CAPWAP-Session-Id', <<WtpSessionId:128>>}],
    SessionData1 = add_tunnel_info(WTPDataChannelAddress, SessionData0),
    {ok, Session} = ctld_session_sup:new_session(self(), to_session(SessionData1)),
    lager:info("NEW session for ~w at ~p", [MAC, Session]),
    ctld_session:start(Session, to_session([])),
    State#state{ctld_session = Session}.

ctld_disassociation(#state{ctld_session = Session}) ->
    ctld_session:stop(Session, to_session([])),
    ok.

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
