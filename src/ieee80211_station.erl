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

-module(ieee80211_station).

-compile({parse_transform, cut}).

-behaviour(gen_statem).

%% API
-export([start_link/3, handle_ieee80211_frame/2, handle_ieee802_3_frame/3,
         take_over/3, detach/1, delete/1, start_gtk_rekey/4]).
%% Helpers
-export([format_mac/1]).

%% For testing
-export([frame_type/1, frame_type/2]).

%% gen_statem callbacks
-export([callback_mode/0,
	 init/1,
	 init_auth/3,
	 init_assoc/3,
	 init_start/3,
	 connected/3,
	 terminate/3, code_change/4]).

-include("capwap_debug.hrl").
-include("capwap_packet.hrl").
-include("capwap_config.hrl").
-include("capwap_ac.hrl").
-include("ieee80211.hrl").
-include("ieee80211_station.hrl").
-include("eapol.hrl").

-import(ergw_aaa_session, [to_session/1, attr_get/2]).

-define(SERVER, ?MODULE).
-define(IDLE_TIMEOUT, 30 * 1000).
-define(SHUTDOWN_TIMEOUT, 1 * 1000).

-define(OPEN_SYSTEM, 0).
-define(SUCCESS, 0).
-define(REFUSED, 1).

-record(state, {
          ac,
          ac_monitor,
	  aaa_session,
          data_path,
          data_channel_address,
	  wtp_id,
	  wtp_session_id,
          mac,
          mac_mode,
          tunnel_mode,
          out_action,
	  aid,
	  capabilities,

          radio_mac,
	  response_ies,
	  wpa_config,
	  gtk,
	  igtk,

	  eapol_state,
	  eapol_retransmit,
	  eapol_timer,
	  cipher_state,

	  rekey_running,
	  rekey_pending,
	  rekey_control,

	  rekey_tref
         }).

-record(auth_frame, {algo, seq_no, status, params}).

-define(DEBUG_OPTS,[{install, {fun lager_sys_debug:lager_gen_fsm_trace/3, ?MODULE}}]).

-define(GTK_KDE,  1).
-define(IGTK_KDE, 9).

%%%===================================================================
%%% API
%%%===================================================================
start_link(AC, ClientMAC, StationCfg) ->
    gen_statem:start_link(?MODULE, [AC, ClientMAC, StationCfg], [{debug, ?DEBUG_OPTS}]).

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

handle_ieee802_3_frame(AC, RadioMAC, <<_EthDst:6/bytes, EthSrc:6/bytes, _/binary>> = Frame) ->
    with_station(AC, RadioMAC, EthSrc, gen_statem:cast(_, {'802.3', Frame}));
handle_ieee802_3_frame(_, _, _Frame) ->
    {error, unhandled}.

take_over(Pid, AC, StationCfg) ->
    gen_statem:call(Pid, {take_over, AC, StationCfg}).

detach(ClientMAC) ->
    case capwap_station_reg:lookup(ClientMAC) of
	{ok, Pid} ->
	    gen_statem:call(Pid, detach);
	_ ->
	    not_found
    end.

delete(Pid) when is_pid(Pid) ->
    gen_statem:call(Pid, delete).

start_gtk_rekey(Station, Controller, GTK, IGTK) ->
    gen_statem:cast(Station, {start_gtk_rekey, Controller, GTK, IGTK}).

%%%===================================================================
%%% gen_statem callbacks
%%%===================================================================
callback_mode() ->
    state_functions.

init([AC, ClientMAC, StationCfg = #station_config{bss = RadioMAC,
						  mac_mode = MacMode}]) ->
    State0 = init_state_from_cfg(StationCfg),

    lager:debug("Register station ~p ~p as ~w", [AC, ClientMAC, self()]),
    capwap_station_reg:register(ClientMAC),
    capwap_station_reg:register(AC, RadioMAC, ClientMAC),
    ACMonitor = erlang:monitor(process, AC),

    State = State0#state{ac = AC,
			 ac_monitor = ACMonitor,
			 mac = ClientMAC},
    {ok, initial_state(MacMode), State}.

%%
%% State transitions follow IEEE 802.11-2012, Section 10.3.2
%%

%%
%% State 1
%%
init_auth(timeout, _, State) ->
    lager:warning("idle timeout in INIT_AUTH"),
    {stop, normal, State};

init_auth(cast, Event = {'Authentication', DA, SA, BSS, 0, 0, Frame},
	  State = #state{radio_mac = BSS}) ->
    lager:debug("in INIT_AUTH got Authentication Request: ~p", [Event]),
    AuthFrame = decode_auth_frame(Frame),
    case AuthFrame of
	#auth_frame{algo   = ?OPEN_SYSTEM,
		    status = ?SUCCESS} ->
	    %% send Auth OK
	    wtp_send_80211(gen_auth_ok(DA, SA, BSS, Frame), State),
	    {next_state, init_assoc, State, ?IDLE_TIMEOUT};
	_ ->
	    %% send Auth Fail
	    wtp_send_80211(gen_auth_fail(DA, SA, BSS, Frame), State),
	    {keep_state_and_data, [?IDLE_TIMEOUT]}
    end;

init_auth({call, _} = EventType, Event, State)
  when element(1, Event) == take_over ->
    lager:debug("in INIT_AUTH got TAKE-OVER: ~p", [Event]),
    handle_take_over(EventType, Event, State);

init_auth({call, From}, Event, _State) when Event == detach; Event == delete ->
    {keep_state_and_data, [{reply, From, {error, not_attached}}, ?IDLE_TIMEOUT]};

init_auth(info, Msg, State) ->
    handle_info(Msg, init_auth, State);

init_auth(Type, Event, _State) ->
    lager:warning("in INIT_AUTH got unexpexted: ~p:~p", [Type, Event]),
    {keep_state_and_data, [?IDLE_TIMEOUT]}.

%%
%% State 2
%%
init_assoc(timeout, _, State) ->
    lager:warning("idle timeout in INIT_ASSOC"),
    {stop, normal, State};

init_assoc(cast, Event = {'Authentication', _DA, _SA, BSS, 0, 0, _Frame},
	   #state{radio_mac = BSS, mac_mode = local_mac}) ->
    lager:debug("in INIT_ASSOC Local-MAC Mode got Authentication Request: ~p", [Event]),
    {keep_state_and_data, [?IDLE_TIMEOUT]};

init_assoc(cast, Event = {FrameType, _DA, _SA, BSS, 0, 0, Frame},
	   State0 = #state{radio_mac = BSS, mac_mode = MacMode})
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

    State1 = assign_aid(State0),
    State2 = update_sta_from_mgmt_frame(FrameType, Frame, State1),
    State3 = aaa_association(State2),
    State = wtp_add_station(State3),

    {next_state, connected, State, ?IDLE_TIMEOUT};

init_assoc(cast, Event = {'Authentication', _DA, _SA, BSS, 0, 0, _Frame},
	   State = #state{radio_mac = BSS}) ->
    lager:debug("in INIT_ASSOC got Authentication Request: ~p", [Event]),
    %% fall-back to init_auth....
    {next_state, init_auth, State, [{next_event, cast, Event}]};

init_assoc(cast, Event = {'Deauthentication', _DA, _SA, BSS, 0, 0, _Frame},
	   State = #state{radio_mac = BSS, mac_mode = MacMode}) ->
    lager:debug("in INIT_ASSOC got Deauthentication: ~p", [Event]),
    {next_state, initial_state(MacMode), State, ?SHUTDOWN_TIMEOUT};

init_assoc(cast, Event = {FrameType, DA, SA, BSS, 0, 0, ReqFrame},
	   #state{radio_mac = BSS,
		  response_ies = ResponseIEs0,
		  wpa_config = #wpa_config{
				  rsn = #wtp_wlan_rsn{
					   version = RSNversion,
					   management_frame_protection = MFP}}
		 } = State0)
  when (FrameType == 'Association Request' orelse FrameType == 'Reassociation Request') ->
    lager:debug("in INIT_ASSOC got Association Request: ~p", [Event]),

    State1 = assign_aid(State0),
    State2 = update_sta_from_mgmt_frame(FrameType, ReqFrame, State1),
    State3 = aaa_association(State2),

    %% TODO: validate RSNE against Wlan Config
    #state{capabilities = #sta_cap{rsn = StaRSN0}} = State3,
    StaRSN = StaRSN0#wtp_wlan_rsn{version = RSNversion},
    StaBinRSN =capwap_ac:rsn_ie(StaRSN, MFP /= false),
    ResponseIEs1 = lists:keystore(?WLAN_EID_RSN, 1, ResponseIEs0, {?WLAN_EID_RSN, StaBinRSN}),

    %% TODO: NasId and R1KH (MAC)
    R0KH = <<"scg4.tpip.net">>,
    ResponseIEs = [encode_fte(R0KH, BSS) | ResponseIEs1],

    IEs = build_ies(ResponseIEs),
    MgmtFrame = <<16#01:16/integer-little, 0:16/integer-little,
		  (State3#state.aid):16/integer-little, IEs/binary>>,

    {Type, SubType} = frame_type('Association Response'),
    FrameControl = <<SubType:4, Type:2, 0:2, 0:6, 0:1, 0:1>>,
    Duration = 0,
    SequenceControl = 0,
    Frame = <<FrameControl/binary,
	      Duration:16/integer-little,
	      SA:6/bytes, DA:6/bytes, BSS:6/bytes,
	      SequenceControl:16,
	      MgmtFrame/binary>>,
    wtp_send_80211(Frame, State3),

    State = wtp_add_station(State3),

    {next_state, connected, State, ?IDLE_TIMEOUT};

init_assoc({call, _} = EventType, Event, State)
  when element(1, Event) == take_over ->
    lager:debug("in INIT_ASSOC got TAKE-OVER: ~p", [Event]),
    handle_take_over(EventType, Event, State);

init_assoc({call, From}, Event, _State) when Event == detach; Event == delete ->
    {keep_state_and_data, [{reply, From, {error, not_attached}}, ?IDLE_TIMEOUT]};

init_assoc(info, Msg, State) ->
    handle_info(Msg, init_assoc, State);

init_assoc(Type, Event, _State) ->
    lager:warning("in INIT_ASSOC got unexpexted: ~p:~p", [Type, Event]),
    {keep_state_and_data, [?IDLE_TIMEOUT]}.

%%
%% State 3
%%
init_start(timeout, _, State) ->
    lager:warning("idle timeout in INIT_START"),
    {stop, normal, State};

init_start(cast, Event = {'Disassociation', _DA, _SA, BSS, 0, 0, _Frame},
	   State = #state{radio_mac = BSS}) ->
    lager:debug("in INIT_START got Disassociation: ~p", [Event]),
    wtp_del_station(State),
    aaa_disassociation(State),
    {next_state, init_assoc, State, ?SHUTDOWN_TIMEOUT};

init_start(cast, Event = {'Deauthentication', _DA, _SA, BSS, 0, 0, _Frame},
	   State = #state{radio_mac = BSS, mac_mode = MacMode}) ->
    lager:debug("in INIT_START got Deauthentication: ~p", [Event]),
    wtp_del_station(State),
    aaa_disassociation(State),
    {next_state, initial_state(MacMode), State, ?SHUTDOWN_TIMEOUT};

init_start(cast, Event = {'Null', _DA, _SA, BSS, 0, 1, <<>>},
	   State0 = #state{radio_mac = BSS}) ->
    lager:debug("in INIT_START got Null: ~p", [Event]),
    State = wtp_add_station(State0),
    {next_state, connected, State, ?IDLE_TIMEOUT};

init_start({call, _} = EventType, Event, State)
  when element(1, Event) == take_over ->
    lager:debug("in INIT_START got TAKE-OVER: ~p", [Event]),
    handle_take_over(EventType, Event, State);

init_start({call, From}, Event, _State) when Event == detach; Event == delete ->
    {keep_state_and_data, [{reply, From, {error, not_attached}}, ?IDLE_TIMEOUT]};

init_start(info, Msg, State) ->
    handle_info(Msg, init_start, State);

init_start(Type, Event, _State) ->
    lager:warning("in INIT_START got unexpexted: ~p:~p", [Type, Event]),
    {keep_state_and_data, [?IDLE_TIMEOUT]}.

%%
%% State 4
%%
connected(timeout, _, _State) ->
    lager:warning("idle timeout in CONNECTED"),
    {keep_state_and_data, [?IDLE_TIMEOUT]};

connected(cast, {'802.3', Data}, _State) ->
    lager:error("in CONNECTED got 802.3 Data:~n~s", [flower_tools:hexdump(Data)]),
    {keep_state_and_data, [?IDLE_TIMEOUT]};

connected(cast, Event = {FrameType, _DA, _SA, BSS, 0, 0, Frame},
	  State0 = #state{radio_mac = BSS, mac_mode = MacMode})
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

    State1 = update_sta_from_mgmt_frame(FrameType, Frame, State0),
    State = wtp_add_station(State1),
    {keep_state, State, [?IDLE_TIMEOUT]};

connected(cast, Event = {'Disassociation', _DA, _SA, BSS, 0, 0, _Frame},
	  State = #state{radio_mac = BSS}) ->
    lager:debug("in CONNECTED got Disassociation: ~p", [Event]),
    wtp_del_station(State),
    aaa_disassociation(State),
    {next_state, init_assoc, State, ?SHUTDOWN_TIMEOUT};

connected(cast, Event = {'Deauthentication', _DA, _SA, BSS, 0, 0, _Frame},
	  State = #state{radio_mac = BSS, mac_mode = MacMode}) ->
    lager:debug("in CONNECTED got Deauthentication: ~p", [Event]),
    wtp_del_station(State),
    aaa_disassociation(State),
    {next_state, initial_state(MacMode), State, ?SHUTDOWN_TIMEOUT};

connected(cast, {'EAPOL', _DA, _SA, BSS, AuthData},
	  State0 = #state{radio_mac = BSS, rekey_running = ptk}) ->
    State = rsna_4way_handshake(eapol:decode(AuthData), State0),
    {keep_state, State, [?IDLE_TIMEOUT]};

connected(cast, {'EAPOL', _DA, _SA, BSS, AuthData},
	  State0 = #state{radio_mac = BSS, rekey_running = gtk}) ->
    State = rsna_2way_handshake(eapol:decode(AuthData), State0),
    {keep_state, State, [?IDLE_TIMEOUT]};

connected(cast, {'EAPOL', _DA, _SA, BSS, EAPData},
	  State0 = #state{radio_mac = BSS, eapol_state = {request, _}}) ->
    State = eap_handshake(eapol:decode(EAPData), State0),
    {keep_state, State, [?IDLE_TIMEOUT]};

connected(info, {rekey, Type}, State0) ->
    lager:warning("in CONNECTED got REKEY: ~p", [Type]),
    State = rekey_start(Type, State0),
    {keep_state, State, [?IDLE_TIMEOUT]};

connected(info, Event = {eapol_retransmit, {packet, EAPData}},
	  State0 = #state{eapol_retransmit = TxCnt})
  when TxCnt < 4 ->
    lager:warning("in CONNECTED got EAPOL retransmit: ~p", [Event]),
    State = send_eapol_packet(EAPData, State0),
    {keep_state, State, [?IDLE_TIMEOUT]};

connected(info, Event = {eapol_retransmit, {key, Flags, KeyData}},
	  State0 = #state{eapol_retransmit = TxCnt})
  when TxCnt < 4 ->
    lager:warning("in CONNECTED got EAPOL retransmit: ~p", [Event]),
    State = send_eapol_key(Flags, KeyData, State0),
    {keep_state, State, [?IDLE_TIMEOUT]};

connected(info, Event = {eapol_retransmit, _Msg},
	  State = #state{mac_mode = MacMode}) ->
    lager:warning("in CONNECTED got EAPOL retransmit final TIMEOUT: ~p", [Event]),
    wtp_del_station(State),
    aaa_disassociation(State),
    {next_state, initial_state(MacMode), State, ?SHUTDOWN_TIMEOUT};

connected(cast, {start_gtk_rekey, RekeyCtl, GTKnew, IGTKnew},
	  #state{gtk = GTK, igtk = IGTK} = State)
  when GTKnew#ieee80211_key.index == GTK#ieee80211_key.index andalso
       IGTKnew#ieee80211_key.index == IGTK#ieee80211_key.index ->
    capwap_ac_gtk_rekey:gtk_rekey_done(RekeyCtl, self()),
    {keep_state, State, [?IDLE_TIMEOUT]};

connected(cast, Event = {start_gtk_rekey, RekeyCtl, GTKnew, IGTKnew},
	  #state{gtk = GTK, igtk = IGTK} = State0)
  when GTKnew#ieee80211_key.index /= GTK#ieee80211_key.index orelse
       IGTKnew#ieee80211_key.index /= IGTK#ieee80211_key.index ->
    lager:debug("in CONNECTED got Group rekey: ~p", [Event]),
    State = rekey_start(gtk, State0#state{gtk = GTKnew, igtk = IGTKnew, rekey_control = RekeyCtl}),
    {keep_state, State, [?IDLE_TIMEOUT]};

connected({call, _} = EventType, Event, State)
  when element(1, Event) == take_over ->
    lager:debug("in CONNECTED got TAKE-OVER: ~p", [Event]),
    aaa_disassociation(State),
    handle_take_over(EventType, Event, State);

connected({call, From}, delete, State = #state{mac_mode = MacMode}) ->
    wtp_del_station(State),
    aaa_disassociation(State),
    {next_state, initial_state(MacMode), State, [{reply, From, ok}, ?SHUTDOWN_TIMEOUT]};

connected({call, From}, detach, State = #state{mac_mode = MacMode}) ->
    wtp_del_station(State),
    aaa_disassociation(State),
    {next_state, initial_state(MacMode), State, [{reply, From, ok}, ?SHUTDOWN_TIMEOUT]};

connected(info, Msg, State) ->
    handle_info(Msg, connected, State);

connected(Type, Event, State) ->
    lager:warning("in CONNECTED got unexpexted: ~p:~p", [Type, Event]),
    {keep_state, State, [?IDLE_TIMEOUT]}.

handle_info({'DOWN', _ACMonitor, process, AC, _Info}, _StateName,
	    State = #state{ac = AC}) ->
    lager:warning("AC died ~w", [AC]),
    {stop, normal, State};

handle_info(Msg, StateName, _State) ->
    lager:warning("in State ~p unexpected Info: ~p", [StateName, Msg]),
    {keep_state_and_data, [?IDLE_TIMEOUT]}.

terminate(_Reason, StateName, State = #state{ac = AC, mac = MAC}) ->
    if StateName == connected ->
	    wtp_del_station(State),
	    aaa_disassociation(State);
       true ->
	    ok
    end,
    capwap_ac:station_detaching(AC),
    lager:warning("Station ~s terminated in State ~w", [format_mac(MAC), StateName]),
    ok.

code_change(_OldVsn, StateName, State, _Extra) ->
    {ok, StateName, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
init_state_from_cfg(StationCfg) ->
    update_state_from_cfg(StationCfg,
			  #state{capabilities = #sta_cap{},
				 rekey_running = false,
				 rekey_pending = []}).

convert_ies_from_bss(IEs) ->
    lists:foldl(fun({IE = <<Id:8, _/binary>>, Flags}, Acc) ->
			case proplists:get_bool(probe_response, Flags) of
			    true -> [{Id, IE} | Acc];
			    _    -> Acc
			end
		end, [], IEs).

build_ies(IEs) ->
    << <<IE/binary>> || {_Id, IE} <- lists:keysort(1, IEs) >>.

update_state_from_cfg(#station_config{data_path = DataPath,
				      wtp_data_channel_address = WTPDataChannelAddress,
				      wtp_id = WtpId,
				      wtp_session_id = SessionId,
				      mac_mode = MacMode,
				      tunnel_mode = TunnelMode,
				      bss = BSS,
				      bss_ies = IEs,
				      wpa_config = WpaConfig,
				      gtk = GTK,
				      igtk = IGTK
				     }, State) ->
    State#state{data_path = DataPath,
		data_channel_address = WTPDataChannelAddress,
		wtp_id = WtpId,
		wtp_session_id = SessionId,
		mac_mode = MacMode,
		tunnel_mode = TunnelMode,
		radio_mac = BSS,
		response_ies = convert_ies_from_bss(IEs),
		wpa_config = WpaConfig,
		gtk = GTK,
		igtk = IGTK
	       }.

with_station(AC, BSS, StationMAC, Fun) ->
    lager:debug("search Station ~p", [{AC, StationMAC}]),
    case capwap_station_reg:lookup(AC, BSS, StationMAC) of
        not_found ->
            lager:debug("Station not found"),
            {error, not_found};

        {ok, Station} ->
            lager:debug("found Station as ~p", [Station]),
	    Fun(Station)
    end.

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

station_from_mgmt_frame(DA, SA, BSS) ->
    case BSS of
	DA -> SA;
	SA -> DA;
	_  -> undefined
    end.

ieee80211_request(AC, FrameType, DA, SA, BSS, FromDS, ToDS, Frame)
  when FrameType == 'Deauthentication';
       FrameType == 'Disassociation' ->
    lager:warning("got IEEE 802.11 Frame: ~p", [{FrameType, DA, SA, BSS, FromDS, ToDS, Frame}]),

    STA = station_from_mgmt_frame(DA, SA, BSS),
    with_station(AC, BSS, STA, gen_statem:cast(_, {FrameType, DA, SA, BSS, FromDS, ToDS, Frame}));

ieee80211_request(_AC, _FrameType, _DA, SA, BSS, _FromDS, _ToDS, _Frame)
  when SA == BSS ->
    %% OpenCAPWAP is stupid, it mirrors our own Frame back to us....
    ok;

ieee80211_request(AC, FrameType, DA, SA, BSS, FromDS, ToDS, Frame)
  when FrameType == 'Authentication';
       FrameType == 'Association Request';
       FrameType == 'Reassociation Request';
       FrameType == 'Null' ->
    lager:debug("search Station ~p", [{AC, SA}]),
    Found = case capwap_station_reg:lookup(AC, BSS, SA) of
		not_found ->
		    lager:debug("not found"),
		    capwap_ac:new_station(AC, BSS, SA);
		Ok = {ok, Station0} ->
		    lager:debug("found as ~p", [Station0]),
		    Ok
	    end,
    case Found of
	{ok, Station} ->
	    gen_statem:cast(Station, {FrameType, DA, SA, BSS, FromDS, ToDS, Frame});
	Other ->
	    Other
    end;

ieee80211_request(_AC, FrameType, _DA, _SA, _BSS, _FromDS, _ToDS, _Frame)
  when FrameType == 'Probe Request' ->
    ok;

ieee80211_request(AC, 'QoS Data', DA, SA, BSS, _FromDS = 0, _ToDS = 1,
		  _Frame = <<_QoS:16, ?LLC_DSAP_SNAP, ?LLC_SSAP_SNAP,
			    ?LLC_CNTL_SNAP, ?SNAP_ORG_ETHERNET,
			    ?ETH_P_PAE:16, AuthData/binary>>) ->
    with_station(AC, BSS, SA, gen_statem:cast(_, {'EAPOL', DA, SA, BSS, AuthData})),
    ok;
ieee80211_request(AC, 'Data', DA, SA, BSS, _FromDS = 0, _ToDS = 1,
		  _Frame = <<?LLC_DSAP_SNAP, ?LLC_SSAP_SNAP,
			    ?LLC_CNTL_SNAP, ?SNAP_ORG_ETHERNET,
			    ?ETH_P_PAE:16, AuthData/binary>>) ->
    with_station(AC, BSS, SA, gen_statem:cast(_, {'EAPOL', DA, SA, BSS, AuthData})),
    ok;
ieee80211_request(_AC, FrameType, DA, SA, BSS, FromDS, ToDS, Frame) ->
    lager:warning("unhandled IEEE 802.11 Frame: ~p", [{FrameType, DA, SA, BSS, FromDS, ToDS, Frame}]),
    {error, unhandled}.

handle_take_over({call, From},
		 {take_over, AC, StationCfg = #station_config{
						 bss = RadioMAC,
						 mac_mode = MacMode}},
		 State0 = #state{ac = OldAC, ac_monitor = OldACMonitor,
				 data_path = _OldDataPath,
				 radio_mac = OldRadioMAC, mac = ClientMAC}) ->
    lager:debug("Takeover station ~p as ~w", [{OldAC, OldRadioMAC, ClientMAC}, self()]),
    lager:debug("Register station ~p as ~w", [{AC, RadioMAC, ClientMAC}, self()]),

    wtp_del_station(State0),
    capwap_ac:station_detaching(OldAC),
    capwap_station_reg:unregister(OldAC, OldRadioMAC, ClientMAC),
    erlang:demonitor(OldACMonitor, [flush]),

    capwap_station_reg:register(AC, RadioMAC, ClientMAC),
    ACMonitor = erlang:monitor(process, AC),

    State = update_state_from_cfg(StationCfg, State0#state{ac = AC, ac_monitor = ACMonitor}),
    {next_state, initial_state(MacMode), State, [{reply, From, {ok, self()}}, ?IDLE_TIMEOUT]}.

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

assign_aid(State) ->
    %% FIXME: generate uniq value...
    State#state{aid = (rand:uniform(2007) + 1) bor 16#C000}.

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

update_sta_from_mgmt_frame_ies(IEs, #state{aid = AID, capabilities = Cap0} = State0) ->
    State1 = State0#state{capabilities = Cap0#sta_cap{aid = AID}},
    ListIE = [ {Id, Data} || <<Id:8, Len:8, Data:Len/bytes>> <= IEs ],
    State = lists:foldl(fun update_sta_from_mgmt_frame_ie/2, State1, ListIE),

    lager:debug("New Station Caps: ~p", [lager:pr(State#state.capabilities, ?MODULE)]),
    case State#state.capabilities of
	#sta_cap{rsn = #wtp_wlan_rsn{} = RSN} ->
	    lager:info("STA: ~p, Ciphers: Group ~p, PairWise: ~p, AKM: ~p, Caps: ~w, Mgmt: ~p",
		       [flower_tools:format_mac(State#state.mac),
			RSN#wtp_wlan_rsn.group_cipher_suite, RSN#wtp_wlan_rsn.cipher_suites,
			RSN#wtp_wlan_rsn.akm_suites, RSN#wtp_wlan_rsn.capabilities,
			RSN#wtp_wlan_rsn.group_mgmt_cipher_suite]);
	_ -> nothing
    end,
    State.

smps2atom(0) -> static;
smps2atom(1) -> dynamic;
smps2atom(2) -> reserved;
smps2atom(3) -> disabled.

update_sta_from_mgmt_frame_ie(IE = {?WLAN_EID_HT_CAP, HtCap},
				  #state{capabilities = Cap} = State) ->
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

    State#state{
      capabilities =
	  Cap#sta_cap{sgi_20mhz = (SGI20Mhz == 1), sgi_40mhz = (SGI40Mhz == 1),
		      smps = smps2atom(SMPS), back_delay = (BAckDelay == 1),
		      ampdu_density = AMPDU_Density, ampdu_factor = AMPDU_Factor,
		      rx_mask = RxMask, rx_highest = RxHighest
		     }};

%% Vendor Specific:
%%  OUI:  00-50-F2 - Microsoft
%%  Type: 2        - WMM/WME
%%  WME Subtype: 0 - IE
%%  WME Version: 1
update_sta_from_mgmt_frame_ie(IE = {?WLAN_EID_VENDOR_SPECIFIC,
				    <<16#00, 16#50, 16#F2, 2, 0, 1, _/binary>>},
				  #state{capabilities = Cap} = State) ->
    lager:debug("Mgmt IE WMM: ~p", [IE]),
    State#state{
      capabilities =
	  Cap#sta_cap{wmm = true}};

update_sta_from_mgmt_frame_ie(IE = {?WLAN_EID_RSN, <<RSNVersion:16/little, RSNData/binary>> = RSNE},
			      #state{capabilities = Cap} = State) ->
    lager:debug("Mgmt IE RSN: ~p", [IE]),
    RSN = decode_rsne(group_cipher_suite, RSNData, #wtp_wlan_rsn{version = RSNVersion}),
    State#state{
      capabilities =
	  Cap#sta_cap{last_rsne = RSNE, rsn = RSN}};

update_sta_from_mgmt_frame_ie(IE = {_Id, _Value}, State) ->
    lager:debug("Mgmt IE: ~p", [IE]),
    State.

decode_rsne(_, <<>>, RSN) ->
    RSN;
decode_rsne(group_cipher_suite, <<GroupCipherSuite:4/bytes, Next/binary>>, RSN) ->
    decode_rsne(pairwise_cipher_suite, Next, RSN#wtp_wlan_rsn{group_cipher_suite = GroupCipherSuite});
decode_rsne(pairwise_cipher_suite, <<Count:16/little, Data/binary>>, RSN) ->
    Length = Count * 4,
    <<Suites:Length/bytes, Next/binary>> = Data,
    decode_rsne(auth_key_management, Next,
		RSN#wtp_wlan_rsn{cipher_suites = [ Id || <<Id:4/bytes>> <= Suites ]});
decode_rsne(auth_key_management, <<Count:16/little, Data/binary>>, RSN) ->
    Length = Count * 4,
    <<Suites:Length/bytes, Next/binary>> = Data,
    decode_rsne(rsn_capabilities, Next,
		RSN#wtp_wlan_rsn{akm_suites =
				     [ capwap_packet:decode_akm_suite(Id) || <<Id:32>> <= Suites ]});
decode_rsne(rsn_capabilities, <<RSNCaps:16/little, Next/binary>>, RSN) ->
    decode_rsne(pmkid, Next, RSN#wtp_wlan_rsn{capabilities = RSNCaps});
decode_rsne(pmkid, <<0:16/little, Next/binary>>, RSN) ->
    decode_rsne(group_management_cipher, Next, RSN);
decode_rsne(pmkid, <<Count:16/little, Data/binary>>, RSN) ->
    Length = Count * 16,
    <<PMKIds:Length/bytes, Next/binary>> = Data,
    decode_rsne(group_management_cipher, Next, RSN#wtp_wlan_rsn{pmk_ids = [ Id || <<Id:16/bytes>> <= PMKIds ]});
decode_rsne(group_management_cipher, <<GroupMgmtCipherSuite:32>>, RSN)
  when (RSN#wtp_wlan_rsn.capabilities band 16#0080) /= 0 ->
    RSN#wtp_wlan_rsn{group_mgmt_cipher_suite = capwap_packet:decode_cipher_suite(GroupMgmtCipherSuite)};
decode_rsne(group_management_cipher, <<GroupMgmtCipherSuite:32>>, RSN) ->
    lager:error("STA send a GroupMgmtCipher but DID NOT indicate MFP capabilities: ~p, ~4.16.0b",
		[capwap_packet:decode_cipher_suite(GroupMgmtCipherSuite), RSN#wtp_wlan_rsn.capabilities]),
    RSN.

ft_ie(R0KH, R1KH) ->
%% Page 1312
%% The (Re)Association Response frame from the AP shall contain an MDE, with contents as presented in
%% Beacon and Probe Response frames. The FTE shall include the key holder identities of the AP, the R0KH-ID
%% and R1KH-ID, set to the values of dot11FTR0KeyHolderID and dot11FTR1KeyHolderID, respectively. The
%% FTE shall have a MIC element count of zero (i.e., no MIC present) and have ANonce, SNonce, and MIC
%% fields set to 0.
    R1KHie = <<1:8, (size(R1KH)):8, R1KH/binary>>,
    R0KHie = <<3:8, (size(R0KH)):8, R0KH/binary>>,
    capwap_ac:ieee_802_11_ie(?WLAN_EID_FAST_BSS_TRANSITION, <<0:8, 0:8, 0:(16 * 8), 0:(32 * 8), 0:(32 * 8),
							      R1KHie/binary, R0KHie/binary>>).
encode_fte(R0KH, R1KH) ->
    {?WLAN_EID_FAST_BSS_TRANSITION, ft_ie(R0KH, R1KH)}.

%% ti_ie(Type, Interval) ->
%%     capwap_ac:ieee_802_11_ie(?WLAN_EID_TIMEOUT_INTERVAL, <<Type:8, Interval:32/little>>).

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

wtp_add_station(#state{ac = AC, radio_mac = BSS, mac = MAC, capabilities = Caps,
		       wpa_config = #wpa_config{privacy = Privacy},
		       cipher_state = CipherState} = State) ->
    if Privacy ->
	    capwap_ac:add_station(AC, BSS, MAC, Caps, {true, false, CipherState}),
	    init_eapol(State);
       true ->
	    capwap_ac:add_station(AC, BSS, MAC, Caps, {false, false, undefined}),
	    State
    end.

wtp_del_station(#state{ac = AC, radio_mac = BSS, mac = MAC}) ->
    capwap_ac:del_station(AC, BSS, MAC).

wtp_send_80211(Data,  #state{ac = AC, radio_mac = BSS}) when is_binary(Data) ->
    capwap_ac:send_80211(AC, BSS, Data).

accounting_update(STA, SessionOpts) ->
    lager:debug("accounting_update: ~p, ~p", [STA, attr_get('MAC', SessionOpts)]),
    case attr_get('MAC', SessionOpts) of
	{ok, MAC} ->
	    STAStats = capwap_dp:get_station(MAC),
	    lager:debug("STA Stats: ~p", [STAStats]),
	    {_MAC, _VLan, _RadioId, _BSS, {RcvdPkts, SendPkts, RcvdBytes, SendBytes}} = STAStats,
	    Acc = [{'InPackets',  RcvdPkts},
		    {'OutPackets', SendPkts},
		    {'InOctets',   RcvdBytes},
		    {'OutOctets',  SendBytes}],
	    ergw_aaa_session:merge(SessionOpts, to_session(Acc));
	_ ->
	    SessionOpts
    end.

aaa_association(State = #state{mac = MAC, data_channel_address = WTPDataChannelAddress,
				wtp_id = WtpId, wtp_session_id = WtpSessionId}) ->
    MACStr = format_mac(MAC),
    SessionData0 = [{'Accouting-Update-Fun', fun accounting_update/2},
                    {'AAA-Application-Id', capwap_station},
		    {'Service-Type', 'TP-CAPWAP-STA'},
		    {'Framed-Protocol', 'TP-CAPWAP'},
		    {'MAC', MAC},
		    {'Username', MACStr},
		    {'Calling-Station', MACStr},
		    {'Location-Id', WtpId},
		    {'CAPWAP-Session-Id', <<WtpSessionId:128>>}],
    SessionData1 = add_tunnel_info(WTPDataChannelAddress, SessionData0),
    {ok, Session} = ergw_aaa_session_sup:new_session(self(), to_session(SessionData1)),
    lager:info("NEW session for ~w at ~p", [MAC, Session]),
    ergw_aaa_session:start(Session, to_session([])),
    State#state{aaa_session = Session}.

aaa_disassociation(#state{aaa_session = Session}) ->
    ergw_aaa_session:stop(Session, to_session([])),
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

pad_length(Width, Length) ->
    (Width - Length rem Width) rem Width.

%%
%% pad binary to specific length
%%   -> http://www.erlang.org/pipermail/erlang-questions/2008-December/040709.html
%%
pad_to(Width, Binary) ->
    case pad_length(Width, size(Binary)) of
        0 -> Binary;
        N -> <<Binary/binary, 0:(N*8)>>
    end.

cancel_timer(Ref) ->
    case erlang:cancel_timer(Ref) of
	false ->
	    receive {timeout, Ref, _} -> 0
	    after 0 -> false
	    end;
	RemainingTime ->
	    RemainingTime
    end.

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

stop_eapol_timer(#state{eapol_timer = TRef} = State)
  when is_reference(TRef) ->
    cancel_timer(TRef),
    State#state{eapol_timer = undefined};
stop_eapol_timer(State) ->
    State.

start_eapol_timer(Msg, State0) ->
    Interval = 500,
    State = stop_eapol_timer(State0),
    lager:debug("Starting EAPOL Timer ~w ms", [Interval]),
    TRef = erlang:send_after(Interval, self(), {eapol_retransmit, Msg}),
    State#state{eapol_timer = TRef}.

send_eapol(EAPData, State = #state{mac = StationMAC, radio_mac = BSS}) ->
    Frame = eapol:encode_802_11(StationMAC, BSS, EAPData),
    wtp_send_80211(Frame, State).

send_eapol_packet(EAPData, State = #state{eapol_retransmit = TxCnt}) ->
    send_eapol(eapol:packet(EAPData), State),
    start_eapol_timer({packet, EAPData}, State#state{eapol_retransmit = TxCnt + 1}).

send_eapol_key(Flags, KeyData,
	       State = #state{eapol_retransmit = TxCnt,
			      cipher_state =
				  #ccmp{replay_counter = ReplayCounter} = CipherState0
			     }) ->
    CipherState = CipherState0#ccmp{replay_counter = ReplayCounter + 1},
    KeyFrame = eapol:key(Flags, KeyData, CipherState),
    send_eapol(KeyFrame, State),
    start_eapol_timer({key, Flags, KeyData},
		      State#state{eapol_retransmit = TxCnt + 1,
				  cipher_state = CipherState}).

init_eapol(#state{capabilities = #sta_cap{rsn = #wtp_wlan_rsn{akm_suites = [AKM]}},
		  wpa_config = #wpa_config{ssid = SSID, secret = Secret}} = State)
  when AKM == 'PSK'; AKM == 'FT-PSK' ->
    {ok, PSK} = eapol:phrase2psk(Secret, SSID),
    lager:debug("PSK: ~s", [pbkdf2:to_hex(PSK)]),
    rsna_4way_handshake({init, PSK}, State#state{rekey_running = ptk});

init_eapol(#state{capabilities = #sta_cap{rsn = #wtp_wlan_rsn{akm_suites = [AKM]}},
		  wpa_config = #wpa_config{ssid = SSID}} = State)
  when AKM == '802.1x'; AKM == 'FT-802.1x' ->
    ReqData = <<0, "networkid=", SSID/binary, ",nasid=SCG4,portid=1">>,
    Id = 1,
    EAPData = eapol:request(Id, identity, ReqData),
    send_eapol_packet(EAPData, State#state{rekey_running = 'WPA',
					   eapol_state = {request, Id},
					   eapol_retransmit = 0}).

eap_handshake({start, _Data},
	      #state{eapol_state = {request, _}} = State0) ->
    %% restart the handshake
    State = stop_eapol_timer(State0),
    init_eapol(State);

eap_handshake(Data = {response, Id, EAPData, Response},
	      #state{eapol_state = {request, Id}} = State0) ->
    lager:debug("EAP Handshake: ~p", [Data]),
    State = stop_eapol_timer(State0),
    Next =
	case Response of
	    {identity, Identity} ->
		%% Start ctld Authentication....
		Opts = [{'Username', Identity},
			{'Authentication-Method', 'EAP'},
			{'EAP-Data', EAPData}],
		{authenticate, Opts};

	    _ ->
		Opts = [{'EAP-Data', EAPData}],
		{authenticate, Opts}

	    %% _ ->
	    %% 	{disassociation, []}
	end,
    eap_handshake_next(Next, State);

eap_handshake(Data, State0) ->
    lager:warning("unexpected EAP Handshake: ~p", [Data]),
    State = stop_eapol_timer(State0),
    wtp_del_station(State),
    aaa_disassociation(State),
    State#state{eapol_state = undefined}.

eap_handshake_next({authenticate, Opts}, #state{aaa_session = Session} = State) ->
    case ergw_aaa_session:authenticate(Session, to_session(Opts)) of
	success ->
	    lager:info("AuthResult: success"),

	    SessionOpts = ergw_aaa_session:get(Session),

	    case ergw_aaa_session:attr_get('EAP-Data', SessionOpts) of
		{ok, EAPData} ->
		    send_eapol(eapol:packet(EAPData), State);
		_ ->
		    ok
	    end,

	    MSK = << (ergw_aaa_session:attr_get('MS-MPPE-Recv-Key', SessionOpts, <<>>))/binary,
		     (ergw_aaa_session:attr_get('MS-MPPE-Send-Key', SessionOpts, <<>>))/binary>>,
	    lager:debug("MSK: ~s", [flower_tools:hexdump(MSK)]),
	    rsna_4way_handshake({init, MSK}, State);

	challenge ->
	    lager:info("AuthResult: challenge"),
	    {ok, EAPData} = ergw_aaa_session:get(Session, 'EAP-Data'),
	    <<_Code:8, Id:8, _/binary>> = EAPData,
	    lager:info("EAP Challenge: ~p", [EAPData]),

	    send_eapol_packet(EAPData, State#state{eapol_state = {request, Id}});

	Other ->
	    lager:info("AuthResult: ~p", [Other]),

	    case ergw_aaa_session:get(Session, 'EAP-Data') of
		{ok, EAPData} ->
		    send_eapol_packet(EAPData, State);
		_ ->
		    ok
	    end,
	    wtp_del_station(State),
	    aaa_disassociation(State),
	    State#state{eapol_state = undefined}
    end;

eap_handshake_next({disassociation, _}, State) ->
    wtp_del_station(State),
    aaa_disassociation(State),
    State#state{eapol_state = undefined}.

encode_gtk_ie(Tx, #ieee80211_key{index = Index, key = Key}) ->
    <<16#dd, (byte_size(Key) + 6):8,
      16#00, 16#0F, 16#AC, ?GTK_KDE:8,
      0:5, Tx:1, (Index + 1):2, 0, Key/binary>>.

encode_igtk_ie(#ieee80211_key{index = Index, key = Key}) ->
    <<16#dd, (byte_size(Key) + 12):8,
      16#00, 16#0F, 16#AC, ?IGTK_KDE:8,
      (Index + 4):16/little-integer, 0:48, Key/binary>>.

mic_for_akm('802.1x')			-> 'HMAC-SHA1-128';
mic_for_akm('PSK')			-> 'HMAC-SHA1-128';
mic_for_akm('FT-802.1x')		-> 'AES-128-CMAC';
mic_for_akm('FT-PSK')			-> 'AES-128-CMAC';
mic_for_akm('802.1x-SHA256')		-> 'AES-128-CMAC';
mic_for_akm('PSK-SHA256')		-> 'AES-128-CMAC';
mic_for_akm('802.1x-Suite-B')		-> 'HMAC-SHA256';
mic_for_akm('802.1x-Suite-B-192')	-> 'HMAC-SHA384';
mic_for_akm('FT-802.1x-SHA384')		-> 'HMAC-SHA384';
mic_for_akm(X)				-> X.

rsna_4way_handshake({init, MSK}, #state{capabilities =
					    #sta_cap{
					       rsn = #wtp_wlan_rsn{
							akm_suites = [AKM],
							group_mgmt_cipher_suite = GroupMgmtCipherSuite}}}
		    = State) ->

    %% IEEE 802.11-2012, Sect. 11.6.1.3
    <<PMK:32/bytes, _/binary>> = MSK,

    ANonce = crypto:strong_rand_bytes(32),
    CipherState = #ccmp{akm_algo = AKM,
			mic_algo = mic_for_akm(AKM),
			group_mgmt_cipher_suite = GroupMgmtCipherSuite,
			replay_counter = 0,
			master_session_key = MSK,
			pre_master_key = PMK,
			nonce = ANonce},
    send_eapol_key([pairwise, ack], <<>>,
		   State#state{eapol_state = init,
			       eapol_retransmit = 0,
			       rekey_running = ptk,
			       cipher_state = CipherState});

rsna_4way_handshake(rekey, State = #state{eapol_state = installed,
					  cipher_state = CipherState0}) ->
    ANonce = crypto:strong_rand_bytes(32),
    CipherState = CipherState0#ccmp{nonce = ANonce},
    send_eapol_key([pairwise, ack], <<>>,
		   State#state{eapol_state = init,
			       eapol_retransmit = 0,
			       cipher_state = CipherState});

rsna_4way_handshake({key, _Flags, MICAlgo, ReplayCounter, SNonce, KeyData, MICData},
		    State0 = #state{radio_mac = BSS, mac = StationMAC,
				    wpa_config = #wpa_config{
						    ssid = SSID,
						    mobility_domain = MDomain,
						    rsn = #wtp_wlan_rsn{
							     management_frame_protection = MFP} = RSN},
				    gtk = GTK,
				    igtk = IGTK,
				    eapol_state = init,
				    cipher_state =
					#ccmp{
					   akm_algo = AKM,
					   mic_algo = MICAlgo,
					   group_mgmt_cipher_suite = GroupMgmtCipherSuite,
					   replay_counter = ReplayCounter,
					   master_session_key = MSK,
					   pre_master_key = PMK,
					   nonce = ANonce} = CipherState0})
  when AKM == 'FT-802.1x'; AKM == 'FT-PSK' ->
    %%
    %% Expected Msg: S1KH→R1KH: EAPOL-Key(0, 1, 0, 0, P, 0, 0, SNonce, MIC, RSNE[PMKR1Name], MDE, FTE)
    %%

    %% CipherSuite and ReplayCounter match...
    lager:debug("KeyData: ~p", [pbkdf2:to_hex(KeyData)]),
    lager:debug("PMK: ~p", [pbkdf2:to_hex(PMK)]),
    lager:debug("BSS: ~p", [pbkdf2:to_hex(BSS)]),
    lager:debug("StationMAC: ~p", [pbkdf2:to_hex(StationMAC)]),
    lager:debug("ANonce: ~p", [pbkdf2:to_hex(ANonce)]),
    lager:debug("SNonce: ~p", [pbkdf2:to_hex(SNonce)]),
    lager:debug("CipherState: ~p", [lager:pr(CipherState0, ?MODULE)]),
    State = stop_eapol_timer(State0),

    %%
    %% 802.11-2012, Sect. 11.6.6.3: 4-Way Handshake Message 2
    %%
    %%    Processing for PTK generation is as follows:
    %%
    %%    ...
    %%
    %%    On reception of Message 2, the Authenticator checks that the key
    %%    replay counter corresponds to the outstanding Message 1. If not,
    %%    it silently discards the message. Otherwise, the Authenticator:
    %%
    %%       a) Derives PTK.
    %%       b) Verifies the Message 2 MIC.
    %%       c)
    %%            1) If the calculated MIC does not match the MIC that the
    %%               Supplicant included in the EAPOL-Key frame, the
    %%               Authenticator silently discards Message 2.
    %%
    %%
    %% 802.11-2012, Sect. 12.4.2 FT initial mobility domain association in an RSN
    %%
    %%    The message sequence is similar to that of 11.6.6. The contents of
    %%    each message shall be as described in 11.6.6 except as follows:
    %%      - Message 2: the S1KH shall include the PMKR1Name in the PMKID field of
    %%        the RSNE. The PMKR1Name shall be as calculated by the S1KH according
    %%        to the procedures of 11.6.1.7.4; all other fields of the RSNE shall be
    %%        identical to the RSNE present in the (Re)Association Request frame. The
    %%        S1KH shall include the FTE and MDE; the FTE and MDE shall be the same as
    %%        those provided in the AP’s (Re)Association Response frame.
    %%
    R0KH = <<"scg4.tpip.net">>,
    {KCK, KEK, TK, _PMKR0Name, PMKR1Name} =
	eapol:ft_msk2ptk(MSK, SNonce, ANonce, BSS, StationMAC,
			 SSID, MDomain, R0KH, BSS, StationMAC, StationMAC),
    CipherState = CipherState0#ccmp{rsn = RSN, kck = KCK, kek = KEK, tk = TK},

    case eapol:validate_mic(CipherState, MICData) of
	ok ->
	    lager:debug("rsna_4way_handshake 2 of 4: ok"),
	    %% R1KH→S1KH: EAPOL-Key(1, 1, 1, 1, P, 0, 0, ANonce, MIC, RSNE[PMKR1Name], MDE,
	    %%                      GTK[N], IGTK[M], FTE, TIE[ReassociationDeadline],
	    %%                      TIE[KeyLifetime])

	    RSNIE = capwap_ac:rsn_ie(RSN, [PMKR1Name], MFP == required),
	    MDE = capwap_ac:ieee_802_11_ie(?WLAN_EID_MOBILITY_DOMAIN, <<MDomain:16, 1>>),
	    Tx = 0,
	    GTKIE = encode_gtk_ie(Tx, GTK),
	    IGTKIE = case GroupMgmtCipherSuite of
			 'AES-CMAC' ->
			     encode_igtk_ie(IGTK);
			 _ ->
			     <<>>
		     end,
	    FTE = ft_ie(R0KH, BSS),

	    %% TODO: possibly....
	    %%
	    %% IEEE 802.11 says ReassociationDeadline and KeyLifetime should be
	    %% present, but it seems to work without....
	    %%
	    %% TIEReassociationDeadLine = ti_ie(1, ReassociationDeadline),
	    %% TIEKeyLifetime = ti_ie(2, KeyLifetime),

	    TxKeyData = pad_key_data(<<RSNIE/binary, MDE/binary, GTKIE/binary,
				       IGTKIE/binary, FTE/binary>>),
				     %% TIEReassociationDeadLine/binary,
				     %% TIEKeyLifetime/binary>>),
	    lager:debug("TxKeyData: ~p", [pbkdf2:to_hex(TxKeyData)]),
	    EncTxKeyData = eapol:aes_key_wrap(KEK, TxKeyData),
	    lager:debug("EncTxKeyData: ~p", [pbkdf2:to_hex(EncTxKeyData)]),

	    send_eapol_key([pairwise, install, ack, mic, secure, enc], EncTxKeyData,
			   State#state{eapol_state = install,
				       eapol_retransmit = 0,
				       cipher_state = CipherState});

	Other ->
	    lager:debug("rsna_4way_handshake FT 2 of 4: ~p", [Other]),
	    %% silently discard, see above
	    State
    end;

rsna_4way_handshake({key, _Flags, MICAlgo, ReplayCounter, SNonce, KeyData, MICData},
		    State0 = #state{radio_mac = BSS, mac = StationMAC,
				    capabilities = #sta_cap{last_rsne = LastRSNE},
				    wpa_config = #wpa_config{
						    rsn = #wtp_wlan_rsn{
							     management_frame_protection = MFP} = RSN},
				    gtk = GTK,
				    igtk = IGTK,
				    eapol_state = init,
				    cipher_state =
					#ccmp{
					   akm_algo = AKM,
					   mic_algo = MICAlgo,
					   group_mgmt_cipher_suite = GroupMgmtCipherSuite,
					   replay_counter = ReplayCounter,
					   pre_master_key = PMK,
					   nonce = ANonce} = CipherState0})
  when AKM == '802.1x'; AKM == 'PSK' ->
    %% CipherSuite and ReplayCounter match...
    lager:debug("KeyData: ~p", [pbkdf2:to_hex(KeyData)]),
    lager:debug("PMK: ~p", [pbkdf2:to_hex(PMK)]),
    lager:debug("BSS: ~p", [pbkdf2:to_hex(BSS)]),
    lager:debug("StationMAC: ~p", [pbkdf2:to_hex(StationMAC)]),
    lager:debug("ANonce: ~p", [pbkdf2:to_hex(ANonce)]),
    lager:debug("SNonce: ~p", [pbkdf2:to_hex(SNonce)]),
    lager:debug("CipherState: ~p", [lager:pr(CipherState0, ?MODULE)]),
    State = stop_eapol_timer(State0),

    %%
    %% 802.11-2012, Sect. 11.6.6.3: 4-Way Handshake Message 2
    %%
    %%    Processing for PTK generation is as follows:
    %%
    %%    ...
    %%
    %%    On reception of Message 2, the Authenticator checks that the key
    %%    replay counter corresponds to the outstanding Message 1. If not,
    %%    it silently discards the message. Otherwise, the Authenticator:
    %%
    %%       a) Derives PTK.
    %%       b) Verifies the Message 2 MIC.
    %%       c)
    %%            1) If the calculated MIC does not match the MIC that the
    %%               Supplicant included in the EAPOL-Key frame, the
    %%               Authenticator silently discards Message 2.
    %%

    {KCK, KEK, TK} = eapol:pmk2ptk(PMK, BSS, StationMAC, ANonce, SNonce, 384),
    lager:debug("KCK: ~p", [pbkdf2:to_hex(KCK)]),
    lager:debug("KEK: ~p", [pbkdf2:to_hex(KEK)]),
    lager:debug("TK: ~p", [pbkdf2:to_hex(TK)]),

    CipherState = CipherState0#ccmp{rsn = RSN, kck = KCK, kek = KEK, tk = TK},

    case {eapol:validate_mic(CipherState, MICData), KeyData} of
	{ok, <<?WLAN_EID_RSN, RSNLen:8, LastRSNE:RSNLen/bytes, _/binary>>} ->
	    lager:debug("rsna_4way_handshake 2 of 4: ok"),
	    RSNIE = capwap_ac:rsn_ie(RSN, MFP == required),
	    Tx = 0,
	    GTKIE = encode_gtk_ie(Tx, GTK),
	    IGTKIE = case GroupMgmtCipherSuite of
			 'AES-CMAC' ->
			     encode_igtk_ie(IGTK);
			 _ ->
			     <<>>
		     end,
	    TxKeyData = pad_key_data(<<RSNIE/binary, GTKIE/binary, IGTKIE/binary>>),
	    lager:debug("TxKeyData: ~p", [pbkdf2:to_hex(TxKeyData)]),
	    EncTxKeyData = eapol:aes_key_wrap(KEK, TxKeyData),
	    lager:debug("EncTxKeyData: ~p", [pbkdf2:to_hex(EncTxKeyData)]),

	    send_eapol_key([pairwise, install, ack, mic, secure, enc], EncTxKeyData,
			   State#state{eapol_state = install,
				       eapol_retransmit = 0,
				       cipher_state = CipherState});

	{ok, _} ->
	    %% MIC is ok, but RSNE does not match
	    lager:debug("rsna_4way_handshake 2 of 4: MIC ok, RSNE don't match (~p != ~p)",
		       [pbkdf2:to_hex(KeyData), pbkdf2:to_hex(LastRSNE)]),
	    wtp_del_station(State),
	    aaa_disassociation(State),
	    State#state{eapol_state = undefined, cipher_state = undefined};

	Other ->
	    lager:debug("rsna_4way_handshake 2 of 4: ~p", [Other]),
	    %% silently discard, see above
	    State
    end;

rsna_4way_handshake({key, _Flags, _CipherSuite, ReplayCounter, _SNonce, _KeyData, MICData},
		    State0 = #state{ac = AC, radio_mac = BSS, mac = StationMAC, capabilities = Caps,
				    eapol_state = install,
				    cipher_state =
					#ccmp{
					   replay_counter = ReplayCounter} = CipherState}) ->
    State = stop_eapol_timer(State0),

    %%
    %% 802.11-2012, Sect. 11.6.6.5: 4-Way Handshake Message 4
    %%
    %%    Processing for PTK generation is as follows:
    %%
    %%    ...
    %%
    %%    On reception of Message 4, the Authenticator verifies that the Key
    %%    Replay Counter field value is one that it used on this 4-Way Handshake;
    %%    if it is not, it silently discards the message. Otherwise:
    %%
    %%       a) The Authenticator checks the MIC. If the calculated MIC does not
    %%          match the MIC that the Supplicant included in the EAPOL-Key frame,
    %%          the Authenticator silently discards Message 4.
    %%

    case eapol:validate_mic(CipherState, MICData) of
	ok ->
	    lager:debug("rsna_4way_handshake 4 of 4: ok"),
	    capwap_ac:add_station(AC, BSS, StationMAC, Caps, {false, true, CipherState}),
	    rekey_done(ptk, State#state{eapol_state = installed});

	Other ->
	    lager:debug("rsna_4way_handshake 4 of 4: ~p", [Other]),
	    %% silently discard, see above
	    State
    end;

rsna_4way_handshake(Frame, State) ->
    lager:warning("got unexpexted EAPOL data in 4way Handshake: ~p", [Frame]),
    %% silently discard, both Message 2 and Message are handles this way
    State.

rsna_2way_handshake(rekey, State = #state{eapol_state = installed,
					  cipher_state = #ccmp{
							    group_mgmt_cipher_suite = GroupMgmtCipherSuite,
							    kek = KEK},
					  gtk = GTK, igtk = IGTK}) ->
    %% EAPOL-Key(1,1,1,0,G,0,Key RSC,0, MIC,GTK[N],IGTK[M])

    Tx = 0,
    GTKIE = encode_gtk_ie(Tx, GTK),
    IGTKIE = case GroupMgmtCipherSuite of
		 'AES-CMAC' ->
		     encode_igtk_ie(IGTK);
		 _ ->
		     <<>>
	     end,
    TxKeyData = pad_key_data(<<GTKIE/binary, IGTKIE/binary>>),
    EncTxKeyData = eapol:aes_key_wrap(KEK, TxKeyData),
    lager:debug("TxKeyData: ~p", [pbkdf2:to_hex(TxKeyData)]),
    lager:debug("EncTxKeyData: ~p", [pbkdf2:to_hex(EncTxKeyData)]),

    send_eapol_key([group, ack, mic, secure, enc], EncTxKeyData,
		   State#state{eapol_state = install,
			       eapol_retransmit = 0});

rsna_2way_handshake({key, _Flags, _MICAlgo, ReplayCounter, _SNonce, _KeyData, MICData},
		    State0 = #state{eapol_state = install,
				    rekey_control = RekeyCtl,
				    cipher_state =
					#ccmp{
					   replay_counter = ReplayCounter} = CipherState}) ->
    %% EAPOL-Key(1,1,0,0,G,0,0,0,MIC,0)
    State = stop_eapol_timer(State0),
    capwap_ac_gtk_rekey:gtk_rekey_done(RekeyCtl, self()),

    case eapol:validate_mic(CipherState, MICData) of
	ok ->
	    lager:debug("rsna_2way_handshake 2 of 2: ok"),
	    rekey_done(gtk, State#state{eapol_state = installed});

	Other ->
	    lager:debug("rsna_2way_handshake 2 of 2: ~p", [Other]),
	    wtp_del_station(State),
	    aaa_disassociation(State),
	    State#state{eapol_state = undefined, cipher_state = undefined}
    end;

rsna_2way_handshake(Frame, State) ->
    lager:warning("got unexpexted EAPOL data in 2way Handshake: ~p", [Frame]),
    State.

pad_key_data(KD) when byte_size(KD) < 15 ->
    pad_to(16, <<KD/binary, 16#dd>>);
pad_key_data(KD) when byte_size(KD) rem 8 /= 0 ->
    pad_to(8, <<KD/binary, 16#dd>>);
pad_key_data(KD) ->
    KD.

rekey_timer_start(ptk, #state{wpa_config = #wpa_config{peer_rekey = Interval},
			      rekey_tref = undefined} = State)
  when is_integer(Interval) andalso Interval > 0 ->
    lager:debug("Starting rekey for PTK in ~w", [Interval]),
    TRef = erlang:send_after(Interval * 1000, self(), {rekey, ptk}),
    State#state{rekey_tref = TRef};
rekey_timer_start(_Type, State) ->
    State.

rekey_timer_stop(ptk, #state{rekey_tref = TRef} = State)
  when is_reference(TRef) ->
    cancel_timer(TRef),
    State#state{rekey_tref = undefined};
rekey_timer_stop(_Type, State) ->
    State.

rekey_timer_start(State) ->
    lists:foldl(fun rekey_timer_start/2, State, [ptk]).

rekey_done(_Type, State0) ->
    State = rekey_timer_start(State0#state{rekey_running = false}),
    case State#state.rekey_pending of
	[Next | Pending] ->
	    rekey_init(Next, State#state{rekey_pending = Pending});
	_ ->
	    State#state{rekey_pending = []}
    end.

rekey_init(ptk, State) ->
    rsna_4way_handshake(rekey, State#state{rekey_running = ptk});
rekey_init(gtk, State) ->
    rsna_2way_handshake(rekey, State#state{rekey_running = gtk});
rekey_init(Type, State) ->
    rekey_done(Type, State).

rekey_start(Type, State0 = #state{rekey_running = false}) ->
    State = rekey_timer_stop(Type, State0),
    rekey_init(Type, State);
rekey_start(Type, State = #state{rekey_pending = Pending}) ->
    rekey_timer_stop(Type, State#state{rekey_pending = [Type, Pending]}).
