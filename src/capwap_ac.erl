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

-module(capwap_ac).

-compile({parse_transform, cut}).

-behaviour(gen_fsm).

%% API
-export([start_link/1, accept/3, get_data_channel_address/1, take_over/1, new_station/3,
         station_detaching/1, gtk_rekey_done/1]).

%% Extern API
-export([get_state/1,
	 firmware_download/3,
         set_ssid/4,
         stop_radio/2]).

%% API for Station process
-export([add_station/5, del_station/3, send_80211/3, rsn_ie/2]).

%% gen_fsm callbacks
-export([init/1, listen/2, idle/2, join/2, configure/2, data_check/2, run/2,
	 run/3,
	 handle_event/3,
	 handle_sync_event/4, handle_info/3, terminate/3, code_change/4]).

-export([handle_packet/2, handle_data/3]).

-include_lib("public_key/include/OTP-PUB-KEY.hrl").
-include("capwap_debug.hrl").
-include("capwap_packet.hrl").
-include("capwap_config.hrl").
-include("capwap_ac.hrl").
-include("ieee80211.hrl").
-include("ieee80211_station.hrl").
-include("eapol.hrl").

-import(ergw_aaa_session, [to_session/1]).

-define(SERVER, ?MODULE).
-define(TRACE_LOCAL_CONTROL, {{127,0,0,1}, 5246}).
-define(TRACE_LOCAL_DATA,    {{127,0,0,1}, 5247}).

%% TODO: convert constants into configuration values
-define(IDLE_TIMEOUT, 30 * 1000).
-define(SSL_ACCEPT_TIMEOUT, 30 * 1000).
-define(ChangeStatePendingTimeout, 25 * 1000).
-define(RetransmitInterval, 3 * 1000).
-define(MaxRetransmit, 5).

%% -define(MgmtSuites, ['AES-CMAC', 'BIP-GMAC-128', 'BIP-GMAC-256', 'BIP-CMAC-256']).

-record(state, {
	  id,
	  session_id,
	  ctrl_channel_address,
	  data_channel_address,
	  data_path,
	  socket,
	  ctrl_stream,
	  session,
	  config,
	  mac_types,
	  tunnel_modes,

	  %% Join Information
	  location,
	  board_data,
	  descriptor,
	  name,

	  start_time,

	  last_response,
	  request_queue,
	  retransmit_timer,
	  retransmit_counter,
	  echo_request_timer,
	  echo_request_timeout,

	  change_state_pending_timeout,
	  protocol_timer,	  	  %% used for the CAPWAP ChangeStatePendingTimer

	  seqno = 0,
	  version,
          station_count = 0,
          wlans
}).

-define(IS_RUN_CONTROL_EVENT(E),
	(is_tuple(E) andalso
			   (element(1, E) == add_station orelse
			    element(1, E) == del_station orelse
			    element(1, E) == detach_station orelse
			    element(1, E) == delete_station orelse
			    element(1, E) == firmware_download))).

-define(DEBUG_OPTS,[{install, {fun lager_sys_debug:lager_gen_fsm_trace/3, ?MODULE}}]).

-define(log_capwap_control(Id, MsgType, SeqNo, Elements, Header),
	try
	    #capwap_header{radio_id = RadioId, wb_id = WBID} = Header,
	    lager:info("~s: ~s(Seq: ~w, R-Id: ~w, WB-Id: ~w): ~p", [Id, capwap_packet:msg_description(MsgType), SeqNo, RadioId, WBID, [lager:pr(E, ?MODULE) || E <- Elements]])
	catch
	    _:_ -> ok
	end).

-define(log_capwap_keep_alive(Id, PayLoad, Header),
	try
	    #capwap_header{radio_id = RadioId, wb_id = WBID} = Header,
	    lager:info("~s: Keep-Alive(R-Id: ~w, WB-Id: ~w): ~p", [Id, RadioId, WBID, [lager:pr(E, ?MODULE) || E <- PayLoad]])
	catch
	    _:_ -> ok
	end).

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
start_link(WTPControlChannelAddress) ->
    gen_fsm:start_link(?MODULE, [WTPControlChannelAddress], [{debug, ?DEBUG_OPTS}]).

handle_packet(WTPControlChannelAddress, Packet) ->
    try
	capwap_trace:trace(WTPControlChannelAddress, ?TRACE_LOCAL_CONTROL, Packet),
	Peer = format_peer(WTPControlChannelAddress),
	case capwap_packet:decode(control, Packet) of
	    {Header, {discovery_request, 1, Seq, Elements}} ->
		?log_capwap_control(Peer, discovery_request, Seq, Elements, Header),
		Answer = answer_discover(Peer, Seq, Elements, Header),
		{reply, Answer};
	    {Header, {join_request, 1, Seq, Elements}} ->
		?log_capwap_control(Peer, join_request, Seq, Elements, Header),
		handle_plain_join(Peer, Seq, Elements, Header);
	    Pkt ->
		lager:warning("unexpected CAPWAP packet: ~p", [Pkt]),
		{error, not_capwap}
	end
    catch
	Class:Error ->
	    lager:debug("failure: ~p:~p", [Class, Error]),
	    {error, not_capwap}
    end.

handle_data(DataPath, WTPDataChannelAddress, Packet) ->
    try
	capwap_trace:trace(WTPDataChannelAddress, ?TRACE_LOCAL_DATA, Packet),
	lager:debug("capwap_data: ~p, ~p", [WTPDataChannelAddress, Packet]),
	case capwap_packet:decode(data, Packet) of
	    {Header, PayLoad} ->
		KeepAlive = proplists:get_bool('keep-alive', Header#capwap_header.flags),
		handle_capwap_data(DataPath, WTPDataChannelAddress, Header, KeepAlive, PayLoad);
	    _ ->
		lager:warning("invalid CAPWAP data from ~s", [format_peer(WTPDataChannelAddress)]),
		{error, not_capwap}
	end
    catch
	Class:Error ->
	    lager:debug("failure: ~p:~p", [Class, Error]),
	    {error, not_capwap}
    end.

accept(WTP, Type, Socket) ->
    gen_fsm:send_event(WTP, {accept, Type, Socket}).

get_data_channel_address(WTP) ->
    gen_fsm:sync_send_all_state_event(WTP, get_data_channel_address).

take_over(WTP) ->
    gen_fsm:sync_send_all_state_event(WTP, {take_over, self()}).

new_station(WTP, BSS, SA) ->
    gen_fsm:sync_send_event(WTP, {new_station, BSS, SA}).

station_detaching(AC) ->
    gen_fsm:send_all_state_event(AC, station_detaching).

gtk_rekey_done({AC, WlanIdent}) ->
    gen_fsm:send_event(AC, {gtk_rekey_done, WlanIdent}).

%%%===================================================================
%%% extern APIs
%%%===================================================================
with_cn(CN, Fun) ->
    case capwap_wtp_reg:lookup(CN) of
        {ok, Pid} ->
	    Fun(Pid);
        not_found ->
            {error, not_found}
    end.

get_state(CN) ->
    case with_cn(CN, gen_fsm:sync_send_all_state_event(_, get_state)) of
	{ok, State} ->
	    Fields = record_info(fields, state),
	    [_Tag| Values] = tuple_to_list(State),
	    PMap = maps:from_list(lists:zip(Fields, Values)),
	    {ok, PMap};
	Other ->
	    Other
    end.

firmware_download(CN, DownloadLink, Sha) ->
    with_cn(CN, gen_fsm:send_event(_, {firmware_download, DownloadLink, Sha})).

set_ssid(CN, RadioId, SSID, SuppressSSID) ->
    WlanId = 1,
    WlanIdent = {RadioId, WlanId},
    with_cn(CN, gen_fsm:sync_send_all_state_event(_, {set_ssid, WlanIdent, SSID, SuppressSSID})).

stop_radio(CN, RadioId) ->
    with_cn(CN, gen_fsm:sync_send_all_state_event(_, {stop_radio, RadioId})).

%%%===================================================================
%%% Station APIs
%%%===================================================================

add_station(AC, BSS, MAC, StaCaps, CryptoState) ->
    gen_fsm:sync_send_event(AC, {add_station, BSS, MAC, StaCaps, CryptoState}).

del_station(AC, BSS, MAC) ->
    gen_fsm:send_event(AC, {del_station, BSS, MAC}).

send_80211(AC, BSS, Data) ->
    gen_fsm:send_event(AC, {send_80211, BSS, Data}).

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
init([WTPControlChannelAddress]) ->
    process_flag(trap_exit, true),
    lager:md([{control_channel_address, WTPControlChannelAddress}]),
    exometer:update([capwap, ac, wtp_count], 1),
    capwap_wtp_reg:register(WTPControlChannelAddress),
    MTU = capwap_config:get(ac, mtu, 1500),
    {ok, listen, #state{ctrl_channel_address = WTPControlChannelAddress,
			request_queue = queue:new(),
			ctrl_stream = capwap_stream:init(MTU),
			change_state_pending_timeout = ?ChangeStatePendingTimeout,
                        wlans = []}, 5000}.

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
listen({accept, udp, Socket}, State0) ->
    capwap_udp:setopts(Socket, [{active, true}, {mode, binary}]),
    lager:info("udp_accept: ~p", [Socket]),
    {ok, Session} = start_session(Socket, State0),

    {ok, WTPControlChannelAddress} = capwap_udp:peername(Socket),
    PeerName = iolist_to_binary(format_peer(WTPControlChannelAddress)),

    Opts = [{'Username', PeerName},
	    {'Authentication-Method', {'TLS', 'Pre-Shared-Key'}},
            {'WTP-Config', capwap_config:wtp_config(PeerName)}],
    case ergw_aaa_session:authenticate(Session, to_session(Opts)) of
	success ->
	    lager:info("AuthResult: success"),
	    {ok, Config} = ergw_aaa_session:attr_get('WTP-Config', ergw_aaa_session:get(Session)),
	    State1 = State0#state{session = Session,
				  config = Config,
				  socket = {udp, Socket},
				  id = undefined},

	    next_state(idle, State1);

	Other ->
	    lager:info("AuthResult: ~p", [Other]),
	    {stop, normal, State0#state{session=Session}}
    end;

listen({accept, dtls, Socket}, State) ->
    {ok, Session} = start_session(Socket, State),
    lager:info("ssl_accept on: ~p, Opts: ~p", [Socket, mk_ssl_opts(Session)]),

    case dtlsex:ssl_accept(Socket, mk_ssl_opts(Session), ?SSL_ACCEPT_TIMEOUT) of
        {ok, SslSocket} ->
            lager:info("ssl_accept: ~p", [SslSocket]),
            {ok, WTPControlChannelAddress} = dtlsex:peername(SslSocket),
            dtlsex:setopts(SslSocket, [{active, true}, {mode, binary}]),

            CommonName = common_name(SslSocket),
	    lager:md([{wtp, CommonName}]),
	    lager:debug("ssl_cert: ~p", [CommonName]),

            maybe_takeover(CommonName),
            capwap_wtp_reg:register_args(CommonName, WTPControlChannelAddress),

	    {ok, Config} = ergw_aaa_session:attr_get('WTP-Config', ergw_aaa_session:get(Session)),
            State1 = State#state{socket = {dtls, SslSocket}, session = Session,
				 config = Config, id = CommonName},
            %% TODO: find old connection instance, take over their StationState and stop them
            next_state(idle, State1);
        Other ->
            lager:error("ssl_accept failed: ~p", [Other]),
            {stop, normal, State#state{session=Session}}
    end;


listen(timeout, State) ->
    {stop, normal, State}.

idle({keep_alive, _DataPath, _WTPDataChannelAddress, Header, PayLoad}, State) ->
    lager:warning("in IDLE got unexpected keep_alive: ~p", [{Header, PayLoad}]),
    next_state(idle, State);

idle(timeout, State) ->
    lager:info("timeout in IDLE -> stop"),
    {stop, normal, State};

idle({discovery_request, Seq, Elements, #capwap_header{
				radio_id = RadioId, wb_id = WBID, flags = Flags}},
     State) ->
    RespElements = ac_info(discover, Elements),
    Header = #capwap_header{radio_id = RadioId, wb_id = WBID, flags = Flags},
    State1 = send_response(Header, discovery_response, Seq, RespElements, State),
    next_state(idle, State1);

idle({join_request, Seq, Elements, #capwap_header{
			   radio_id = RadioId, wb_id = WBID, flags = Flags}},
     State0 = #state{ctrl_channel_address = WTPControlChannelAddress,
		     session = Session, id = CommonName,
		     config = Config0}) ->
    {Address, _} = WTPControlChannelAddress,
    Version = get_wtp_version(Elements),
    SessionId = proplists:get_value(session_id, Elements),
    capwap_wtp_reg:register_sessionid(Address, SessionId),

    RadioInfos = get_ies(ieee_802_11_wtp_radio_information, Elements),
    Config = capwap_config:wtp_set_radio_infos(CommonName, RadioInfos, Config0),

    StartTime = erlang:system_time(milli_seconds),
    MacTypes = ie(wtp_mac_type, Elements),
    TunnelModes = ie(wtp_frame_tunnel_mode, Elements),
    State1 = State0#state{config = Config,
			  session_id = SessionId, mac_types = MacTypes,
			  tunnel_modes = TunnelModes, version = Version,
			  location = ie(location_data, Elements),
			  board_data = get_ie(wtp_board_data, Elements),
			  descriptor = get_ie(wtp_descriptor, Elements),
			  name = ie(wtp_name, Elements),
			  start_time = StartTime
			 },

    RespElements = ac_info_version(join, Version)
	++ [#ecn_support{ecn_support = full},
	    #local_ipv4_address{ip_address = <<127,0,0,1>>},
	    #result_code{result_code = 0}],
    Header = #capwap_header{radio_id = RadioId, wb_id = WBID, flags = Flags},
    State = send_response(Header, join_response, Seq, RespElements, State1),
    SessionOpts = wtp_accounting_infos(Elements, [{'CAPWAP-Radio-Id', RadioId}]),
    lager:info("WTP Session Start Opts: ~p", [SessionOpts]),

    exometer:update_or_create([capwap, wtp, CommonName, start_time], StartTime, gauge, []),
    exometer:update_or_create([capwap, wtp, CommonName, stop_time], 0, gauge, []),
    exometer:update_or_create([capwap, wtp, CommonName, station_count], 0, gauge, []),
    lists:foreach(fun(X) ->
			  exometer:update_or_create([capwap, wtp, CommonName, X], 0, gauge, [])
		  end, ['InPackets', 'OutPackets', 'InOctets', 'OutOctets',
			'Received-Fragments', 'Send-Fragments', 'Error-Invalid-Stations',
			'Error-Fragment-Invalid', 'Error-Fragment-Too-Old']),

    ergw_aaa_session:start(Session, to_session(SessionOpts)),
    next_state(join, State);

idle(Event, State) when ?IS_RUN_CONTROL_EVENT(Event) ->
    lager:debug("in IDLE got control event: ~p", [Event]),
    next_state(idle, State);

idle({Msg, Seq, Elements, Header}, State) ->
    lager:warning("in IDLE got unexpexted: ~p", [{Msg, Seq, Elements, Header}]),
    next_state(idle, State).

join({keep_alive, _DataPath, _WTPDataChannelAddress, Header, PayLoad}, State) ->
    lager:warning("in JOIN got unexpected keep_alive: ~p", [{Header, PayLoad}]),
    next_state(join, State);

join(timeout, State) ->
    lager:info("timeout in JOIN -> stop"),
    {stop, normal, State};

join({configuration_status_request, Seq, Elements, #capwap_header{
						      wb_id = WBID, flags = Flags}},
     #state{config = Config0} = State0) ->

    Config = update_radio_information(Elements, Config0),
    #wtp{
       psm_idle_timeout           = PSMIdleTimeout,
       psm_busy_timeout           = PSMBusyTimeout,
       echo_request_interval      = EchoRequestInterval,
       discovery_interval         = DiscoveryInterval,
       idle_timeout               = IdleTimeout,
       data_channel_dead_interval = DataChannelDeadInterval,
       ac_join_timeout            = ACJoinTimeout,
       admin_pw                   = AdminPW,
       radios                     = Radios
      } = Config,

    AdminPwIE = if is_binary(AdminPW) ->
                        [#wtp_administrator_password_settings{password = AdminPW}];
		   true ->
                        []
                end,
    AdminWlans = get_admin_wifi_updates(State0, Elements),
    RespElements0 = [#timers{discovery = DiscoveryInterval,
			     echo_request = EchoRequestInterval},
		     #tp_data_channel_dead_interval{data_channel_dead_interval = DataChannelDeadInterval},
		     #tp_ac_join_timeout{ac_join_timeout = ACJoinTimeout},
		     #idle_timeout{timeout = IdleTimeout},
		     #wtp_fallback{mode = disabled},
		     #power_save_mode{idle_timeout = PSMIdleTimeout,
				      busy_timeout = PSMBusyTimeout}
		    ]
	++ AdminPwIE
	++ AdminWlans
	++ ac_addresses(),
    RespElements = lists:foldl(fun radio_configuration/2, RespElements0, Radios),

    Header = #capwap_header{radio_id = 0, wb_id = WBID, flags = Flags},
    State1 = send_response(Header, configuration_status_response, Seq, RespElements, State0),
    State2 = start_change_state_pending_timer(State1),
    State = State2#state{
	      config = Config,
	      echo_request_timeout = EchoRequestInterval * 2},

    next_state(configure, State);

join(Event, State) when ?IS_RUN_CONTROL_EVENT(Event) ->
    lager:debug("in JOIN got control event: ~p", [Event]),
    next_state(join, State);

join({Msg, Seq, Elements, Header}, State) ->
    lager:warning("in JOIN got unexpexted: ~p", [{Msg, Seq, Elements, Header}]),
    next_state(join, State).

configure({keep_alive, _DataPath, _WTPDataChannelAddress, Header, PayLoad}, State) ->
    lager:warning("in CONFIGURE got unexpected keep_alive: ~p", [{Header, PayLoad}]),
    next_state(configure, State);

configure(timeout, State) ->
    lager:info("timeout in CONFIGURE -> stop"),
    {stop, normal, State};

configure({change_state_event_request, Seq, _Elements, #capwap_header{
					      radio_id = RadioId, wb_id = WBID, flags = Flags}},
	  State) ->
    Header = #capwap_header{radio_id = RadioId, wb_id = WBID, flags = Flags},
    State1 = send_response(Header, change_state_event_response, Seq, [], State),
    State2 = cancel_change_state_pending_timer(State1),
    next_state(data_check, State2);

configure(Event, State) when ?IS_RUN_CONTROL_EVENT(Event) ->
    lager:debug("in CONFIGURE got control event: ~p", [Event]),
    next_state(configure, State);

configure({Msg, Seq, Elements, Header}, State) ->
    lager:debug("in configure got: ~p", [{Msg, Seq, Elements, Header}]),
    next_state(configure, State).

data_check({keep_alive, DataPath, WTPDataChannelAddress, Header, PayLoad},
	   State0 = #state{ctrl_stream = CtrlStreamState}) ->
    lager:md([{data_channel_address, WTPDataChannelAddress}]),
    ?log_capwap_keep_alive(peer_log_str(WTPDataChannelAddress, State0), PayLoad, Header),

    capwap_wtp_reg:register(WTPDataChannelAddress),
    MTU = capwap_stream:get_mtu(CtrlStreamState),
    capwap_dp:add_wtp(WTPDataChannelAddress, MTU),
    State = State0#state{data_channel_address = WTPDataChannelAddress, data_path = DataPath},

    gen_fsm:send_event(self(), configure),

    sendto(Header, PayLoad, State),
    next_state(run, State);

data_check(timeout, State) ->
    lager:info("timeout in DATA_CHECK -> stop"),
    {stop, normal, State};

data_check(Event, State) when ?IS_RUN_CONTROL_EVENT(Event) ->
    lager:debug("in DATA_CHECK got control event: ~p", [Event]),
    next_state(data_check, State);

data_check({Msg, Seq, Elements, Header}, State) ->
    lager:warning("in DATA_CHECK got unexpexted: ~p", [{Msg, Seq, Elements, Header}]),
    next_state(data_check, State).

run({new_station, BSS, SA}, _From, State0) ->
    lager:info("in RUN got new_station: ~p", [SA]),

    %% TODO: rework session context to handle this again
    %% {ok, MaxStations} = ergw_aaa_session:get(Session, 'CAPWAP-Max-WIFI-Clients'),

    Wlan = get_wlan_by_bss(BSS, State0),
    {Reply, State} = internal_new_station(Wlan, SA, State0),
    reply(Reply, run, State);

run(Event = {add_station, BSS, MAC, StaCaps, CryptoState}, From, State0) ->
    lager:warning("in RUN got expexted: ~p", [Event]),
    Wlan = get_wlan_by_bss(BSS, State0),
    lager:warning("WLAN: ~p", [Wlan]),
    State = internal_add_station(Wlan, MAC, StaCaps, CryptoState, response_fsm_reply(From), State0),
    next_state(run, State).

run({keep_alive, _DataPath, WTPDataChannelAddress, Header, PayLoad}, State) ->
    ?log_capwap_keep_alive(peer_log_str(WTPDataChannelAddress, State), PayLoad, Header),
    sendto(Header, PayLoad, State),
    next_state(run, State);

run(echo_timeout, State) ->
    lager:info("Echo Timeout in Run"),
    {stop, normal, State};

run({echo_request, Seq, Elements, #capwap_header{
			  radio_id = RadioId, wb_id = WBID, flags = Flags}},
    State) ->
    lager:debug("EchoReq in Run got: ~p", [{Seq, Elements}]),
    Header = #capwap_header{radio_id = RadioId, wb_id = WBID, flags = Flags},
    State1 = send_response(Header, echo_response, Seq, Elements, State),
    next_state(run, State1);

run({ieee_802_11_wlan_configuration_response, _Seq, Elements, _Header}, State0) ->
    State =
	case proplists:get_value(result_code, Elements) of
	    0 ->
		lager:debug("IEEE 802.11 WLAN Configuration ok"),
		lists:foldl(fun(#ieee_802_11_assigned_wtp_bssid{radio_id = RadioId,
							       wlan_id = WlanId,
							       bssid = BSS}, S0) ->
				   update_wlan_state({RadioId, WlanId},
						     fun(W) -> W#wlan{bss = BSS} end, S0)
			   end, State0, get_ies(ieee_802_11_assigned_wtp_bssid, Elements));

	    Code ->
		lager:warning("IEEE 802.11 WLAN Configuration failed with ~w", [Code]),
		%% TODO: handle Update failures
		State0
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
	    lager:warning("Station Configuration failed with ~w", [Code]),
	    ok
    end,
    next_state(run, State);

run({configuration_update_response, _Seq,
     Elements, _Header}, State) ->
    %% TODO: Error handling
    case proplists:get_value(result_code, Elements) of
    0 ->
        lager:debug("Configuration Update ok"),
        ok;
    Code ->
        lager:warning("Configuration Update failed with ~w", [Code]),
        ok
    end,
    next_state(run, State);

run({wtp_event_request, Seq, Elements, RequestHeader =
	 #capwap_header{radio_id = RadioId, wb_id = WBID, flags = Flags}}, State) ->
    ResponseHeader = #capwap_header{radio_id = RadioId, wb_id = WBID, flags = Flags},
    State1 = send_response(ResponseHeader, wtp_event_response, Seq, [], State),
    State2 = handle_wtp_event(Elements, RequestHeader, State1),
    next_state(run, State2);

run(configure, State = #state{id = WtpId, config = #wtp{radios = Radios},
			      session = Session}) ->
    lager:debug("configure WTP: ~p, Session: ~p, Radios: ~p", [WtpId, Session, Radios]),

    State1 =
	lists:foldl(fun(#wtp_radio{wlans = Wlans} = Radio, RState) ->
			    lists:foldl(internal_add_wlan(Radio, _, undefined, _), RState, Wlans)
		    end, State, Radios),
    next_state(run, State1);

run({del_station, BSS, MAC}, State0) ->
    Wlan = get_wlan_by_bss(BSS, State0),
    State = internal_del_station(Wlan, MAC, State0),
    next_state(run, State);

run({send_80211, BSS, Data}, State) ->
    Wlan = get_wlan_by_bss(BSS, State),
    internal_send_80211_station(Wlan, Data, State),
    next_state(run, State);

run({firmware_download, DownloadLink, Sha}, State) ->
    Flags = [{frame,'802.3'}],
    ReqElements = [#firmware_download_information{
        sha256_image_hash = Sha,
        download_uri = DownloadLink}],
    Header1 = #capwap_header{radio_id = 0, wb_id = 1, flags = Flags},
    State1 = send_request(Header1, configuration_update_request, ReqElements, State),
    next_state(run, State1);

run(Event = {group_rekey, WlanIdent}, State0) ->
    lager:warning("in RUN got GTK rekey: ~p", [Event]),
    Wlan = get_wlan(WlanIdent, State0),
    State = start_gtk_rekey(WlanIdent, Wlan, State0),
    next_state(run, State);

run(Event = {gtk_rekey_done, WlanIdent}, State0) ->
    lager:warning("in RUN got GTK rekey DONE: ~p", [Event]),
    Wlan = get_wlan(WlanIdent, State0),
    State = finish_gtk_rekey(WlanIdent, Wlan, State0),
    next_state(run, State);

run(Event, State) ->
    lager:warning("in RUN got unexpexted: ~p", [Event]),
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
handle_event(station_detaching, StateName, State=#state{id = WtpId, station_count = SC}) ->
    if SC == 0 ->
            lager:error("Station counter and stations got out of sync", []),
            next_state(StateName, State);
       true ->
	    exometer:update([capwap, ac, station_count], -1),
	    exometer:update([capwap, wtp, WtpId, station_count], SC - 1),
            next_state(StateName, State#state{station_count = SC - 1})
    end;

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

handle_sync_event(get_state, _From, StateName, State) ->
    reply({ok, State}, StateName, State);

handle_sync_event({set_ssid, {RadioId, WlanId} = WlanIdent, SSID, SuppressSSID},
		  From, run, #state{config = Config0} = State0) ->
    Settings = [{ssid, SSID}, {suppress_ssid, SuppressSSID}],
    Config = capwap_config:update_wlan_config(RadioId, WlanId, Settings, Config0),
    State1 = State0#state{config = Config},

    AddResponseFun = fun(Code, _, DState) ->
			     lager:debug("AddResponseFun: ~w", [Code]),
			     case Code of
				 0 -> gen_fsm:reply(From, ok);
				 _ -> gen_fsm:reply(From, {error, Code})
			     end,
			     DState
		     end,

    State =
	case get_wlan(WlanIdent, State1) of
	    false ->
		internal_add_wlan(RadioId, WlanId, AddResponseFun, State1);

	    #wlan{} ->
		DelResponseFun = fun(0, _, DState) ->
					 lager:debug("DelResponseFun: success"),
					 internal_add_wlan(RadioId, WlanId, AddResponseFun, DState);
				    (Code, Arg, DState) ->
					 lager:debug("DelResponseFun: ~w", [Code]),
					 AddResponseFun(Code, Arg, DState)
				 end,
		internal_del_wlan(WlanIdent, DelResponseFun, State1)
	end,
    next_state(run, State);

handle_sync_event({stop_radio, RadioId}, _From, run, State) ->
    State1 =
	lists:foldl(fun(WlanIdent = {RId, _}, S) when RId == RadioId->
			    internal_del_wlan(WlanIdent, undefined, S);
		       (_, S) ->
			    S
		    end, State, State#state.wlans),
    reply(ok, run, State1);

handle_sync_event({set_ssid, _SSID, _RadioId}, _From, StateName, State)
  when StateName =/= run ->
    reply({error, not_in_run_state}, StateName, State);

handle_sync_event(get_data_channel_address, _From, run, State) ->
    Reply = {ok, State#state.data_channel_address},
    reply(Reply, run, State);
handle_sync_event(get_data_channel_address, _From, StateName, State) ->
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
    lager:debug("in State ~p got UDP: ~p", [StateName, Packet]),
    handle_capwap_packet(Packet, StateName, State);

handle_info({ssl, Socket, Packet}, StateName, State = #state{socket = {_, Socket}}) ->
    lager:debug("in State ~p got DTLS: ~p", [StateName, Packet]),
    handle_capwap_packet(Packet, StateName, State);

handle_info({timeout, _, retransmit}, StateName, State) ->
    resend_request(StateName, State);
handle_info({'EXIT', _Pid, normal}, StateName, State) ->
    next_state(StateName, State);
handle_info(Info, StateName, State) ->
    lager:warning("in State ~p unexpected Info: ~p", [StateName, Info]),
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
	  State = #state{socket = Socket, session = Session,
			 id = CommonName, station_count = StationCount}) ->
    error_logger:info_msg("AC session terminating in state ~p with state ~p with reason ~p~n",
			  [StateName, State, Reason]),
    AcctValues = stop_wtp(StateName, State),
    if Session /= undefined ->
	    ergw_aaa_session:stop(Session, to_session(AcctValues)),

	    exometer:update([capwap, wtp, CommonName, station_count], 0),
	    StopTime = erlang:system_time(milli_seconds),
	    exometer:update_or_create([capwap, wtp, CommonName, stop_time], StopTime, gauge, []);
       true -> ok
    end,

    exometer:update([capwap, ac, station_count], -StationCount),
    exometer:update([capwap, ac, wtp_count], -1),
    socket_close(Socket),
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
gpsutc_to_iso(GPSTime, GPSDate) ->
    try
	{ok, [Hour, Minute, Second], _} = io_lib:fread("~2s~2s~s", GPSTime),
	{ok, [Day, Month, Year], _} = io_lib:fread("~2s~2s~2s", GPSDate),
	lists:flatten(["20", Year, "-", Month, "-", Day, "T", Hour, ":", Minute, ":", Second, "Z"])
    catch
	_:_ -> "2000-01-01T00:00:00Z"
    end.

format_peer({IP, Port}) ->
    io_lib:format("~s:~w", [inet_parse:ntoa(IP), Port]);
format_peer(IP) ->
    io_lib:format("~p", [IP]).

peer_log_str(State = #state{ctrl_channel_address = WTPControlChannelAddress}) ->
    peer_log_str(WTPControlChannelAddress, State).

peer_log_str(Address, #state{id = undefined}) ->
    io_lib:format("~p", [Address]);
peer_log_str(Address, #state{id = Id}) ->
    io_lib:format("~s[~s]", [Id, format_peer(Address)]).

next_state(NextStateName, State)
  when NextStateName == idle; NextStateName == run ->
    {next_state, NextStateName, State};
next_state(NextStateName, State) ->
    {next_state, NextStateName, State, ?IDLE_TIMEOUT}.

reply(Reply, NextStateName, State)
  when NextStateName == idle; NextStateName == run  ->
    {reply, Reply, NextStateName, State};
reply(Reply, NextStateName, State) ->
    {reply, Reply, NextStateName, State, ?IDLE_TIMEOUT}.

%% non-DTLS join-reqeust, check app config
handle_plain_join(Peer, Seq, _Elements, #capwap_header{
					   wb_id = WBID, flags = Flags}) ->
    case capwap_config:get(ac, enforce_dtls_control, true) of
	false ->
	    lager:warning("Accepting JOIN without DTLS from ~s", [Peer]),
	    accept;
	_ ->
	    lager:warning("Rejecting JOIN without DTLS from ~s", [Peer]),
	    RespElems = [#result_code{result_code = 18}],
	    Header = #capwap_header{radio_id = 0, wb_id = WBID, flags = Flags},
	    ?log_capwap_control(Peer, join_response, Seq, RespElems, Header),
	    Answer = hd(capwap_packet:encode(control, {Header, {join_response, Seq, RespElems}})),
	    {reply, Answer}
    end.

handle_capwap_data(DataPath, WTPDataChannelAddress, Header, true, PayLoad) ->
    lager:debug("CAPWAP Data KeepAlive: ~p", [PayLoad]),

    {Address, _Port} = WTPDataChannelAddress,
    SessionId = proplists:get_value(session_id, PayLoad),
    case capwap_wtp_reg:lookup_sessionid(Address, SessionId) of
	not_found ->
	    lager:warning("CAPWAP data from unknown WTP ~s", [format_peer(WTPDataChannelAddress)]),
	    ok;
	{ok, AC} ->
	    gen_fsm:send_event(AC, {keep_alive, DataPath, WTPDataChannelAddress, Header, PayLoad})
    end;

handle_capwap_data(_DataPath, WTPDataChannelAddress,
		   Header = #capwap_header{
			       flags = Flags, radio_mac = RecvRadioMAC},
		   false, Frame) ->
    lager:debug("CAPWAP Data PayLoad:~n~p~n~p", [lager:pr(Header, ?MODULE), Frame]),

    case capwap_wtp_reg:lookup(WTPDataChannelAddress) of
	not_found ->
	    lager:warning("AC for data session no found: ~p", [WTPDataChannelAddress]),
	    {error, not_found};
	{ok, AC} ->
	    case proplists:get_value(frame, Flags) of
		'802.3' ->
		    ieee80211_station:handle_ieee802_3_frame(AC, RecvRadioMAC, Frame);

		native ->
		    ieee80211_station:handle_ieee80211_frame(AC, Frame);

		_ ->
		    {error, unknown_frame_format}
	    end
    end.

handle_capwap_packet(Packet, StateName, State = #state{ctrl_channel_address = WTPControlChannelAddress,
						       ctrl_stream = CtrlStreamState0}) ->
    capwap_trace:trace(WTPControlChannelAddress, ?TRACE_LOCAL_CONTROL, Packet),
    case capwap_stream:recv(control, Packet, CtrlStreamState0) of
	{ok, {Header, Msg}, CtrlStreamState1} ->
	    handle_capwap_message(Header, Msg, StateName, State#state{ctrl_stream = CtrlStreamState1});

	{ok, more, CtrlStreamState1} ->
	    next_state(StateName, State#state{ctrl_stream = CtrlStreamState1});

	{error, Error} ->
	    lager:error([{capwap_packet, decode}, {error, Error}], "Decode error ~p", [Error]),
	    next_state(StateName, State)
    end.

handle_capwap_message(Header, {Msg, 1, Seq, Elements}, StateName,
		      State0 = #state{last_response = LastResponse}) ->
    %% Request
    ?log_capwap_control(peer_log_str(State0), Msg, Seq, Elements, Header),
    State = reset_echo_request_timer(State0),
    case LastResponse of
	{Seq, _} ->
	    NewState = resend_response(State),
	    next_state(StateName, NewState);
	{LastSeq, _} when ?SEQ_LE(Seq, LastSeq) ->
	    %% old request, silently ignore
	    next_state(StateName, State);
	_ ->
	    ?MODULE:StateName({Msg, Seq, Elements, Header}, State)
    end;

handle_capwap_message(Header, {Msg, 0, Seq, Elements}, StateName,
		      State = #state{request_queue = Queue}) ->
    %% Response
    ?log_capwap_control(peer_log_str(State), Msg, Seq, Elements, Header),
    case queue:peek(Queue) of
	{value, {Seq, _, NotifyFun}} ->
	    State1 = ack_request(State),
	    State2 = response_notify(NotifyFun, proplists:get_value(result_code, Elements),
				     {Msg, Elements, Header}, State1),
	    ?MODULE:StateName({Msg, Seq, Elements, Header}, State2);
	_ ->
	    %% invalid Seq, out-of-order packet, silently ignore,
	    next_state(StateName, State)
    end.

maybe_takeover(CommonName) ->
    case capwap_wtp_reg:lookup(CommonName) of
        {ok, OldPid} ->
            lager:info("take_over: ~p", [OldPid]),
            capwap_ac:take_over(OldPid);
        _ ->
            ok
    end.

handle_wtp_event(Elements, Header, State = #state{session = Session}) ->
    SessionOptsList = lists:foldl(fun(Ev, SOptsList) -> handle_wtp_stats_event(Ev, Header, SOptsList) end, [], Elements),
    if length(SessionOptsList) /= 0 ->
	    ergw_aaa_session:interim_batch(Session, SessionOptsList);
       true -> ok
    end,
    lists:foldl(fun(Ev, State0) -> handle_wtp_action_event(Ev, Header, State0) end, State, Elements).

handle_wtp_action_event(#delete_station{radio_id = RadioId, mac = MAC}, _Header, State) ->
    case capwap_station_reg:lookup(self(), RadioId, MAC) of
	{ok, Station} ->
	    ieee80211_station:delete(Station);
	Other ->
	    lager:debug("station ~p not found: ~p", [MAC, Other]),
	    ok
    end,
    State;
handle_wtp_action_event(_Action, _Header, State) ->
    State.

handle_wtp_stats_event(#gps_last_acquired_position{timestamp = _EventTimestamp,
                                                   wwan_id = _WwanId,
                                                   gpsatc = GpsString},
                       _Header, SOptsList) ->
    case [string:strip(V) || V <- string:tokens(binary_to_list(GpsString), ",:")] of
        [_, GPSTime, Latitude, Longitude, Hdop, Altitude, _Fix, _Cog, _Spkm, _Spkn, GPSDate, _Nsat] ->
	    GPSTimestamp = gpsutc_to_iso(GPSTime, GPSDate),
            Opts = [{'CAPWAP-GPS-Timestamp', GPSTimestamp},
                    {'CAPWAP-GPS-Latitude', Latitude},
                    {'CAPWAP-GPS-Longitude', Longitude},
                    {'CAPWAP-GPS-Altitude', Altitude},
                    {'CAPWAP-GPS-Hdop', Hdop}
                   ],
            lager:debug("WTP Event Opts: ~p", [Opts]),
            [to_session(Opts) | SOptsList];
        _ ->
            lager:error("Unable to parse GPSATC string from WTP! String: ~p", [GpsString]),
            SOptsList
    end;

handle_wtp_stats_event(#tp_wtp_wwan_statistics_0_9{timestamp = Timestamp, wwan_id = WWanId, rat = RAT,
					     rssi = RSSi, lac = LAC, cell_id = CellId},
		 _Header, SOptsList) ->
    Opts = [{'CAPWAP-Timestamp', Timestamp},
            {'CAPWAP-WWAN-Id',   WWanId},
            {'CAPWAP-WWAN-RAT',       RAT},
            {'CAPWAP-WWAN-RSSi',      RSSi},
            {'CAPWAP-WWAN-LAC',       LAC},
            {'CAPWAP-WWAN-Cell-Id',   CellId}],
    lager:debug("WTP Event Opts: ~p", [Opts]),
    [to_session(Opts) | SOptsList];
handle_wtp_stats_event(#tp_wtp_wwan_statistics{timestamp = Timestamp, wwan_id = WWanId, rat = RAT,
					 rssi = RSSi, creg = CREG, lac = LAC, latency = Latency,
					 mcc = MCC, mnc = MNC, cell_id = CellId},
		 _Header, SOptsList) ->
    Opts = [{'CAPWAP-Timestamp', Timestamp},
            {'CAPWAP-WWAN-Id',   WWanId},
            {'CAPWAP-WWAN-RAT',       RAT},
            {'CAPWAP-WWAN-RSSi',      RSSi},
            {'CAPWAP-WWAN-CREG',      CREG},
            {'CAPWAP-WWAN-LAC',       LAC},
            {'CAPWAP-WWAN-Latency',   Latency},
            {'CAPWAP-WWAN-MCC',       MCC},
            {'CAPWAP-WWAN-MNC',       MNC},
            {'CAPWAP-WWAN-Cell-Id',   CellId}],
    lager:debug("WTP Event Opts: ~p", [Opts]),
    [to_session(Opts) | SOptsList];
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

bool2i(false) -> 0;
bool2i(_)     -> 1.

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
		{_, <<123456:64/integer>>} ->
		    %% old, broken version encoding
		    {16#010103, []};
		{_, Value} ->
		    case split_version(Value) of
			[Major, Minor, Patch|AddOn]
			  when is_integer(Major), is_integer(Minor), is_integer(Patch) ->
			    {Major * 65536 + Minor * 256 + Patch, AddOn};
			_ ->
			    {0, undefined}
		    end;
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
    Acc1 = [{'CAPWAP-Session-Id', <<Value:128>>}|Acc],
    wtp_accounting_infos(Elements, Acc1);
wtp_accounting_infos([_|Elements], Acc) ->
    wtp_accounting_infos(Elements, Acc).

wtp_accounting_descriptor_infos([], Acc) ->
    Acc;
wtp_accounting_descriptor_infos([{{18681,0}, Version}|Elements], Acc)
  when is_binary(Version) ->
    Acc1 = [{'CAPWAP-WTP-Version', Version}|Acc],
    wtp_accounting_descriptor_infos(Elements, Acc1);

wtp_accounting_descriptor_infos([{{0,0}, Version}|Elements], Acc)
  when is_binary(Version) ->
    Acc1 = [{'CAPWAP-Hardware-Version', Version}|Acc],
    wtp_accounting_descriptor_infos(Elements, Acc1);

wtp_accounting_descriptor_infos([{{0,1}, Version}|Elements], Acc)
  when is_binary(Version) ->
    Acc1 = [{'CAPWAP-Software-Version', Version}|Acc],
    wtp_accounting_descriptor_infos(Elements, Acc1);

wtp_accounting_descriptor_infos([{{0,2}, Version}|Elements], Acc)
  when is_binary(Version) ->
    Acc1 = [{'CAPWAP-Boot-Version', Version}|Acc],
    wtp_accounting_descriptor_infos(Elements, Acc1);

wtp_accounting_descriptor_infos([{{0,3}, Version}|Elements], Acc)
  when is_binary(Version) ->
    Acc1 = [{'CAPWAP-Other-Software-Version', Version}|Acc],
    wtp_accounting_descriptor_infos(Elements, Acc1);

wtp_accounting_descriptor_infos([_|Elements], Acc) ->
    wtp_accounting_descriptor_infos(Elements, Acc).

ac_info(Request, Elements) ->
    Version = get_wtp_version(Elements),
    lager:debug("ac_info version: ~p", [Version]),
    ac_info_version(Request, Version).

ac_info_version(Request, {Version, _AddOn}) ->
    AcList = if (Version > 16#010104 andalso Request == discover)
		orelse Version >= 16#010200 ->
		     [map_aalwp(I) || I <- capwap_config:get(ac, ac_address_list_with_prio, [])];
		true -> []
	     end,
    [#ac_descriptor{stations    = 0,
		    limit       = capwap_config:get(ac, limit, 200),
		    active_wtps = 0,
		    max_wtps    = capwap_config:get(ac, max_wtps, 200),
%%		    security    = ['pre-shared'],
		    security    = capwap_config:get(ac, security, ['x509']),
		    r_mac       = supported,
		    dtls_policy = ['clear-text'],
		    sub_elements = [{{0,4}, capwap_config:get(ac, [versions, hardware], <<"Hardware Ver. 1.0">>)},
				    {{0,5}, capwap_config:get(ac, [versions, software], <<"Software Ver. 1.0">>)}]},
     #ac_name{name = capwap_config:get(ac, ac_name, <<"My AC Name">>)}
    ] ++ control_addresses() ++ AcList.

update_radio_sup_rates(SRates, #wtp_radio{supported_rates = SR} = Radio)
  when is_list(SR) ->
    Radio#wtp_radio{supported_rates = SR ++ SRates};
update_radio_sup_rates(SRates, Radio) ->
    Radio#wtp_radio{supported_rates = SRates}.

update_radio_80211n_cfg(#ieee_802_11n_wlan_radio_configuration{
			   a_msdu            = AggMSDU,
			   a_mpdu            = AggMPDU,
			   deny_non_11n      = DenyNon11n,
			   short_gi          = ShortGI,
			   bandwidth_binding = BandwidthBinding,
			   max_supported_mcs = MaxSupportedMCS,
			   max_mandatory_mcs = MaxMandatoryMCS,
			   tx_antenna        = RxAntenna,
			   rx_antenna        = RxAntenna
			  }, Radio) ->
    Radio#wtp_radio{
      a_msdu            = AggMSDU,
      a_mpdu            = AggMPDU,
      deny_non_11n      = DenyNon11n,
      short_gi          = ShortGI,
      bandwidth_binding = BandwidthBinding,
      max_supported_mcs = MaxSupportedMCS,
      max_mandatory_mcs = MaxMandatoryMCS,
      tx_antenna        = RxAntenna,
      rx_antenna        = RxAntenna
     }.

update_radio_cipher_suites(CipherSuites, Radio) ->
    lager:info("CipherSuites: ~p", [[capwap_packet:decode_cipher_suite(Suite) || Suite <- CipherSuites]]),
    Radio#wtp_radio{
      supported_cipher_suites = [capwap_packet:decode_cipher_suite(Suite) || Suite <- CipherSuites]}.

update_radio_cfg(Fun, RadioId, #wtp{radios = Radios} = Config) ->
    case lists:keyfind(RadioId, #wtp_radio.radio_id, Radios) of
	#wtp_radio{} = Radio ->
	    Config#wtp{radios = lists:keystore(RadioId, #wtp_radio.radio_id, Radios, Fun(Radio))};
	_ ->
	    Config
    end.

update_radio_info(#ieee_802_11_supported_rates{
			   radio_id = RadioId,
			   supported_rates = SRates}, Config) ->
    update_radio_cfg(update_radio_sup_rates(SRates, _), RadioId, Config);
update_radio_info(#ieee_802_11n_wlan_radio_configuration{
			   radio_id = RadioId} = Cfg, Config) ->
    update_radio_cfg(update_radio_80211n_cfg(Cfg, _), RadioId, Config);
update_radio_info(#tp_ieee_802_11_encryption_capabilities{
		     radio_id = RadioId,
		     cipher_suites = CipherSuites}, Config) ->
    update_radio_cfg(update_radio_cipher_suites(CipherSuites, _), RadioId, Config);

update_radio_info(_, Config) ->
    Config.

update_radio_information(Elements, Config) ->
    lists:foldl(fun update_radio_info/2, Config, Elements).

rateset('11b-only') ->
    [10, 20, 55, 110];
rateset('11g-only') ->
    [60, 90, 120, 180, 240, 360, 480, 540];
rateset('11bg') ->
    [10, 20, 55, 110, 60, 90, 120, 180, 240, 360, 480, 540].

radio_cfg(decryption_error_report_period,
	  #wtp_radio{radio_id = RadioId,
		    report_interval = ReportInterval}, IEs) ->
    [#decryption_error_report_period{
	radio_id = RadioId,
	report_interval = ReportInterval}
     | IEs];

radio_cfg(ieee_802_11_antenna,
	  #wtp_radio{radio_id = RadioId,
		     diversity = Diversity,
		     combiner = Combiner,
		     antenna_selection = AntennaSelection}, IEs) ->
    [#ieee_802_11_antenna{
	radio_id = RadioId,
	diversity = Diversity,
	combiner = Combiner,
	antenna_selection = << <<X:8>> || X <- AntennaSelection >>}
     | IEs];

radio_cfg(ieee_802_11_direct_sequence_control,
	  #wtp_radio{radio_id = RadioId,
		     operation_mode = OperMode,
		     channel = Channel,
		     channel_assessment = CCA,
		     energy_detect_threshold = EDT}, IEs)
  when Channel >= 1 andalso
       Channel =< 14 andalso
       (OperMode == '802.11b' orelse
	OperMode == '802.11g') ->
    [#ieee_802_11_direct_sequence_control{
	radio_id = RadioId,
	current_chan = Channel,
	current_cca = CCA,
	energy_detect_threshold = EDT}
     | IEs];

radio_cfg(ieee_802_11_ofdm_control,
	  #wtp_radio{radio_id = RadioId,
		     operation_mode = OperMode,
		     channel = Channel,
		     band_support = BandSupport,
		     ti_threshold = TIThreshold}, IEs)
  when OperMode == '802.11a' ->
    [#ieee_802_11_ofdm_control{
	radio_id = RadioId,
	current_chan = Channel,
	band_support = BandSupport,
	ti_threshold = TIThreshold}
     | IEs];

radio_cfg(ieee_802_11_mac_operation,
	  #wtp_radio{radio_id = RadioId,
		     rts_threshold = RTS_threshold,
		     short_retry = ShortRetry,
		     long_retry = LongRetry,
		     fragmentation_threshold = FragThreshold,
		     tx_msdu_lifetime = TX_msdu_lifetime,
		     rx_msdu_lifetime = RX_msdu_lifetime}, IEs) ->
    [#ieee_802_11_mac_operation{
	radio_id = RadioId,
	rts_threshold = RTS_threshold,
	short_retry = ShortRetry,
	long_retry = LongRetry,
	fragmentation_threshold = FragThreshold,
	tx_msdu_lifetime = TX_msdu_lifetime,
	rx_msdu_lifetime = RX_msdu_lifetime}
     | IEs];

%% TODO: read and apply Regulatory Domain DB
radio_cfg(ieee_802_11_multi_domain_capability,
	  #wtp_radio{radio_id = RadioId}, IEs) ->
    [#ieee_802_11_multi_domain_capability{
	radio_id = RadioId,
	first_channel = 1,
	number_of_channels_ = 13,
	max_tx_power_level = 100}
     | IEs];

radio_cfg(ieee_802_11_tx_power,
	  #wtp_radio{radio_id = RadioId,
		     tx_power = TxPower}, IEs) ->
    [#ieee_802_11_tx_power{
	radio_id = RadioId,
	current_tx_power = TxPower}
     | IEs];

radio_cfg(ieee_802_11_wtp_radio_configuration,
	  #wtp_radio{radio_id = RadioId,
		     beacon_interval = BeaconInt,
		     dtim_period = DTIM,
		     short_preamble = ShortPreamble}, IEs) ->
    [#ieee_802_11_wtp_radio_configuration{
	radio_id = RadioId,
	short_preamble = ShortPreamble,
	num_of_bssids = 1,
	dtim_period = DTIM,
	bssid = <<0,0,0,0,0,0>>,
	beacon_period = BeaconInt,
	country_string = <<"DE", $X, 0>>}
     | IEs];

radio_cfg(ieee_802_11_rate_set,
	  #wtp_radio{radio_id = RadioId}, IEs) ->
    Mode = '11g-only',
    RateSet = rateset(Mode),

    {Rates, _} =  lists:split(8, RateSet),
    Basic = [(X div 5) || X <- Rates],
    [#ieee_802_11_rate_set{
	radio_id = RadioId,
	rate_set = Basic}
     | IEs];

radio_cfg(_, _Radio, IEs) ->
    IEs.

radio_configuration(Radio, IEs) ->
    Settings = [decryption_error_report_period, ieee_802_11_antenna,
		ieee_802_11_direct_sequence_control, ieee_802_11_mac_operation,
		ieee_802_11_multi_domain_capability, ieee_802_11_ofdm_control,
		ieee_802_11_tx_power, ieee_802_11_wtp_radio_configuration,
		ieee_802_11_rate_set],
    lists:foldl(radio_cfg(_, Radio, _), IEs, Settings).

reset_echo_request_timer(State = #state{echo_request_timer = Timer,
					echo_request_timeout = Timeout}) ->
    if is_reference(Timer) ->
	    gen_fsm:cancel_timer(Timer);
       true ->
	    ok
    end,
    TRef = if is_integer(Timeout) ->
		   gen_fsm:send_event_after(Timeout * 1000, echo_timeout);
	      true ->
		   undefined
	   end,
    State#state{echo_request_timer = TRef}.

send_info_after(Time, Event) ->
    erlang:start_timer(Time, self(), Event).

bump_seqno(State = #state{seqno = SeqNo}) ->
    State#state{seqno = (SeqNo + 1) rem 256}.

send_response(Header, MsgType, Seq, MsgElems, State) ->
    ?log_capwap_control(peer_log_str(State), MsgType, Seq, MsgElems, Header),
    Msg = {Header, {MsgType, Seq, MsgElems}},
    stream_send(Msg, State#state{last_response = {Seq, Msg}}).

resend_response(State = #state{last_response = {SeqNo, Msg}}) ->
    lager:warning("resend capwap response ~w", [SeqNo]),
    stream_send(Msg, State).

send_request(Header, MsgType, ReqElements, State) ->
    send_request(Header, MsgType, ReqElements, undefined, State).

send_request(Header, MsgType, ReqElements, NotfiyFun,
	     State0 = #state{request_queue = Queue, seqno = SeqNo}) ->
    ?log_capwap_control(peer_log_str(State0), MsgType, SeqNo, ReqElements, Header),
    Msg = {Header, {MsgType, SeqNo, ReqElements}},
    State1 = queue_request(State0, {SeqNo, Msg, NotfiyFun}),
    State2 = bump_seqno(State1),
    case queue:is_empty(Queue) of
        true ->
            State3 = stream_send(Msg, State2),
            init_retransmit(State3, ?MaxRetransmit);
        false ->
            State2
    end.

resend_request(StateName, State = #state{retransmit_counter = 0}) ->
    lager:debug("Final Timeout in ~w, STOPPING", [StateName]),
    {stop, normal, State};
resend_request(StateName,
	       State0 = #state{request_queue = Queue,
			       retransmit_counter = RetransmitCounter}) ->
    lager:warning("resend capwap request", []),
    {value, {_, Msg, _}} = queue:peek(Queue),
    State1 = stream_send(Msg, State0),
    State2 = init_retransmit(State1, RetransmitCounter - 1),
    next_state(StateName, State2).

init_retransmit(State, Counter) ->
    State#state{retransmit_timer = send_info_after(?RetransmitInterval, retransmit),
                retransmit_counter = Counter}.

%% Stop Timer, clear LastRequest
ack_request(State0) ->
    State1 = cancel_retransmit(State0),
    case dequeue_request_next(State1) of
        {{value, {_, Msg, _}}, State2} ->
	    State3 = stream_send(Msg, State2),
            init_retransmit(State3, ?MaxRetransmit);
        {empty, State2} ->
            State2
    end.

cancel_retransmit(State = #state{retransmit_timer = undefined}) ->
    State;
cancel_retransmit(State = #state{retransmit_timer = Timer}) ->
    gen_fsm:cancel_timer(Timer),
    State#state{retransmit_timer = undefined}.

queue_request(State = #state{request_queue = Queue}, Request) ->
    State#state{request_queue = queue:in(Request, Queue)}.

dequeue_request_next(State = #state{request_queue = Queue0}) ->
    Queue1 = queue:drop(Queue0),
    {queue:peek(Queue1), State#state{request_queue = Queue1}}.

control_addresses() ->
    Addrs =
	case capwap_config:get(ac, control_ips) of
	    {ok, IPs} when is_list(IPs) ->
		IPs;
	    _ ->
		case capwap_config:get(ac, server_ip) of
		    {ok, IP} ->
			[IP];
		    _ ->
			all_local_addresses()
		end
	end,
    [control_address(A) || A <- Addrs].

get_wtp_count() ->
    case exometer:get_value([capwap, ac, wtp_count]) of
	{ok, {value, Value}}
	  when is_integer(Value)
	       -> Value;
	_ -> 0
    end.

control_address({A,B,C,D}) ->
    #control_ipv4_address{ip_address = <<A,B,C,D>>,
			  wtp_count = get_wtp_count()};
control_address({A,B,C,D,E,F,G,H}) ->
    #control_ipv6_address{ip_address = <<A:16,B:16,C:16,D:16,E:16,F:16,G:16,H:16>>,
			  wtp_count = get_wtp_count()}.

ac_addresses() ->
    Addrs =
	case capwap_config:get(ac, server_ip) of
	    {ok, IP} ->
		[IP];
	    _ ->
		all_local_addresses()
	end,
    IE0 =
	case [I || I = {_,_,_,_} <- Addrs] of
	    [] -> [];
	    IPv4 -> [#ac_ipv4_list{ip_address = IPv4}]
	end,
    case [I || I = {_,_,_,_,_,_,_,_} <- Addrs] of
	[] -> IE0;
	IPv6 -> [#ac_ipv6_list{ip_address = IPv6} | IE0]
    end.

all_local_addresses() ->
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
    process_ifopt(Rest, [IP|Acc]);
process_ifopt([_|Rest], Acc) ->
    process_ifopt(Rest, Acc).

answer_discover(Peer, Seq, Elements, #capwap_header{
		       radio_id = RadioId, wb_id = WBID, flags = Flags}) ->
    RespElems = ac_info(discover, Elements),
    Header = #capwap_header{radio_id = RadioId, wb_id = WBID, flags = Flags},
    ?log_capwap_control(Peer, discovery_response, Seq, RespElems, Header),
    hd(capwap_packet:encode(control, {Header, {discovery_response, Seq, RespElems}})).

stream_send(Msg, State = #state{ctrl_channel_address = WTPControlChannelAddress,
				ctrl_stream = CtrlStreamState0,
				socket = Socket}) ->
    {BinMsg, CtrlStreamState1} = capwap_stream:encode(control, Msg, CtrlStreamState0),
    lists:foreach(fun(M) ->
			  capwap_trace:trace(?TRACE_LOCAL_CONTROL, WTPControlChannelAddress, M),
			  ok = socket_send(Socket, M)
		  end, BinMsg),
    State#state{ctrl_stream = CtrlStreamState1}.

socket_send({udp, Socket}, Data) ->
    capwap_udp:send(Socket, Data);
socket_send({dtls, Socket}, Data) ->
    dtlsex:send(Socket, Data).

socket_close({udp, Socket}) ->
    capwap_udp:close(Socket);
socket_close({dtls, Socket}) ->
    dtlsex:close(Socket);
socket_close(undefined) ->
    ok;
socket_close(Socket) ->
    lager:warning("Got Close on: ~p", [Socket]),
    ok.

common_name(SslSocket) ->
    {ok, Cert} = dtlsex:peercert(SslSocket),
    #'OTPCertificate'{
       tbsCertificate =
       #'OTPTBSCertificate'{
          subject = {rdnSequence, SubjectList}
         }} = public_key:pkix_decode_cert(Cert, otp),
    Subject = [erlang:hd(S)|| S <- SubjectList],
    {value, #'AttributeTypeAndValue'{value = {utf8String, CommonName}}} =
        lists:keysearch(?'id-at-commonName', #'AttributeTypeAndValue'.type, Subject),
    CommonName.

user_lookup(srp, Username, _UserState) ->
    lager:debug("srp: ~p", [Username]),
    Salt = dtlsex:random_bytes(16),
    UserPassHash = crypto:hash(sha, [Salt, crypto:hash(sha, [Username, <<$:>>, <<"secret">>])]),
    {ok, {srp_1024, Salt, UserPassHash}};

user_lookup(psk, Username, Session) ->
    lager:debug("user_lookup: Username: ~p", [Username]),
    Opts = [{'Username', Username},
	    {'Authentication-Method', {'TLS', 'Pre-Shared-Key'}},
	    {'WTP-Config', capwap_config:wtp_config(Username)}],
    case ergw_aaa_session:authenticate(Session, to_session(Opts)) of
	success ->
	    lager:info("AuthResult: success"),
	    case ergw_aaa_session:get(Session, 'TLS-Pre-Shared-Key') of
		{ok, PSK} ->
		    lager:info("AuthResult: PSK: ~p", [PSK]),
		    {ok, PSK};
		_ ->
		    lager:info("AuthResult: NO PSK"),
		    {error, "no PSK"}
	    end;
	Other ->
	    lager:info("AuthResult: ~p", [Other]),
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
    lager:info("AuthResult: attempt for ~p", [CommonName]),
    Opts = [{'Username', CommonName},
	    {'Authentication-Method', {'TLS', 'X509-Subject-CN'}},
	    {'WTP-Config', capwap_config:wtp_config(CommonName)}],
    case ergw_aaa_session:authenticate(Session, to_session(Opts)) of
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
    Dir = case capwap_config:get(ac, certs) of
	      {ok, Path} ->
		  Path;
	      _ ->
		  filename:join([code:lib_dir(capwap), "priv", "certs"])
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
    iolist_to_binary(inet_parse:ntoa(IP)).

tunnel_medium({_,_,_,_}) ->
    'IPv4';
tunnel_medium({_,_,_,_,_,_,_,_}) ->
    'IPv6'.

accounting_update(WTP, SessionOpts) ->
    case get_data_channel_address(WTP) of
	{ok, WTPDataChannelAddress} ->
	    WTPStats = capwap_dp:get_wtp(WTPDataChannelAddress),
	    lager:debug("WTP: ~p, ~p, ~p", [WTP, WTPDataChannelAddress, WTPStats]),
	    lager:debug("WTP SessionOpts: ~p", [SessionOpts]),
	    {_, _STAs, _RefCnt, _MTU, Stats} = WTPStats,
	    Acc = wtp_stats_to_accouting(Stats),

	    CommonName = maps:get('Username', SessionOpts, <<"unknown">>),
	    lists:foreach(fun ({Key, Value}) ->
				  exometer:update([capwap, wtp, CommonName, Key], Value)
			  end, Acc),

	    ergw_aaa_session:merge(SessionOpts, to_session(Acc));
	_ ->
	    SessionOpts
    end.

start_session(Socket, _State) ->
    {ok, {Address, _Port}} = capwap_udp:peername(Socket),
    SessionOpts = [{'Accouting-Update-Fun', fun accounting_update/2},
		    {'Service-Type', 'TP-CAPWAP-WTP'},
		    {'Framed-Protocol', 'TP-CAPWAP'},
		    {'Calling-Station', ip2str(Address)},
		    {'Tunnel-Type', 'CAPWAP'},
		    {'Tunnel-Medium-Type', tunnel_medium(Address)},
		    {'Tunnel-Client-Endpoint', ip2str(Address)}],
    ergw_aaa_session_sup:new_session(self(), to_session(SessionOpts)).

ie(Key, Elements) ->
    proplists:get_value(Key, Elements).

get_ie(Key, Elements) ->
    get_ie(Key, Elements, undefined).

get_ie(Key, Elements, Default) ->
    case lists:keyfind(Key, 1, Elements) of
	false -> Default;
	Value -> Value
    end.

get_ies(Key, Elements) ->
    [E || E <- Elements, element(1, E) == Key].

select_mac_mode(#wtp_wlan_config{mac_mode = local}, local) ->
    local_mac;
select_mac_mode(#wtp_wlan_config{mac_mode = split}, split) ->
    split_mac;
select_mac_mode(#wtp_wlan_config{mac_mode = Mode}, both) ->
    Mode.

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

%% AttrNamesAndDefaults = [{LocalName, RemoteName, Default}, ...]
wtp_config_get(CommonName, AttrNamesAndDefaults) when is_list(AttrNamesAndDefaults) ->
    App = capwap,
    Wtps = application:get_env(App, wtps, []),
    LocalCnf = proplists:get_value(CommonName, Wtps, []),
    lager:debug("found config for wtp ~p: ~p", [CommonName, LocalCnf]),

    [wtp_config_get(LocalCnf, AttrSelector)
     || AttrSelector <- AttrNamesAndDefaults];

wtp_config_get(LocalCnf, {DefaultName, LocalName, Default}) ->
    DefaultValue = wtp_config_get(LocalCnf, {DefaultName, Default}),
    proplists:get_value(LocalName, LocalCnf, DefaultValue);

wtp_config_get(_, {DefaultName, Default}) ->
    application:get_env(capwap, DefaultName, Default).

ieee_802_11_ie(Id, Data) ->
    <<Id:8, (byte_size(Data)):8, Data/bytes>>.

capwap_802_11_ie(#wtp_radio{radio_id = RadioId},
		 #wlan{wlan_identifier = {_, WlanId}},
		 {IE, Flags}, IEs) ->
    [#ieee_802_11_information_element{
	radio_id = RadioId,
	wlan_id = WlanId,
	flags = Flags,
	ie = IE}
     | IEs].

init_wlan_information_elements(Radio, WlanState) ->
    ProbeResponseFlags = ['beacon','probe_response'],
    IEList = [
	      {fun wlan_rateset_ie/2, ProbeResponseFlags},
	      {fun wlan_wmm_ie/2, ProbeResponseFlags},
	      {fun wlan_ht_opmode_ie/2, ProbeResponseFlags},
	      {fun wlan_rsn_ie/2, ProbeResponseFlags},
	      {fun wlan_ht_cap_ie/2, ProbeResponseFlags}],
    lists:foldl(fun({Fun, Flags}, WS = #wlan{information_elements = IEs}) ->
			case Fun(Radio, WS) of
			    IE when is_binary(IE) ->
				WS#wlan{information_elements = [{IE, Flags} | IEs]};
			    _ ->
				WS
			end
		end, WlanState, IEList).

wlan_rateset_ie(_Radio, #wlan{mode = Mode, rate_set = RateSet}) ->
    case lists:split(8, RateSet) of
	{_, []} ->
	    undefined;
	{_, ExtRates} ->
	    ieee_802_11_ie(?WLAN_EID_EXT_SUPP_RATES,
			   << <<(capwap_packet:encode_rate(Mode, X)):8>> || X <- ExtRates>>)
    end.

wlan_wmm_ie(_Radio, _WlanState) ->
    ieee_802_11_ie(?WLAN_EID_VENDOR_SPECIFIC,
		   <<16#00, 16#50, 16#f2, 16#02, 16#01, 16#01, 16#00, 16#00,
		     16#03, 16#a4, 16#00, 16#00, 16#27, 16#a4, 16#00, 16#00,
		     16#42, 16#43, 16#5e, 16#00, 16#62, 16#32, 16#2f, 16#00>>).

wlan_ht_cap_ie(_Radio, _WlanState) ->
    ieee_802_11_ie(?WLAN_EID_HT_CAP,
		   <<16#0c, 16#00, 16#1b, 16#ff, 16#ff, 16#00, 16#00, 16#00,
		     16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#01,
		     16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00,
		     16#00, 16#00>>).

wlan_ht_opmode_ie(#wtp_radio{channel = Channel}, _WlanState) ->
    ieee_802_11_ie(?WLAN_EID_HT_OPERATION,
		   <<Channel:8, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00,
		     16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00,
		     16#00, 16#00, 16#00, 16#00, 16#00, 16#00>>).

rsn_ie(#wtp_wlan_rsn{version = RSNVersion,
		     capabilities = RSNCaps,
		     group_cipher_suite = GroupCipherSuite,
		     group_mgmt_cipher_suite = GroupMgmtCipherSuite,
		     cipher_suites = CipherSuites,
		     akm_suites = AKMs}, PMF) ->
    CipherSuitesBin = << <<X/binary>> || X <- CipherSuites >>,
    AKMsBin = << <<(capwap_packet:encode_akm_suite(X)):32>> || X <- AKMs >>,

    IE0 = <<RSNVersion:16/little, GroupCipherSuite/binary,
	    (length(CipherSuites)):16/little, CipherSuitesBin/binary,
	    (length(AKMs)):16/little, AKMsBin/binary,
	    RSNCaps:16/little>>,
    IE = if PMF == true andalso is_atom(GroupMgmtCipherSuite) ->
		 <<IE0/binary, 0, 0, (capwap_packet:encode_cipher_suite(GroupMgmtCipherSuite)):32>>;
	    true ->
		 IE0
	 end,
    ieee_802_11_ie(?WLAN_EID_RSN, IE).

wlan_rsn_ie(_Radio, #wlan{wpa_config =
			      #wpa_config{
				 privacy = true,
				 rsn = #wtp_wlan_rsn{
					  management_frame_protection = MFP} = RSN}}) ->
    rsn_ie(RSN, MFP == required);
wlan_rsn_ie(_, _) ->
    undefined.

wlan_cfg_tp_hold_time(#wtp_radio{radio_id = RadioId},
		      #wlan{wlan_identifier = {_, WlanId}},
		      #wtp{wlan_hold_time = WlanHoldTime}, IEs) ->
    [#tp_ieee_802_11_wlan_hold_time{radio_id  = RadioId,
				   wlan_id   = WlanId,
				   hold_time = WlanHoldTime}
     | IEs ].

internal_add_wlan(RadioId, WlanId, NotifyFun,
		  #state{config = #wtp{radios = Radios}} = State)
  when is_integer(RadioId), is_integer(WlanId) ->
    Radio = lists:keyfind(RadioId, #wtp_radio.radio_id, Radios),
    WLAN = lists:keyfind(WlanId, #wtp_wlan_config.wlan_id, Radio#wtp_radio.wlans),
    internal_add_wlan(Radio, WLAN, NotifyFun, State);

internal_add_wlan(#wtp_radio{radio_id = RadioId} = Radio,
		  #wtp_wlan_config{wlan_id = WlanId,
				   ssid = SSID,
				   suppress_ssid = SuppressSSID} = WlanConfig,
		  NotifyFun,
		  #state{config = Config} = State0) ->
    WBID = ?CAPWAP_BINDING_802_11,
    Flags = [{frame,'802.3'}],
    Header = #capwap_header{radio_id = RadioId, wb_id = WBID, flags = Flags},

    WlanState = init_wlan_state(Radio, WlanId, WlanConfig, State0),
    State = update_wlan_state({RadioId, WlanId}, fun(_W) -> WlanState end, State0),

    AddWlan = #ieee_802_11_add_wlan{
		 radio_id      = RadioId,
		 wlan_id       = WlanId,
		 capability    = [ess, short_slot_time],
		 auth_type     = open_system,
		 mac_mode      = WlanState#wlan.mac_mode,
		 tunnel_mode   = WlanState#wlan.tunnel_mode,
		 suppress_ssid = SuppressSSID,
		 ssid          = SSID
		},
    ReqElements0 = [set_wlan_keys(WlanState, AddWlan)],
    ReqElements1 = lists:foldl(capwap_802_11_ie(Radio, WlanState, _, _), ReqElements0,
			       WlanState#wlan.information_elements),
    ReqElements2 = wlan_cfg_tp_hold_time(Radio, WlanState, Config, ReqElements1),
    ReqElements = add_wlan_keys(WlanState, ReqElements2),
    ResponseNotifyFun = internal_add_wlan_result({RadioId, WlanId}, NotifyFun, _, _, _),
    send_request(Header, ieee_802_11_wlan_configuration_request, ReqElements, ResponseNotifyFun, State);

internal_add_wlan(RadioId, WlanId, NotifyFun, State)
  when RadioId == false orelse WlanId == false ->
    %% the requested Radio/WLan combination might not be configured,
    %% do nothing....
    response_notify(NotifyFun, -1, unconfigured, State).

internal_add_wlan_result(WlanIdent, NotifyFun, Code, Arg, State0)
  when Code == 0 ->
    State = update_wlan_state(WlanIdent,
			      fun(W0) ->
				      W = W0#wlan{state = running},
				      start_group_rekey_timer(W)
			      end, State0),
    response_notify(NotifyFun, Code, Arg, State);

internal_add_wlan_result(WlanIdent, NotifyFun, Code, Arg, State0) ->
    State = update_wlan_state(WlanIdent,
			      fun(W) -> W#wlan{state = unconfigured} end, State0),
    response_notify(NotifyFun, Code, Arg, State).

internal_del_wlan(WlanIdent = {RadioId, WlanId}, NotifyFun, State) ->
    WBID = ?CAPWAP_BINDING_802_11,
    Flags = [{frame,'802.3'}],
    Header = #capwap_header{radio_id = RadioId, wb_id = WBID, flags = Flags},
    ReqElemDel = [#ieee_802_11_delete_wlan{
                     radio_id = RadioId,
                     wlan_id = WlanId}
                 ],
    State0 = send_request(Header, ieee_802_11_wlan_configuration_request, ReqElemDel, NotifyFun, State),
    remove_wlan(WlanIdent, State0).

remove_wlan(WlanIdent, State = #state{wlans = Wlans}) ->
    case get_wlan(WlanIdent, State) of
	Wlan = #wlan{} ->
	    stop_group_rekey_timer(Wlan);
	_ ->
	    ok
    end,
    LessWlans = lists:keydelete(WlanIdent, #wlan.wlan_identifier, Wlans),
    State#state{wlans = LessWlans}.

radio_rsn_cipher_capabilities(#wtp_radio{supported_cipher_suites = Suites},
			      #wtp_wlan_config{
				 rsn = #wtp_wlan_rsn{
					  group_mgmt_cipher_suite = MgmtSuite,
					  capabilities = Caps0} = RSN0,
				 management_frame_protection = MFP})
  when MFP /= false ->
    lager:debug("Suites: ~p", [Suites]),
    Caps1 = Caps0 band bnot 16#00C0,
    case lists:member(MgmtSuite, Suites) of
	true ->
	    Caps = case MFP of
		       optional -> Caps1 bor 16#0080;
		       required -> Caps1 bor 16#00C0;
		       _        -> Caps1
		   end,
	    RSN0#wtp_wlan_rsn{management_frame_protection = MFP,
			      capabilities = Caps};

	false ->
	    RSN0#wtp_wlan_rsn{management_frame_protection = false}
    end;
radio_rsn_cipher_capabilities(_Radio, #wtp_wlan_config{
					 rsn = RSN,
					 management_frame_protection = false}) ->
    RSN#wtp_wlan_rsn{management_frame_protection = false}.

init_wlan_state(#wtp_radio{radio_id = RadioId} = Radio, WlanId,
		#wtp_wlan_config{
		   ssid = SSID,
		   suppress_ssid = SuppressSSID,
		   mac_mode = MacMode,
		   privacy = Privacy,
		   secret = Secret,
		   peer_rekey = PeerRekey,
		   group_rekey = GroupRekey,
		   strict_group_rekey = StrictGroupRekey} = WlanConfig,
		#state{mac_types = MacTypes, tunnel_modes = TunnelModes}) ->

    MacMode = select_mac_mode(WlanConfig, MacTypes),
    TunnelMode = select_tunnel_mode(TunnelModes, MacMode),

    Mode = '11g-only',
    W0 = #wlan{wlan_identifier = {RadioId, WlanId},
	       mode = Mode,
	       rate_set = rateset(Mode),
	       ssid = SSID,
	       suppress_ssid = SuppressSSID,
	       mac_mode = MacMode,
	       tunnel_mode = TunnelMode,
	       privacy = Privacy,
	       information_elements = [],
	       wpa_config = #wpa_config{
			       ssid = SSID,
			       privacy = Privacy,
			       rsn = radio_rsn_cipher_capabilities(Radio, WlanConfig),
			       secret = Secret,
			       peer_rekey = PeerRekey,
			       group_rekey = GroupRekey,
			       strict_group_rekey = StrictGroupRekey
			      },
	       state = initializing,
	       group_rekey_state = idle
	      },
    W1 = init_wlan_privacy(W0),
    init_wlan_information_elements(Radio, W1).

init_key(Cipher) ->
    #ieee80211_key{cipher = Cipher,
		   index = 0,
		   key = crypto:strong_rand_bytes(eapol:key_len(Cipher))}.

update_key(#ieee80211_key{cipher = Cipher, index = Index}) ->
    #ieee80211_key{index = Index bxor 1,
		   key = crypto:strong_rand_bytes(eapol:key_len(Cipher))};
update_key(undefined) ->
    undefined.

init_wlan_gtk(Wlan) ->
    Wlan#wlan{group_tsc = 0, gtk = init_key('CCMP')}.

init_wlan_igtk(Wlan = #wlan{wpa_config = #wpa_config{
					    rsn = #wtp_wlan_rsn{
						     management_frame_protection = MFP,
						     group_mgmt_cipher_suite = Cipher}}})
  when MFP /= false, Cipher /= undefined ->
    Wlan#wlan{igtk = init_key(Cipher)};
init_wlan_igtk(Wlan) ->
    Wlan.

init_wlan_privacy(Wlan0 = #wlan{privacy = true}) ->
    Wlan1 = init_wlan_gtk(Wlan0),
    init_wlan_igtk(Wlan1);
init_wlan_privacy(Wlan) ->
    Wlan.

update_wlan_group_keys(Wlan = #wlan{privacy = true, gtk = GTK, igtk = IGTK}) ->
    Wlan#wlan{gtk = update_key(GTK), igtk = update_key(IGTK)};
update_wlan_group_keys(Wlan) ->
    Wlan.

set_wlan_keys(#wlan{privacy = true, group_tsc = TSC,
		    gtk = #ieee80211_key{index = Index, key = Key}},
	      #ieee_802_11_add_wlan{capability = Capability} = IE) ->
    IE#ieee_802_11_add_wlan{capability = ['privacy' | Capability],
			    key_index = Index + 1, key = Key, group_tsc = <<TSC:64>>};
set_wlan_keys(#wlan{privacy = true,
		    gtk = #ieee80211_key{index = Index, key = Key}},
	      #ieee_802_11_update_wlan{capability = Capability} = IE) ->
    IE#ieee_802_11_update_wlan{capability = ['privacy' | Capability],
			       key_index = Index + 1, key = Key};
set_wlan_keys(_Wlan, IE) ->
    IE.

add_wlan_keys(#wlan{wlan_identifier = {RadioId, WlanId}, privacy = true,
		     gtk = #ieee80211_key{index = Index, key = Key}}, IEs) ->
    [#tp_ieee_802_11_update_key{radio_id = RadioId, wlan_id = WlanId,
				key_index = Index + 4,
				key_status = completed_rekeying,
				cipher_suite = capwap_packet:encode_cipher_suite('AES-CMAC'),
				key = Key} | IEs];
add_wlan_keys(_, IEs) ->
    IEs.

get_wlan(WlanIdent, #state{wlans = Wlans}) ->
    lists:keyfind(WlanIdent, #wlan.wlan_identifier, Wlans).

get_wlan_by_bss(BSS, #state{config = #wtp{broken_add_wlan_workarround = true},
			    wlans = Wlans}) ->
    case lists:keyfind(BSS, #wlan.bss, Wlans) of
	false when length(Wlans) == 1 ->
	    hd(Wlans);
	Other ->
	    Other
    end;
get_wlan_by_bss(BSS, #state{wlans = Wlans}) ->
    lists:keyfind(BSS, #wlan.bss, Wlans).

update_wlan_state(WlanIdent, Fun, State = #state{wlans = Wlans})
  when is_function(Fun, 1) ->
    Wlan =
	case get_wlan(WlanIdent, State) of
	    false ->
		#wlan{wlan_identifier = WlanIdent};
	    Tuple ->
		Tuple
	end,
    State#state{wlans =
		    lists:keystore(WlanIdent, #wlan.wlan_identifier, Wlans, Fun(Wlan))}.

internal_new_station(#wlan{}, StationMAC,
		     State = #state{config = #wtp{max_stations = MaxStations},
				    station_count  = StationCount})
  when StationCount + 1 > MaxStations ->
    lager:debug("Station ~p trying to associate, but wtp is full: ~p >= ~p",
		[StationMAC, StationCount, MaxStations]),
    {{error, too_many_clients}, State};

internal_new_station(#wlan{bss = BSS, mac_mode = MacMode, tunnel_mode = TunnelMode,
			   information_elements = IEs,
			   wpa_config = WpaConfig, gtk = GTK, igtk = IGTK},
		     StationMAC,
		     State = #state{id = WtpId, session_id = SessionId,
				    data_channel_address = WTPDataChannelAddress, data_path = DataPath,
				    station_count  = StationCount}) ->

    %% we have to repeat the search again to avoid a race
    lager:debug("search for station ~p", [{self(), StationMAC}]),
    case capwap_station_reg:lookup(self(), BSS, StationMAC) of
	not_found ->
	    exometer:update([capwap, ac, station_count], 1),
	    exometer:update([capwap, wtp, WtpId, station_count], StationCount + 1),
	    StationCfg = #station_config{
			    data_path = DataPath, wtp_data_channel_address = WTPDataChannelAddress,
			    wtp_id = WtpId, wtp_session_id = SessionId,
			    mac_mode = MacMode, tunnel_mode = TunnelMode,
			    bss = BSS, bss_ies = IEs, wpa_config = WpaConfig,
			    gtk = GTK, igtk = IGTK
			   },
	    Reply =
		case capwap_station_reg:lookup(StationMAC) of
		    not_found ->
			lager:debug("starting station: ~p", [StationMAC]),
			capwap_station_sup:new_station(self(), StationMAC, StationCfg);
		    {ok, Station0} ->
			lager:debug("TAKE-OVER: station ~p found as ~p", [{self(), StationMAC}, Station0]),
			ieee80211_station:take_over(Station0, self(), StationCfg)
		end,
	    {Reply, State#state{station_count = StationCount + 1}};

	Ok = {ok, Station0} ->
	    lager:debug("station ~p found as ~p", [{self(), StationMAC}, Station0]),
	    {Ok, State}
    end;
internal_new_station(_, StationMAC, State) ->
    lager:debug("Station ~p trying to associate on invalid Wlan", [StationMAC]),
    {{error, invalid_bss}, State}.

internal_add_station(#wlan{wlan_identifier = {RadioId, WlanId}, bss = BSS}, MAC, StaCaps,
		     {_, Encryption, _} = CryptoState,
		     NotifyFun, State = #state{data_channel_address = WTPDataChannelAddress}) ->
    Ret = capwap_dp:attach_station(WTPDataChannelAddress, MAC, RadioId, BSS),
    lager:debug("attach_station(~p, ~p, ~p, ~p): ~p", [WTPDataChannelAddress, MAC, RadioId, BSS, Ret]),

    WBID = ?CAPWAP_BINDING_802_11,
    Flags = [{frame,'802.3'}],

    ReqElements0 = [#add_station{
		      radio_id	= RadioId,
		      mac	= MAC,
		      vlan_name = <<>>},
		   #ieee_802_11_station{
		      radio_id	= RadioId,
		      association_id = StaCaps#sta_cap.aid,
		      mac_address = MAC,
		      capabilities = [ess, short_slot_time] ++ [ 'privacy' || Encryption ],
		      wlan_id = WlanId,
		      supported_rate = [6,9,12,18,22,36,48,54]},
		   #ieee_802_11n_station_information{
		      %% FIXME: test RADIO and Station for 802.11n support
		      mac_address = MAC,
		      bandwith_40mhz = 0,
		      power_save_mode = StaCaps#sta_cap.smps,
		      sgi_20mhz = bool2i(StaCaps#sta_cap.sgi_20mhz),
		      sgi_40mhz = bool2i(StaCaps#sta_cap.sgi_40mhz),
		      ba_delay_mode = bool2i(StaCaps#sta_cap.back_delay),
		      max_a_msdu = 0,
		      max_rxfactor = StaCaps#sta_cap.ampdu_factor,
		      min_staspacing = StaCaps#sta_cap.ampdu_density,
		      hisuppdatarate = StaCaps#sta_cap.rx_highest,
		      ampdubufsize = 0,
		      htcsupp = 0,
		      mcs_set = StaCaps#sta_cap.rx_mask}],
    ReqElements = station_session_key(RadioId, WlanId, MAC, CryptoState, ReqElements0),
    Header = #capwap_header{radio_id = RadioId, wb_id = WBID, flags = Flags},
    send_request(Header, station_configuration_request, ReqElements, NotifyFun, State);

internal_add_station(_, _MAC, _StaCaps, _CryptoState, NotifyFun, State) ->
    response_notify(NotifyFun, -1, [], State).

station_session_key(_RadioId, _WlanId, MAC, {AKMonly, false, _CipherState}, IEs) ->
    IE = #ieee_802_11_station_session_key{
	    mac_address = MAC,
	    flags = ['akm_only' || AKMonly],
	    pairwise_tsc = <<0:48>>,
	    pairwise_rsc = <<0:48>>,
	    key = <<0:128>>},
    [IE | IEs];
station_session_key(RadioId, WlanId, MAC, {AKMonly, true, #ccmp{rsn = RSN,
								group_mgmt_cipher_suite = MgmtCS,
								tk = TK}}, IEs) ->
    [#ieee_802_11_station_session_key{
	mac_address = MAC,
	flags = ['akm_only' || AKMonly],
	pairwise_tsc = <<0:48>>,
	pairwise_rsc = <<0:48>>,
	key = TK},
     #ieee_802_11_information_element{
	radio_id = RadioId,
	wlan_id = WlanId,
	flags = [],
	ie = rsn_ie(RSN, MgmtCS /= undefined)}
     | IEs];
station_session_key(_, _, _, _, IEs) ->
    IEs.

internal_del_station(#wlan{wlan_identifier = {RadioId, _WlanId}}, MAC, State) ->
    Ret = capwap_dp:detach_station(MAC),
    lager:debug("detach_station(~p): ~p", [MAC, Ret]),

    WBID = ?CAPWAP_BINDING_802_11,
    Flags = [{frame,'802.3'}],
    ReqElements = [#delete_station{
		      radio_id	= RadioId,
		      mac	= MAC
		     }],
    Header = #capwap_header{radio_id = RadioId, wb_id = WBID, flags = Flags},
    send_request(Header, station_configuration_request, ReqElements, State);

internal_del_station(_, MAC, State) ->
    Ret = capwap_dp:detach_station(MAC),
    lager:debug("detach_station(~p, ~p): ~p", [MAC, Ret]),
    State.

sendto(Header, Data, #state{data_channel_address = WTPDataChannelAddress}) ->
    Packet = hd(capwap_packet:encode(data, {Header, Data})),
    capwap_trace:trace(?TRACE_LOCAL_DATA, WTPDataChannelAddress, Packet),
    capwap_dp:sendto(WTPDataChannelAddress, Packet).

internal_send_80211_station(#wlan{wlan_identifier = {RadioId, _WlanId}}, Data, State) ->
    WBID = ?CAPWAP_BINDING_802_11,
    Header = #capwap_header{
		 radio_id = RadioId,
		 wb_id = WBID,
		 flags = [{frame, 'native'}]},
    sendto(Header, Data, State);

internal_send_80211_station(_, _, _) ->
    ok.

get_admin_wifi_updates(State, IEs) ->
    StartedWlans = [X || X <- IEs, element(1, X) == ieee_802_11_tp_wlan],
    lager:debug("Found Admin Wlans started by the WTP: ~p", [StartedWlans]),
    AdminSSIds = wtp_config_get(State#state.id, [{admin_ssids, admin_ssids, []}]),
    get_admin_wifi_update(StartedWlans, AdminSSIds).

get_admin_wifi_update(Wlans, AdminSSIds) ->
    get_admin_wifi_update(Wlans, AdminSSIds, []).

get_admin_wifi_update([], _, Accu) ->
    Accu;

get_admin_wifi_update([#ieee_802_11_tp_wlan{radio_id = RadioId,
                                            wlan_id = WlanId,
                                            ssid = RemoteConfSSId,
                                            key = RemoteConfKey} = Wlan | RestWlan],
                      AdminSSIds, Accu) ->
    {LocalConfSSId, LocalConfKey} =
        case proplists:get_value({RadioId, WlanId}, AdminSSIds) of
            {A, B} = V when is_binary(A), is_binary(B) ->
                V;
            A when is_binary(A) ->
                {A, RemoteConfKey};
            _ ->
                {RemoteConfSSId, RemoteConfKey}
        end,
    if RemoteConfSSId == LocalConfSSId andalso RemoteConfKey == LocalConfKey ->
            get_admin_wifi_update(RestWlan, AdminSSIds, Accu);
       true ->
            lager:debug("Sending ieee_802_11_tp_wlan to change a preconfigured Admin SSID: ~p->~p",
                        [RemoteConfSSId, LocalConfSSId]),
            UpdatedWlan = Wlan#ieee_802_11_tp_wlan{ssid = LocalConfSSId, key = LocalConfKey},
            get_admin_wifi_update(RestWlan, AdminSSIds, [UpdatedWlan | Accu])
    end.

start_change_state_pending_timer(#state{change_state_pending_timeout = Timeout}
				 = State) ->
    TRef = gen_fsm:send_event_after(Timeout, timeout),
    State#state{protocol_timer = TRef}.

cancel_change_state_pending_timer(#state{protocol_timer = TRef} = State) ->
    gen_fsm:cancel_timer(TRef),
    State#state{protocol_timer = undefined}.

start_group_rekey_timer(#wlan{wlan_identifier = WlanIdent,
			      wpa_config = #wpa_config{group_rekey = Timeout}} = Wlan)
  when is_integer(Timeout) andalso Timeout > 0 ->
    TRef = gen_fsm:send_event_after(Timeout * 1000, {group_rekey, WlanIdent}),
    Wlan#wlan{group_rekey_timer = TRef};
start_group_rekey_timer(Wlan) ->
    Wlan.

stop_group_rekey_timer(#wlan{group_rekey_timer = TRef} = Wlan)
  when is_reference(TRef) ->
    gen_fsm:cancel_timer(TRef),
    Wlan#wlan{group_rekey_timer = undefined};
stop_group_rekey_timer(Wlan) ->
    Wlan.

start_gtk_rekey(WlanIdent = {RadioId, WlanId},
		Wlan0 = #wlan{bss = BSS, group_rekey_state = idle},
		State0) ->
    Wlan1 = stop_group_rekey_timer(Wlan0),
    Wlan2 = update_wlan_group_keys(Wlan1),

    Stations = capwap_station_reg:list_stations(self(), BSS),
    lager:debug("GTK ReKey Stations: ~p", [Stations]),

    WBID = ?CAPWAP_BINDING_802_11,
    Flags = [{frame,'802.3'}],
    Header = #capwap_header{radio_id = RadioId, wb_id = WBID, flags = Flags},

    UpdateWlan0 = #ieee_802_11_update_wlan{
		    radio_id   = RadioId,
		    wlan_id    = WlanId,
		    capability = [ess, short_slot_time]
		},

    if length(Stations) == 0 ->
	    Wlan = Wlan2#wlan{group_rekey_state = finalizing},

	    UpdateWlan = UpdateWlan0#ieee_802_11_update_wlan{key_status = completed_rekeying},
	    ReqElements = [set_wlan_keys(Wlan, UpdateWlan)],
	    NotifyFun = finish_gtk_rekey_result(WlanIdent, _, _, _);

       true ->
	    Wlan = Wlan2#wlan{group_rekey_state = init},

	    UpdateWlan = UpdateWlan0#ieee_802_11_update_wlan{key_status = begin_rekeying},
	    ReqElements0 = [set_wlan_keys(Wlan, UpdateWlan)],
	    ReqElements = add_wlan_keys(Wlan, ReqElements0),
	    NotifyFun = start_gtk_rekey_result(WlanIdent, Stations, _, _, _)
    end,

    State1 = update_wlan_state(WlanIdent, fun(_W) -> Wlan end, State0),
    send_request(Header, ieee_802_11_wlan_configuration_request, ReqElements, NotifyFun, State1);

start_gtk_rekey({RadioId, WlanId}, Wlan, State) ->
    lager:warning("failed to start GTK rekey for ~w:~w (~p)", [RadioId, WlanId, lager:pr(Wlan, ?MODULE)]),
    State.

%% Note: failures will be handled the FSM event function
start_gtk_rekey_result(WlanIdent, Stations, Code, _Arg, State)
  when Code == 0 ->
    update_wlan_state(WlanIdent,
		      fun(W = #wlan{gtk = GTK, igtk = IGTK}) ->
			      {ok, _Pid} = capwap_ac_gtk_rekey:start_link({self(), WlanIdent},
									  GTK, IGTK, Stations),
			      W#wlan{group_rekey_state = running}
		      end, State);

start_gtk_rekey_result(WlanIdent, _Stations, _Code, _Arg, State) ->
    update_wlan_state(WlanIdent, fun(W) -> W#wlan{group_rekey_state = failed} end, State).




finish_gtk_rekey(WlanIdent = {RadioId, WlanId},
		 Wlan0 = #wlan{group_rekey_state = running},
		 State0) ->
    WBID = ?CAPWAP_BINDING_802_11,
    Flags = [{frame,'802.3'}],
    Header = #capwap_header{radio_id = RadioId, wb_id = WBID, flags = Flags},

    UpdateWlan0 = #ieee_802_11_update_wlan{
		    radio_id   = RadioId,
		    wlan_id    = WlanId,
		    capability = [ess, short_slot_time]
		},

    Wlan = Wlan0#wlan{group_rekey_state = finalizing},

    UpdateWlan = UpdateWlan0#ieee_802_11_update_wlan{key_status = completed_rekeying},
    NotifyFun = finish_gtk_rekey_result(WlanIdent, _, _, _),

    State1 = update_wlan_state(WlanIdent, fun(_W) -> Wlan end, State0),
    ReqElements = [set_wlan_keys(Wlan, UpdateWlan)],
    send_request(Header, ieee_802_11_wlan_configuration_request, ReqElements, NotifyFun, State1);

finish_gtk_rekey({RadioId, WlanId}, Wlan, State) ->
    lager:warning("failed to start GTK rekey for ~w:~w (~p)", [RadioId, WlanId, lager:pr(Wlan, ?MODULE)]),
    State.

%% Note: failures will be handled the FSM event function
finish_gtk_rekey_result(WlanIdent, Code, _Arg, State) ->
    ReKeyState = if Code == 0 -> idle;
		    true      -> failed
		 end,
    update_wlan_state(WlanIdent, fun(W0) ->
					 W = W0#wlan{group_rekey_state = ReKeyState},
					 start_group_rekey_timer(W)
				 end, State).

wtp_stats_to_accouting({RcvdPkts, SendPkts, RcvdBytes, SendBytes,
			RcvdFragments, SendFragments,
			ErrInvalidStation, ErrFragmentInvalid, ErrFragmentTooOld}) ->
    [{'InPackets',  RcvdPkts},
     {'OutPackets', SendPkts},
     {'InOctets',   RcvdBytes},
     {'OutOctets',  SendBytes},
     {'Received-Fragments',     RcvdFragments},
     {'Send-Fragments',         SendFragments},
     {'Error-Invalid-Stations', ErrInvalidStation},
     {'Error-Fragment-Invalid', ErrFragmentInvalid},
     {'Error-Fragment-Too-Old', ErrFragmentTooOld}];
wtp_stats_to_accouting(_) ->
    [].

stop_wtp(run, #state{data_channel_address = WTPDataChannelAddress}) ->
    lager:error("STOP_WTP in run"),
    case catch (capwap_dp:del_wtp(WTPDataChannelAddress)) of
	{ok, {WTPDataChannelAddress, _Stations, _RefCnt, _MTU, Stats} = Values} ->
	    lager:debug("Delete WTP: ~p, ~p", [WTPDataChannelAddress, Values]),
	    wtp_stats_to_accouting(Stats);
	Other ->
	    lager:debug("WTP del failed with: ~p", [Other]),
	    []
    end;
stop_wtp(StateName, State) ->
    lager:error("STOP_WTP in ~p with ~p", [StateName, State]),
    [].

response_notify(NotifyFun, Code, Arg, State)
  when is_function(NotifyFun, 3) ->
    try
	NotifyFun(Code, Arg, State)
    catch
	Class:Cause ->
	    lager:debug("notify failed with ~p:~p", [Class, Cause]),
	    State
    end;
response_notify(_, _, _, State) ->
    State.

response_fsm_reply(From) ->
    response_fsm_reply(From, _, _, _).

response_fsm_reply(From, 0, _, State) ->
    gen_fsm:reply(From, ok),
    State;
response_fsm_reply(From, Code, _, State) ->
    gen_fsm:reply(From, {error, Code}),
    State.
