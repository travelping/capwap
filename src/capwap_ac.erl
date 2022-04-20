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

-behaviour(gen_statem).

%% API
-export([start_link/1, accept/3, get_data_channel_address/1, take_over/1, new_station/3,
	 station_detaching/1, gtk_rekey_done/1]).

%% Extern API
-export([get_state/1, get_info/1,
	 firmware_download/3,
	 set_ssid/4,
	 stop_radio/2]).

%% API for Station process
-export([add_station/5, del_station/3, send_80211/3, ieee_802_11_ie/2,
	 rsn_ie/2, rsn_ie/3, get_station_config/2]).

%% gen_statem callbacks
-export([callback_mode/0, init/1, handle_event/4,
	 terminate/3, code_change/4]).

-export([handle_packet/2, handle_data/3]).

-include_lib("kernel/include/logger.hrl").
-include_lib("kernel/include/inet.hrl").
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
-define(SSL_ACCEPT_TIMEOUT, 30 * 1000).
-define(WaitJoinTimeout, 60 * 1000).
-define(ChangeStatePendingTimeout, 25 * 1000).
-define(DataCheckTimeout, 30 * 1000).
-define(RetransmitInterval, 3 * 1000).
-define(MaxRetransmit, 5).

%% -define(MgmtSuites, ['AES-CMAC', 'BIP-GMAC-128', 'BIP-GMAC-256', 'BIP-CMAC-256']).

-record(data, {
	  id,
	  session_id,
	  ctrl_channel_address,
	  data_channel_address,
	  data_path,
	  socket,
	  ctrl_stream,
	  session,
	  config_provider_state,
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

	  %% protocol timeouts
	  wait_join_timeout,
	  change_state_pending_timeout,
	  data_check_timeout,

	  seqno = 0,
	  version,
	  station_count = 0,
	  wlans,
	  last_gps_pos,

	  timers = #{}
}).

-define(IS_RUN_CONTROL_EVENT(E),
	(is_tuple(E) andalso
			   (element(1, E) == add_station orelse
			    element(1, E) == del_station orelse
			    element(1, E) == detach_station orelse
			    element(1, E) == delete_station orelse
			    element(1, E) == firmware_download))).

-define(DEBUG_OPTS,[]).

-define(log_capwap_control(Id, MsgType, SeqNo, Elements, Header),
	try
	    #capwap_header{radio_id = RadioId, wb_id = WBID} = Header,
	    ?LOG(info, "~s: ~s(Seq: ~w, R-Id: ~w, WB-Id: ~w): ~s",
		 [Id, capwap_packet:msg_description(MsgType), SeqNo, RadioId, WBID,
		  log_fmt_capwap_ies(Elements)])
	catch
	    _:_ -> ok
	end).

-define(log_capwap_keep_alive(Id, PayLoad, Header),
	try
	    #capwap_header{radio_id = RadioId, wb_id = WBID} = Header,
	    ?LOG(info, "~s: Keep-Alive(R-Id: ~w, WB-Id: ~w): ~s",
		 [Id, RadioId, WBID, log_fmt_capwap_ies(PayLoad)])
	catch
	    _:_ -> ok
	end).

log_fmt_capwap_ies(IEs) when is_map(IEs) ->
    lists:join(", ", [capwap_packet:pretty_print(E) || E <- maps:values(IEs)]);
log_fmt_capwap_ies(IEs) when is_list(IEs) ->
    lists:join(", ", [capwap_packet:pretty_print(E) || E <- IEs]);
log_fmt_capwap_ies(IEs) ->
    io_lib:format("~p", [IEs]).

%%%===================================================================
%%% API
%%%===================================================================

start_link(WTPControlChannelAddress) ->
    gen_statem:start_link(?MODULE, [WTPControlChannelAddress], [{debug, ?DEBUG_OPTS}]).

handle_packet(WTPControlChannelAddress, Packet) ->
    try
	capwap_trace:trace(WTPControlChannelAddress, ?TRACE_LOCAL_CONTROL, Packet),
	Peer = capwap_tools:format_peer(WTPControlChannelAddress),
	case capwap_packet:decode(control, Packet) of
	    {Header, {discovery_request, 1, Seq, Elements}} ->
		?log_capwap_control(Peer, discovery_request, Seq, Elements, Header),
		Answer = answer_discover(Peer, Seq, Elements, Header),
		{reply, Answer};
	    {Header, {join_request, 1, Seq, Elements}} ->
		?log_capwap_control(Peer, join_request, Seq, Elements, Header),
		handle_plain_join(Peer, Seq, Elements, Header);
	    Pkt ->
		?LOG(warning, "unexpected CAPWAP packet: ~p", [Pkt]),
		{error, not_capwap}
	end
    catch
	Class:Error:ST ->
	    ?LOG(debug, "failure: ~p:~p with ~0p", [Class, Error, ST]),
	    {error, not_capwap}
    end.

handle_data(DataPath, WTPDataChannelAddress, Packet) ->
    try
	capwap_trace:trace(WTPDataChannelAddress, ?TRACE_LOCAL_DATA, Packet),
	?LOG(debug, "capwap_data: ~p, ~p", [WTPDataChannelAddress, Packet]),
	case capwap_packet:decode(data, Packet) of
	    {Header, PayLoad} ->
		KeepAlive = proplists:get_bool('keep-alive', Header#capwap_header.flags),
		handle_capwap_data(DataPath, WTPDataChannelAddress, Header, KeepAlive, PayLoad);
	    _ ->
		?LOG(warning, "invalid CAPWAP data from ~s", [capwap_tools:format_peer(WTPDataChannelAddress)]),
		{error, not_capwap}
	end
    catch
	Class:Error:ST ->
	    ?LOG(debug, "failure: ~p:~p with ~0p", [Class, Error, ST]),
	    {error, not_capwap}
    end.

accept(WTP, Type, Socket) ->
    gen_statem:cast(WTP, {accept, Type, Socket}).

get_data_channel_address(WTP) ->
    gen_statem:call(WTP, get_data_channel_address).

take_over(WTP) ->
    gen_statem:call(WTP, {take_over, self()}).

new_station(WTP, BSS, SA) ->
    gen_statem:call(WTP, {new_station, BSS, SA}).

station_detaching(AC) ->
    gen_statem:cast(AC, station_detaching).

gtk_rekey_done({AC, WlanIdent}) ->
    gen_statem:cast(AC, {gtk_rekey_done, WlanIdent}).

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
    case with_cn(CN, gen_statem:call(_, get_state)) of
	{ok, Data} ->
	    Fields = record_info(fields, data),
	    [_Tag| Values] = tuple_to_list(Data),
	    PMap = maps:from_list(lists:zip(Fields, Values)),
	    {ok, PMap};
	Other ->
	    Other
    end.

get_info(Pid) when is_pid(Pid) ->
    gen_statem:call(Pid, get_info).

firmware_download(CN, DownloadLink, Sha) ->
    with_cn(CN, gen_statem:cast(_, {firmware_download, DownloadLink, Sha})).

set_ssid(CN, RadioId, SSID, SuppressSSID) ->
    WlanId = 1,
    WlanIdent = {RadioId, WlanId},
    with_cn(CN, gen_statem:call(_, {set_ssid, WlanIdent, SSID, SuppressSSID})).

stop_radio(CN, RadioId) ->
    with_cn(CN, gen_statem:call(_, {stop_radio, RadioId})).

%%%===================================================================
%%% Station APIs
%%%===================================================================

add_station(AC, BSS, MAC, StaCaps, CryptoData) ->
    gen_statem:call(AC, {add_station, BSS, MAC, StaCaps, CryptoData}).

del_station(AC, BSS, MAC) ->
    gen_statem:cast(AC, {del_station, BSS, MAC}).

send_80211(AC, BSS, Data) ->
    gen_statem:cast(AC, {send_80211, BSS, Data}).

get_station_config(AC, BSS) ->
    gen_statem:call(AC,  {get_station_config, BSS}).

%%%===================================================================
%%% gen_statem callbacks
%%%===================================================================
callback_mode() ->
    [handle_event_function, state_enter].

init([WTPControlChannelAddress]) ->
    process_flag(trap_exit, true),
    logger:set_process_metadata(#{control_channel_address => WTPControlChannelAddress}),
    exometer:update([capwap, ac, wtp_count], 1),
    capwap_wtp_reg:register(WTPControlChannelAddress),
    MTU = capwap_config:get(ac, mtu, 1500),
    {ok, listen, #data{ctrl_channel_address = WTPControlChannelAddress,
		       request_queue = queue:new(),
		       ctrl_stream = capwap_stream:init(MTU),
		       wait_join_timeout = ?WaitJoinTimeout,
		       change_state_pending_timeout = ?ChangeStatePendingTimeout,
		       data_check_timeout = ?DataCheckTimeout,
		       wlans = []}}.

%% Listen

handle_event(enter, _OldState, listen, _Data) ->
    Actions = [{state_timeout, 5000, listen_timeout}],
    {keep_state_and_data, Actions};

handle_event(state_timeout, _, listen, Data) ->
    ?LOG(info, "Timeout in LISTEN -> stop"),
    {stop, normal, Data};

handle_event(cast, {accept, udp, Socket}, listen, Data0) ->
    capwap_udp:setopts(Socket, [{active, true}, {mode, binary}]),
    ?LOG(info, "udp_accept: ~p", [Socket]),
    {ok, Session} = start_session(Socket, Data0),

    {ok, WTPControlChannelAddress} = capwap_udp:peername(Socket),
    PeerName = iolist_to_binary(capwap_tools:format_peer(WTPControlChannelAddress)),

    {ok, CfgProvStateInit} = capwap_config:wtp_init_config_provider(PeerName),
    Opts = [{'Username', PeerName},
	    {'Authentication-Method', {'TLS', 'Pre-Shared-Key'}},
	    {'Config-Provider-State', CfgProvStateInit}],
    case ergw_aaa_session:invoke(Session, to_session(Opts), authenticate, [inc_session_id]) of
	{ok, #{'Config-Provider-State' := CfgProvState} = SOpts, Evs} ->
	    ?LOG(info, #{'AuthResult' => success, session => SOpts, events => Evs}),
	    Config = capwap_config:wtp_config(CfgProvState),
	    Data1 = Data0#data{session = Session,
			       config_provider_state = CfgProvState,
			       config = Config,
			       socket = {udp, Socket},
			       id = undefined},
	    Data2 = handle_session_evs(Evs, Data1),

	    {next_state, join, Data2};

	Other ->
	    ?LOG(info, "AuthResult: ~p", [Other]),
	    {stop, normal, Data0#data{session=Session}}
    end;

handle_event(cast, {accept, dtls, Socket}, listen, Data) ->
    {ok, Session} = start_session(Socket, Data),
    ?LOG(info, "ssl_accept on: ~p, Opts: ~p", [Socket, mk_ssl_opts(Session)]),

    case dtlsex:ssl_accept(Socket, mk_ssl_opts(Session), ?SSL_ACCEPT_TIMEOUT) of
	{ok, SslSocket} ->
	    ?LOG(info, "ssl_accept: ~p", [SslSocket]),
	    {ok, WTPControlChannelAddress} = dtlsex:peername(SslSocket),
	    dtlsex:setopts(SslSocket, [{active, true}, {mode, binary}]),

	    CommonName = common_name(SslSocket),
	    logger:set_process_metadata(#{wtp => CommonName}),
	    ?LOG(debug, "ssl_cert: ~p", [CommonName]),

	    maybe_takeover(CommonName),
	    capwap_wtp_reg:register_args(CommonName, WTPControlChannelAddress),

	    {ok, CfgProvState} = ergw_aaa_session:get(Session, 'Config-Provider-State'),
	    Config = capwap_config:wtp_config(CfgProvState),
	    Data1 = Data#data{socket = {dtls, SslSocket},
			      session = Session,
			      config_provider_state = CfgProvState,
			      config = Config,
			      id = CommonName},
	    %% TODO: find old connection instance, take over their StationData and stop them
	    {next_state, join, Data1};
	{error, {tls_alert,"certificate expired"}} ->
	    ?LOG(warning, "ssl_accept failed: certificate expired"),
	    exometer:update([capwap, ac, ssl_expired_certs_count], 1),
	    {stop, normal, Data#data{session=Session}};
	Other ->
	    ?LOG(error, "ssl_accept failed: ~p", [Other]),
	    {stop, normal, Data#data{session=Session}}
    end;

%% Join

handle_event(enter, _OldState, join, #data{wait_join_timeout = Timeout}) ->
    Actions = [{state_timeout, Timeout, wait_join_timeout}],
    {keep_state_and_data, Actions};

handle_event(state_timeout, _, join, Data) ->
    ?LOG(info, "WaitJoin timeout in JOIN -> stop"),
    {stop, normal, Data};

handle_event(cast, {session_evs, Evs}, join, Data0) ->
    Data = handle_session_evs(Evs, Data0),
    {keep_state, Data};
handle_event(cast, {session_evs, _}, _, _) ->
    {keep_state_and_data, [postpone]};

handle_event(cast, {discovery_request, Seq, Elements,
		    #capwap_header{
		       radio_id = RadioId, wb_id = WBID, flags = Flags}},
	     join, Data) ->
    RespElements = ac_info(discover, Elements),
    Header = #capwap_header{radio_id = RadioId, wb_id = WBID, flags = Flags},
    Data1 = send_response(Header, discovery_response, Seq, RespElements, Data),
    {keep_state, Data1};

handle_event(cast, {join_request, Seq,
		    #{session_id := #session_id{session_id = SessionId},
		      wtp_mac_type := #wtp_mac_type{mac_type = MacTypes},
		      wtp_frame_tunnel_mode :=
			  #wtp_frame_tunnel_mode{mode = TunnelModes},
		      location_data := #location_data{location = Location},
		      wtp_board_data := BoardData,
		      wtp_descriptor := Descriptor,
		      wtp_name := #wtp_name{wtp_name = Name}
		     } = Elements,
		    #capwap_header{
		       radio_id = RId, wb_id = WBID, flags = Flags}},
	     join, Data0 = #data{ctrl_channel_address = WTPControlChannelAddress,
				 session = Session, id = CommonName,
				 config_provider_state = CfgProvState,
				 config = Config0}) ->
    {Address, _} = WTPControlChannelAddress,
    Version = get_wtp_version(Elements),
    capwap_wtp_reg:register_sessionid(Address, SessionId),

    Config =
	Config0#wtp{
	  radios =
	      lists:map(
		fun(#ieee_802_11_wtp_radio_information{
		       radio_id = RadioId, radio_type = RadioType}) ->
			capwap_config:wtp_radio_config(CfgProvState, RadioId, RadioType)
		end, get_ies(ieee_802_11_wtp_radio_information, Elements))},

    Now = erlang:monotonic_time(),
    StartTime = erlang:convert_time_unit(Now + erlang:time_offset(), native, milli_seconds),
    Data1 = Data0#data{config = Config,
			  session_id = SessionId, mac_types = MacTypes,
			  tunnel_modes = TunnelModes, version = Version,
			  location = Location,
			  board_data = BoardData,
			  descriptor = Descriptor,
			  name = Name,
			  start_time = StartTime
			 },

    RespElements = ac_info_version(join, Version)
	++ [#ecn_support{ecn_support = full},
	    #local_ipv4_address{ip_address = <<127,0,0,1>>},
	    #result_code{result_code = 0}],
    Header = #capwap_header{radio_id = RId, wb_id = WBID, flags = Flags},
    Data2 = send_response(Header, join_response, Seq, RespElements, Data1),
    SessionOpts = wtp_accounting_infos(maps:values(Elements), [{'CAPWAP-Radio-Id', RId}]),
    ?LOG(info, "WTP Session Start Opts: ~p", [SessionOpts]),

    exometer:update_or_create([capwap, wtp, CommonName, start_time], StartTime, gauge, []),
    exometer:update_or_create([capwap, wtp, CommonName, stop_time], 0, gauge, []),
    exometer:update_or_create([capwap, wtp, CommonName, station_count], 0, gauge, []),
    lists:foreach(fun(X) ->
			  exometer:update_or_create([capwap, wtp, CommonName, X], 0, gauge, [])
		  end, ['InPackets', 'OutPackets', 'InOctets', 'OutOctets',
			'Received-Fragments', 'Send-Fragments', 'Error-Invalid-Stations',
			'Error-Fragment-Invalid', 'Error-Fragment-Too-Old']),

    SOpts = #{now => Now, dev_name => Name},
    ergw_aaa_session:invoke(Session, to_session(SessionOpts), start, SOpts),
    Data = start_session_timers(Data2),

    {next_state, join, Data};

handle_event(cast, {configuration_status_request, Seq, Elements,
		    #capwap_header{
		       wb_id = WBID, flags = Flags}},
	     join, #data{config = Config0} = Data0) ->

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
    AdminWlans = get_admin_wifi_updates(Data0, Elements),
    RespElements0 =
	[#timers{discovery = DiscoveryInterval,
		 echo_request = EchoRequestInterval},
	 #tp_data_channel_dead_interval{
	    data_channel_dead_interval = DataChannelDeadInterval},
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
    Data1 = send_response(Header, configuration_status_response, Seq, RespElements, Data0),
    Data = Data1#data{
	      config = Config,
	      echo_request_timeout = EchoRequestInterval * 2},

    {next_state, configure, Data};

%% Configure

handle_event(enter, _OldState, configure, #data{change_state_pending_timeout = Timeout}) ->
    Actions = [{state_timeout, Timeout, change_state_pending_timeout}],
    {keep_state_and_data, Actions};

handle_event(state_timeout, _, configure, Data) ->
    ?LOG(info, "Change State Pending timeout in CONFIGURE -> stop"),
    {stop, normal, Data};

handle_event(cast, {change_state_event_request, Seq, _Elements,
		    #capwap_header{
		       radio_id = RadioId, wb_id = WBID, flags = Flags}},
	     configure, Data) ->
    Header = #capwap_header{radio_id = RadioId, wb_id = WBID, flags = Flags},
    Data1 = send_response(Header, change_state_event_response, Seq, [], Data),
    {next_state, data_check, Data1};

%% Data Check

handle_event(enter, _OldState, data_check, #data{data_check_timeout = Timeout}) ->
    Actions = [{state_timeout, Timeout, data_check_timeout}],
    {keep_state_and_data, Actions};

handle_event(state_timeout, _, data_check, Data) ->
    ?LOG(info, "DataCheck timeout in DATA_CHECK -> stop"),
    {stop, normal, Data};

handle_event(cast, {keep_alive, DataPath, WTPDataChannelAddress, Header, PayLoad},
	     data_check, Data0 = #data{ctrl_stream = CtrlStreamData}) ->
    logger:set_process_metadata(#{data_channel_address => WTPDataChannelAddress}),
    ?log_capwap_keep_alive(peer_log_str(WTPDataChannelAddress, Data0), PayLoad, Header),

    capwap_wtp_reg:register(WTPDataChannelAddress),
    MTU = capwap_stream:get_mtu(CtrlStreamData),
    capwap_dp:add_wtp(WTPDataChannelAddress, MTU),
    Data = Data0#data{data_channel_address = WTPDataChannelAddress, data_path = DataPath},

    sendto(Header, PayLoad, Data),
    {next_state, run, Data, [{next_event, cast, configure}]};

%% Run

handle_event({call, From}, {new_station, BSS, SA}, run, Data0) ->
    ?LOG(info, "in RUN got new_station: ~p", [SA]),

    %% TODO: rework session context to handle this again
    %% {ok, MaxStations} = ergw_aaa_session:get(Session, 'CAPWAP-Max-WIFI-Clients'),

    Wlan = get_wlan_by_bss(BSS, Data0),
    {Reply, Data} = internal_new_station(Wlan, SA, BSS, Data0),
    {keep_state, Data, [{reply, From, Reply}]};

handle_event({call, From}, Event = {add_station, BSS, MAC, StaCaps, CryptoData}, run, Data0) ->
    ?LOG(warning, "in RUN got expected: ~p", [Event]),
    Wlan = get_wlan_by_bss(BSS, Data0),
    ?LOG(warning, "WLAN: ~p", [Wlan]),
    Data = internal_add_station(Wlan, MAC, StaCaps, CryptoData,
				internal_add_station_response_fun(From), Data0),
    {keep_state, Data};

handle_event({call, From}, {get_station_config, BSS}, run, Data) ->
    Reply =
	case get_wlan_by_bss(BSS, Data) of
	    Wlan = #wlan{state = running} ->
		get_station_cfg(Wlan, BSS, Data);
	    _ ->
		{error, invalid}
	end,
    {keep_state, Data, [{reply, From, Reply}]};

handle_event(cast, {echo_request, Seq, Elements,
		    #capwap_header{
		       radio_id = RadioId, wb_id = WBID, flags = Flags}},
	     run, Data) ->
    ?LOG(debug, "EchoReq in Run got: ~p", [{Seq, Elements}]),
    Header = #capwap_header{radio_id = RadioId, wb_id = WBID, flags = Flags},
    Data1 = send_response(Header, echo_response, Seq, Elements, Data),
    {keep_state, Data1};

handle_event(cast, {keep_alive, _DataPath, WTPDataChannelAddress, Header, PayLoad},
	     run, Data) ->
    ?log_capwap_keep_alive(peer_log_str(WTPDataChannelAddress, Data), PayLoad, Header),
    sendto(Header, PayLoad, Data),
    keep_state_and_data;

handle_event(cast, {configuration_update_response, _Seq,
		    #{result_code := #result_code{result_code = 0}}, _Header}, run, _Data) ->
    ?LOG(debug, "Configuration Update ok"),
    keep_state_and_data;
handle_event(cast, {configuration_update_response, _Seq,
		    #{result_code := #result_code{result_code = Code}}, _Header}, run, _Data) ->
    %% TODO: Error handling
    ?LOG(warning, "Configuration Update failed with ~w", [Code]),
    keep_state_and_data;

handle_event(cast, {wtp_event_request, Seq, Elements, RequestHeader =
			#capwap_header{radio_id = RadioId, wb_id = WBID, flags = Flags}},
	     run, Data) ->
    ResponseHeader = #capwap_header{radio_id = RadioId, wb_id = WBID, flags = Flags},
    Data1 = send_response(ResponseHeader, wtp_event_response, Seq, [], Data),
    Data2 = handle_wtp_event(Elements, RequestHeader, Data1),
    {keep_state, Data2};

handle_event(cast, configure, run,
	     Data = #data{id = WtpId, config = #wtp{radios = Radios},
			  session = Session}) ->
    ?LOG(debug, "configure WTP: ~p, Session: ~p, Radios: ~p", [WtpId, Session, Radios]),

    Data1 =
	lists:foldl(fun(#wtp_radio{wlans = Wlans} = Radio, RData) ->
			    lists:foldl(internal_add_wlan(Radio, _, undefined, _), RData, Wlans)
		    end, Data, Radios),
    {keep_state, Data1};

handle_event(cast, {del_station, BSS, MAC}, run, Data0) ->
    Wlan = get_wlan_by_bss(BSS, Data0),
    Data = internal_del_station(Wlan, MAC, Data0),
    {keep_state, Data};

handle_event(cast, {send_80211, BSS, PayLoad}, run, Data) ->
    Wlan = get_wlan_by_bss(BSS, Data),
    internal_send_80211_station(Wlan, PayLoad, Data),
    keep_state_and_data;

handle_event(cast, {firmware_download, DownloadLink, Sha}, run, Data) ->
    Flags = [{frame,'802.3'}],
    ReqElements = [#firmware_download_information{
		      sha256_image_hash = Sha,
		      download_uri = DownloadLink}],
    Header1 = #capwap_header{radio_id = 0, wb_id = 1, flags = Flags},
    Data1 = send_request(Header1, configuration_update_request, ReqElements, Data),
    {keep_state, Data1};

handle_event(info, Event = {group_rekey, WlanIdent}, run, Data0) ->
    ?LOG(warning, "in RUN got GTK rekey: ~p", [Event]),
    Wlan = get_wlan(WlanIdent, Data0),
    Data = start_gtk_rekey(WlanIdent, Wlan, Data0),
    {keep_state, Data};

handle_event(cast, Event = {gtk_rekey_done, WlanIdent}, run, Data0) ->
    ?LOG(warning, "in RUN got GTK rekey DONE: ~p", [Event]),
    Wlan = get_wlan(WlanIdent, Data0),
    Data = finish_gtk_rekey(WlanIdent, Wlan, Data0),
    {keep_state, Data};

handle_event(enter, _OldState, _State, _Data) ->
    keep_state_and_data;

handle_event(cast, {keep_alive, _DataPath, _WTPDataChannelAddress, Header, PayLoad},
	     State, _Data) ->
    ?LOG(warning, "in ~p got unexpected keep_alive: ~p", [State, {Header, PayLoad}]),
    keep_state_and_data;

handle_event(cast, Event, State, _Data)
  when ?IS_RUN_CONTROL_EVENT(Event) ->
    ?LOG(debug, "in ~p got control event: ~p", [State, Event]),
    keep_state_and_data;

handle_event(cast, station_detaching, _State, Data=#data{id = WtpId, station_count = SC}) ->
    if SC == 0 ->
	    ?LOG(error, "Station counter and stations got out of sync", []),
	    keep_state_and_data;
       true ->
	    exometer:update([capwap, ac, station_count], -1),
	    exometer:update([capwap, wtp, WtpId, station_count], SC - 1),
	    {keep_state, Data#data{station_count = SC - 1}}
    end;

handle_event(cast, {Msg, Seq, Elements, Header}, State, _Data) ->
    ?LOG(warning, "in ~s got unexpected: ~p",
		  [State, {Msg, Seq, Elements, Header}]),
    keep_state_and_data;

handle_event({call, From}, get_state, _State, Data) ->
    {keep_state_and_data, [{reply, From, {ok, Data}}]};

handle_event({call, From}, get_info, _State, Data) ->
    #data{
       version = Version,
       location = Location,
       board_data = BoardData,
       descriptor = Descriptor,
       name = Name,
       start_time = StartTime,
       last_gps_pos = LastPos} = Data,
    Info = #{version => Version,
	     location => Location,
	     board_data => BoardData,
	     descriptor => Descriptor,
	     name => Name,
	     start_time => StartTime,
	     last_gps_pos => LastPos},
    {keep_state_and_data, [{reply, From, {ok, Info}}]};

handle_event({call, From}, {set_ssid, {RadioId, WlanId} = WlanIdent, SSID, SuppressSSID},
	     run, #data{id = CommonName, config = Config0} = Data0) ->
    Settings = [{ssid, SSID}, {suppress_ssid, SuppressSSID}],
    Config = update_wlan_config(RadioId, WlanId, Settings, Config0),
    Data1 = Data0#data{config = Config},

    AddResponseFun =
	fun(Code, _, DData) ->
		?LOG(debug, "Add WLAN response for ~p: ~p", [CommonName, Code]),
		case Code of
		    0 -> gen_statem:reply(From, ok);
		    _ -> gen_statem:reply(From, {error, Code})
		end,
		DData
	end,

    Data =
	case get_wlan(WlanIdent, Data1) of
	    false ->
		internal_add_wlan(RadioId, WlanId, AddResponseFun, Data1);

	    #wlan{} ->
		DelResponseFun =
		    fun(0, _, DData) ->
			    ?LOG(debug, "Del WLAN ok for ~p", [CommonName]),
			    ?LOG(debug, "DelResponseFun: success"),
			    internal_add_wlan(RadioId, WlanId, AddResponseFun, DData);

		       (Code, Arg, DData) ->
			    ?LOG(debug, "Del WLAN failed for ~p with ~w", [CommonName, Code]),
			    ?LOG(debug, "DelResponseFun: ~w", [Code]),
			    AddResponseFun(Code, Arg, DData)
		    end,
		internal_del_wlan(WlanIdent, DelResponseFun, Data1)
	end,
    {keep_state, Data};

handle_event({call, From}, {stop_radio, RadioId}, run, #data{id = CommonName} = Data) ->
    ResponseFun =
	fun(0, _, RData) ->
		?LOG(debug, "Del WLAN ok for ~p", [CommonName]),
		RData;

	   (Code, _Arg, RData) ->
		?LOG(debug, "Del WLAN failed for ~p with ~w", [CommonName, Code]),
		RData
	end,

    Data1 =
	lists:foldl(fun(WlanIdent = {RId, _}, S) when RId == RadioId->
			    internal_del_wlan(WlanIdent, ResponseFun, S);
		       (_, S) ->
			    S
		    end, Data, Data#data.wlans),
    {keep_state, Data1, [{reply, From, ok}]};

handle_event({call, From}, {set_ssid, _SSID, _RadioId}, State, Data)
  when State =/= run ->
    {keep_state, Data, [{reply, From, {error, not_in_run_state}}]};

handle_event({call, From}, get_data_channel_address, run, Data) ->
    Reply = {ok, Data#data.data_channel_address},
    {keep_state, Data, [{reply, From, Reply}]};
handle_event({call, From}, get_data_channel_address, _State, Data) ->
    Reply = {error, not_connected},
    {keep_state, Data, [{reply, From, Reply}]};
handle_event({call, From}, {take_over, NewWtp}, _State, Data) ->
    %% TODO: move Stations to new wtp
    ?LOG(debug, "take_over: old: ~p, new: ~p", [self(), NewWtp]),
    capwap_wtp_reg:unregister(),
    {stop_and_reply, normal, {reply, From, ok}, Data};
handle_event({call, From}, _Event, _State, Data) ->
    {keep_state, Data, [{reply, From, ok}]};

handle_event(info, {capwap_udp, Socket, Packet}, State, Data = #data{socket = {_, Socket}}) ->
    ?LOG(debug, "in state ~p got UDP: ~p", [State, Packet]),
    handle_capwap_packet(Packet, Data);

handle_event(info, {ssl, Socket, Packet}, State, Data = #data{socket = {_, Socket}}) ->
    ?LOG(debug, "in state ~p got DTLS: ~p", [State, Packet]),
    handle_capwap_packet(Packet, Data);

handle_event(info, {timeout, TRef, retransmit}, State, #data{retransmit_timer = TRef} = Data) ->
    resend_request(State, Data);

handle_event(info, {timeout, TRef, Ev}, run, Data) ->
    handle_session_timer(TRef, Ev, Data);

handle_event(info, echo_timeout, run, Data) ->
    ?LOG(info, "Echo Timeout in Run"),
    {stop, normal, Data};

handle_event(info, {'EXIT', _Pid, normal}, _State, _Data) ->
    keep_state_and_data;
handle_event(info, {'EXIT', _Pid, shutdown}, _State, _Data) ->
    {stop, shutdown};
handle_event(info, Info, State, _Data) ->
    ?LOG(warning, "in state ~p unexpected Info: ~p", [State, Info]),
    keep_state_and_data.

terminate(Reason, State,
	  Data = #data{socket = Socket, session = Session,
			 id = CommonName, station_count = StationCount}) ->
    error_logger:info_msg("AC session terminating in state ~p with state ~p with reason ~p~n",
			  [State, Data, Reason]),
    AcctValues = stop_wtp(State, Data),
    if Session /= undefined ->
	    ergw_aaa_session:invoke(Session, AcctValues, stop, #{async => true}),

	    exometer:update([capwap, wtp, CommonName, station_count], 0),
	    StopTime = erlang:system_time(milli_seconds),
	    exometer:update_or_create([capwap, wtp, CommonName, stop_time], StopTime, gauge, []);
       true -> ok
    end,

    exometer:update([capwap, ac, station_count], -StationCount),
    exometer:update([capwap, ac, wtp_count], -1),
    socket_close(Socket),
    ok.

code_change(_OldVsn, State, Data, _Extra) ->
    {ok, State, Data}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
cancel_timer(Ref) ->
    case erlang:cancel_timer(Ref) of
	false ->
	    receive {timeout, Ref, _} -> 0
	    after 0 -> false
	    end;
	RemainingTime ->
	    RemainingTime
    end.

gpsutc_to_iso(GPSTime, GPSDate) ->
    try
	{ok, [Hour, Minute, Second], _} = io_lib:fread("~2s~2s~s", GPSTime),
	{ok, [Day, Month, Year], _} = io_lib:fread("~2s~2s~2s", GPSDate),
	lists:flatten(["20", Year, "-", Month, "-", Day, "T", Hour, ":", Minute, ":", Second, "Z"])
    catch
	_:_ -> "2000-01-01T00:00:00Z"
    end.

peer_log_str(Data = #data{ctrl_channel_address = WTPControlChannelAddress}) ->
    peer_log_str(WTPControlChannelAddress, Data).

peer_log_str(Address, #data{id = undefined}) ->
    io_lib:format("~p", [Address]);
peer_log_str(Address, #data{id = Id}) ->
    io_lib:format("~s[~s]", [Id, capwap_tools:format_peer(Address)]).

%% non-DTLS join-reqeust, check app config
handle_plain_join(Peer, Seq, _Elements, #capwap_header{
					   wb_id = WBID, flags = Flags}) ->
    case capwap_config:get(ac, enforce_dtls_control, true) of
	false ->
	    ?LOG(warning, "Accepting JOIN without DTLS from ~s", [Peer]),
	    accept;
	_ ->
	    ?LOG(warning, "Rejecting JOIN without DTLS from ~s", [Peer]),
	    RespElems = [#result_code{result_code = 18}],
	    Header = #capwap_header{radio_id = 0, wb_id = WBID, flags = Flags},
	    ?log_capwap_control(Peer, join_response, Seq, RespElems, Header),
	    Answer = hd(capwap_packet:encode(control, {Header, {join_response, Seq, RespElems}})),
	    {reply, Answer}
    end.

handle_capwap_data(DataPath, WTPDataChannelAddress, Header, true,
		   #{session_id := #session_id{session_id = SessionId}} = PayLoad) ->
    ?LOG(debug, "CAPWAP Data KeepAlive: ~p", [PayLoad]),

    {Address, _Port} = WTPDataChannelAddress,
    case capwap_wtp_reg:lookup_sessionid(Address, SessionId) of
	not_found ->
	    ?LOG(warning, "CAPWAP data from unknown WTP ~s", [capwap_tools:format_peer(WTPDataChannelAddress)]),
	    ok;
	{ok, AC} ->
	    gen_statem:cast(AC, {keep_alive, DataPath, WTPDataChannelAddress, Header, PayLoad})
    end;

handle_capwap_data(_DataPath, WTPDataChannelAddress,
		   Header = #capwap_header{
			       flags = Flags, radio_mac = RecvRadioMAC},
		   false, Frame) ->
    ?LOG(debug, "CAPWAP Data PayLoad:~n~s~n~p", [capwap_packet:pretty_print(Header), Frame]),

    case capwap_wtp_reg:lookup(WTPDataChannelAddress) of
	not_found ->
	    ?LOG(warning, "AC for data session no found: ~p", [WTPDataChannelAddress]),
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

handle_capwap_packet(Packet, Data = #data{ctrl_channel_address = WTPControlChannelAddress,
					  ctrl_stream = CtrlStreamData0}) ->
    capwap_trace:trace(WTPControlChannelAddress, ?TRACE_LOCAL_CONTROL, Packet),
    case capwap_stream:recv(control, Packet, CtrlStreamData0) of
	{ok, {Header, Msg}, CtrlStreamData1} ->
	    handle_capwap_message(Header, Msg, Data#data{ctrl_stream = CtrlStreamData1});

	{ok, more, CtrlStreamData1} ->
	    {keep_state, Data#data{ctrl_stream = CtrlStreamData1}};

	{error, Error} ->
	    ?LOG(error, [{capwap_packet, decode}, {error, Error}], "Decode error ~p", [Error]),
	    keep_state_and_data
    end.

-define(SEQ_LE(S1, S2), (S1 < S2 andalso (S2-S1) < 128) orelse (S1>S2 andalso (S1-S2) > 128)).

handle_capwap_message(Header, {Msg, 1, Seq, Elements},
		      Data0 = #data{last_response = LastResponse}) ->
    %% Request
    ?log_capwap_control(peer_log_str(Data0), Msg, Seq, Elements, Header),
    Data = reset_echo_request_timer(Data0),
    case LastResponse of
	{Seq, _} ->
	    NewData = resend_response(Data),
	    {keep_state, NewData};
	{LastSeq, _} when ?SEQ_LE(Seq, LastSeq) ->
	    %% old request, silently ignore
	    {keep_state, Data};
	_ ->
	    {keep_state, Data, {next_event, cast, {Msg, Seq, Elements, Header}}}
    end;

handle_capwap_message(Header, {Msg, 0, Seq,
			       #{result_code := #result_code{result_code = Code}} = Elements},
		      Data = #data{request_queue = Queue}) ->
    %% Response
    ?log_capwap_control(peer_log_str(Data), Msg, Seq, Elements, Header),
    case queue:peek(Queue) of
	{value, {Seq, _, NotifyFun}} ->
	    Data1 = ack_request(Data),
	    if is_function(NotifyFun) ->
		    Data2 = response_notify(NotifyFun, Code, {Msg, Elements, Header}, Data1),
		    {keep_state, Data2};
	       true ->
		    {keep_state, Data1, {next_event, cast, {Msg, Seq, Elements, Header}}}
	    end;
	_ ->
	    %% invalid Seq, out-of-order packet, silently ignore,
	    keep_state_and_data
    end.

maybe_takeover(CommonName) ->
    case capwap_wtp_reg:lookup(CommonName) of
	{ok, OldPid} ->
	    ?LOG(info, "take_over: ~p", [OldPid]),
	    capwap_ac:take_over(OldPid);
	_ ->
	    ok
    end.

handle_wtp_event(Elements, Header, Data0 = #data{session = Session}) ->
    IEs = maps:values(Elements),
    SessionOptsList = handle_wtp_stats_event(IEs, Header, []),
    lists:foreach(
      fun(Ev) ->
	      ergw_aaa_session:invoke(Session, Ev, interim, #{async => true})
      end, SessionOptsList),
    Data = handle_wtp_action_event(IEs, Header, Data0),
    update_last_gps_position(IEs, Data).

update_last_gps_position(IEs, #data{last_gps_pos = LastPos} = Data) ->
    Data#data{last_gps_pos = update_last_gps_position_1(IEs, LastPos)}.

update_last_gps_position_1(IEs, LastPos)
  when is_list(IEs) ->
    lists:foldl(fun update_last_gps_position_1/2, LastPos, IEs);
update_last_gps_position_1(#gps_last_acquired_position{gpsatc = GpsString}, LastPos) ->
    case [string:strip(V) || V <- string:tokens(binary_to_list(GpsString), ",:")] of
	[_, GPSTime, Latitude, Longitude, Hdop, Altitude, _Fix, _Cog, _Spkm, _Spkn, GPSDate, _Nsat] ->
	    case {gpsutc_to_iso(GPSTime, GPSDate), LastPos} of
		{GPSTimestamp, undefined} ->
		    {GPSTimestamp, Latitude, Longitude, Altitude, Hdop};
		{GPSTimestamp, {LastEvTs, _, _, _, _}}
		  when GPSTimestamp > LastEvTs ->
		    {GPSTimestamp, Latitude, Longitude, Altitude, Hdop};
		_ ->
		    LastPos
	    end;
	_ ->
	    LastPos
    end;
update_last_gps_position_1(_, LastPos) ->
    LastPos.

handle_wtp_action_event(IEs, Header, Data)
  when is_list(IEs) ->
    lists:foldl(handle_wtp_action_event(_, Header, _), Data, IEs);
handle_wtp_action_event(#delete_station{radio_id = RadioId, mac = MAC}, _Header, Data) ->
    case capwap_station_reg:lookup(self(), RadioId, MAC) of
	{ok, Station} ->
	    ieee80211_station:delete(Station);
	Other ->
	    ?LOG(debug, "station ~p not found: ~p", [MAC, Other]),
	    ok
    end,
    Data;
handle_wtp_action_event(_Action, _Header, Data) ->
    Data.

handle_wtp_stats_event(IEs, Header, SOptsList)
  when is_list(IEs) ->
    lists:foldl(handle_wtp_stats_event(_, Header, _), SOptsList, IEs);
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
	    ?LOG(debug, "WTP Event Opts: ~p", [Opts]),
	    [to_session(Opts) | SOptsList];
	_ ->
	    ?LOG(error, "Unable to parse GPSATC string from WTP! String: ~p", [GpsString]),
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
    ?LOG(debug, "WTP Event Opts: ~p", [Opts]),
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
    ?LOG(debug, "WTP Event Opts: ~p", [Opts]),
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

get_wtp_version(#{wtp_descriptor :=
		      #wtp_descriptor{sub_elements=SubElements}}) ->
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
get_wtp_version(_) ->
    {0, undefined}.

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
    ?LOG(debug, "ac_info version: ~p", [Version]),
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
    ?LOG(info, "CipherSuites: ~p", [[capwap_packet:decode_cipher_suite(Suite) || Suite <- CipherSuites]]),
    Radio#wtp_radio{
      supported_cipher_suites = [capwap_packet:decode_cipher_suite(Suite) || Suite <- CipherSuites]}.

update_radio_cfg(Fun, RadioId, #wtp{radios = Radios} = Config) ->
    case lists:keyfind(RadioId, #wtp_radio.radio_id, Radios) of
	#wtp_radio{} = Radio ->
	    Config#wtp{radios = lists:keystore(RadioId, #wtp_radio.radio_id, Radios, Fun(Radio))};
	_ ->
	    Config
    end.

update_radio_info(K, V, Config) when is_list(V) ->
    lists:foldl(update_radio_info(K, _, _), Config, V);
update_radio_info(_, #ieee_802_11_supported_rates{
			radio_id = RadioId,
			supported_rates = SRates}, Config) ->
    update_radio_cfg(update_radio_sup_rates(SRates, _), RadioId, Config);
update_radio_info(_, #ieee_802_11n_wlan_radio_configuration{
			radio_id = RadioId} = Cfg, Config) ->
    update_radio_cfg(update_radio_80211n_cfg(Cfg, _), RadioId, Config);
update_radio_info(_, #tp_ieee_802_11_encryption_capabilities{
			radio_id = RadioId,
			cipher_suites = CipherSuites}, Config) ->
    update_radio_cfg(update_radio_cipher_suites(CipherSuites, _), RadioId, Config);
update_radio_info(_, _, Config) ->
    Config.

update_radio_information(Elements, Config) ->
    maps:fold(fun update_radio_info/3, Config, Elements).

update_wlan_cfg(Fun, WlanId, #wtp_radio{wlans = WLANs} = Radio) ->
    case lists:keyfind(WlanId, #wtp_wlan_config.wlan_id, WLANs) of
	#wtp_wlan_config{} = WLAN ->
	    Radio#wtp_radio{
	      wlans = lists:keystore(WlanId, #wtp_wlan_config.wlan_id, WLANs, Fun(WLAN))};
	_ ->
	    Radio
    end.

update_wlan_config(RadioId, WlanId, Settings, Config) ->
    update_radio_cfg(
      update_wlan_cfg(capwap_config:'#set-'(Settings, _), WlanId, _), RadioId, Config).

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

reset_echo_request_timer(Data = #data{echo_request_timer = Timer,
					echo_request_timeout = Timeout}) ->
    if is_reference(Timer) ->
	    cancel_timer(Timer);
       true ->
	    ok
    end,
    TRef = if is_integer(Timeout) ->
		   erlang:send_after(Timeout * 1000, self(), echo_timeout);
	      true ->
		   undefined
	   end,
    Data#data{echo_request_timer = TRef}.

send_info_after(Time, Event) ->
    erlang:start_timer(Time, self(), Event).

bump_seqno(Data = #data{seqno = SeqNo}) ->
    Data#data{seqno = (SeqNo + 1) rem 256}.

send_response(Header, MsgType, Seq, MsgElems, Data) ->
    ?log_capwap_control(peer_log_str(Data), MsgType, Seq, MsgElems, Header),
    Msg = {Header, {MsgType, Seq, MsgElems}},
    stream_send(Msg, Data#data{last_response = {Seq, Msg}}).

resend_response(Data = #data{last_response = {SeqNo, Msg}}) ->
    ?LOG(warning, "resend capwap response ~w", [SeqNo]),
    stream_send(Msg, Data).

send_request(Header, MsgType, ReqElements, Data) ->
    send_request(Header, MsgType, ReqElements, undefined, Data).

send_request(Header, MsgType, ReqElements, NotfiyFun,
	     Data0 = #data{request_queue = Queue, seqno = SeqNo}) ->
    ?log_capwap_control(peer_log_str(Data0), MsgType, SeqNo, ReqElements, Header),
    Msg = {Header, {MsgType, SeqNo, ReqElements}},
    Data1 = queue_request(Data0, {SeqNo, Msg, NotfiyFun}),
    Data2 = bump_seqno(Data1),
    case queue:is_empty(Queue) of
	true ->
	    Data3 = stream_send(Msg, Data2),
	    init_retransmit(Data3, ?MaxRetransmit);
	false ->
	    Data2
    end.

resend_request(State, Data = #data{retransmit_counter = 0}) ->
    ?LOG(debug, "Final Timeout in ~w, STOPPING", [State]),
    {stop, normal, Data};
resend_request(_State,
	       Data0 = #data{request_queue = Queue,
			       retransmit_counter = RetransmitCounter}) ->
    ?LOG(warning, "resend capwap request", []),
    {value, {_, Msg, _}} = queue:peek(Queue),
    Data1 = stream_send(Msg, Data0),
    Data2 = init_retransmit(Data1, RetransmitCounter - 1),
    {keep_state, Data2}.

init_retransmit(Data, Counter) ->
    Data#data{retransmit_timer = send_info_after(?RetransmitInterval, retransmit),
	      retransmit_counter = Counter}.

%% Stop Timer, clear LastRequest
ack_request(Data0) ->
    Data1 = cancel_retransmit(Data0),
    case dequeue_request_next(Data1) of
	{{value, {_, Msg, _}}, Data2} ->
	    Data3 = stream_send(Msg, Data2),
	    init_retransmit(Data3, ?MaxRetransmit);
	{empty, Data2} ->
	    Data2
    end.

cancel_retransmit(Data = #data{retransmit_timer = undefined}) ->
    Data;
cancel_retransmit(Data = #data{retransmit_timer = Timer}) ->
    cancel_timer(Timer),
    Data#data{retransmit_timer = undefined}.

queue_request(Data = #data{request_queue = Queue}, Request) ->
    Data#data{request_queue = queue:in(Request, Queue)}.

dequeue_request_next(Data = #data{request_queue = Queue0}) ->
    Queue1 = queue:drop(Queue0),
    {queue:peek(Queue1), Data#data{request_queue = Queue1}}.

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
    [control_address(A) || A <- resolve_ips(Addrs)].

get_wtp_count() ->
    case exometer:get_value([capwap, ac, wtp_count]) of
	{ok, {value, Value}}
	  when is_integer(Value)
	       -> Value;
	_ -> 0
    end.

resolve_ips(Addrs) ->
    lists:reverse(
      lists:foldl(
	fun(Addr, Acc)
	      when is_list(Addr); is_atom(Addr) ->
		case inet:gethostbyname(Addr) of
		    {ok, #hostent{h_addr_list = HAL}} ->
			[hd(HAL) | Acc];
		    _ ->
			[Addr | Acc]
		end;
	   (Addr, Acc) ->
		[Addr | Acc]
	end, [], Addrs)).

control_address({A,B,C,D}) ->
    #control_ipv4_address{ip_address = <<A,B,C,D>>,
			  wtp_count = get_wtp_count()};
control_address({A,B,C,D,E,F,G,H}) ->
    #control_ipv6_address{ip_address = <<A:16,B:16,C:16,D:16,E:16,F:16,G:16,H:16>>,
			  wtp_count = get_wtp_count()}.

ac_addresses() ->
    Addrs0 =
	case capwap_config:get(ac, server_ip) of
	    {ok, IP} ->
		[IP];
	    _ ->
		all_local_addresses()
	end,
    Addrs = resolve_ips(Addrs0),
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

stream_send(Msg, Data = #data{ctrl_channel_address = WTPControlChannelAddress,
				ctrl_stream = CtrlStreamData0,
				socket = Socket}) ->
    {BinMsg, CtrlStreamData1} = capwap_stream:encode(control, Msg, CtrlStreamData0),
    lists:foreach(fun(M) ->
			  capwap_trace:trace(?TRACE_LOCAL_CONTROL, WTPControlChannelAddress, M),
			  ok = socket_send(Socket, M)
		  end, BinMsg),
    Data#data{ctrl_stream = CtrlStreamData1}.

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
    ?LOG(warning, "Got Close on: ~p", [Socket]),
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

user_lookup(srp, Username, _UserData) ->
    ?LOG(debug, "srp: ~p", [Username]),
    Salt = dtlsex:random_bytes(16),
    UserPassHash = crypto:hash(sha, [Salt, crypto:hash(sha, [Username, <<$:>>, <<"secret">>])]),
    {ok, {srp_1024, Salt, UserPassHash}};

user_lookup(psk, Username, {WTP, Session}) ->
    ?LOG(debug, "user_lookup: Username: ~p", [Username]),
    {ok, CfgProvStateInit} = capwap_config:wtp_init_config_provider(Username),
    Opts = [{'Username', Username},
	    {'Authentication-Method', {'TLS', 'Pre-Shared-Key'}},
	    {'Config-Provider-State', CfgProvStateInit}],
    case ergw_aaa_session:invoke(Session, to_session(Opts), authenticate, [inc_session_id]) of
	{ok, SOpts, Evs} ->
	    ?LOG(info, #{'AuthResult' => success, session => SOpts}),
	    case SOpts of
		#{'TLS-Pre-Shared-Key' := PSK} ->
		    ?LOG(info, "AuthResult: PSK: ~p", [PSK]),
		    gen_statem:cast(WTP, {session_evs, Evs}),
		    {ok, PSK};
		_ ->
		    ?LOG(info, "AuthResult: NO PSK"),
		    {error, "no PSK"}
	    end;
	Other ->
	    ?LOG(info, "AuthResult: ~p", [Other]),
	    {error, Other}
    end.

verify_cert(_,{bad_cert, _} = Reason, _) ->
    {fail, Reason};
verify_cert(_,{extension, _}, UserData) ->
    {unknown, UserData};
verify_cert(_, valid, UserData) ->
    {valid, UserData};
verify_cert(#'OTPCertificate'{
	       tbsCertificate =
		   #'OTPTBSCertificate'{
		 subject = {rdnSequence, SubjectList},
		 extensions = Extensions
		}}, valid_peer, UserData) ->
    Subject = [erlang:hd(S)|| S <- SubjectList],
    {value, #'AttributeTypeAndValue'{value = {utf8String, CommonName}}} =
	lists:keysearch(?'id-at-commonName', #'AttributeTypeAndValue'.type, Subject),
    #'Extension'{extnValue = ExtnValue} =
	lists:keyfind(?'id-ce-extKeyUsage', #'Extension'.extnID, Extensions),

    case lists:member(?'id-kp-capwapWTP', ExtnValue) of
	true -> verify_cert_auth_cn(CommonName, UserData);
	_    -> {fail, "not a valid WTP certificate"}
    end.

verify_cert_auth_cn(CommonName, {WTP, Session}) ->
    ?LOG(info, "AuthResult: attempt for ~p", [CommonName]),
    {ok, CfgProvStateInit} = capwap_config:wtp_init_config_provider(CommonName),
    Opts = [{'Username', CommonName},
	    {'Authentication-Method', {'TLS', 'X509-Subject-CN'}},
	    {'Config-Provider-State', CfgProvStateInit}],
    case ergw_aaa_session:invoke(Session, to_session(Opts), authenticate, [inc_session_id]) of
	{ok, _, Evs} ->
	    ?LOG(info, "AuthResult: success for ~p", [CommonName]),
	    gen_statem:cast(WTP, {session_evs, Evs}),
	    {valid, Session};
	{{fail, Reason}, _, _} ->
	    ?LOG(info, "AuthResult: fail, ~p for ~p", [Reason, CommonName]),
	    {fail, Reason};
	Other ->
	    ?LOG(info, "AuthResult: ~p for ~p", [Other, CommonName]),
	    {fail, Other}
    end.

mk_ssl_opts(Session) ->
    Dir = case capwap_config:get(ac, certs) of
	      {ok, Path} ->
		  Path;
	      _ ->
		  filename:join([code:lib_dir(capwap), "priv", "certs"])
	  end,
    UserState = {self(), Session},

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
     {verify_fun, {fun verify_cert/3, UserState}},
     {fail_if_no_peer_cert, true},

     {psk_identity, "CAPWAP"},
     {user_lookup_fun, {fun user_lookup/3, UserState}},
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

start_session(Socket, _Data) ->
    {ok, {Address, _Port}} = capwap_udp:peername(Socket),
    SessionOpts = [{'AAA-Application-Id', capwap_wtp},
		   {'Service-Type', 'TP-CAPWAP-WTP'},
		   {'Framed-Protocol', 'TP-CAPWAP'},
		   {'Calling-Station', ip2str(Address)},
		   {'Tunnel-Type', 'CAPWAP'},
		   {'Tunnel-Medium-Type', tunnel_medium(Address)},
		   {'Tunnel-Client-Endpoint', ip2str(Address)}],
    ergw_aaa_session_sup:new_session(self(), to_session(SessionOpts)).

get_ies(Key, Elements) ->
    case maps:get(Key, Elements, []) of
	IEs when is_list(IEs) ->
	    IEs;
	IE when is_tuple(IE) ->
	    [IE]
    end.

select_mac_mode(#wtp_wlan_config{mac_mode = local_mac}, local) ->
    local_mac;
select_mac_mode(#wtp_wlan_config{mac_mode = split_mac}, split) ->
    split_mac;
select_mac_mode(#wtp_wlan_config{mac_mode = Mode}, both) ->
    Mode.

%% CAPWAP RFC says the 802.3 tunnel is only permited with
%% Local MAC. However, I don't see a reason why is shouldn't
%% work in Split MAC with encryption provided by WTP as well.
%%
%% Select 802.3 tunnel mode by default if it is supported
%%
select_tunnel_mode(Modes, _MAC) ->
    case proplists:get_bool('802.3', Modes) of
	true -> '802_3_tunnel';
	_    -> '802_11_tunnel'
    end.

%% select_tunnel_mode(Modes, Local_mac) ->
%%     case proplists:get_bool('802.3', Modes) of
%%	true -> '802_3_tunnel';
%%	_    -> '802_11_tunnel'
%%     end;
%% select_tunnel_mode(_Modes, split_mac) ->
%%     '802_11_tunnel'.

tuple_to_ip({A, B, C, D}) ->
    <<A:8, B:8, C:8, D:8>>;
tuple_to_ip({A, B, C, D, E, F, G, H}) ->
    <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>.

%% AttrNamesAndDefaults = [{LocalName, RemoteName, Default}, ...]
wtp_config_get(CommonName, AttrNamesAndDefaults) when is_list(AttrNamesAndDefaults) ->
    App = capwap,
    Wtps = application:get_env(App, wtps, []),
    LocalCnf = proplists:get_value(CommonName, Wtps, []),
    ?LOG(debug, "found config for wtp ~p: ~p", [CommonName, LocalCnf]),

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
		 {IE = <<Id:8, _/binary>>, Flags}, IEs)
  when Id /= ?WLAN_EID_SUPP_RATES ->
    [#ieee_802_11_information_element{
	radio_id = RadioId,
	wlan_id = WlanId,
	flags = Flags,
	ie = IE}
     | IEs];
capwap_802_11_ie(_Radio, _WlanData, _IE, IEs) ->
    IEs.

init_wlan_information_elements(Radio, WlanData) ->
    ProbeResponseFlags = ['beacon','probe_response'],
    IEList = [
	      {fun wlan_supported_rateset_ie/2, ProbeResponseFlags},
	      {fun wlan_extended_supported_rateset_ie/2, ProbeResponseFlags},
	      {fun wlan_wmm_ie/2, ProbeResponseFlags},
	      {fun wlan_ht_opmode_ie/2, ProbeResponseFlags},
	      {fun wlan_rsn_ie/2, ProbeResponseFlags},
	      {fun wlan_ht_cap_ie/2, ProbeResponseFlags},
	      {fun wlan_md_ie/2, ProbeResponseFlags},
	      {fun wlan_time_zone_ie/2, ProbeResponseFlags}],
    lists:foldl(fun({Fun, Flags}, WS = #wlan{information_elements = IEs}) ->
			case Fun(Radio, WS) of
			    IE when is_binary(IE) ->
				WS#wlan{information_elements = [{IE, Flags} | IEs]};
			    _ ->
				WS
			end
		end, WlanData, IEList).

wlan_supported_rateset_ie(_Radio, #wlan{mode = Mode, rate_set = RateSet}) ->
    {Rates, _} = lists:split(8, RateSet),
    ieee_802_11_ie(?WLAN_EID_SUPP_RATES,
		   << <<(capwap_packet:encode_rate(Mode, X)):8>> || X <- Rates>>).

wlan_extended_supported_rateset_ie(_Radio, #wlan{mode = Mode, rate_set = RateSet}) ->
    case lists:split(8, RateSet) of
	{_, []} ->
	    undefined;
	{_, ExtRates} ->
	    ieee_802_11_ie(?WLAN_EID_EXT_SUPP_RATES,
			   << <<(capwap_packet:encode_rate(Mode, X)):8>> || X <- ExtRates>>)
    end.

wlan_wmm_ie(_Radio, _WlanData) ->
    ieee_802_11_ie(?WLAN_EID_VENDOR_SPECIFIC,
		   <<16#00, 16#50, 16#f2, 16#02, 16#01, 16#01, 16#00, 16#00,
		     16#03, 16#a4, 16#00, 16#00, 16#27, 16#a4, 16#00, 16#00,
		     16#42, 16#43, 16#5e, 16#00, 16#62, 16#32, 16#2f, 16#00>>).

wlan_ht_cap_ie(_Radio, _WlanData) ->
    ieee_802_11_ie(?WLAN_EID_HT_CAP,
		   <<16#0c, 16#00, 16#1b, 16#ff, 16#ff, 16#00, 16#00, 16#00,
		     16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#01,
		     16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00,
		     16#00, 16#00>>).

wlan_ht_opmode_ie(#wtp_radio{channel = Channel}, _WlanData) ->
    ieee_802_11_ie(?WLAN_EID_HT_OPERATION,
		   <<Channel:8, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00,
		     16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00,
		     16#00, 16#00, 16#00, 16#00, 16#00, 16#00>>).
rsn_ie(RSN, PMF) ->
    rsn_ie(RSN, [], PMF).

rsn_ie(#wtp_wlan_rsn{version = RSNVersion,
		     capabilities = RSNCaps,
		     group_cipher_suite = GroupCipherSuite,
		     group_mgmt_cipher_suite = GroupMgmtCipherSuite,
		     cipher_suites = CipherSuites,
		     akm_suites = AKMs}, PMKIds, PMF) ->
    CipherSuitesBin = << <<X/binary>> || X <- CipherSuites >>,
    AKMsBin = << <<(capwap_packet:encode_akm_suite(X)):32>> || X <- AKMs >>,

    IE0 = <<RSNVersion:16/little, GroupCipherSuite/binary,
	    (length(CipherSuites)):16/little, CipherSuitesBin/binary,
	    (length(AKMs)):16/little, AKMsBin/binary,
	    RSNCaps:16/little>>,
    IE1 = if length(PMKIds) /= 0 orelse
	     (PMF == true andalso is_atom(GroupMgmtCipherSuite)) ->
		  <<IE0/binary, (length(PMKIds)):16/little, << <<X/binary>> || X <- PMKIds >>/binary >>;
	     true ->
		  IE0
	  end,
    IE = if PMF == true andalso is_atom(GroupMgmtCipherSuite) ->
		 <<IE1/binary, (capwap_packet:encode_cipher_suite(GroupMgmtCipherSuite)):32>>;
	    true ->
		 IE1
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

wlan_md_ie(_Radio, #wlan{fast_transition = true, mobility_domain = MDomain}) ->
    ieee_802_11_ie(?WLAN_EID_MOBILITY_DOMAIN, <<MDomain:16, 1>>);
wlan_md_ie(_, _) ->
    undefined.

wlan_time_zone_ie(_Radio, _WlanState) ->
    ieee_802_11_ie(?WLAN_EID_TIME_ZONE, <<"CEST">>).

wlan_cfg_tp_hold_time(#wtp_radio{radio_id = RadioId},
		      #wlan{wlan_identifier = {_, WlanId}},
		      #wtp{wlan_hold_time = WlanHoldTime}, IEs) ->
    [#tp_ieee_802_11_wlan_hold_time{radio_id  = RadioId,
				   wlan_id   = WlanId,
				   hold_time = WlanHoldTime}
     | IEs ].

internal_add_wlan(RadioId, WlanId, NotifyFun,
		  #data{config = #wtp{radios = Radios}} = Data)
  when is_integer(RadioId), is_integer(WlanId) ->
    Radio = lists:keyfind(RadioId, #wtp_radio.radio_id, Radios),
    WLAN = lists:keyfind(WlanId, #wtp_wlan_config.wlan_id, Radio#wtp_radio.wlans),
    internal_add_wlan(Radio, WLAN, NotifyFun, Data);

internal_add_wlan(#wtp_radio{radio_id = RadioId} = Radio,
		  #wtp_wlan_config{wlan_id = WlanId,
				   ssid = SSID,
				   suppress_ssid = SuppressSSID} = WlanConfig,
		  NotifyFun,
		  #data{config = Config} = Data0) ->
    WBID = ?CAPWAP_BINDING_802_11,
    Flags = [{frame,'802.3'}],
    Header = #capwap_header{radio_id = RadioId, wb_id = WBID, flags = Flags},

    WlanData = init_wlan_state(Radio, WlanId, WlanConfig, Data0),
    Data = update_wlan_state({RadioId, WlanId}, fun(_W) -> WlanData end, Data0),

    AddWlan = #ieee_802_11_add_wlan{
		 radio_id      = RadioId,
		 wlan_id       = WlanId,
		 capability    = [ess, short_slot_time],
		 auth_type     = open_system,
		 mac_mode      = WlanData#wlan.mac_mode,
		 tunnel_mode   = WlanData#wlan.tunnel_mode,
		 suppress_ssid = SuppressSSID,
		 ssid          = SSID
		},
    ReqElements0 = [set_wlan_keys(WlanData, AddWlan)],
    ReqElements1 = lists:foldl(capwap_802_11_ie(Radio, WlanData, _, _), ReqElements0,
			       WlanData#wlan.information_elements),
    ReqElements2 = wlan_cfg_tp_hold_time(Radio, WlanData, Config, ReqElements1),
    ReqElements = add_wlan_keys(WlanData, ReqElements2),
    ResponseNotifyFun = internal_add_wlan_result({RadioId, WlanId}, NotifyFun, _, _, _),
    send_request(Header, ieee_802_11_wlan_configuration_request, ReqElements, ResponseNotifyFun, Data);

internal_add_wlan(RadioId, WlanId, NotifyFun, Data)
  when RadioId == false orelse WlanId == false ->
    %% the requested Radio/WLan combination might not be configured,
    %% do nothing....
    response_notify(NotifyFun, -1, unconfigured, Data).

internal_add_wlan_result({RadioId, WlanId} = WlanIdent,
			 NotifyFun, Code, {_, Elements, _} = Arg,
			 #data{data_channel_address = WTPDataChannelAddress,
			       id = CommonName, config = Config, wlans = Wlans} = Data0)
  when Code == 0 ->
    ?LOG(debug, "IEEE 802.11 WLAN Configuration ok for ~p", [CommonName]),
    BSSIdIEs = get_ies(ieee_802_11_assigned_wtp_bssid, Elements),
    Data1 = Data0#data{config = Config#wtp{broken_add_wlan_workaround = (BSSIdIEs =:= [])}},

    if (BSSIdIEs == [] andalso length(Wlans) /= 1) ->
	    %% no BSS Id and multiple Wlans, this can not work, error out
	    ?LOG(error, "~p: WTP with broken Add WLAN Response and multiple "
			"WLAN is not working", [CommonName]);
       BSSIdIEs == [] ->
	    %% no BSS Ids means the WTP is broken, activate workaround
	    ?LOG(warning, "~p: WTP with broken Add WLAN Response, "
			  "upgrade as soon as possible", [CommonName]);
       true ->
	    ok
    end,

    Data = update_wlan_state(
	     WlanIdent,
	     fun(W0 = #wlan{vlan = VlanId}) ->
		     W = case BSSIdIEs of
			     [#ieee_802_11_assigned_wtp_bssid{bssid = BSS}] ->
				 %% TODO: include the Mobility Domain ?
				 ok = capwap_wtp_reg:register(BSS),
				 capwap_dp:add_wlan(WTPDataChannelAddress,
						    RadioId, WlanId, BSS, VlanId),
				 W0#wlan{state = running, bss = BSS};
			     _ ->
				 W0#wlan{state = running}
			  end,
		     start_group_rekey_timer(W)
	     end, Data1),
    response_notify(NotifyFun, Code, Arg, Data);

internal_add_wlan_result(WlanIdent, NotifyFun, Code, Arg, #data{id = CommonName} = Data0) ->
    ?LOG(warning, "IEEE 802.11 WLAN Configuration failed for ~p with ~w", [CommonName, Code]),
    Data = update_wlan_state(WlanIdent,
			      fun(W) -> W#wlan{state = unconfigured} end, Data0),
    response_notify(NotifyFun, Code, Arg, Data).

internal_del_wlan(WlanIdent = {RadioId, WlanId}, NotifyFun,
		  Data = #data{data_channel_address = WTPDataChannelAddress}) ->
    capwap_dp:del_wlan(WTPDataChannelAddress, RadioId, WlanId),
    WBID = ?CAPWAP_BINDING_802_11,
    Flags = [{frame,'802.3'}],
    Header = #capwap_header{radio_id = RadioId, wb_id = WBID, flags = Flags},
    ReqElemDel = [#ieee_802_11_delete_wlan{
		     radio_id = RadioId,
		     wlan_id = WlanId}
		 ],
    Data0 = send_request(Header, ieee_802_11_wlan_configuration_request, ReqElemDel, NotifyFun, Data),
    remove_wlan(WlanIdent, Data0).

remove_wlan(WlanIdent, Data = #data{wlans = Wlans}) ->
    case get_wlan(WlanIdent, Data) of
	Wlan = #wlan{bss = BSS} ->
	    ok = capwap_wtp_reg:unregister(BSS),
	    stop_group_rekey_timer(Wlan);
	_ ->
	    ok
    end,
    LessWlans = lists:keydelete(WlanIdent, #wlan.wlan_identifier, Wlans),
    Data#data{wlans = LessWlans}.

radio_rsn_cipher_capabilities(#wtp_radio{supported_cipher_suites = Suites},
			      #wtp_wlan_config{
				 rsn = #wtp_wlan_rsn{
					  group_mgmt_cipher_suite = MgmtSuite,
					  capabilities = Caps0} = RSN0,
				 management_frame_protection = MFP})
  when MFP /= false ->
    ?LOG(debug, "Suites: ~p", [Suites]),
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
		   vlan = VlanId,
		   privacy = Privacy,
		   fast_transition = FT,
		   mobility_domain = MDomain,
		   secret = Secret,
		   peer_rekey = PeerRekey,
		   group_rekey = GroupRekey,
		   strict_group_rekey = StrictGroupRekey} = WlanConfig,
		#data{mac_types = MacTypes, tunnel_modes = TunnelModes}) ->

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
	       vlan = VlanId,
	       privacy = Privacy,
	       fast_transition = FT,
	       mobility_domain = MDomain,
	       information_elements = [],
	       wpa_config = #wpa_config{
			       ssid = SSID,
			       privacy = Privacy,
			       mobility_domain = MDomain,
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

update_key(Key = #ieee80211_key{cipher = Cipher, index = Index}) ->
    Key#ieee80211_key{index = Index bxor 1,
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

maybe_fixup_wlan(RadioMAC, #wlan{wlan_identifier = WlanIdent, bss = undefined},
		 #data{config = #wtp{broken_add_wlan_workaround = true}} = Data) ->
    update_wlan_state(WlanIdent, fun(W) -> W#wlan{bss = RadioMAC} end, Data);
maybe_fixup_wlan(_RadioMAC, _Wlan, Data) ->
    Data.

get_wlan(WlanIdent, #data{wlans = Wlans}) ->
    lists:keyfind(WlanIdent, #wlan.wlan_identifier, Wlans).

get_wlan_by_bss(BSS, #data{config = #wtp{broken_add_wlan_workaround = true},
			    wlans = Wlans}) ->
    case lists:keyfind(BSS, #wlan.bss, Wlans) of
	false when length(Wlans) == 1 ->
	    hd(Wlans);
	Other ->
	    Other
    end;
get_wlan_by_bss(BSS, #data{wlans = Wlans}) ->
    lists:keyfind(BSS, #wlan.bss, Wlans).

update_wlan_state(WlanIdent, Fun, Data = #data{wlans = Wlans})
  when is_function(Fun, 1) ->
    Wlan =
	case get_wlan(WlanIdent, Data) of
	    false ->
		#wlan{wlan_identifier = WlanIdent};
	    Tuple ->
		Tuple
	end,
    Data#data{wlans =
		    lists:keystore(WlanIdent, #wlan.wlan_identifier, Wlans, Fun(Wlan))}.

get_station_cfg(#wlan{mac_mode = MacMode, tunnel_mode = TunnelMode,
		      information_elements = IEs,
		      wpa_config = WpaConfig, gtk = GTK, igtk = IGTK},
		BSS,
		#data{id = WtpId, session_id = SessionId,
		       data_channel_address = WTPDataChannelAddress, data_path = DataPath}) ->
    #station_config{
       data_path = DataPath, wtp_data_channel_address = WTPDataChannelAddress,
       wtp_id = WtpId, wtp_session_id = SessionId,
       mac_mode = MacMode, tunnel_mode = TunnelMode,
       bss = BSS, bss_ies = IEs, wpa_config = WpaConfig,
       gtk = GTK, igtk = IGTK
      }.

internal_new_station(#wlan{}, StationMAC, _BSS,
		     Data = #data{config = #wtp{max_stations = MaxStations},
				    station_count  = StationCount})
  when StationCount + 1 > MaxStations ->
    ?LOG(debug, "Station ~p trying to associate, but wtp is full: ~p >= ~p",
		[StationMAC, StationCount, MaxStations]),
    {{error, too_many_clients}, Data};

internal_new_station(Wlan = #wlan{}, StationMAC, BSS,
		     Data0 = #data{id = WtpId, station_count = StationCount}) ->

    Data = maybe_fixup_wlan(BSS, Wlan, Data0),

    %% we have to repeat the search again to avoid a race
    ?LOG(debug, "search for station ~p", [{self(), StationMAC}]),
    case capwap_station_reg:lookup(self(), BSS, StationMAC) of
	not_found ->
	    exometer:update([capwap, ac, station_count], 1),
	    exometer:update([capwap, wtp, WtpId, station_count], StationCount + 1),
	    StationCfg = get_station_cfg(Wlan, BSS, Data),
	    Reply =
		case capwap_station_reg:lookup(StationMAC) of
		    not_found ->
			?LOG(debug, "starting station: ~p", [StationMAC]),
			capwap_station_sup:new_station(self(), StationMAC, StationCfg);
		    {ok, Station0} ->
			?LOG(debug, "TAKE-OVER: station ~p found as ~p", [{self(), StationMAC}, Station0]),
			ieee80211_station:take_over(Station0, self(), StationCfg)
		end,
	    {Reply, Data#data{station_count = StationCount + 1}};

	Ok = {ok, Station0} ->
	    ?LOG(debug, "station ~p found as ~p", [{self(), StationMAC}, Station0]),
	    {Ok, Data}
    end;
internal_new_station(_, StationMAC, BSS, Data) ->
    ?LOG(debug, "Station ~p trying to associate on invalid Wlan ~p", [StationMAC, BSS]),
    {{error, invalid_bss}, Data}.

internal_add_station(#wlan{wlan_identifier = {RadioId, WlanId}, vlan = VlanId, bss = BSS}, MAC, StaCaps,
		     {_, Encryption, _} = CryptoData,
		     NotifyFun, Data = #data{data_channel_address = WTPDataChannelAddress}) ->
    Ret = capwap_dp:attach_station(WTPDataChannelAddress, MAC, VlanId, RadioId, BSS),
    ?LOG(debug, "attach_station(~p, ~p, ~p, ~p, ~p): ~p", [WTPDataChannelAddress, MAC, VlanId, RadioId, BSS, Ret]),

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
    ReqElements = station_session_key(RadioId, WlanId, MAC, CryptoData, ReqElements0),
    Header = #capwap_header{radio_id = RadioId, wb_id = WBID, flags = Flags},
    send_request(Header, station_configuration_request, ReqElements, NotifyFun, Data);

internal_add_station(_, _MAC, _StaCaps, _CryptoData, NotifyFun, Data) ->
    response_notify(NotifyFun, -1, [], Data).

station_session_key(_RadioId, _WlanId, MAC, {AKMonly, false, CipherData}, IEs)
  when is_record(CipherData, ccmp) ->
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

internal_del_station(#wlan{wlan_identifier = {RadioId, _WlanId}}, MAC, Data) ->
    Ret = capwap_dp:detach_station(MAC),
    ?LOG(debug, "detach_station(~p): ~p", [MAC, Ret]),

    WBID = ?CAPWAP_BINDING_802_11,
    Flags = [{frame,'802.3'}],
    ReqElements = [#delete_station{
		      radio_id	= RadioId,
		      mac	= MAC
		     }],
    Header = #capwap_header{radio_id = RadioId, wb_id = WBID, flags = Flags},
    send_request(Header, station_configuration_request, ReqElements, Data);

internal_del_station(_, MAC, Data) ->
    Ret = capwap_dp:detach_station(MAC),
    ?LOG(debug, "detach_station(~p, ~p): ~p", [MAC, Ret]),
    Data.

sendto(Header, PayLoad, #data{data_channel_address = WTPDataChannelAddress}) ->
    Packet = hd(capwap_packet:encode(data, {Header, PayLoad})),
    capwap_trace:trace(?TRACE_LOCAL_DATA, WTPDataChannelAddress, Packet),
    capwap_dp:sendto(WTPDataChannelAddress, Packet).

internal_send_80211_station(#wlan{wlan_identifier = {RadioId, _WlanId}}, PayLoad, Data) ->
    WBID = ?CAPWAP_BINDING_802_11,
    Header = #capwap_header{
		 radio_id = RadioId,
		 wb_id = WBID,
		 flags = [{frame, 'native'}]},
    sendto(Header, PayLoad, Data);

internal_send_80211_station(_, _, _) ->
    ok.

get_admin_wifi_updates(Data, IEs) ->
    StartedWlans = get_ies(ieee_802_11_tp_wlan, IEs),
    ?LOG(debug, "Found Admin Wlans started by the WTP: ~p", [StartedWlans]),
    AdminSSIds = wtp_config_get(Data#data.id, [{admin_ssids, admin_ssids, []}]),
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
	    ?LOG(debug, "Sending ieee_802_11_tp_wlan to change a preconfigured Admin SSID: ~p->~p",
			[RemoteConfSSId, LocalConfSSId]),
	    UpdatedWlan = Wlan#ieee_802_11_tp_wlan{ssid = LocalConfSSId, key = LocalConfKey},
	    get_admin_wifi_update(RestWlan, AdminSSIds, [UpdatedWlan | Accu])
    end.

start_group_rekey_timer(#wlan{wlan_identifier = WlanIdent,
			      wpa_config = #wpa_config{group_rekey = Timeout}} = Wlan)
  when is_integer(Timeout) andalso Timeout > 0 ->
    TRef = erlang:send_after(Timeout * 1000, self(), {group_rekey, WlanIdent}),
    Wlan#wlan{group_rekey_timer = TRef};
start_group_rekey_timer(Wlan) ->
    Wlan.

stop_group_rekey_timer(#wlan{group_rekey_timer = TRef} = Wlan)
  when is_reference(TRef) ->
    cancel_timer(TRef),
    Wlan#wlan{group_rekey_timer = undefined};
stop_group_rekey_timer(Wlan) ->
    Wlan.

start_gtk_rekey(WlanIdent = {RadioId, WlanId},
		Wlan0 = #wlan{bss = BSS, group_rekey_state = idle},
		Data0) ->
    Wlan1 = stop_group_rekey_timer(Wlan0),
    Wlan2 = update_wlan_group_keys(Wlan1),

    Stations = capwap_station_reg:list_stations(self(), BSS),
    ?LOG(debug, "GTK ReKey Stations: ~p", [Stations]),

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

    Data1 = update_wlan_state(WlanIdent, fun(_W) -> Wlan end, Data0),
    send_request(Header, ieee_802_11_wlan_configuration_request, ReqElements, NotifyFun, Data1);

start_gtk_rekey({RadioId, WlanId}, Wlan, Data) ->
    ?LOG(warning, "failed to start GTK rekey for ~w:~w (~p)", [RadioId, WlanId, Wlan]),
    Data.

%% Note: failures will be handled the FSM event function
start_gtk_rekey_result(WlanIdent, Stations, Code, _Arg, Data)
  when Code == 0 ->
    update_wlan_state(WlanIdent,
		      fun(W = #wlan{gtk = GTK, igtk = IGTK}) ->
			      {ok, _Pid} = capwap_ac_gtk_rekey:start_link({self(), WlanIdent},
									  GTK, IGTK, Stations),
			      W#wlan{group_rekey_state = running}
		      end, Data);

start_gtk_rekey_result(WlanIdent, _Stations, _Code, _Arg, Data) ->
    update_wlan_state(WlanIdent, fun(W) -> W#wlan{group_rekey_state = failed} end, Data).




finish_gtk_rekey(WlanIdent = {RadioId, WlanId},
		 Wlan0 = #wlan{group_rekey_state = running},
		 Data0) ->
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

    Data1 = update_wlan_state(WlanIdent, fun(_W) -> Wlan end, Data0),
    ReqElements = [set_wlan_keys(Wlan, UpdateWlan)],
    send_request(Header, ieee_802_11_wlan_configuration_request, ReqElements, NotifyFun, Data1);

finish_gtk_rekey({RadioId, WlanId}, Wlan, Data) ->
    ?LOG(warning, "failed to start GTK rekey for ~w:~w (~p)", [RadioId, WlanId, Wlan]),
    Data.

%% Note: failures will be handled the FSM event function
finish_gtk_rekey_result(WlanIdent, Code, _Arg, Data) ->
    ReKeyData = if Code == 0 -> idle;
		   true      -> failed
		 end,
    update_wlan_state(WlanIdent, fun(W0) ->
					 W = W0#wlan{group_rekey_state = ReKeyData},
					 start_group_rekey_timer(W)
				 end, Data).

wtp_stats_to_accouting({RcvdPkts, SendPkts, RcvdBytes, SendBytes,
			RcvdFragments, SendFragments,
			ErrInvalidStation, ErrFragmentInvalid, ErrFragmentTooOld}) ->
    #{'InPackets'  => RcvdPkts,
      'OutPackets' => SendPkts,
      'InOctets'   => RcvdBytes,
      'OutOctets'  => SendBytes,
      'Received-Fragments'     => RcvdFragments,
      'Send-Fragments'         => SendFragments,
      'Error-Invalid-Stations' => ErrInvalidStation,
      'Error-Fragment-Invalid' => ErrFragmentInvalid,
      'Error-Fragment-Too-Old' => ErrFragmentTooOld};
wtp_stats_to_accouting(_) ->
    #{}.

accounting_update(#data{session = Session, data_channel_address = WTPDataChannelAddress}) ->
    CommonName = ergw_aaa_session:get(Session, 'Username', <<"unknown">>),
    WTPStats = capwap_dp:get_wtp(WTPDataChannelAddress),
    ?LOG(debug, "WTP: ~p, ~p", [WTPDataChannelAddress, WTPStats]),
    {_, _WLANs, _STAs, _RefCnt, _MTU, Stats} = WTPStats,
    Acc = wtp_stats_to_accouting(Stats),

    maps:fold(fun(Key, Value, _) ->
		      exometer:update([capwap, wtp, CommonName, Key], Value)
	      end, ok, Acc),
    Acc.

stop_wtp(run, #data{data_channel_address = WTPDataChannelAddress}) ->
    ?LOG(error, "STOP_WTP in run"),
    case catch (capwap_dp:del_wtp(WTPDataChannelAddress)) of
	{ok, {WTPDataChannelAddress, _WLANs, _Stations, _RefCnt, _MTU, Stats} = Values} ->
	    ?LOG(debug, "Delete WTP: ~p, ~p", [WTPDataChannelAddress, Values]),
	    wtp_stats_to_accouting(Stats);
	Other ->
	    ?LOG(debug, "WTP del failed with: ~p", [Other]),
	    #{}
    end;
stop_wtp(State, Data) ->
    ?LOG(error, "STOP_WTP in ~p with ~p", [State, Data]),
    #{}.

response_notify(NotifyFun, Code, Arg, Data)
  when is_function(NotifyFun, 3) ->
    NotifyFun(Code, Arg, Data);
response_notify(undefined, _, _, Data) ->
    Data.

internal_add_station_response_fun(From) ->
    internal_add_station_response(From, _, _, _).

internal_add_station_response(From, 0, _, Data) ->
    ?LOG(debug, "Station Configuration ok"),
    gen_statem:reply(From, ok),
    Data;
internal_add_station_response(From, Code, _, Data) ->
    ?LOG(warning, "Station Configuration failed with ~w", [Code]),
    gen_statem:reply(From, {error, Code}),
    Data.

%%%===================================================================
%%% Accounting/Charging support
%%%===================================================================

handle_session_evs([], Data) ->
    Data;
handle_session_evs([H|T], Data) ->
    handle_session_ev(H, handle_session_evs(T, Data)).

update_timer_svc_def(Service, Definition, Map) ->
    maps:update_with(Service,
		     fun({_, TRef}) -> {Definition, TRef} end,
		     {Definition, undefined}, Map).

update_timer(Level, Service, Definition, Timers) ->
    maps:update_with(Level, update_timer_svc_def(Service, Definition, _),
		     #{Service => {Definition, undefined}}, Timers).

handle_session_ev({set, {Service, {Type, Level, Interval, Opts}}},
		  #data{timers = Timers} = Data) ->
    Definition = {Type, Interval, Opts},
    Data#data{timers = update_timer(Level, Service, Definition, Timers)};
handle_session_ev(_, Data) ->
    Data.

start_session_timers(#data{timers = Timers} = Data) ->
    Data#data{timers =
		  maps:fold(fun start_session_timers/3, Timers, Timers)}.

start_session_timers('IP-CAN' = K, V, M) ->
    M#{K => maps:fold(fun start_session_timer/3, V, V)};
start_session_timers(_, _, M) ->
    M.

stop_session_timer(Ref) when is_reference(Ref) ->
    erlang:cancel_timer(Ref, [{async, true}, {info, false}]);
stop_session_timer(_) ->
    ok.

start_session_timer(K, {{_, TimeOut, _} = Type, TRef}, M) ->
    stop_session_timer(TRef),
    M#{K => {Type, erlang:start_timer(TimeOut * 1000, self(), K)}}.

handle_session_timer(TRef, {accounting, Level, _} = Ev, #data{timers = Timers0} = Data)
  when is_map_key(Level, Timers0) ->
    case maps:take(Level, Timers0) of
	{#{Ev := {Timer, TRef}}, Timers} ->
	    handle_session_timer_ev(Ev, Timer, Data#data{timers = Timers});
	_ ->
	    keep_state_and_data
    end;
handle_session_timer(_TRef, _Ev, _Data) ->
    keep_state_and_data.

handle_session_timer_ev({_, Level, _} = Ev, {Interval, _, _Opts} = Timer,
			#data{session = Session, timers = Timers} = Data0) ->
    Acc = accounting_update(Data0),
    ergw_aaa_session:invoke(Session, Acc, interim, #{async => true}),

    Data =
	case Interval of
	    periodic ->
		M = maps:get(Level, Timers, #{}),
		Data0#data{
		  timers = Timers#{Level => start_session_timer(Ev, {Timer, undefined}, M)}};
	    _ ->
		Data0
	end,
    {keep_state, Data}.
