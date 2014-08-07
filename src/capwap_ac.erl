-module(capwap_ac).

-behaviour(gen_fsm).

%% API
-export([start_link/1, accept/3, get_peer_data/1, take_over/1, new_station/3,
         station_terminating/1]).

%% Extern API
-export([firmware_download/3,
         set_ssid/3,
         stop_radio/2]).

%% gen_fsm callbacks
-export([init/1, listen/2, idle/2, join/2, configure/2, data_check/2, run/2,
	 idle/3, join/3, configure/3, data_check/3, run/3,
	 handle_event/3,
	 handle_sync_event/4, handle_info/3, terminate/3, code_change/4]).

-export([handle_packet/3, handle_data/5]).

-compile({inline,log_capwap_control/5}).

-include_lib("public_key/include/OTP-PUB-KEY.hrl").
-include("capwap_debug.hrl").
-include("capwap_packet.hrl").

-define(SERVER, ?MODULE).

%% TODO: convert constants into configuration values
-define(IDLE_TIMEOUT, 30 * 1000).
-define(SSL_ACCEPT_TIMEOUT, 30 * 1000).
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
	  request_queue,
	  retransmit_timer,
	  retransmit_counter,
	  echo_request_timer,
	  echo_request_timeout,
	  seqno = 0,
	  version,
	  event_log,
          station_count = 0,
          radios
}).

-record(radio, {
          radio_id,
          ssid,
          started = false,
          reply_to_after_start
         }).

-define(DEBUG_OPTS,[{install, {fun lager_sys_debug:lager_gen_fsm_trace/3, ?MODULE}}]).

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
    gen_fsm:start_link(?MODULE, [Peer], [{debug, ?DEBUG_OPTS}]).

handle_packet(Address, Port, Packet) ->
    try
	Peer = format_peer({Address, Port}),
	case capwap_packet:decode(control, Packet) of
	    {Header, {discovery_request, 1, Seq, Elements}} ->
		log_capwap_control(Peer, discovery_request, Seq, Elements, Header),
		Answer = answer_discover(Peer, Seq, Elements, Header),
		{reply, Answer};
	    {Header, {join_request, 1, Seq, Elements}} ->
		log_capwap_control(Peer, join_request, Seq, Elements, Header),
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

handle_data(FlowSwitch, Sw, Address, Port, Packet) ->
    try
	lager:debug("capwap_data: ~p, ~p, ~p", [Address, Port, Packet]),
	case capwap_packet:decode(data, Packet) of
	    {Header, PayLoad} ->
		KeepAlive = proplists:get_bool('keep-alive', Header#capwap_header.flags),
		handle_capwap_data(FlowSwitch, Sw, Address, Port, Header, KeepAlive, PayLoad);
	    _ ->
		{error, not_capwap}
	end
    catch
	Class:Error ->
	    lager:debug("failure: ~p:~p", [Class, Error]),
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

station_terminating(AC) ->
    gen_fsm:send_all_state_event(AC, station_terminating).

%%%===================================================================
%%% extern APIs
%%%===================================================================

firmware_download(CommonName, DownloadLink, Sha) ->
    case capwap_wtp_reg:lookup(CommonName) of
        {ok, Pid} ->
            gen_fsm:send_event(Pid, {firmware_download, DownloadLink, Sha});
        not_found ->
            {error, not_found}
    end.

set_ssid(CommonName, SSID, RadioID) ->
    case capwap_wtp_reg:lookup(CommonName) of
        {ok, Pid} ->
            gen_fsm:sync_send_all_state_event(Pid, {set_ssid, SSID, RadioID});
        not_found ->
            {error, not_found}
    end.

stop_radio(CommonName, RadioID) ->
    case capwap_wtp_reg:lookup(CommonName) of
        {ok, Pid} ->
            gen_fsm:sync_send_all_state_event(Pid, {stop_radio, RadioID});
        not_found ->
            {error, not_found}
    end.

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
    process_flag(trap_exit, true),
    capwap_wtp_reg:register(Peer),
    {ok, listen, #state{peer = Peer, request_queue = queue:new(),
                        radios = []}, 5000}.

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

    State1 = State0#state{event_log = open_log(),
                          session = Session,
                          socket = {udp, Socket},
                          id = undefined},
    next_state(idle, State1);

listen({accept, dtls, Socket}, State) ->
    lager:info("ssl_accept on: ~p", [Socket]),

    {ok, Session} = start_session(Socket, State),
    case ssl:ssl_accept(Socket, mk_ssl_opts(Session), ?SSL_ACCEPT_TIMEOUT) of
        {ok, SslSocket} ->
            lager:info("ssl_accept: ~p", [SslSocket]),
            {ok, {Address, _Port}} = ssl:peername(SslSocket),
            ssl:setopts(SslSocket, [{active, true}, {mode, binary}]),

            CommonName = common_name(SslSocket),
            lager:debug("ssl_cert: ~p", [CommonName]),

            maybe_takeover(CommonName),
            capwap_wtp_reg:register_args(CommonName, Address),

            State1 = State#state{event_log = open_log(), socket = {dtls, SslSocket}, session = Session, id = CommonName},
            %% TODO: find old connection instance, take over their StationState and stop them
            next_state(idle, State1);
        Other ->
            lager:error("ssl_accept failed: ~p", [Other]),
            {stop, normal, State#state{session=Session}}
    end;


listen(timeout, State) ->
    {stop, normal, State}.

idle({keep_alive, _FlowSwitch, _Sw, _PeerId, Header, PayLoad}, _From, State) ->
    lager:warning("in IDLE got unexpected keep_alive: ~p", [{Header, PayLoad}]),
    reply({error, unexpected}, idle, State).

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
     State0 = #state{peer = {Address, _}, session = Session}) ->
    Version = get_wtp_version(Elements),
    SessionId = proplists:get_value(session_id, Elements),
    capwap_wtp_reg:register_sessionid(Address, SessionId),

    MacTypes = ie(wtp_mac_type, Elements),
    TunnelModes = ie(wtp_frame_tunnel_mode, Elements),
    State1 = State0#state{mac_types = MacTypes, tunnel_modes = TunnelModes, version = Version},

    RespElements = ac_info_version(join, Version) ++ [#result_code{result_code = 0}],
    Header = #capwap_header{radio_id = RadioId, wb_id = WBID, flags = Flags},
    State = send_response(Header, join_response, Seq, RespElements, State1),
    SessionOpts = wtp_accounting_infos(Elements, [{'TP-CAPWAP-Radio-Id', RadioId}]),
    lager:info("WTP Session Start Opts: ~p", [SessionOpts]),
    ctld_session:start(Session, SessionOpts),
    next_state(join, State);

idle({Msg, Seq, Elements, Header}, State) ->
    lager:warning("in IDLE got unexpexted: ~p", [{Msg, Seq, Elements, Header}]),
    next_state(idle, State).

join({keep_alive, _FlowSwitch, _Sw, _PeerId, Header, PayLoad}, _From, State) ->
    lager:warning("in JOIN got unexpected keep_alive: ~p", [{Header, PayLoad}]),
    reply({error, unexpected}, join, State).

join(timeout, State) ->
    lager:info("timeout in JOIN -> stop"),
    {stop, normal, State};

join({configuration_status_request, Seq, Elements, #capwap_header{
					   radio_id = RadioId, wb_id = WBID, flags = Flags}},
     State) ->
    SessionAttrs = ['TP-CAPWAP-Power-Save-Idle-Timeout',
                    'TP-CAPWAP-Power-Save-Busy-Timeout',
                    'CAPWAP-Echo-Request-Interval',
                    'CAPWAP-Discovery-Interval',
                    'CAPWAP-Idle-Timeout',
                    'CAPWAP-Data-Channel-Dead-Interval',
                    'CAPWAP-AC-Join-Timeout'],
    [PSMIdleTimeout, PSMBusyTimeout, EchoRequestInterval, DiscoveryInterval,
     IdleTimeout, DataChannelDeadInterval, ACJoinTimeout] =
        [Val || {ok, Val} <- [ctld_session:get(State#state.session, Key) || Key <- SessionAttrs]],
    %% only add admin pw when defined
    AdminPwIE = case ctld_session:get(State#state.session, 'CAPWAP-Admin-PW') of
                    {ok, Val} when is_binary(Val) ->
                        [#wtp_administrator_password_settings{password = Val}];
                    _ ->
                        []
                end,
    AdminWlans = get_admin_wifi_updates(State, Elements),
    {ok, WlanHoldTime} = ctld_session:get(State#state.session, 'CAPWAP-Wlan-Hold-Time'),
    RespElements = [%%#ac_ipv4_list{ip_address = [<<0,0,0,0>>]},
                    #timers{discovery = DiscoveryInterval,
                            echo_request = EchoRequestInterval},
                    #tp_data_channel_dead_interval{data_channel_dead_interval = DataChannelDeadInterval},
                    #tp_ac_join_timeout{ac_join_timeout = ACJoinTimeout},
                    #decryption_error_report_period{
                       radio_id = RadioId,
                       report_interval = 15},
                    #idle_timeout{timeout = IdleTimeout},
                    #power_save_mode{idle_timeout = PSMIdleTimeout,
                                     busy_timeout = PSMBusyTimeout},
                    #tp_ieee_802_11_wlan_hold_time{radio_id  = RadioId,
                                                   wlan_id   = 1,
                                                   hold_time = WlanHoldTime}
                   ] ++ AdminPwIE ++ AdminWlans,
    Header = #capwap_header{radio_id = RadioId, wb_id = WBID, flags = Flags},
    State1 = send_response(Header, configuration_status_response, Seq, RespElements, State),

    EchoRequestTimeout = EchoRequestInterval * 2,
    next_state(configure, State1#state{echo_request_timeout = EchoRequestTimeout});

join({Msg, Seq, Elements, Header}, State) ->
    lager:warning("in JOIN got unexpexted: ~p", [{Msg, Seq, Elements, Header}]),
    next_state(join, State).

configure({keep_alive, _FlowSwitch, _Sw, _PeerId, Header, PayLoad}, _From, State) ->
    lager:warning("in CONFIGURE got unexpected keep_alive: ~p", [{Header, PayLoad}]),
    reply({error, unexpected}, configure, State).

configure(timeout, State) ->
    lager:info("timeout in CONFIGURE -> stop"),
    {stop, normal, State};

configure({change_state_event_request, Seq, _Elements, #capwap_header{
					      radio_id = RadioId, wb_id = WBID, flags = Flags}},
	  State) ->
    Header = #capwap_header{radio_id = RadioId, wb_id = WBID, flags = Flags},
    State1 = send_response(Header, change_state_event_response, Seq, [], State),
    next_state(data_check, State1);

configure({Msg, Seq, Elements, Header}, State) ->
    lager:debug("in configure got: ~p", [{Msg, Seq, Elements, Header}]),
    next_state(configure, State).

data_check({keep_alive, FlowSwitch, Sw, PeerId, Header, PayLoad}, _From, State) ->
    lager:info("in DATA_CHECK got expected keep_alive: ~p", [{Sw, Header, PayLoad}]),
    capwap_wtp_reg:register(PeerId),
    gen_fsm:send_event(self(), configure),
    reply({reply, {Header, PayLoad}}, run, State#state{peer_data = PeerId, flow_switch = FlowSwitch}).

data_check(timeout, State) ->
    lager:info("timeout in DATA_CHECK -> stop"),
    {stop, normal, State};

data_check({Msg, Seq, Elements, Header}, State) ->
    lager:warning("in DATA_CHECK got unexpexted: ~p", [{Msg, Seq, Elements, Header}]),
    next_state(data_check, State).

run({new_station, BSS, SA}, _From, State = #state{peer_data = PeerId, flow_switch = FlowSwitch,
                                                  mac_mode = MacMode, tunnel_mode = TunnelMode,
                                                  station_count  = StationCount,
                                                  session=Session}) ->
    lager:info("in RUN got new_station: ~p", [SA]),
    {ok, MaxStations} = ctld_session:get(Session, 'TP-CAPWAP-Max-WIFI-Clients'),
    WTPFullPred = StationCount + 1 > MaxStations,
    %% we have to repeat the search again to avoid a race
    lager:debug("search for station ~p", [{self(), SA}]),
    {State0, Reply} =
        case {capwap_station_reg:lookup(self(), SA),  WTPFullPred} of
            {not_found, true} ->
                lager:debug("Station ~p trying to associate, but wtp is full: ~p >= ~p", [SA, StationCount, MaxStations]),
                {State, {error, too_many_clients}};
            {not_found, false} ->
                case capwap_station_reg:lookup(SA) of
                    not_found ->
                        lager:debug("starting station: ~p", [SA]),
                        {State#state{station_count = StationCount + 1},
                         capwap_station_sup:new_station(self(), FlowSwitch, PeerId, BSS, SA, MacMode, TunnelMode)};
                    {ok, Station0} ->
                        lager:debug("TAKE-OVER: station ~p found as ~p", [{self(), SA}, Station0]),
                        {State#state{station_count = StationCount + 1},
                         ieee80211_station:take_over(Station0, self(), FlowSwitch, PeerId, BSS, MacMode, TunnelMode)}
                end;
            {Ok = {ok, Station0}, _} ->
                lager:debug("station ~p found as ~p", [{self(), SA}, Station0]),
                {State, Ok}
        end,
    reply(Reply, run, State0);

run({keep_alive, _FlowSwitch, Sw, _PeerId, Header, PayLoad}, _From, State) ->
    lager:debug("in RUN got expected keep_alive: ~p", [{Sw, Header, PayLoad}]),
    reply({reply, {Header, PayLoad}}, run, State).

run(echo_timeout, State) ->
    lager:info("Echo Timeout in Run"),
    {stop, normal, State};

run({echo_request, Seq, Elements, #capwap_header{
			  radio_id = RadioId, wb_id = WBID, flags = Flags}},
    State) ->
    lager:debug("EchoReq in Run got: ~p", [{Seq, Elements}]),
    Header = #capwap_header{radio_id = RadioId, wb_id = WBID, flags = Flags},
    State1 = send_response(Header, echo_response, Seq, Elements, State),
    State2 = reset_echo_request_timer(State1),
    next_state(run, State2);

run({ieee_802_11_wlan_configuration_response, _Seq,
     Elements, _Header}, State = #state{}) ->
    State1 =
        case proplists:get_value(result_code, Elements) of
            0 ->
                lager:debug("IEEE 802.11 WLAN Configuration ok"),
                case lists:keyfind(false, #radio.started, State#state.radios) of
                    #radio{ssid = SSID, radio_id = RadioId,
                           reply_to_after_start=From} ->
                        State0 = internal_add_wlan(State, SSID, RadioId),
                        gen_fsm:reply(From, ok),
                        State0;
                    _ ->
                        State
                end;
            Code ->
                lager:warning("IEEE 802.11 WLAN Configuration failed with ~w", [Code]),
                State
        end,
    State2 = reset_echo_request_timer(State1),
    next_state(run, State2);

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
    State1 = reset_echo_request_timer(State),
    next_state(run, State1);

run({configuration_update_responce, _Seq,
     Elements, _Header}, State) ->
    %% TODO: timeout and Error handling, e.g. shut the station process down when the Add Station failed
    case proplists:get_value(result_code, Elements) of
    0 ->
        lager:debug("Configuration Update ok"),
        ok;
    Code ->
        lager:warning("Configuration Update failed with ~w", [Code]),
        ok
    end,
    State1 = reset_echo_request_timer(State),
    next_state(run, State1);

run(configure, State = #state{id = WtpId, session = Session}) ->
    lager:debug("configure WTP: ~p", [WtpId]),
    RadioId = 1,
    {ok, SSID} = ctld_session:get(Session, 'TP-CAPWAP-SSID'),
    State1 = internal_add_wlan(State, SSID, RadioId),
    next_state(run, State1);

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

run({wtp_event_request, Seq, Elements, RequestHeader =
	 #capwap_header{radio_id = RadioId, wb_id = WBID, flags = Flags}}, State = #state{peer = Peer, id = Id}) ->
    ResponseHeader = #capwap_header{radio_id = RadioId, wb_id = WBID, flags = Flags},
    State1 = send_response(ResponseHeader, wtp_event_response, Seq, [], State),
    State2 = handle_wtp_event(Elements, RequestHeader, State1),
    Now = calendar:now_to_universal_time(erlang:now()),
    {FormatString, FormatVars} = lists:foldl(
                                   fun
                                       ({Key, Value}, {FStr, FVars}) ->
                                           {FStr ++ "~p(~p), ", FVars ++ [Key, Value]};
                                       (Record, {FStr, FVars}) ->
                                           {FStr ++ "~p, ", FVars ++ [Record]}
                                   end, {"~p(~p)@~p: ", [Peer, Id, Now]}, Elements),
    EventData = io_lib:format(FormatString ++ "~n", FormatVars),
    ok = disk_log:blog(State#state.event_log, EventData),
    State3 = reset_echo_request_timer(State2),
    next_state(run, State3);

run({firmware_download, DownloadLink, Sha}, State) ->
    Flags = [{frame,'802.3'}],
    ReqElements = [#firmware_download_information{
        sha256_image_hash = Sha,
        download_uri = DownloadLink}],
    Header1 = #capwap_header{radio_id = 1, wb_id = 1, flags = Flags},
    State1 = send_request(Header1, configuration_update_request, ReqElements, State),
    next_state(run, State1);

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
handle_event(station_terminating, StateName, State=#state{station_count = SC}) ->
    if SC == 0 ->
            lager:error("Station counter and stations got out of sync", []),
            next_state(StateName, State);
       true ->
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
handle_sync_event({set_ssid, SSID, RadioId}, From, run, State) ->
    case get_radio(State, RadioId) of
        false ->
            State1 = internal_add_wlan(State, SSID, RadioId),
            reply(ok, run, State1);
        #radio{} ->
            State1 = internal_del_wlan(State, RadioId),
            State2 = set_radio(State1, #radio{started=false,
                                              reply_to_after_start=From,
                                              ssid = SSID,
                                              radio_id = RadioId}),
            next_state(run, State2)
    end;

handle_sync_event({stop_radio, RadioId}, _From, run, State) ->
    case get_radio(State, RadioId) of
        false ->
            reply({error, not_active}, run, State);
        #radio{} ->
            State1 = internal_del_wlan(State, RadioId),
            reply(ok, run, State1)
    end;

handle_sync_event({set_ssid, _SSID, _RadioId}, _From, StateName, State)
  when StateName =/= run ->
    reply({error, not_in_run_state}, StateName, State);

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
    lager:debug("in State ~p got UDP: ~p", [StateName, Packet]),
    handle_capwap_packet(Packet, StateName, State);

handle_info({ssl, Socket, Packet}, StateName, State = #state{socket = {_, Socket}}) ->
    lager:debug("in State ~p got DTLS: ~p", [StateName, Packet]),
    handle_capwap_packet(Packet, StateName, State);

handle_info({timeout, _, retransmit}, StateName, State) ->
    resend_request(StateName, State);
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
	  State = #state{peer_data = PeerId,
			 flow_switch = FlowSwitch, socket = Socket,
			 session = Session}) ->
    error_logger:info_msg("AC session terminating in state ~p with state ~p with reason ~p~n", [StateName, State, Reason]),
    case StateName of
        run ->
            FlowSwitch ! {wtp_down, PeerId},
            ok;
        _ ->
            ok
    end,
    if Session /= undefined -> ctld_session:stop(Session, []);
       true -> ok
    end,
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
format_peer({IP, Port}) ->
    io_lib:format("~s:~w", [inet_parse:ntoa(IP), Port]);
format_peer(IP) ->
    io_lib:format("~p", [IP]).

peer_log_str(#state{id = undefined, peer = Peer}) ->
    io_lib:format("~p", [Peer]);
peer_log_str(#state{id = Id, peer = Peer}) ->
    io_lib:format("~s[~s]", [Id, format_peer(Peer)]).

log_capwap_control(Id, MsgType, SeqNo, Elements,
		   #capwap_header{radio_id = RadioId, wb_id = WBID}) ->
    lager:info("~s: ~s(Seq: ~w, R-Id: ~w, WB-Id: ~w): ~p", [Id, capwap_packet:msg_description(MsgType), SeqNo, RadioId, WBID, [lager:pr(E, ?MODULE) || E <- Elements]]).

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
					   radio_id = RadioId, wb_id = WBID, flags = Flags}) ->
    case application:get_env(capwap, enforce_dtls_control, true) of
	false ->
	    lager:warning("Accepting JOIN without DTLS from ~s", [Peer]),
	    accept;
	_ ->
	    lager:warning("Rejecting JOIN without DTLS from ~s", [Peer]),
	    RespElems = [#result_code{result_code = 18}],
	    Header = #capwap_header{radio_id = RadioId, wb_id = WBID, flags = Flags},
	    log_capwap_control(Peer, join_response, Seq, RespElems, Header),
	    Answer = capwap_packet:encode(control, {Header, {join_response, Seq, RespElems}}),
	    {reply, Answer}
    end.

handle_capwap_data(FlowSwitch, Sw, Address, Port, Header, true, PayLoad) ->
    lager:debug("CAPWAP Data KeepAlive: ~p", [PayLoad]),

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
    lager:debug("CAPWAP Data PayLoad:~n~p~n~p", [Header, Frame]),
    PeerId = {Address, Port},
    case capwap_wtp_reg:lookup(PeerId) of
	not_found ->
	    lager:warning("AC for data session no found: ~p", [PeerId]),
	    {error, not_found};
	{ok, AC} ->
	    %% TODO: multiple highly redundant case to follow, find a way to simplify
	    case proplists:get_value(frame, Flags) of
		'802.3' ->
		    lager:warning("got 802.3 payload Frame, what TODO with it???"),
		    case ieee80211_station:handle_ieee802_3_frame(AC, Frame) of
			{add, RadioMAC, MAC, MacMode, TunnelMode} ->
			    gen_fsm:send_event(AC, {add_station, Header, MAC}),
			    lager:debug("MacMode: ~w, TunnelMode ~w", [MacMode, TunnelMode]),
			    {add_flow, Sw, self(), Address, Port, RadioMAC, MAC, MacMode, TunnelMode, true};

			{flow, RadioMAC, MAC, MacMode, TunnelMode} ->
			    {add_flow, Sw, self(), Address, Port, RadioMAC, MAC, MacMode, TunnelMode, true};

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
			    lager:debug("MacMode: ~w, TunnelMode ~w", [MacMode, TunnelMode]),
			    {add_flow, Sw, self(), Address, Port, RadioMAC, MAC, MacMode, TunnelMode, false};

			{flow, RadioMAC, MAC, MacMode, TunnelMode} ->
			    {add_flow, Sw, self(), Address, Port, RadioMAC, MAC, MacMode, TunnelMode, false};

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
						   request_queue = Queue}) ->
    try	capwap_packet:decode(control, Packet) of
	{Header, {Msg, 1, Seq, Elements}} ->
	    %% Request
	    log_capwap_control(peer_log_str(State), Msg, Seq, Elements, Header),
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
	    log_capwap_control(peer_log_str(State), Msg, Seq, Elements, Header),
	    case queue:peek(Queue) of
            {value, {Seq, _}} ->
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

maybe_takeover(CommonName) ->
    case capwap_wtp_reg:lookup(CommonName) of
        {ok, OldPid} ->
            lager:info("take_over: ~p", [OldPid]),
            capwap_ac:take_over(OldPid);
        _ ->
            ok
    end.

open_log() ->
    EventLogBasePath = application:get_env(capwap, event_log_base_path, "."),
    EventLogPath = filename:join([EventLogBasePath, "events-capwap.log"]),
    lager:info("EventLogP: ~s", [EventLogPath]),

    ok = filelib:ensure_dir(EventLogPath),
    {ok, EventLog} = disk_log:open([{name, capwap_ac_log}, {file, EventLogPath}, {format, external}, {type, halt}]),
    EventLog.

handle_wtp_event(Elements, Header, State = #state{session = Session}) ->
    SessionOptsList = lists:foldl(fun(Ev, SOptsList) -> handle_wtp_stats_event(Ev, Header, SOptsList) end, [], Elements),
    if length(SessionOptsList) /= 0 ->
	    ctld_session:interim_batch(Session, SessionOptsList);
       true -> ok
    end,
    State.

handle_wtp_stats_event(#gps_last_acquired_position{timestamp = Timestamp,
                                                   wwan_id = _WwanId,
                                                   gpsatc = GpsString},
                       _Header, SOptsList) ->
    case [string:strip(V) || V <- string:tokens(binary_to_list(GpsString), ",:")] of
        [_, _Timestamp, Latitude, Longitude, Hdop, Altitude, _Fix, _Cog, _Spkm, _Spkn, _Date, _Nsat] ->
            Opts = [{'TP-CAPWAP-GPS-Timestamp', Timestamp},
                    {'TP-CAPWAP-GPS-Latitude', Latitude},
                    {'TP-CAPWAP-GPS-Longitude', Longitude},
                    {'TP-CAPWAP-GPS-Altitude', Altitude},
                    {'TP-CAPWAP-GPS-Hdop', Hdop}
                   ],
            lager:debug("WTP Event Opts: ~p", [Opts]),
            [ctld_session:to_session(Opts) | SOptsList];
        _ ->
            lager:error("Unable to parse GPSATC string from WTP! String: ~p", [GpsString]),
            SOptsList
    end;

handle_wtp_stats_event(#tp_wtp_wwan_statistics_0_9{timestamp = Timestamp, wwan_id = WWanId, rat = RAT,
					     rssi = RSSi, lac = LAC, cell_id = CellId},
		 _Header, SOptsList) ->
    Opts = [{'TP-CAPWAP-Timestamp', Timestamp},
            {'TP-CAPWAP-WWAN-Id',   WWanId},
            {'TP-CAPWAP-WWAN-RAT',       RAT},
            {'TP-CAPWAP-WWAN-RSSi',      RSSi},
            {'TP-CAPWAP-WWAN-LAC',       LAC},
            {'TP-CAPWAP-WWAN-Cell-Id',   CellId}],
    lager:debug("WTP Event Opts: ~p", [Opts]),
    [ctld_session:to_session(Opts) | SOptsList];
handle_wtp_stats_event(#tp_wtp_wwan_statistics{timestamp = Timestamp, wwan_id = WWanId, rat = RAT,
					 rssi = RSSi, creg = CREG, lac = LAC, latency = Latency,
					 mcc = MCC, mnc = MNC, cell_id = CellId},
		 _Header, SOptsList) ->
    Opts = [{'TP-CAPWAP-Timestamp', Timestamp},
            {'TP-CAPWAP-WWAN-Id',   WWanId},
            {'TP-CAPWAP-WWAN-RAT',       RAT},
            {'TP-CAPWAP-WWAN-RSSi',      RSSi},
            {'TP-CAPWAP-WWAN-CREG',      CREG},
            {'TP-CAPWAP-WWAN-LAC',       LAC},
            {'TP-CAPWAP-WWAN-Latency',   Latency},
            {'TP-CAPWAP-WWAN-MCC',       MCC},
            {'TP-CAPWAP-WWAN-MNC',       MNC},
            {'TP-CAPWAP-WWAN-Cell-Id',   CellId}],
    lager:debug("WTP Event Opts: ~p", [Opts]),
    [ctld_session:to_session(Opts) | SOptsList];
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
    Acc1 = [{'TP-CAPWAP-Session-Id', <<Value:128>>}|Acc],
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
    App = capwap,
    Versions = application:get_env(App, versions, []),
    AcList = if (Version > 16#010104 andalso Request == discover)
		orelse Version >= 16#010200 ->
		     [map_aalwp(I) || I <- application:get_env(App, ac_address_list_with_prio, [])];
		true -> []
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

reset_echo_request_timer(State = #state{echo_request_timer = Timer, echo_request_timeout = Timeout}) ->
    if is_reference(Timer) -> gen_fsm:cancel_timer(Timer);
       true -> ok
    end,
    State#state{echo_request_timer = gen_fsm:send_event_after(Timeout * 1000, echo_timeout)}.

send_info_after(Time, Event) ->
    erlang:start_timer(Time, self(), Event).

bump_seqno(State = #state{seqno = SeqNo}) ->
    State#state{seqno = (SeqNo + 1) rem 256}.

send_response(Header, MsgType, Seq, MsgElems,
	      State = #state{socket = Socket}) ->
    log_capwap_control(peer_log_str(State), MsgType, Seq, MsgElems, Header),
    BinMsg = capwap_packet:encode(control, {Header, {MsgType, Seq, MsgElems}}),
    ok = socket_send(Socket, BinMsg),
    State#state{last_response = {Seq, BinMsg}}.

resend_response(#state{socket = Socket, last_response = {SeqNo, BinMsg}}) ->
    lager:warning("resend capwap response ~w", [SeqNo]),
    ok = socket_send(Socket, BinMsg).

send_request(Header, MsgType, ReqElements, State = #state{seqno = SeqNo}) ->
    log_capwap_control(peer_log_str(State), MsgType, SeqNo, ReqElements, Header),
    BinMsg = capwap_packet:encode(control, {Header, {MsgType, SeqNo, ReqElements}}),
    State1 = send_request_queue(BinMsg, State),
    bump_seqno(State1).

send_request_queue(BinMsg, State = #state{socket = Socket, request_queue = Queue, seqno = SeqNo}) ->
    NewState = queue_request(State, {SeqNo, BinMsg}),
    case queue:is_empty(Queue) of
        true ->
            ok = socket_send(Socket, BinMsg),
            init_retransmit(NewState);
        false ->
            NewState
    end.

resend_request(StateName, State = #state{retransmit_counter = 0}) ->
    lager:debug("Final Timeout in ~w, STOPPING", [StateName]),
    {stop, normal, State};
resend_request(StateName,
	       State = #state{socket = Socket,
                          request_queue = Queue,
                          retransmit_counter = MaxRetransmit}) ->
    lager:warning("resend capwap request", []),
    {value, {_, BinMsg}} = queue:peek(Queue),
    ok = socket_send(Socket, BinMsg),
    State1 = State#state{retransmit_timer = send_info_after(?RetransmitInterval, retransmit),
			 retransmit_counter = MaxRetransmit - 1
			},
    {next_state, StateName, State1, ?IDLE_TIMEOUT}.

init_retransmit(State) ->
    State#state{retransmit_timer = send_info_after(?RetransmitInterval, retransmit),
                retransmit_counter = ?MaxRetransmit}.

%% Stop Timer, clear LastRequest
ack_request(State0 = #state{socket = Socket}) ->
    State1 = cancel_retransmit(State0),
    case dequeue_request_next(State1) of
        {{value, {_, BinMsg}}, State2} ->
            ok = socket_send(Socket, BinMsg),
            init_retransmit(State2);
        {empty, State2} ->
            State2
    end.

cancel_retransmit(State = #state{retransmit_timer = undefined}) ->
    State;
cancel_retransmit(State = #state{retransmit_timer = Timer}) ->
    gen_fsm:cancel_timer(Timer),
    State#state{retransmit_timer = undefined}.

queue_request(State = #state{request_queue = Queue}, {SeqNo, BinMsg}) ->
    State#state{request_queue = queue:in({SeqNo, BinMsg}, Queue)}.

dequeue_request_next(State = #state{request_queue = Queue0}) ->
    Queue1 = queue:drop(Queue0),
    {queue:peek(Queue1), State#state{request_queue = Queue1}}.

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

answer_discover(Peer, Seq, Elements, #capwap_header{
		       radio_id = RadioId, wb_id = WBID, flags = Flags}) ->
    RespElems = ac_info(discover, Elements),
    Header = #capwap_header{radio_id = RadioId, wb_id = WBID, flags = Flags},
    log_capwap_control(Peer, discovery_response, Seq, RespElems, Header),
    capwap_packet:encode(control, {Header, {discovery_response, Seq, RespElems}}).

socket_send({udp, Socket}, Data) ->
    capwap_udp:send(Socket, Data);
socket_send({dtls, Socket}, Data) ->
    ssl:send(Socket, Data).

socket_close({udp, Socket}) ->
    capwap_udp:close(Socket);
socket_close({dtls, Socket}) ->
    ssl:close(Socket);
socket_close(undefined) ->
    ok;
socket_close(Socket) ->
    lager:warning("Got Close on: ~p", [Socket]),
    ok.

common_name(SslSocket) ->
    {ok, Cert} = ssl:peercert(SslSocket),
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
    Salt = ssl:random_bytes(16),
    UserPassHash = crypto:hash(sha, [Salt, crypto:hash(sha, [Username, <<$:>>, <<"secret">>])]),
    {ok, {srp_1024, Salt, UserPassHash}};

user_lookup(psk, Username, Session) ->
    lager:debug("user_lookup: Username: ~p", [Username]),
    Opts = [{'Username', Username},
	    {'Authentication-Method', {'TLS', 'Pre-Shared-Key'}}
            | create_initial_ctld_params(Username)],
    case ctld_session:authenticate(Session, ctld_session:to_session(Opts)) of
	success ->
	    lager:info("AuthResult: success"),
	    case ctld_session:get(Session, 'TLS-Pre-Shared-Key') of
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
    Opts = [{'Username', CommonName},
	    {'Authentication-Method', {'TLS', 'X509-Subject-CN'}}
            | create_initial_ctld_params(CommonName)],
    case ctld_session:authenticate(Session, ctld_session:to_session(Opts)) of
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

create_initial_ctld_params(CommonName) ->
    [WlanHoldTime, PsmIdle, PsmBusy, MaxWifi, SSIDs, DefaultSSID,
     DynSSIDSuffixLen, EchoRequestInterval, DiscoveryInterval,
     IdleTimeout, DataChannelDeadInterval, ACJoinTimeout, AdminPW] =
        wtp_config_get(CommonName,
                       [{wlan_hold_time, wlan_hold_time, 15},
                        {psm_idle_timeout, psm_idle_timeout, 30},
                        {psm_busy_timeout, psm_busy_timeout, 300},
                        {max_stations, max_stations, 100},
                        {ssids, ssids, []},
                        {default_ssid, <<"CAPWAP">>},
                        {dynamic_ssid_suffix_len, false},
                        {echo_request_interval, 10},
                        {discovery_interval, 20},
                        {idle_timeout, 300},
                        {data_channel_dead_interval, 70},
                        {ac_join_timeout, 60},
                        {default_admin_pw, admin_pw, undefined}
                       ]),
    RadioId = 1,
    SSID = proplists:get_value(RadioId, SSIDs),
    SSID2 = case SSID of
                undefined when is_integer(DynSSIDSuffixLen), is_binary(CommonName) ->
                    binary:list_to_bin([DefaultSSID, $-, binary:part(CommonName, size(CommonName) - DynSSIDSuffixLen, DynSSIDSuffixLen)]);
                undefined -> DefaultSSID;
                _ -> SSID
            end,
    [{'TP-CAPWAP-Power-Save-Idle-Timeout', PsmIdle},
     {'TP-CAPWAP-Power-Save-Busy-Timeout', PsmBusy},
     {'TP-CAPWAP-Max-WIFI-Clients', MaxWifi},
     {'TP-CAPWAP-SSID', SSID2},
     {'CAPWAP-Echo-Request-Interval', EchoRequestInterval},
     {'CAPWAP-Discovery-Interval', DiscoveryInterval},
     {'CAPWAP-Idle-Timeout', IdleTimeout},
     {'CAPWAP-Data-Channel-Dead-Interval', DataChannelDeadInterval},
     {'CAPWAP-AC-Join-Timeout', ACJoinTimeout},
     {'CAPWAP-Admin-PW', AdminPW},
     {'CAPWAP-Wlan-Hold-Time', WlanHoldTime}
    ].

internal_add_wlan(State, SSID, RadioID) ->
    WBID = 1,
    WlanId = 1,
    Flags = [{frame,'802.3'}],
    MacMode = select_mac_mode(State#state.mac_types),
    TunnelMode = select_tunnel_mode(State#state.tunnel_modes, MacMode),
    Header = #capwap_header{radio_id = RadioID, wb_id = WBID, flags = Flags},
    State0 = State#state{mac_mode = MacMode, tunnel_mode = TunnelMode},
    ReqElements = [#ieee_802_11_add_wlan{
                      radio_id      = RadioID,
                      wlan_id       = WlanId,
                      capability    = [ess, short_slot_time],
                      auth_type     = open_system,
                      mac_mode      = MacMode,
                      tunnel_mode   = TunnelMode,
                      suppress_ssid = 1,
                      ssid          = SSID
                     }
                  ],
    State1 = send_request(Header, ieee_802_11_wlan_configuration_request, ReqElements, State0),
    set_radio(State1, #radio{radio_id = RadioID, ssid = SSID, started = true}).

internal_del_wlan(State, RadioID) ->
    WBID = 1,
    Flags = [{frame,'802.3'}],
    MacMode = select_mac_mode(State#state.mac_types),
    TunnelMode = select_tunnel_mode(State#state.tunnel_modes, MacMode),
    Header = #capwap_header{radio_id = RadioID, wb_id = WBID, flags = Flags},
    State0 = State#state{mac_mode = MacMode, tunnel_mode = TunnelMode},
    ReqElemDel = [#ieee_802_11_delete_wlan{
                     radio_id = RadioID,
                     wlan_id = 1}
                 ],
    State1 = send_request(Header, ieee_802_11_wlan_configuration_request, ReqElemDel, State0),
    remove_radio(State1, RadioID).

remove_radio(State = #state{radios = Radios}, RadioId) ->
    LessRadios = lists:keydelete(RadioId, 2, Radios),
    State#state{radios = LessRadios}.

get_radio(#state{radios = Radios}, RadioId) ->
    lists:keyfind(RadioId, #radio.radio_id, Radios).

set_radio(State = #state{radios=Radios}, Radio = #radio{radio_id = RadioId})
  when is_integer(RadioId), RadioId > 0 ->
    Radios1 = lists:keystore(RadioId, #radio.radio_id, Radios, Radio),
    State#state{radios = Radios1}.

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
