%% Copyright (C) 2013-2023, Travelping GmbH <info@travelping.com>

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

-module(wtp_mockup_fsm).

-behaviour(gen_statem).

-include_lib("kernel/include/logger.hrl").
-include("../include/ieee80211.hrl").
-include("../include/capwap_config.hrl").
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

%% gen_statem callbacks
-export([callback_mode/0, init/1, handle_event/4, terminate/3, code_change/4]).

-define(SERVER, ?MODULE).
-define(Default_WTP_MAC, <<8,8,8,8,8,8>>).
-define(Default_Local_Control_Port, 5248).
-define(Default_SCG, {{127,0,0,1}, 5246}).

-record(data, {control_socket,
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
               echo_request_timeout,
               capwap_wtp_session_id,
               wifi_up,
               request_pending,
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
    gen_statem:start_link(?MODULE, [SCG, IP, Port, CertDir, RootCert, Mac, RemoteMode, self(), Options], []).

stop(WTP) ->
    MonitorRef = monitor(process, WTP),
    gen_statem:call(WTP, stop),
    receive
        {'DOWN', MonitorRef, _, _, _} ->
            ok
    end.

send_discovery(WTP_FSM) ->
    gen_statem:call(WTP_FSM, send_discovery).

send_join(WTP_FSM) ->
    gen_statem:call(WTP_FSM, send_join).

send_config_status(WTP_FSM) ->
    gen_statem:call(WTP_FSM, send_config_status).

send_change_state_event(WTP_FSM) ->
    gen_statem:call(WTP_FSM, send_change_state_event).

send_keep_alive(WTP_FSM) ->
    gen_statem:call(WTP_FSM, send_keep_alive).

send_wwan_statistics(WTP_FSM) ->
    gen_statem:call(WTP_FSM, send_wwan_statistics).

send_wwan_statistics(WTP_FSM, NoIEs) ->
    gen_statem:call(WTP_FSM, {send_wwan_statistics, NoIEs}).

add_station(WTP_FSM, Mac) ->
    case gen_statem:call(WTP_FSM, {add_station, Mac}) of
        wait_for_wifi ->
            timer:sleep(100),
            add_station(WTP_FSM, Mac);
        {ok, Msg} = Result ->
            Result
    end.

%%%===================================================================
%%% gen_statem callbacks
%%%===================================================================
callback_mode() ->
    handle_event_function.

init([SCG = {SCGIP, SCGControlPort}, IP, Port,
      CertDir, RootCert, Mac, RemoteMode, Owner, Options]) ->
    {ok, ControlSocket} =
        capwap_udp:connect(SCGIP, SCGControlPort, [{active, false}, {mode, binary}, {ip, IP}]),

    DataSocket =
        case RemoteMode of
            true ->
                {ok, UdpDataSocket} =
                    capwap_udp:connect(SCGIP, SCGControlPort + 1,
                                       [{active, false}, {mode, binary}, {ip, IP}]),
                ok = capwap_udp:setopts(UdpDataSocket, [{active, true}]),
                UdpDataSocket;
            false ->
                undefined
        end,

    Data = #data{
              control_socket = ControlSocket,
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
              echo_request_timeout = 0,
              keep_alive_timeout = 0,
              capwap_wtp_session_id = rand:uniform(329785637896618622174542098706248598340),
              wifi_up = false,
              request_pending = undefined,
              options = Options
             },
    {ok, idle, Data}.

handle_event({call, From}, send_discovery, idle, Data) ->
    IEs = [#discovery_type{discovery_type = static}]
        ++ create_default_ies(),
    {resp, Resp, Data0, Actions} =
        do_transition(Data, control, {discovery_request, IEs},
                      udp_sync, req, undefined),
    ?LOG(debug, "got discovery response:  ~p", [Resp]),
    {next_state, discovery, Data0, [{reply, From, {ok, Resp}} | Actions]};

handle_event({call, From}, send_join, discovery,
             Data = #data{control_socket = CS, ip = IP,
                          capwap_wtp_session_id = CapwapWtpSessionId}) ->
    S1 = case Data#data.remote_mode of
             true ->
                 ?LOG(debug, "connecting ssl socket with options ~p", [make_ssl_options(Data)]),
                 ok = capwap_udp:setopts(CS, [{active, true}]),
                 {ok, SSLSocket} = ssl:connect(CS, make_ssl_options(Data)),
                 ok = ssl:setopts(SSLSocket, [{active, true}]),
                 ?LOG(debug, "successfully connected ssl socket", []),
                 Data#data{control_socket = SSLSocket};
             _ ->
                 ok = capwap_udp:setopts(CS, [{active, true}]),
                 Data
         end,

    IEs = [#location_data{location = <<"  Next to Fridge">>},
           #local_ipv4_address{ip_address = tuple_to_ip(IP)},
           #wtp_name{wtp_name = <<"My WTP 1">>},
           #session_id{session_id = CapwapWtpSessionId}]
        ++ create_default_ies(),
    {data, DataNew, Actions} =
        do_transition(S1, control, {join_request, IEs},
                      async, req, {join_response, From}),
    {keep_state, DataNew, Actions};

handle_event({call, From}, send_config_status, join, Data) ->
    IEs = [#ac_name{name = <<" My AC">>},
           #ac_name_with_priority{priority = 0, name = <<"ACPrimary">>},
           #ac_name_with_priority{priority = 1, name = <<"ACSecondary">>},
           #radio_administrative_state{radio_id = 0, admin_state = enabled},
           #statistics_timer{statistics_timer = 120},
           #wtp_reboot_statistics{},
           #ieee_802_11_wtp_radio_information{radio_type = ['802.11g','802.11b']},
           #ieee_802_11_supported_rates{supported_rates = [130,132,139,150,12,18,24,36]},
           #ieee_802_11_multi_domain_capability{
              first_channel = 1,
              number_of_channels_ = 14,
              max_tx_power_level = 27}],
    {data, DataNew, Actions} =
        do_transition(Data, control, {configuration_status_request, IEs},
                      async, req, {configuration_status_response, From}),
    {keep_state, DataNew, Actions};

handle_event({call, From}, send_change_state_event, configure, Data) ->
    IEs =[#radio_operational_state{state = enabled},
          #result_code{}],
    {data, DataNew, Actions} =
        do_transition(Data, control, {change_state_event_request, IEs},
                      async, req, {change_state_event_response, From}),
    {keep_state, DataNew, Actions};

handle_event({timeout, echo_request}, _, run, Data) ->
    ?LOG(debug, "Echo Timeout in Run"),
    {data, DataNew, Actions} =
        do_transition(Data, control, {echo_request, []}),
    {keep_state, DataNew, Actions};

handle_event({timeout, keep_alive}, _, run,
             Data = #data{capwap_wtp_session_id = CapwapWtpSessionId}) ->
    ?LOG(debug, "keep-alive Timeout in Run"),
    Flags = ['keep-alive', {frame,'802.3'}],
    KeepAliveIEs=[#session_id{session_id = CapwapWtpSessionId}],
    {data, DataNew, Actions0} =
        do_transition(Data, data, {Flags, KeepAliveIEs}),
    Actions = keep_alive_timer(DataNew) ++ Actions0,
    {keep_state, DataNew, Actions};

handle_event({timeout, Timeout}, _, _State, _Data)
  when Timeout =:= echo_request; Timeout =:= keep_alive ->
    keep_state_and_data;

handle_event({call, From}, send_wwan_statistics, run, Data) ->
    TimeStamp = timestamp(),
    IEs = [#tp_wtp_wwan_statistics{
              latency = 5,
              timestamp = TimeStamp},
           #gps_last_acquired_position{
              timestamp = TimeStamp,
              gpsatc = <<"$GPSACP: 154750.000,5207.6688N,01137.8028E,0.7,62.4,2,196.4,45.7,24.7,030914,09">>}],
    {data, DataNew, Actions} =
        do_transition(Data, control, {wtp_event_request, IEs},
                      async, req, {wtp_event_response, From}),
    {keep_state, DataNew, Actions};

handle_event({call, From}, {send_wwan_statistics, NoIEs}, run, Data) ->
    TimeStamp = timestamp(),
    IE = [#tp_wtp_wwan_statistics{
             latency = 5,
             timestamp = TimeStamp},
          #gps_last_acquired_position{
             timestamp = TimeStamp,
             gpsatc = <<"$GPSACP: 154750.000,5207.6688N,01137.8028E,0.7,62.4,2,196.4,45.7,24.7,030914,09">>}],
    IEs = lists:flatten(lists:duplicate(NoIEs, IE)),
    {data, DataNew, Actions} =
        do_transition(Data, control, {wtp_event_request, IEs},
                      async, req, {wtp_event_response, From}),
    {keep_state, DataNew, Actions};

handle_event({call, From}, {add_station, _}, run, #data{wifi_up = false}) ->
    {keep_state_and_data, {reply, From, wait_for_wifi}};

handle_event({call, From}, {add_station, Mac}, run,
             Data = #data{mac = WTPMac, wifi_up = true}) ->
    Unknown = 0,
    FromDS = 0,
    ToDS=0,
    {Type, SubType} = ieee80211_station:frame_type('Association Request'),
    FrameControl = <<SubType:4, Type:2, 0:2, Unknown:6, FromDS:1, ToDS:1>>,
    Duration = 0,
    DA = <<1:48>>,
    SA = Mac,
    BSS = WTPMac,
    SequenceControl = get_seqno(Data),

    RSN = #wtp_wlan_rsn{
             version = 1,
             capabilities = 0,
             group_cipher_suite = ?IEEE_802_1_CIPHER_SUITE_AES,
             cipher_suites = [?IEEE_802_1_CIPHER_SUITE_AES],
             akm_suites = ['PSK']
            },
    IEs = [<<16#0432:16/little, 0:16>>,
           capwap_ac:ieee_802_11_ie(?WLAN_EID_SSID, <<"DEV CAPWAP WIFI">>),
           capwap_ac:ieee_802_11_ie(?WLAN_EID_SUPP_RATES, <<2, 4, 11, 22, 12, 18, 24, 36>>),
           capwap_ac:rsn_ie(RSN, false),
           capwap_ac:ieee_802_11_ie(?WLAN_EID_EXT_SUPP_RATES, <<48, 72, 96, 108>>)],
    Frame = iolist_to_binary(IEs),
    Payload = <<FrameControl:2/bytes,
                Duration:16, DA:6/bytes, SA:6/bytes, BSS:6/bytes,
                SequenceControl:16/little-integer, Frame/binary>>,
    Flags = [{frame, native}],
    ?LOG(info, "in state run adding station: ~p", [Mac]),
    {data, DataNew, Actions} =
        do_transition(Data, data, {Flags, Payload}, async, req, {add_station_resp, From}),
    {keep_state, DataNew, Actions};

%% this transition provokes an error which occured before request queue was introduce into capwap_ac
%% {TypeDis, SubTypeDis} = ieee80211_station:frame_type('Disassociation'),
%% FrameControlDis = <<SubTypeDis:4, TypeDis:2, 0:2, Unknown:6, FromDS:1, ToDS:1>>,
%% SequenceControlDis = SequenceControl + 1,
%% PayloadDis = <<FrameControlDis:2/bytes,
%%             Duration:16, DA:6/bytes, SA:6/bytes, BSS:6/bytes,
%%             SequenceControlDis:16/little-integer, Frame/binary>>,
%% do_transition(Data, data, run, {Flags, PayloadDis}, async);

handle_event({call, From}, stop, _StateName, Data) ->
    {stop_and_reply, normal, {reply, From, ok}, Data};

%% handle_event({call, From}, _Event, _StateName, _Data) ->
%%     {keep_state_and_data, {reply, From, {error, bad_event}}};

handle_event(info, {ssl, Socket, Packet}, StateName,
             Data = #data{control_socket = Socket}) ->
    DecRequest = capwap_packet:decode(control, Packet),
    ?LOG(debug, "in state ~p got control DTLS: ~p", [StateName, DecRequest]),
    handle_incoming(DecRequest, StateName, control, Data);

handle_event(info, {udp, CS, _IP, _InPort, Packet}, StateName,
             Data = #data{control_socket = CS}) ->
    DecRequest = capwap_packet:decode(control, Packet),
    ?LOG(debug, "in state ~p got control udp: ~p", [StateName, DecRequest]),
    handle_incoming(DecRequest, StateName, control, Data);

handle_event(info, {udp, DS, _IP, _InPort, Packet}, StateName,
             Data = #data{data_socket = DS}) ->
    DecRequest = capwap_packet:decode(data, Packet),
    ?LOG(debug, "in state ~p got data udp: ~p", [StateName, DecRequest]),
    handle_incoming(DecRequest, StateName, data, Data);

handle_event(info, {ssl, DS, _IP, _InPort, Packet}, StateName,
             Data = #data{data_socket = DS}) ->
    DecRequest = capwap_packet:decode(data, Packet),
    ?LOG(debug, "in state ~p got data DTLS: ~p", [StateName, DecRequest]),
    handle_incoming(DecRequest, StateName, data, Data).

terminate(_Reason, _StateName, _Data) ->
    ok.

code_change(_OldVsn, StateName, Data, _Extra) ->
    {ok, StateName, Data}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

bump_seqno(Data = #data{seqno = SeqNo}) ->
    Data#data{seqno = (SeqNo + 1) rem 256}.

get_seqno(#data{seqno=SQNO}) ->
    SQNO.

send_capwap(Data = #data{data_socket=DS, remote_mode=true}, data, Packet) ->
    ct:pal("send data capwap: ~p", [Packet]),
    gen_udp:send(DS, Packet),
    {Data, []};

send_capwap(#data{remote_mode=false} = Data, data, []) ->
    {Data, []};
send_capwap(#data{data_socket=DS, remote_mode=false,
                  simulated_data_port = Port,
                  scg = {SCGIP, _}, ip = IP
                 } = Data,
            data, [Packet|Rest]) ->
    ct:pal("send simulated data capwap: ~p", [Packet]),
    case capwap_ac:handle_data(self(), {IP, Port}, Packet) of
        {reply, Resp}  ->
            {udp, DS, SCGIP, Port + 1, Resp};
        _ ->
            ok
    end,
    send_capwap(Data, data, Rest);

send_capwap(Data = #data{control_socket=CS, remote_mode=true}, control, Packet) ->
    ct:pal("send control ssl capwap: ~p", [Packet]),
    if is_list(Packet) ->
            lists:foreach(fun(P) -> ok = ssl:send(CS, P) end, Packet);
       true ->
            ok = ssl:send(CS, Packet)
    end,
    {Data, echo_request_timer(Data)};

send_capwap(Data = #data{control_socket=CS, remote_mode=false}, control, Packet) ->
    ct:pal("send control udp capwap: ~p", [Packet]),
    if is_list(Packet) ->
            lists:foreach(fun(P) -> ok = gen_udp:send(CS, P) end, Packet);
       true ->
            ok = gen_udp:send(CS, Packet)
    end,
    {Data, echo_request_timer(Data)}.

recv_capwap(#data{control_socket=CS, remote_mode=true}) ->
    {ok, Resp} = ssl:recv(CS, 1500, 2000),
    Resp;

recv_capwap(#data{control_socket=CS, remote_mode=false}) ->
    {ok, Resp} = capwap_udp:recv(CS, 1000, 1000),
    Resp.


create_header(#data{mac = MAC}) ->
    #capwap_header{radio_id = 0,
                   wb_id = 1,
                   flags = [{frame,'802.3'}],
                   radio_mac = MAC,
                   wireless_spec_info = undefined}.

do_transition(Data, Type, Packet) ->
    do_transition(Data, Type, Packet, async, req, undefined).

%% Format packet for data channel
do_transition(Data, data, {Flags, IEs}, Mode, RespSeq, UserCallback)
  when Flags =/= packet  ->
    Header = create_header(Data),
    Header1 = Header#capwap_header{flags=Flags},
    ct:pal("do data encode: ~p", [{Header1, IEs}]),
    Packet = capwap_packet:encode(data,
                                  {Header1, IEs}),
    do_transition(Data, data, {packet, Packet}, Mode, RespSeq, UserCallback);

%% Format packet for control channel
do_transition(Data = #data{ctrl_stream = CtrlStreamData0, seqno = SeqNum},
              control, {ReqType, IEs},
              Mode, RespSeq, UserCallback)
  when ReqType =/= packet ->
    Header = create_header(Data),
    SeqNumToUse = case RespSeq of
                      {resp, RespSeqNum} ->
                          RespSeqNum;
                      req ->
                          SeqNum
                  end,

    Msg = {Header, {ReqType, SeqNumToUse, IEs}},
    {Packet, CtrlStreamData1} = capwap_stream:encode(control, Msg, CtrlStreamData0),
    ?LOG(debug, "in do_transition, ~p to send: ~p", [ReqType, Packet]),

    do_transition(Data#data{ctrl_stream = CtrlStreamData1}, control,
                  {packet, Packet}, Mode, RespSeq, UserCallback);

%% send packet and make state transition
%% mode = async | udp_sync
%% udp_sync: forces udp usage when otherwise capwap-dtls would be used
do_transition(Data = #data{remote_mode = RemoteMode,
                           request_pending=undefined},
              Type, {packet, Packet},
              Mode, RespSeq, UserCallback) ->
    {Data0, Timer} =
        case Mode of
            udp_sync ->
                {S1, Actions} = send_capwap(Data#data{remote_mode = false}, Type, Packet),
                {S1#data{remote_mode = RemoteMode}, Actions};
            _ ->
                send_capwap(Data, Type, Packet)
        end,
    Data1 = case UserCallback of
                undefined ->
                    Data0;
                {RespType, From} ->
                    Data0#data{request_pending={RespType,From}}
            end,
    case {Type, Mode, RespSeq} of
        {control, udp_sync, _} ->
            Resp = recv_capwap(Data1#data{remote_mode = false}),
            DecResp = capwap_packet:decode(control, Resp),
            {resp, DecResp, bump_seqno(Data1), Timer};
        {_, _, {resp, _}} ->
            {data, Data1, Timer};
        {control, _, req} ->
            {data, bump_seqno(Data1), Timer};
        {data, _, req} ->
            {data, Data1, Timer}
    end;
do_transition(Data = #data{remote_mode = RemoteMode,
                           request_pending= RP},
              Type, {packet, Packet},
              Mode, RespSeq, UserCallback) ->
    ct:pal("RequestPending: ~p", [RP]),
    ct:fail(here).

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
    erlang:system_time(second).

handle_incoming(Response = {#capwap_header{},
                            {wtp_event_response, _, _RemoteSeq, _IEs}},
                run, control,
                Data = #data{request_pending={wtp_event_response, From}}) ->
    {keep_state, remove_rp(Data), {reply, From, {ok, Response}}};

handle_incoming(Response = {#capwap_header{},
                            {join_response, _, _RemoteSeq, _IEs}},
                discovery, control,
                Data = #data{request_pending={join_response, From}}) ->
    {next_state, join, remove_rp(Data), {reply, From, {ok, Response}}};

handle_incoming(Response = {#capwap_header{},
                            {configuration_status_response, _, _RemoteSeq,
                             #{timers := #timers{echo_request = EchoTimer}} = IEs}},
                join, control,
                Data = #data{request_pending={configuration_status_response, From}}) ->
    {next_state, configure, remove_rp(Data#data{echo_request_timeout = EchoTimer}),
     {reply, From, {ok, Response}}};

handle_incoming(Request = {#capwap_header{},
                           {ieee_802_11_wlan_configuration_request, _, RemoteSeq, _WlanConfigIEs}} = Req,
                _StateName, control,
                Data = #data{owner = Owner, request_pending = RP}) ->
    ?LOG(debug, "Got expected wlan_config_request in ~p: ~p", [_StateName, Req]),
    Owner ! Request,
    {data, Data1, Actions} =
        do_transition(Data#data{wifi_up = true, request_pending = undefined},
                      control,
                      {ieee_802_11_wlan_configuration_response,[#result_code{}]},
                      async, {resp, RemoteSeq}, undefined),
    {keep_state, Data1#data{request_pending = RP}, Actions};

handle_incoming(Request = {#capwap_header{},
                           {station_configuration_request, _, RemoteSeq, _StationConfigIEs}} = Req,
                run, control,
                Data = #data{request_pending = {add_station_resp, From}}) ->
    ?LOG(debug, "got expected station_config_request: ~p", [Req]),
    {data, DataNew, Actions} =
        do_transition(remove_rp(Data), control,
                      {station_configuration_response, [#result_code{}]},
                      async, {resp, RemoteSeq}, undefined),
    {keep_state, DataNew, [{reply, From, {ok, Request}} | Actions]};

handle_incoming(Response = {_Header, {change_state_event_response, _, _, #{}}},
                configure, control,
                Data = #data{capwap_wtp_session_id = CapwapWtpSessionId,
                             request_pending = {change_state_event_response, From},
                             options = Options})  ->
    %% establish dtls on data socket if remote_mode = true
    %% currently not in use (TODO add option for dtls usage on data socket)
    %% Data0 = case Data#data.remote_mode of
    %%           true ->
    %%               %% {ok, DataSocket} = ssl:connect(UdpDataSocket, make_ssl_options(Data1)),
    %%               %% ?LOG(info, "successfull ssl handshake done for data socket", []),
    %%               %% ok = ssl:setopts(DataSocket, [{active, true}]),
    %%               Data#data{data_socket = UdpDataSocket};
    %%           false ->
    %%               Data
    %%       end,

    Flags = ['keep-alive', {frame,'802.3'}],
    KeepAliveIEs = [#session_id{session_id = CapwapWtpSessionId}],
    KeepAliveTimeout = proplists:get_value(data_keep_alive_timeout, Options, 30),
    {data, DataNew, Actions0} =
        do_transition(remove_rp(Data#data{keep_alive_timeout = KeepAliveTimeout}),
                      data, {Flags, KeepAliveIEs}),
    Actions = keep_alive_timer(DataNew) ++ Actions0,
    {next_state, run, DataNew, [{reply, From, {ok, Response}} | Actions]};

handle_incoming({Header, _} = Req, run, data, Data) ->
    KeepAlive = proplists:get_bool('keep-alive', Header#capwap_header.flags),
    case KeepAlive of
        true ->
            ?LOG(debug, "WTP ~p received keep-alive in RUN state! ~p",
                 [Data#data.ip, Data#data.keep_alive_timeout]),
            keep_state_and_data;
        false ->
            ?LOG(warning, "in ~p received a data response not expected: ~p", [run, Req]),
            keep_state_and_data
    end;

handle_incoming(Req, StateName, Type, _Data) ->
    ?LOG(warning, "handle_incoming: in ~p received a ~p response not expected: ~p",
         [StateName, Type, Req]),
    keep_state_and_data.

make_ssl_options(#data{cert_dir = CertDir,
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

echo_request_timer(#data{echo_request_timeout = 0}) ->
    [{{timeout, echo_request}, infinity, echo_request}];
echo_request_timer(#data{echo_request_timeout = Timeout}) ->
    [{{timeout, echo_request}, Timeout * 1000, echo_request}].

keep_alive_timer(#data{keep_alive_timeout = 0}) ->
    [{{timeout, keep_alive}, infinity, keep_alive}];
keep_alive_timer(#data{keep_alive_timeout = Timeout}) ->
    [{{timeout, keep_alive}, Timeout * 1000, keep_alive}].

remove_rp(Data=#data{}) ->
    Data#data{request_pending = undefined}.
