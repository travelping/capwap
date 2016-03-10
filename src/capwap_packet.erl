-module(capwap_packet).

-export([decode/2, decode/3, encode/2, encode/4, msg_description/1]).
-export([decode_rate/1, encode_rate/2]).
-compile(export_all).

-include("capwap_packet.hrl").

%%%-------------------------------------------------------------------
%%% decoder
%%%-------------------------------------------------------------------

decode(Type, <<0:4, 0:4,
	       HLen:5/integer, RID:5/integer, WBID:5/integer,
	       T:1, F:1, L:1, W:1, M:1, K:1, _:3,
	       FragmentId:16/integer, FragmentOffset:13/integer, _:3,
	       Rest/binary>>)
  when Type == control; Type == data ->
    RestHeaderLen = (HLen - 2) * 4,
    <<RestHeader0:RestHeaderLen/bytes, PayLoad/binary>> = Rest,
    {RadioMAC, RestHeader1} = extract_header(M, RestHeader0),
    {WirelessSpecInfo, _} = extract_header(W, RestHeader1),
    F0 = if
	     T == 1 -> {frame, native};
	     true   -> {frame, '802.3'}
	 end,
    F1 = if
	     K == 1 -> ['keep-alive', F0];
	     true   -> [F0]
	 end,
    Header = #capwap_header{radio_id = RID,
			    wb_id = WBID,
			    flags = F1,
			    radio_mac = RadioMAC,
			    wireless_spec_info = WirelessSpecInfo},

    KeepAlive = decode_bool(K),
    Last = decode_bool(L),

    if F == 1 ->
	    {fragment, Type, KeepAlive, FragmentId, FragmentOffset, FragmentOffset + size(PayLoad), Last, Header,  PayLoad};
       true ->
	    decode_packet(Type, KeepAlive , Header, PayLoad)
    end.

decode(control, Header, PayLoad) ->
    {Header, decode_control_msg(PayLoad)}.

decode_packet(control, _, Header, PayLoad) ->
    {Header, decode_control_msg(PayLoad)};
decode_packet(data, false, Header, PayLoad) ->
    {Header, PayLoad};
decode_packet(data, true, Header, PayLoad) ->
    PayLoadLength = byte_size(PayLoad),
    case PayLoad of
	<<PayLoadLength:16, ME/binary>> ->
	    {Header, decode_elements(ME, [])};
	_ ->
	    %% FIXME: workarround for broken OpenCAPWAP encoding
	    {Header, decode_elements(PayLoad, [])}
    end.

%%%-------------------------------------------------------------------
%%% encoder
%%%-------------------------------------------------------------------

encode(Type, Msg) ->
    encode(Type, Msg, 0, 1500).

encode(control, {Header, {MsgType, _, SeqNum, IEs}}, FragId, MTU) ->
    encode(control, {Header, {MsgType, SeqNum, IEs}}, FragId, MTU);

encode(control, {#capwap_header{radio_id = RID,
				wb_id = WBID,
				flags = Flags,
				radio_mac = RadioMAC,
				wireless_spec_info = WirelessSpecInfo},
		 {MsgType, SeqNum, IEs}}, FragId, MTU) ->
    T = encode_transport(proplists:get_value(frame, Flags, native)),
    {W, WirelessSpecInfoBin} = encode_header(WirelessSpecInfo),
    {M, RadioMACbin} = encode_header(RadioMAC),
    K = encode_flag('keep-alive', Flags),
    {Vendor, MType} = message_type(MsgType),
    MsgElements = << <<(encode_element(X))/binary>> || X <- IEs>>,
    PayLoad = <<Vendor:24, MType:8, SeqNum:8, (byte_size(MsgElements) + 3):16, 0:8, MsgElements/binary>>,
    HeaderLen = (8 + byte_size(RadioMACbin) + byte_size(WirelessSpecInfoBin)),
    HLen = HeaderLen div 4,
    Header = {HLen, RID, WBID, T, W, M, K, <<RadioMACbin/binary, WirelessSpecInfoBin/binary>>},
    encode_part(Header, FragId, 0, PayLoad, MTU - HeaderLen);

encode(data, {Header = #capwap_header{flags = Flags}, PayLoad}, FragId, MTU) ->
    case proplists:get_bool('keep-alive', Flags) of
	true ->
	    encode_data_keep_alive(Header, PayLoad, FragId, MTU);
	_ ->
	    encode_data_packet(Header, PayLoad, FragId, MTU)
    end.

%%%===================================================================
%%% Internal functions
%%%===================================================================

-include("capwap_packet_gen.hrl").

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

extract_header(0, Header) ->
    {undefined, Header};
extract_header(1, <<Len:8/integer, Field:Len/bytes, _/binary>> = Header) ->
    PLen = Len + pad_length(4, Len + 1),
    <<_:PLen/bytes, Next/binary>> = Header,
    {Field, Next}.

encode_header(undefined) ->
    {0, <<>>};
encode_header(Bin) when is_binary(Bin) ->
    Len = byte_size(Bin),
    {1, pad_to(4, <<Len:8, Bin/binary>>)}.

encode_part(Header, FragmentId, FragmentOffset, PayLoad, MTU)
  when size(PayLoad) =< MTU ->
    [encode_partbin(Header, 0, 0, FragmentId, FragmentOffset, PayLoad)];

encode_part(Header, FragmentId, FragmentOffset, PayLoad, MTU) ->
    encode_part(Header, FragmentId, FragmentOffset, PayLoad, MTU, []).

encode_part(Header, FragmentId, FragmentOffset, PayLoad, MTU, Acc)
  when size(PayLoad) =< MTU ->
    lists:reverse([encode_partbin(Header, 1, 1, FragmentId, FragmentOffset, PayLoad)|Acc]);
encode_part(Header, FragmentId, FragmentOffset, PayLoad, MTU, Acc) ->
    <<Part:MTU/bytes, Rest/binary>> = PayLoad,
    Acc1 = [encode_partbin(Header, 1, 0, FragmentId, FragmentOffset, Part)|Acc],
    encode_part(Header, FragmentId, FragmentOffset + MTU, Rest, MTU, Acc1).

encode_partbin(Header, F, L, FragmentId, FragmentOffset, PayLoad) ->
    {HLen, RID, WBID, T, W, M, K, Tail} = Header,
    <<0:4, 0:4, HLen:5, RID:5, WBID:5, T:1, F:1, L:1, W:1, M:1, K:1, 0:3,
      FragmentId:16, FragmentOffset:13, 0:3, Tail/binary, PayLoad/binary>>.

%%%-------------------------------------------------------------------
%%% decoder
%%%-------------------------------------------------------------------

decode_control_msg(<<Vendor:24/integer, MsgType:8/integer, SeqNum:8/integer,
	      Length:16/integer, 0:8, IEs/binary>>)
  when size(IEs) == (Length - 3)->
    DecIEs = decode_elements(IEs, []),
    {message_type({Vendor, MsgType}), MsgType band 1, SeqNum, DecIEs}.

decode_elements(<<>>, Acc) ->
    lists:reverse(Acc);
decode_elements(<<Type:16/integer, Len:16/integer, Value:Len/bytes, Next/binary>>, Acc) ->
    IE = decode_element(Type, Value),
    decode_elements(Next, [IE|Acc]).

decode_mac_list(<<_Num:8/integer, Len:8/integer, MACs/binary>>) ->
    [X || <<X:Len/bytes>> <= MACs].

decode_ipv4_list(IPs) ->
    [X || <<X:4/bytes>> <= IPs].

decode_ipv6_list(IPs) ->
    [X || <<X:16/bytes>> <= IPs].

decode_subelements(Data) ->
    decode_subelements(Data, []).

decode_subelements(<<>>, Acc) ->
    lists:reverse(Acc);
decode_subelements(<<Type:16/integer, Len:16/integer,
		     Value:Len/bytes, Next/binary>>, Acc) ->
    decode_subelements(Next, [{Type, Value}|Acc]).

decode_vendor_subelements(Data) ->
    decode_vendor_subelements(Data, []).

decode_vendor_subelements(<<>>, Acc) ->
    lists:reverse(Acc);
decode_vendor_subelements(<<Vendor:32/integer, Type:16/integer, Len:16/integer,
			    Value:Len/bytes, Next/binary>>, Acc) ->
    decode_vendor_subelements(Next, [{{Vendor, Type}, Value}|Acc]).

decode_rate(Rate) -> (Rate band 16#7F) * 5.

%%%-------------------------------------------------------------------
%%% encoder
%%%-------------------------------------------------------------------

encode_transport('802.3') -> 0;
encode_transport(native)  -> 1.

encode_bool(false) -> 0;
encode_bool(_)     -> 1.

decode_bool(0) -> false;
decode_bool(_) -> true.

basic_rate('11b-only', Rate)
  when Rate == 10; Rate == 20 ->
    16#80;
basic_rate('11g-only', Rate)
  when Rate == 60; Rate == 120; Rate == 240 ->
    16#80;
basic_rate('11bg', Rate)
  when Rate == 10; Rate == 20; Rate == 55; Rate == 110 ->
    16#80;
basic_rate(_, _) ->
    0.

encode_rate(Mode, Rate) ->
    (Rate div 5) bor basic_rate(Mode, Rate).

encode_flag(Key, List) ->
    encode_bool(proplists:get_bool(Key, List)).

encode_mac_list(MACs = [H|_]) ->
    Num = length(MACs),
    Len = byte_size(H),
    M = << <<X/binary>> || X <- MACs>>,
    <<Num:8, Len:8, M/binary>>.

encode_ipv4_list(IPs) when is_list(IPs) ->
    binary:list_to_bin([encode_ipv4(Ip) || Ip <- IPs ]).

encode_ipv4({A, B, C, D}) ->
    <<A,B,C,D>>;
encode_ipv4(Ip) when is_binary(Ip) ->
    Ip.

encode_ipv6_list(IPs) when is_list(IPs) ->
    binary:list_to_bin([encode_ipv6(Ip) || Ip <- IPs ]).

encode_ipv6({A, B, C, D, E, F, G, H}) ->
    <<A:16,B:16,C:16,D:16,E:16,F:16,G:16,H:16>>;
encode_ipv6(Ip) when is_binary(Ip) ->
    Ip.

encode_subelement(Type, Value) ->
    Len = byte_size(Value),
    <<Type:16/integer, Len:16/integer, Value/bytes>>.

encode_subelements(IEs) ->
    << <<(encode_subelement(Type, Value))/binary>> || {Type, Value} <- IEs >>.

encode_vendor_subelement(Vendor, Type, Value) ->
    Len = byte_size(Value),
    <<Vendor:32, Type:16, Len:16, Value/bytes>>.

encode_vendor_subelements(IEs) ->
    << <<(encode_vendor_subelement(Vendor, Type, Value))/binary>> || {{Vendor, Type}, Value} <- IEs >>.

encode_element(Type, Value) ->
    <<Type:16, (byte_size(Value)):16, Value/binary>>.

encode_vendor_element({Vendor, Type}, Value) ->
    encode_element(37, <<Vendor:32, Type:16, Value/binary>>).

encode_data_keep_alive(#capwap_header{}, IEs, FragId, MTU) ->
    %%   In the CAPWAP Data Channel Keep-Alive packet, all of the fields in
    %%   the CAPWAP Header, except the HLEN field and the 'K' bit, are set to
    %%   zero upon transmission.
    Header = {2, 0, 0, 0, 0, 0, 1, <<>>},
    MsgElements = << <<(encode_element(X))/binary>> || X <- IEs>>,
    PayLoad = <<(byte_size(MsgElements) + 2):16, MsgElements/binary>>,
    encode_part(Header, FragId, 0, PayLoad, MTU - 8).

encode_data_packet(#capwap_header{radio_id = RID,
				  wb_id = WBID,
				  flags = Flags,
				  radio_mac = RadioMAC,
				  wireless_spec_info = WirelessSpecInfo},
		   PayLoad, FragId, MTU) ->
    T = encode_transport(proplists:get_value(frame, Flags, native)),
    {W, WirelessSpecInfoBin} = encode_header(WirelessSpecInfo),
    {M, RadioMACbin} = encode_header(RadioMAC),
    HeaderLen = (8 + byte_size(RadioMACbin) + byte_size(WirelessSpecInfoBin)),
    HLen = HeaderLen div 4,
    Header = {HLen, RID, WBID, T, W, M, 0, <<RadioMACbin/binary, WirelessSpecInfoBin/binary>>},
    encode_part(Header, FragId, 0, PayLoad, MTU - HeaderLen).
