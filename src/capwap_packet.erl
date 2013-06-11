-module(capwap_packet).

-export([decode/2, encode/2]).

-include("capwap_packet.hrl").

decode(Type, <<0:4, 0:4,
		  HLen:5/integer, RID:5/integer, WBID:5/integer,
		  T:1, 0:1, 0:1, W:1, M:1, K:1, _:3,
		  _FragmentId:16/integer, _FragmentOffset:13/integer, _:3,
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
    case {Type, K} of
	{control, _} ->
	    {Header, decode_control_msg(PayLoad)};
	{data, 0} ->
	    {Header, PayLoad};
	{data, 1} ->
	    case PayLoad of
		<<MELength:16, ME:MELength/bytes, _/binary>> ->
		    {Header, decode_elements(ME, [])};
		_ ->
		    %% FIXME: workarround for broken OpenCAPWAP encoding
		    {Header, decode_elements(PayLoad, [])}
	    end
    end.

encode(control, {Header, {MsgType, _, SeqNum, IEs}}) ->
    encode(control, {Header, {MsgType, SeqNum, IEs}});

encode(control, {#capwap_header{radio_id = RID,
				wb_id = WBID,
				flags = Flags,
				radio_mac = RadioMAC,
				wireless_spec_info = WirelessSpecInfo},
		 {MsgType, SeqNum, IEs}}) ->
    FragmentId = 0,
    FragmentOffset = 0,
    T = encode_transport(proplists:get_value(frame, Flags, native)),
    {W, WirelessSpecInfoBin} = encode_header(WirelessSpecInfo),
    {M, RadioMACbin} = encode_header(RadioMAC),
    K = encode_flag('keep-alive', Flags),
    {Vendor, MType} = message_type(MsgType),
    PayLoad = << <<(encode_element(X))/binary>> || X <- IEs>>,
    HLen = (8 + byte_size(RadioMACbin) + byte_size(WirelessSpecInfoBin)) div 4,
    <<0:4, 0:4, HLen:5, RID:5, WBID:5,
      T:1, 0:1, 0:1, W:1, M:1, K:1, 0:3,
      FragmentId:16, FragmentOffset:13, 0:3,
      RadioMACbin/binary, WirelessSpecInfoBin/binary,
      Vendor:24, MType:8, SeqNum:8, (byte_size(PayLoad) + 3):16, 0:8,
      PayLoad/binary>>;

encode(data, {Header = #capwap_header{flags = Flags}, PayLoad}) ->
    case proplists:get_bool('keep-alive', Flags) of
	true ->
	    encode_data_keep_alive(Header, PayLoad);
	_ ->
	    encode_data_packet(Header, PayLoad)
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
extract_header(1, <<Len:8/integer, Field:Len/bytes, _>> = Header) ->
    PLen = Len + pad_length(4, Len + 1),
    <<_:PLen/bytes, Next/binary>> = Header,
    {Field, Next}.

encode_header(undefined) ->
    {0, <<>>};
encode_header(Bin) when is_binary(Bin) ->
    Len = byte_size(Bin),
    {1, pad_to(4, <<Len:8, Bin/binary>>)}.

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

%%%-------------------------------------------------------------------
%%% encoder
%%%-------------------------------------------------------------------

encode_transport('802.3') -> 0;
encode_transport(native)  -> 1.

encode_bool(false) -> 0;
encode_bool(_)     -> 1.

encode_flag(Key, List) ->
    encode_bool(proplists:get_bool(Key, List)).

encode_mac_list(MACs = [H|_]) ->

    Num = length(MACs),
    Len = byte_size(H),
    M = << <<X/binary>> || X <- MACs>>,
    <<Num:8, Len:8, M/binary>>.

encode_ipv4_list(IPs) ->
    << <<X:4/bytes>> || X <- IPs >>.

encode_ipv6_list(IPs) ->
    << <<X:16/bytes>> || X <- IPs >>.

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

encode_data_keep_alive(#capwap_header{wb_id = WBID,
				      radio_mac = RadioMAC,
				      wireless_spec_info = WirelessSpecInfo},
		       MessageElements) ->
    FragmentId = 0,
    FragmentOffset = 0,
    {W, WirelessSpecInfoBin} = encode_header(WirelessSpecInfo),
    {M, RadioMACbin} = encode_header(RadioMAC),
    PayLoad = << <<(encode_element(X))/binary>> || X <- MessageElements>>,
    HLen = (8 + byte_size(RadioMACbin) + byte_size(WirelessSpecInfoBin)) div 4,
    <<0:4, 0:4, HLen:5, 0:5, WBID:5,
      0:1, 0:1, 0:1, W:1, M:1, 1:1, 0:3,
      FragmentId:16, FragmentOffset:13, 0:3,
      RadioMACbin/binary, WirelessSpecInfoBin/binary,
%%      (byte_size(PayLoad) + 3):16,
      PayLoad/binary>>.

encode_data_packet(#capwap_header{radio_id = RID,
				  wb_id = WBID,
				  flags = Flags,
				  radio_mac = RadioMAC,
				  wireless_spec_info = WirelessSpecInfo},
		   PayLoad) ->
    FragmentId = 0,
    FragmentOffset = 0,
    T = encode_transport(proplists:get_value(frame, Flags, native)),
    {W, WirelessSpecInfoBin} = encode_header(WirelessSpecInfo),
    {M, RadioMACbin} = encode_header(RadioMAC),
    HLen = (8 + byte_size(RadioMACbin) + byte_size(WirelessSpecInfoBin)) div 4,
    <<0:4, 0:4, HLen:5, RID:5, WBID:5,
      T:1, 0:1, 0:1, W:1, M:1, 0:1, 0:3,
      FragmentId:16, FragmentOffset:13, 0:3,
      RadioMACbin/binary, WirelessSpecInfoBin/binary,
      PayLoad/binary>>.
