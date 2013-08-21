#!/usr/bin/env escript
%% -*- erlang -*-
%%! -smp enable

ies() ->
    [{1, "AC Descriptor",
      [{"Stations", 16, integer},
       {"Limit", 16, integer},
       {"Active WTPs", 16, integer},
       {"Max WTPs", 16, integer},
       {'_', 5},
       {"Security", {flags, ["pre-shared", "x509"]}},
       {'_', 1},
       {"R-MAC", 8, {enum, [reserved, supported, not_supported]}},
       {'_', 8},
       {'_', 5},
       {"DTLS Policy", {flags, ["enc-data", "clear-text"]}},
       {'_', 1},
       {"Sub-Elements", vendor_subelements}]},
     {2, "AC IPv4 List",
      [{"IP Address", ipv4_list}]},
     {3, "AC IPv6 List",
      [{"IP Address", ipv6_list}]},
     {4, "AC Name",
      [{"Name", 0, binary}]},
     {5, "AC Name with Priority",
      [{"Priority", 8, integer},
       {"Name", 0, binary}]},
     {6, "AC Timestamp",
      [{"Timestamp", 32, integer}]},
     {7, "Add MAC ACL",
      [{"MACs", mac_list}]},
     {8, "Add Station",
      [{"Radio ID", 8, integer},
       {"MAC", 8, length_binary},
       {"VLAN Name", 0, binary}]},
     {10, "Control IPv4 Address",
      [{"IP Address", 4, bytes},
       {"WTP count", 16, integer}]},
     {11, "Control IPv6 Address",
      [{"IP Address", 16, bytes},
       {"WTP count", 16, integer}]},
     {30, "Local IPv4 Address",
      [{"IP Address", 4, bytes}]},
     {50, "Local IPv6 Address",
      [{"IP Address", 16, bytes}]},
     {12, "Timers",
      [{"Discovery", 8, integer},
       {"Echo Request", 8, integer}]},
     {51, "Transport Protocol",
      [{"Transport", 8, {enum, [{1, udp_lite}, {2, udp}]}}]},
     {13, "Data Transfer Data",
      [{"Data Type", 8, {enum, [{1, included}, {2, eof}, {5, error}]}},
       {"Data Mode", 8, {enum, [reserved, crash_data, memory_dump]}},
       {"Data", 16, length_binary}]},
     {14, "Data Transfer Mode",
      [{"Data Mode", 8, {enum, [reserved, crash_data, memory_dump]}}]},
     {15, "Decryption Error Report",
      [{"Radio ID", 8, integer},
       {"MACs", mac_list}]},
     {16, "Decryption Error Report Period",
      [{"Radio ID", 8, integer},
       {"Report Interval", 16, integer}]},
     {17, "Delete MAC ACL Entry",
      [{"MACs", mac_list}]},
     {18, "Delete Station",
      [{"Radio ID", 8, integer},
       {"MAC", 8, length_binary}]},
     {20, "Discovery Type",
      [{"Discovery Type", 8, {enum, [unknown, static, dhcp, dns, 'AC-Referral']}}]},
     {21, "Duplicate IPv4 Address",
      [{"IP Address", 4, bytes},
       {"Status", 8, integer},
       {"MAC", 8, length_binary}]},
     {22, "Duplicate IPv6 Address",
      [{"IP Address", 16, bytes},
       {"Status", 8, integer},
       {"MAC", 8, length_binary}]},
     {23, "Idle Timeout",
      [{"Timeout", 32, integer}]},
     {53, "ECN Support",
      [{"ECN Support", 8, {enum, [limited, full]}}]},
     {24, "Image Data",
      [{"Data Type", 8, {enum, [{1, included}, {2, eof}, {5, error}]}},
       {"Data", 0, binary}]},
     {25, "Image Identifier",
      [{"Vendor", 32, integer},
       {"Data", 0, binary}]},
     {26, "Image Information",
      [{"File Size", 32, integer},
       {"Hash", 16, bytes}]},
     {27, "Initiate Download",
      []},
     {28, "Location Data",
      [{"Location", 0, binary}]},
     {29, "Maximum Message Length",
      [{"Maximum Message Length", 16, integer}]},
     {52, "MTU Discovery Padding",
      [{"Padding", 0, binary}]},
     {31, "Radio Administrative State",
      [{"Radio ID", 8, integer},
       {"Admin State", 8, {enum, [reserved, enabled, disabled]}}]},
     {32, "Radio Operational State",
      [{"Radio ID", 8, integer},
       {"State", 8, {enum, [reserved, enabled, disabled]}},
       {"Cause", 8, {enum, [normal, radio_failure, software_failure, admin_set]}}]},
     {33, "Result Code",
      %% TODO: might want to use a ENUM here
      [{"Result Code", 32, integer}]},
     {34, "Returned Message Element",
      [{"Reason", 8, {enum, [reserved, unknown_ie, unsupported_ie, unknown_ie_value, unsupported_ie_value]}},
       {"Message Element", 0, binary}]},
     {35, "Session ID",
      [{"Session ID", 128, integer}]},
     {36, "Statistics Timer",
      [{"Statistics Timer", 16, integer}]},
     {37, "Vendor Specific Payload",
      [{"Data", 0, vendor_element}]},
     {38, "WTP Board Data",
      [{"Vendor", 32, integer},
       {"Board Data Sub-Elements", subelements}]},
     {39, "WTP Descriptor",
      [{"Max Radios", 8, integer},
       {"Radios in use", 8, integer},
       {"Encryption Sub-Element", 8, {array, 3}},
       {"Sub-Elements", vendor_subelements}]},
     {40, "WTP Fallback",
      [{"Mode", 8, {enum, [reserved, enabled, disabled]}}]},
     {41, "WTP Frame Tunnel Mode",
      [{'_', 4},
       {"Mode", {flags, ["native", "802.3", "local"]}},
       {'_', 1}]},
     {44, "WTP MAC Type",
      [{"MAC Type", 8, {enum, [local, split, both]}}]},
     {45, "WTP Name",
      [{"WTP Name", 0, binary}]},
     {47, "WTP Radio Statistics",
      [{"Radio ID", 8, integer},
       {"Last Fail Type", 8, {enum, [unsuported, software, hardware, {255, other}]}},
       {"Reset Count", 16, integer},
       {"SW Failure Count", 16, integer},
       {"HW Failure Count", 16, integer},
       {"Other  Failure Count", 16, integer},
       {"Unknown Failure Count", 16, integer},
       {"Config Update Count", 16, integer},
       {"Channel Change Count", 16, integer},
       {"Band Change Count", 16, integer},
       {"Current Noise Floor", 16, integer}]},
     {48, "WTP Reboot Statistics",
      [{"Reboot Count ", 16, integer},
       {"AC Initiated Count", 16, integer},
       {"Link Failure Count", 16, integer},
       {"SW Failure Count", 16, integer},
       {"HW Failure Count", 16, integer},
       {"Other Failure Count", 16, integer},
       {"Unknown Failure Count", 16, integer},
       {"Last Failure Type", 8, {enum, [unsuported, ac_initiated, link_failure, software, hardware, {255, other}]}}]},
     {49, "WTP Static IP Address Information",
      [{"IP Address", 4, bytes},
       {"Netmask", 4, bytes},
       {"Gateway", 4, bytes},
       {"Static", 8, integer}]},

     {1024, "IEEE 802.11 Add WLAN",
      [{"Radio ID", 8, integer},
       {"WLAN ID", 8, integer},
       {"Capability", {flags, ["ess", "ibss", "cf-pollable", "cf-poll-request", "privacy", "short_preamble", "pbcc",
			       "channel_agility", "spectrum_management", "qos", "short_slot_time", "apsd", "reserved",
			       "dsss_ofdm", "delayed_block_ack", "immediate_block_ack"]}},
       {"Key Index", 8, integer},
       {"Key Status", 8, {enum, [per_station, static_wep, begin_rekeying, completed_rekeying]}},
       {"Key", 16, length_binary},
       {"Group TSC", 6, bytes},
       {"QoS", 8, {enum, [best_effort, video, voice, backgroung]}},
       {"Auth Type", 8, {enum, [open_system, wep_shared_key]}},
       {"MAC Mode", 8, {enum, [local_mac, split_mac]}},
       {"Tunnel Mode", 8, {enum, [local_bridge, '802_3_tunnel', '802_11_tunnel']}},
       {"Suppress SSID", 8, integer},
       {"SSID", 0, binary}]},
     {1025, "IEEE 802.11 Antenna",
      [{"Radio ID", 8, integer},
       {"Diversity", 8, {enum, [disabled, enabled]}},
       {"Combiner", 8, {enum, [{1 , left}, right, omni, mimo]}},
       {"Antenna Selection", 8, length_binary}]},
     {1026, "IEEE 802.11 Assigned WTP BSSID",
      [{"Radio ID", 8, integer},
       {"WLAN ID", 8, integer},
       {"BSSID", 6, bytes}]},
     {1027, "IEEE 802.11 Delete WLAN",
      [{"Radio ID", 8, integer},
       {"WLAN ID", 8, integer}]},
     {1028, "IEEE 802.11 Direct Sequence Control",
      [{"Radio ID", 8, integer},
       {'_', 8},
       {"Current Chan", 8, integer},
       {"Current CCA", 8, {enum, [{1, edonly}, {2, csonly}, {4, edandcs}, {8, cswithtimer}, {16, hrcsanded}]}},
       {"Energy Detect Threshold", 32, integer}]},
     {1029, "IEEE 802.11 Information Element",
      [{"Radio ID", 8, integer},
       {"WLAN ID", 8, integer},
       {"Flags", {flags, ["beacon", "probe_response"]}},
       {'_', 6},
       {"IE", 0, binary}]},
     {1030, "IEEE 802.11 MAC Operation",
      [{"Radio ID", 8, integer},
       {'_', 8},
       {"RTS Threshold", 16, integer},
       {"Short Retry", 8, integer},
       {"Long Retry", 8, integer},
       {"Fragmentation Threshold", 16, integer},
       {"Tx MSDU Lifetime", 32, integer},
       {"Rx MSDU Lifetime", 32, integer}]},
     {1031, "IEEE 802.11 MIC Countermeasures",
      [{"Radio ID", 8, integer},
       {"WLAN ID", 8, integer},
       {"MAC", 6, bytes}]},
     {1032, "IEEE 802.11 Multi-Domain Capability",
      [{"Radio ID", 8, integer},
       {'_', 8},
       {"First Channel", 16, integer},
       {"Number of Channels ", 16, integer},
       {"Max Tx Power Level", 16, integer}]},
     {1033, "IEEE 802.11 OFDM Control",
      [{"Radio ID", 8, integer},
       {'_', 8},
       {"Current Chan", 8, integer},
       {"Band Support", 8, integer},
       {"TI Threshold", 32, integer}]},
     {1034, "IEEE 802.11 Rate Set",
      [{"Radio ID", 8, integer},
       {"Rate Set", 0, binary}]},
     {1035, "IEEE 802.11 RSNA Error Report From Station",
      [{"Client MAC Address", 6, bytes},
       {"BSSID", 6, bytes},
       {"Radio ID", 8, integer},
       {"WLAN ID", 8, integer},
       {'_', 16},
       {"TKIP ICV Errors", 32, integer},
       {"TKIP Local MIC Failures", 32, integer},
       {"TKIP Remote MIC Failures", 32, integer},
       {"CCMP Replays", 32, integer},
       {"CCMP Decrypt Errors", 32, integer},
       {"TKIP Replays", 32, integer}]},
     {1036, "IEEE 802.11 Station",
      [{"Radio ID", 8, integer},
       {"Association ID", 16, integer},
       {'_', 0},
       {"MAC Address", 6, bytes},
       {"Capabilities", 2, bytes},
       {"WLAN ID", 8, integer},
       {"Supported Rate", 0, binary}]},
     {1037, "IEEE 802.11 Station QoS Profile",
      [{"MAC Address", 6, bytes},
       {'_', 13},
       {"p8021p", 3, integer}]},
     {1038, "IEEE 802.11 Station Session Key",
      [{"MAC Address", 6, bytes},
       {"Flags", {flags, ["akm_only", "ac_crypto"]}},
       {'_', 14},
       {"Pairwise TSC", 6, bytes},
       {"Pairwise RSC", 6, bytes},
       {"Key", 0, binary}]},
     {1039, "IEEE 802.11 Statistics",
      [{"Radio ID", 8, integer},
       {'_', 24},
       {"Tx Fragment Count", 32, integer},
       {"Multicast Tx Count", 32, integer},
       {"Failed Count", 32, integer},
       {"Retry Count", 32, integer},
       {"Multiple Retry Count", 32, integer},
       {"Frame Duplicate Count", 32, integer},
       {"RTS Success Count", 32, integer},
       {"RTS Failure Count", 32, integer},
       {"ACK Failure Count", 32, integer},
       {"Rx Fragment Count", 32, integer},
       {"Multicast RX Count", 32, integer},
       {"FCS Error  Count", 32, integer},
       {"Tx Frame Count", 32, integer},
       {"Decryption Errors", 32, integer},
       {"Discarded QoS Fragment Count", 32, integer},
       {"Associated Station Count", 32, integer},
       {"QoS CF Polls Received Count", 32, integer},
       {"QoS CF Polls Unused Count", 32, integer},
       {"QoS CF Polls Unusable Count", 32, integer}]},
     {1040, "IEEE 802.11 Supported Rates",
      [{"Radio ID", 8, integer},
       {"Supported Rates", 0, binary}]},
     {1041, "IEEE 802.11 Tx Power",
      [{"Radio ID", 8, integer},
       {'_', 8},
       {"Current Tx Power", 16, integer}]},
     {1042, "IEEE 802.11 Tx Power Level",
      [{"Radio ID", 8, integer},
       {"Power Level", 8, {array, 2}}]},
     {1043, "IEEE 802.11 Update Station QoS",
      [{"Radio ID", 8, integer},
       {"MAC Address", 6, bytes},
       {"QoS Sub-Element", 8, bytes}]},
     {1044, "IEEE 802.11 Update WLAN",
      [{"Radio ID", 8, integer},
       {"WLAN ID", 8, integer},
       {"Capability", {flags, ["ess", "ibss", "cf-pollable", "cf-poll-request", "privacy", "short_preamble", "pbcc",
			       "channel_agility", "spectrum_management", "qos", "short_slot_time", "apsd", "reserved",
			       "dsss_ofdm", "delayed_block_ack", "immediate_block_ack"]}},
       {"Key Index", 8, integer},
       {"Key Status", 8, {enum, [per_station, static_wep, begin_rekeying, completed_rekeying]}},
       {"Key", 16, length_binary}]},
     {1045, "IEEE 802.11 WTP Quality of Service",
      [{"Radio ID", 8, integer},
       {'_', 3},
       {"Tagging Policy", 5, bits},
       {"QoS Sub-Element", 32, bytes}]},
     {1046, "IEEE 802.11 WTP Radio Configuration",
      [{"Radio ID", 8, integer},
       {"Short Preamble", 8, {enum, [unsupported, supported]}},
       {"Num of BSSIDs", 8, integer},
       {"DTIM Period", 8, integer},
       {"BSSID", 6, bytes},
       {"Beacon Period", 16, integer},
       {"Country String", 4, bytes}]},
     {1047, "IEEE 802.11 WTP Radio Fail Alarm Indication",
      [{"Radio ID", 8, integer},
       {"Type", 8, {enum, [receiver, transmitter]}},
       {"Status", 8, integer},
       {'_', 8}]},
     {1048, "IEEE 802.11 WTP Radio Information",
      [{"Radio ID", 8, integer},
       {'_', 28},
       {"Radio Type", {flags, ["802.11n", "802.11g", "802.11a", "802.11b"]}}]}
    ].

vendor_ies() ->
    [{{18681, 1}, "TP WTP WWAN Statistics",
      [{"Timestamp", 32, integer},
       {"WWAN Id", 8, integer},
       {"RAT", 8, integer},
       {"RSSi", 8, integer},
       {'_', 8},
       {"LAC", 16, integer},
       {'_', 16},
       {"Cell Id", 32, integer}]},
     {{18681, 2}, "TP WTP Timestamp",
      [{"Timestamp", 32, integer}]},
     {{18681, 3}, "TP WTP WWAN ICCID",
      [{"WWAN Id", 8, integer},
       {"ICCID", 0, binary}]},
     {{18681, 4}, "TP IEEE 802.11 WLAN Hold Time",
      [{"Radio ID", 8, integer},
       {"WLAN ID", 8, integer},
       {'_', 16},
       {"Hold Time", 32, integer}]}
    ].

msgs() ->
    [{1, "Discovery Request"},
     {2, "Discovery Response"},
     {3, "Join Request"},
     {4, "Join Response"},
     {5, "Configuration Status Request"},
     {6, "Configuration Status Response"},
     {7, "Configuration Update Request"},
     {8, "Configuration Update Response"},
     {9, "WTP Event Request"},
     {10, "WTP Event Response"},
     {11, "Change State Event Request"},
     {12, "Change State Event Response"},
     {13, "Echo Request"},
     {14, "Echo Response"},
     {15, "Image Data Request"},
     {16, "Image Data Response"},
     {17, "Reset Request"},
     {18, "Reset Response"},
     {19, "Primary Discovery Request"},
     {20, "Primary Discovery Response"},
     {21, "Data Transfer Request"},
     {22, "Data Transfer Response"},
     {23, "Clear Configuration Request"},
     {24, "Clear Configuration Response"},
     {25, "Station Configuration Request"},
     {26, "Station Configuration Response"},
     {3398913, "IEEE 802.11 WLAN Configuration Request"},
     {3398914, "IEEE 802.11 WLAN Configuration Response"}
    ].

gen_record_def({Value, _}) when is_integer(Value); is_atom(Value) ->
    [];
gen_record_def({Name, {flags, _}}) ->
    [io_lib:format("~s = []", [s2a(Name)])];
gen_record_def({Name, _, {enum, [{_,H}|_]}}) ->
    [io_lib:format("~s = ~w", [s2a(Name), H])];
gen_record_def({Name, _, {enum, [H|_]}}) ->
    [io_lib:format("~s = ~w", [s2a(Name), H])];
gen_record_def({Name, _, integer}) ->
    [io_lib:format("~s = 0", [s2a(Name)])];
gen_record_def({Name, Size, bits}) ->
    [io_lib:format("~s = ~w", [s2a(Name), <<0:Size>>])];
gen_record_def({Name, Size, bytes}) ->
    [io_lib:format("~s = ~w", [s2a(Name), <<0:(Size * 8)>>])];
gen_record_def({Name, _, binary}) ->
    [io_lib:format("~s = <<>>", [s2a(Name)])];
gen_record_def({Name, _, length_binary}) ->
    [io_lib:format("~s = <<>>", [s2a(Name)])];
gen_record_def({Name, _, {array, _}}) ->
    [io_lib:format("~s = []", [s2a(Name)])];
gen_record_def(Tuple) ->
    Name = element(1, Tuple),
    [s2a(Name)].

gen_decoder_header_match({'_', Size}) ->
    [io_lib:format("_:~w", [Size])];
gen_decoder_header_match({Value, Size}) when is_integer(Value); is_atom(Value) ->
    [io_lib:format("~w:~w", [Value, Size])];
gen_decoder_header_match({Name, {flags, Flags}}) ->
    [io_lib:format("M_~s_~s:1", [s2a(Name), s2a(Flag)]) || Flag <- Flags];
gen_decoder_header_match({Name, Size, {enum, _Enum}}) ->
    [io_lib:format("M_~s:~w/integer", [s2a(Name), Size])];
gen_decoder_header_match({Name, _Fun}) ->
    [io_lib:format("M_~s/binary", [s2a(Name)])];
gen_decoder_header_match({Name, Len, {array, _Multi}}) ->
    {stop, [io_lib:format("M_~s_len:~w/integer, M_Rest/binary", [s2a(Name), Len])]};
gen_decoder_header_match({Name, Len, length_binary}) ->
    [io_lib:format("M_~s_len:~w/integer, M_~s:M_~s_len/bytes", [s2a(Name), Len, s2a(Name), s2a(Name)])];
gen_decoder_header_match({Name, 0, Type}) ->
    [io_lib:format("M_~s/~w", [s2a(Name), Type])];
gen_decoder_header_match({Name, Size, Type}) ->
    [io_lib:format("M_~s:~w/~w", [s2a(Name), Size, Type])].

gen_decoder_record_assign({Value, _}) when is_integer(Value); is_atom(Value) ->
    [];
gen_decoder_record_assign({Name, {flags, Flags}}) ->
    F = [io_lib:format("[ '~s' || M_~s_~s =/= 0 ]", [X, s2a(Name), s2a(X)]) || X <- Flags],
    [io_lib:format("~s = ~s", [s2a(Name), string:join(F, " ++ ")])];
gen_decoder_record_assign({Name, _Size, {enum, _Enum}}) ->
    [io_lib:format("~s = enum_~s(M_~s)", [s2a(Name), s2a(Name), s2a(Name)])];
gen_decoder_record_assign({Name, Fun}) ->
    [io_lib:format("~s = decode_~s(M_~s)", [s2a(Name), Fun, s2a(Name)])];
gen_decoder_record_assign({Name, _Size, {array, Multi}}) ->
    [io_lib:format("~s = [X || <<X:~w/bytes>> <= M_~s]", [s2a(Name), Multi, s2a(Name)])];
gen_decoder_record_assign({Name, _Size, _Type}) ->
    [io_lib:format("~s = M_~s", [s2a(Name), s2a(Name)])].

gen_encoder_record_assign({Value, _}) when is_integer(Value); is_atom(Value) ->
    [];
gen_encoder_record_assign(Tuple) ->
    Name = element(1, Tuple),
    [io_lib:format("~s = M_~s", [s2a(Name), s2a(Name)])].

gen_encoder_bin({'_', Size}) ->
    [io_lib:format("0:~w", [Size])];
gen_encoder_bin({Value, Size}) when is_integer(Value); is_atom(Value) ->
    [io_lib:format("~w:~w", [Value, Size])];
gen_encoder_bin({Name, {flags, Flags}}) ->
    [io_lib:format("(encode_flag('~s', M_~s)):1", [Flag, s2a(Name)]) || Flag <- Flags];
gen_encoder_bin({Name, Size, {enum, _Enum}}) ->
    [io_lib:format("(enum_~s(M_~s)):~w/integer", [s2a(Name), s2a(Name), Size])];
gen_encoder_bin({Name, Fun}) ->
    [io_lib:format("(encode_~s(M_~s))/binary", [Fun, s2a(Name)])];
gen_encoder_bin({Name, Len, {array, _Multi}}) ->
    [io_lib:format("(length(M_~s)):~w/integer, (<< <<X/binary>> || X <- M_~s>>)/binary", [s2a(Name), Len, s2a(Name)])];
gen_encoder_bin({Name, Len, length_binary}) ->
    [io_lib:format("(byte_size(M_~s)):~w/integer, M_~s/binary", [s2a(Name), Len, s2a(Name)])];
gen_encoder_bin({Name, 0, Type}) ->
    [io_lib:format("M_~s/~w", [s2a(Name), Type])];
gen_encoder_bin({Name, Size, bytes}) ->
    [io_lib:format("M_~s:~w/bytes", [s2a(Name), Size])];
gen_encoder_bin({Name, Size, bits}) ->
    [io_lib:format("M_~s:~w/bits", [s2a(Name), Size])];
gen_encoder_bin({Name, Size, _Type}) ->
    [io_lib:format("M_~s:~w", [s2a(Name), Size])].

indent(Atom, Extra) when is_atom(Atom) ->
    indent(atom_to_list(Atom), Extra);
indent(List, Extra) ->
    Indent = length(lists:flatten(List)) + Extra,
    lists:duplicate(Indent, " ").

s2a(Name) ->
    lists:map(fun(32) -> $_;
		 ($-) -> $_;
		 ($.) -> $_;
		 (C)  -> C
	      end,
	      string:to_lower(Name)).

append([], Acc) ->
    Acc;
append([H|T], Acc) ->
    append(T, [H|Acc]).

collect(_Fun, [], Acc) ->
    lists:reverse(Acc);
collect(Fun, [F|Fields], Acc) ->
    case Fun(F) of
	[] ->
	    collect(Fun, Fields, Acc);
	{stop, L} ->
	    lists:reverse(append(L, Acc));
	L ->
	    collect(Fun, Fields, append(L, Acc))
    end.

collect(Fun, Fields) ->
    collect(Fun, Fields, []).

gen_enum(Name, Value, Cnt, Next, {FwdFuns, RevFuns}) ->
    Fwd = io_lib:format("enum_~s(~w) -> ~w", [s2a(Name), Value, Cnt]),
    Rev = io_lib:format("enum_~s(~w) -> ~w", [s2a(Name), Cnt, Value]),
    gen_enum(Name, Next, Cnt + 1, {[Fwd|FwdFuns], [Rev|RevFuns]}).

gen_enum(_, [], _, {FwdFuns, RevFuns}) ->
    {lists:reverse(FwdFuns), lists:reverse(RevFuns)};
gen_enum(Name, [{Cnt, Value}|Rest], _, Acc) ->
    gen_enum(Name, Value, Cnt, Rest, Acc);
gen_enum(Name, [Value|Rest], Cnt, Acc) ->
    gen_enum(Name, Value, Cnt, Rest, Acc).

gen_message_type(Value, Name, Next, {FwdFuns, RevFuns}) ->
    Vendor = Value div 256,
    Type = Value rem 256,
    Fwd = io_lib:format("message_type(~s) -> {~w, ~w}", [s2a(Name), Vendor, Type]),
    Rev = io_lib:format("message_type({~w, ~w}) -> ~s", [Vendor, Type, s2a(Name)]),
    gen_message_type(Next, {[Fwd|FwdFuns], [Rev|RevFuns]}).

gen_message_type([], {FwdFuns, RevFuns}) ->
    {lists:reverse(FwdFuns), lists:reverse(RevFuns)};
gen_message_type([{Value, Name}|Rest], Acc) ->
    gen_message_type(Value, Name, Rest, Acc).

collect_late_assign(_, [], Init, Acc) ->
    {Init, lists:reverse(Acc)};
collect_late_assign(do, [H|R], Init, Acc) ->
    Match = gen_decoder_header_match(H),
    collect_late_assign(do, R, Init, [Match|Acc]);
collect_late_assign(init, [{Name, _Len, {array, Multi}}|R], _, _) ->
    Init = io_lib:format("M_~s_size = M_~s_len * ~w", [s2a(Name), s2a(Name), Multi]),
    Match = io_lib:format("M_~s:M_~s_size/bytes", [s2a(Name), s2a(Name)]),
    collect_late_assign(do, R, Init, [Match]);
collect_late_assign(init, [_|R], _, _) ->
    collect_late_assign(init, R, [], []).

collect_enum({Name, _, {enum, Enum}}, Acc) ->
    {FwdFuns, RevFuns} = gen_enum(Name, Enum, 0, {[], []}),
    S = string:join(FwdFuns ++ RevFuns, ";\n") ++ ".\n",
    lists:keystore(Name, 1, Acc, {Name, S});
collect_enum(_, Acc) ->
    Acc.

collect_enums({_, _, Fields}, AccIn) ->
    lists:foldr(fun(X, Acc) -> collect_enum(X, Acc) end, AccIn, Fields).

write_enums(IEs) ->
    E = lists:foldr(fun(X, Acc) -> collect_enums(X, Acc) end, [], IEs),
    {_, Str} = lists:unzip(E),
    string:join(Str, "\n").

write_record({_Id, Name, Fields}) ->
    Indent = "        ",
    RecordDef = string:join(collect(fun(X) -> gen_record_def(X) end, Fields), [",\n", Indent]),
    io_lib:format("-record(~s, {~n~s~s~n}).~n", [s2a(Name), Indent, RecordDef]).

%% hand crafted vendor IE
write_decoder(_FunName, {37, _Name, _Fields}) ->
"decode_element(37, <<M_vendor:32/integer,
                     M_element_id:16/integer,
                     M_data/binary>>) ->
    decode_vendor_element({M_vendor, M_element_id}, M_data)";

write_decoder(FunName, {Id, Name, Fields}) ->
    FunHead = io_lib:format("~s(~w, ", [FunName, Id]),
    MatchIdent = indent(FunHead, 2),
    Match = string:join(collect(fun(X) -> gen_decoder_header_match(X) end, Fields), [",\n", MatchIdent]),

    Body = case collect_late_assign(init, Fields, [], []) of
	       {[], []} ->
		   [];
	       {Init, SubMatch} ->
		   M = io_lib:format("    <<~s>> = M_Rest,", [string:join(SubMatch, ",\n      ")]),
		   ["    ", Init, ",\n", M, "\n"]
	   end,
    RecIdent = indent(Name, 6),
    RecAssign = string:join(collect(fun(X) -> gen_decoder_record_assign(X) end, Fields), [",\n", RecIdent]),
    io_lib:format("~s<<~s>>) ->~n~s    #~s{~s}", [FunHead, Match, Body, s2a(Name), RecAssign]).

write_encoder(FunName, {Id, Name, Fields}) ->
    RecIdent = indent("encode_element(#", 4),
    RecAssign = string:join(collect(fun(X) -> gen_encoder_record_assign(X) end, Fields), [",\n", RecIdent]),
    FunHead = io_lib:format("encode_element(#~s{~n~s~s}) ->~n", [s2a(Name), RecIdent, RecAssign]),
    DecHead = io_lib:format("    ~s(~w, ", [FunName, Id]),
    BinIndent = indent(DecHead, 2),
    BinAssign = string:join(collect(fun(X) -> gen_encoder_bin(X) end, Fields), [",\n", BinIndent]),
    io_lib:format("~s~s<<~s>>)", [FunHead, DecHead, BinAssign]).

main(_) ->
    io:format("ies: ~p~n", [ies()]),

    {FwdFuns, RevFuns} = gen_message_type(msgs(), {[], []}),
    WildFun = ["message_type({Vendor, Type}) when is_integer(Vendor), is_integer(Type) -> {Vendor, Type}"],
    MTypes = string:join(FwdFuns ++ RevFuns ++ WildFun, ";\n") ++ ".\n",

    Records = string:join([write_record(X) || X <- ies() ++ vendor_ies(), element(1, X) /= 37], "\n"),
    HrlRecs = io_lib:format("%% This file is auto-generated. DO NOT EDIT~n~n~s~n", [Records]),
    Enums = write_enums(ies() ++ vendor_ies()),

    CatchAnyDecoder = "decode_element(Tag, Value) ->\n        {Tag, Value}",
    CatchAnyVendorDecoder = "decode_vendor_element(Tag, Value) ->\n        {Tag, Value}",

    Funs = string:join([write_decoder("decode_element", X) || X <- ies()] ++ [CatchAnyDecoder], ";\n\n"),
    VendorFuns = string:join([write_decoder("decode_vendor_element", X) || X <- vendor_ies()] ++ [CatchAnyVendorDecoder], ";\n\n"),

    CatchAnyVendorEncoder = "encode_element({Tag = {_, _}, Value}) ->\n    encode_vendor_element(Tag, Value)",
    CatchAnyEncoder = "encode_element({Tag, Value}) when is_integer(Tag) ->\n    encode_element(Tag, Value)",
    EncFuns = string:join([write_encoder("encode_element", X) || X <- ies(), element(1, X) /= 37] ++
                          [write_encoder("encode_vendor_element", X) || X <- vendor_ies()]
                          ++ [CatchAnyVendorEncoder, CatchAnyEncoder] , ";\n\n"),
 
    ErlDecls = io_lib:format("%% This file is auto-generated. DO NOT EDIT~n~n~s~n~s~n~s.~n~n~s.~n~n~s.~n",
			     [MTypes, Enums, Funs, VendorFuns, EncFuns]),
    io:format(ErlDecls),
    file:write_file("include/capwap_packet_gen.hrl", HrlRecs),
    file:write_file("src/capwap_packet_gen.hrl", ErlDecls).

