%% Copyright (C) 2017, Travelping GmbH <info@travelping.com>

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

-module(eapol).

-export([encode_802_11/3, packet/1, key/3, request/3, decode/1, validate_mic/2]).
-export([phrase2psk/2, prf/5, kdf/5, pmk2ptk/6, ft_msk2ptk/11, aes_key_wrap/2, key_len/1]).

-include_lib("kernel/include/logger.hrl").
-include("eapol.hrl").

-define(is_mac(MAC),(is_binary(MAC) andalso byte_size(MAC) == 6)).

-define('802_1X_VERSION', 2).

-define(EAPOL_PACKET_TYPE_PACKET, 0).
-define(EAPOL_PACKET_TYPE_START, 1).
-define(EAPOL_PACKET_TYPE_LOGOFF, 2).
-define(EAPOL_PACKET_TYPE_KEY, 3).
-define(EAPOL_PACKET_TYPE_ENCAPS_ASF_ALERT, 4).

-define(EAPOL_KEY_RC4, 1).
-define(EAPOL_KEY_802_11, 2).

-define(EAPOL_CODE_REQUEST, 1).
-define(EAPOL_CODE_RESPONSE, 2).

eap_type(identity) -> 1;
eap_type(1) -> identity;
eap_type(X) when is_integer(X) -> X.

key_len(#ccmp{})    -> 16;
key_len('CCMP')     -> 16;
key_len('AES-CMAC') -> 16.

mic_len('HMAC-SHA1-128') -> 16;
mic_len('AES-128-CMAC')  -> 16;
mic_len('HMAC-SHA256')   -> 16;
mic_len('HMAC-SHA384')   -> 24.

keyinfo(group, Info) ->
    Info;
keyinfo(pairwise, Info) ->
    Info bor 16#0008;
keyinfo(install, Info) ->
    Info bor 16#0040;
keyinfo(ack, Info) ->
    Info bor 16#0080;
keyinfo(mic, Info) ->
    Info bor 16#0100;
keyinfo(secure, Info) ->
    Info bor 16#0200;
keyinfo(enc, Info) ->
    Info bor 16#1000;
keyinfo(_, Info) ->
    Info.

dec_keyinfo(16#0008, 0, Flags) ->
    [group | Flags];
dec_keyinfo(16#0008, 1, Flags) ->
    [pairwise | Flags];
dec_keyinfo(16#0040, 1, Flags) ->
    [install | Flags];
dec_keyinfo(16#0080, 1, Flags) ->
    [ack | Flags];
dec_keyinfo(16#0100, 1, Flags) ->
    [mic | Flags];
dec_keyinfo(16#0200, 1, Flags) ->
    [secure | Flags];
dec_keyinfo(16#1000, 1, Flags) ->
    [enc | Flags];
dec_keyinfo(Cnt, 1, Flags) ->
    [Cnt | Flags];
dec_keyinfo(_Cnt, 0, Flags) ->
    Flags.

keyinfo(0, _, Flags) ->
    Flags;
keyinfo(V, Cnt, Flags0) ->
    Flags = dec_keyinfo(Cnt, V band 1, Flags0),
    keyinfo(V bsr 1, Cnt bsl 1, Flags).

keyinfo(Info) ->
    keyinfo(Info bsr 3, 16#08, []).

mic_algo('HMAC-SHA1-128') -> 2;
mic_algo('AES-128-CMAC') -> 3;
mic_algo(X) when is_atom(X) -> 0;

mic_algo(2) -> 'HMAC-SHA1-128';
mic_algo(3) -> 'AES-128-CMAC';
mic_algo(X) when is_integer(X) -> unknown.

calc_hmac(#ccmp{mic_algo = 'HMAC-SHA1-128', kck = KCK}, EAPOL, Data, MICLen) ->
    C1 = crypto:mac_init(hmac, sha, KCK),
    C2 = crypto:mac_update(C1, EAPOL),
    C3 = crypto:mac_update(C2, binary:copy(<<0>>, MICLen)),
    C4 = crypto:mac_update(C3, Data),
    crypto:mac_finalN(C4, MICLen);

calc_hmac(#ccmp{mic_algo = 'AES-128-CMAC', kck = KCK}, EAPOL, Data, MICLen) ->
    crypto:mac(cmac, aes_128_cbc, KCK, <<EAPOL/binary, 0:(MICLen * 8), Data/binary>>).

packet(Data) ->
    DataLen = size(Data),
    <<?'802_1X_VERSION', ?EAPOL_PACKET_TYPE_PACKET, DataLen:16, Data/binary>>.

request(Id, Type, Data) ->
    EAPOLData = <<(eap_type(Type)):8, Data/binary>>,
    DataLen = size(EAPOLData) + 4,
    <<?EAPOL_CODE_REQUEST, Id:8, DataLen:16, EAPOLData/binary>>.

%%
%% EAPOL Key frames are defined in IEEE 802.11-2012, Sect. 11.6.2
%%
key(Flags, KeyData, #ccmp{mic_algo = MICAlgo,
			  replay_counter = ReplayCounter,
			  nonce = Nonce} = CCMP) ->
    KeyInfo = lists:foldl(fun keyinfo/2, 0, Flags)
	bor mic_algo(MICAlgo),
    KeyLen = key_len(CCMP),
    MICLen = mic_len(MICAlgo),
    EAPOLData = <<?EAPOL_KEY_802_11, KeyInfo:16, KeyLen:16, ReplayCounter:64,
		  Nonce:32/bytes,		%% Key Nounce
		  0:128,			%% EAPOL Key IV
		  0:64,				%% Key RSC, see RFC 5416, Sect. 9.1 !!!!
		  0:64>>,			%% reserved
    KeyDataLen = byte_size(KeyData),
    KeyData1 = <<KeyDataLen:16, KeyData/binary>>,
    DataLen = byte_size(EAPOLData) + MICLen + 2 + KeyDataLen,
    EAPOL = <<?'802_1X_VERSION', ?EAPOL_PACKET_TYPE_KEY, DataLen:16, EAPOLData/binary>>,

    MIC = case proplists:get_bool(mic, Flags) of
	      true ->
		  calc_hmac(CCMP, EAPOL, KeyData1, MICLen);
	      _ ->
		  binary:copy(<<0>>, MICLen)
	  end,
    iolist_to_binary([EAPOL, MIC, KeyData1]).

validate_mic(Crypto, {Head, MIC, Tail}) ->
    case calc_hmac(Crypto, Head, Tail, byte_size(MIC)) of
	MIC -> ok;
	V   ->
	    ?LOG(debug, "Algo: ~p", [Crypto#ccmp.mic_algo]),
	    ?LOG(debug, "Head: ~s", [binary:encode_hex(Head)]),
	    ?LOG(debug, "MIC: ~s", [binary:encode_hex(MIC)]),
	    ?LOG(debug, "Tail: ~s", [binary:encode_hex(Tail)]),
	    ?LOG(debug, "invalid MIC: expected: ~s, got: ~s", [binary:encode_hex(MIC), binary:encode_hex(V)]),
	    {error, invalid}
    end.

decode(<<Version:8, ?EAPOL_PACKET_TYPE_START, DataLen:16, Data:DataLen/binary>>)
  when Version == 1; Version == 2 ->
    {start, Data};

decode(Packet = <<Version:8, ?EAPOL_PACKET_TYPE_PACKET, DataLen:16, EAPOLData:DataLen/binary>>)
  when Version == 1; Version == 2 ->
    try EAPOLData of
	<<?EAPOL_CODE_RESPONSE, Id:8, DataLen:16, 1:8, Identity/bytes>>
	  when size(Identity) == DataLen - 5 ->
	    {response, Id, EAPOLData, {identity, Identity}};
	<<?EAPOL_CODE_RESPONSE, Id:8, DataLen:16, Data/bytes>>
	  when size(Data) == DataLen - 4 ->
	    {response, Id, EAPOLData, Data};
	_ ->
	    {unknown, Packet}
    catch
	_:_ -> {invalid, Packet}
    end;

decode(Data = <<Version:8, ?EAPOL_PACKET_TYPE_KEY, DataLen:16, EAPOLData:DataLen/binary>>)
  when Version == 1; Version == 2 ->
    try
	<<?EAPOL_KEY_802_11, KeyInfo:16, _/binary>> = EAPOLData,
	MICAlgo = mic_algo(KeyInfo band 16#07),
	Flags = keyinfo(KeyInfo),
	?LOG(debug, "KeyInfo: ~p", [Flags]),
	MICLen = mic_len(MICAlgo),

	<< ?EAPOL_KEY_802_11, _:16, _KeyLen:16, ReplayCounter:64,
	   Nonce:32/bytes, 0:128, 0:64, 0:64, _:MICLen/bytes,
	   KeyDataLen:16, KeyData:KeyDataLen/bytes>> = EAPOLData,

	<< Head:81/bytes, MIC:MICLen/bytes, Tail/bytes>> = Data,

	{key, Flags, MICAlgo, ReplayCounter, Nonce, KeyData, {Head, MIC, Tail}}
    catch
	_:_ -> {invalid, Data}
    end;
decode(Data) ->
    {unknown, Data}.


encode_802_11(DA, BSS, KeyData)
  when ?is_mac(DA), ?is_mac(BSS) ->

    LLCHdr = <<?LLC_DSAP_SNAP, ?LLC_SSAP_SNAP, ?LLC_CNTL_SNAP, ?SNAP_ORG_ETHERNET, ?ETH_P_PAE:16>>,
    Frame = <<LLCHdr/binary, KeyData/binary>>,

    {Type, SubType} = ieee80211_station:frame_type('QoS Data'),
    FrameControl = <<SubType:4, Type:2, 0:2, 0:6, 1:1, 0:1>>,
    Duration = 0,
    SequenceControl = 0,
    QoS = <<7, 0>>,
    <<FrameControl/binary,
      Duration:16/integer-little,
      DA:6/bytes, BSS:6/bytes, BSS:6/bytes,
      SequenceControl:16,
      QoS/binary,
      Frame/binary>>.

%% IEEE 802.11-2012, Sect. 11.6.1.2, PRF
prf(Type, Key, Label, Data, WantedLength) ->
    prf(Type, Key, Label, Data, WantedLength, 0, []).

prf(_Type, _Key, _Label, _Data, WantedLength, _N, [Last | Acc])
  when WantedLength =< 0 ->
    Keep = bit_size(Last) + WantedLength,
    ?LOG(debug, "Size: ~p, Wanted: ~p, Keep: ~p", [bit_size(Last), WantedLength, Keep]),
    <<B:Keep/bits, _/bits>> = Last,
    list_to_binary(lists:reverse(Acc, [B]));

prf(Type, Key, Label, Data, WantedLength, N, Acc) ->
    Bin = crypto:mac(hmac, Type, Key, [Label, 0, Data, N]),
    prf(Type, Key, Label, Data, WantedLength - bit_size(Bin), N + 1, [Bin|Acc]).

%% IEEE 802.11-2012, Sect. 11.6.1.7.2, KDF
kdf(Type, Key, Label, Data, WantedLength) ->
    kdf(Type, Key, Label, [Data, <<WantedLength:16/little>>], WantedLength, 1, []).

kdf(_Type, _Key, _Label, _Data, WantedLength, _N, [Last | Acc])
  when WantedLength =< 0 ->
    Keep = bit_size(Last) + WantedLength,
    ?LOG(debug, "Size: ~p, Wanted: ~p, Keep: ~p", [bit_size(Last), WantedLength, Keep]),
    <<B:Keep/bits, _/bits>> = Last,
    list_to_binary(lists:reverse(Acc, [B]));

kdf(Type, Key, Label, Data, WantedLength, N, Acc) ->
    Bin = crypto:mac(hmac, Type, Key, [<<N:16/little>>, Label, Data]),
    kdf(Type, Key, Label, Data, WantedLength - bit_size(Bin), N + 1, [Bin|Acc]).


phrase2psk(Phrase, SSID)
  when is_binary(Phrase), is_binary(SSID) ->
    crypto:pbkdf2_hmac(sha, Phrase, SSID, 4096, 32);
phrase2psk(Phrase, SSID)
  when is_list(Phrase) ->
    phrase2psk(iolist_to_binary(Phrase), SSID);
phrase2psk(Phrase, SSID)
  when is_list(SSID) ->
    phrase2psk(Phrase, iolist_to_binary(SSID)).

pmk2ptk(PMK, AA, SPA, ANonce, SNonce, PRFLen) ->
    <<KCK:16/bytes, KEK:16/bytes, TK/binary>> =
	prf(sha, PMK, "Pairwise key expansion", [min(AA, SPA), max(AA, SPA),
						  min(ANonce, SNonce), max(SNonce, ANonce)], PRFLen),
    {KCK, KEK, TK}.

ft_msk2ptk(MSK, SNonce, ANonce, BSS, StationMAC, SSID, MDomain, R0KH, R1KH, S0KH, S1KH) ->
    <<_:256/bits, XXKey:256/bits>> = MSK,

    %% R0-Key-Data = KDF-384(XXKey, "FT-R0", SSIDlength || SSID ||
    %%                        MDID || R0KHlength || R0KH-ID || S0KH-ID)
    %% PMK-R0 = L(R0-Key-Data, 0, 256)
    %% PMK-R0Name-Salt = L(R0-Key-Data, 256, 128)
    %% PPMKR0Name = Truncate-128(SHA-256("FT-R0N" || PMK-R0Name-Salt))

    ?LOG(debug, "FT XXKey: ~p", [binary:encode_hex(XXKey)]),
    ?LOG(debug, "FT: R0KH-Id: ~p", [binary:encode_hex(R0KH)]),

    <<PMKR0:256/bits, PMKR0NameSalt:128/bits>> =
	kdf(sha256, XXKey, "FT-R0", [byte_size(SSID), SSID, <<MDomain:16>>,
					   byte_size(R0KH), R0KH, S0KH], 384),
    <<PMKR0Name:128/bits, _/binary>> = crypto:hash(sha256, ["FT-R0N", PMKR0NameSalt]),

    ?LOG(debug, "FT PMK-R0: ~p", [binary:encode_hex(PMKR0)]),
    ?LOG(debug, "FT PMK-R0Name: ~p", [binary:encode_hex(PMKR0Name)]),

    %% PMK-R1 = KDF-256(PMK-R0, "FT-R1", R1KH-ID || S1KH-ID)
    %% PMKR1Name = Truncate-128(SHA-256(“FT-R1N” || PMKR0Name || R1KH-ID || S1KH-ID))

    PMKR1 =
	kdf(sha256, PMKR0, "FT-R1", [R1KH, S1KH], 256),
    <<PMKR1Name:128/bits, _/binary>> = crypto:hash(sha256, ["FT-R1N", PMKR0Name, BSS, StationMAC]),

    ?LOG(debug, "FT PMK-R1: ~p", [binary:encode_hex(PMKR1)]),
    ?LOG(debug, "FT PMK-R1Name: ~p", [binary:encode_hex(PMKR1Name)]),

    %%PTK = KDF-PTKLen(PMK-R1, "FT-PTK", SNonce || ANonce || BSSID || STA-ADDR)
    <<KCK:128/bits, KEK:128/bits, TK:128/bits>> =
	kdf(sha256, PMKR1, "FT-PTK", [SNonce, ANonce, BSS, StationMAC], 384),
    ?LOG(debug, "KCK: ~p", [binary:encode_hex(KCK)]),
    ?LOG(debug, "KEK: ~p", [binary:encode_hex(KEK)]),
    ?LOG(debug, "TK: ~p", [binary:encode_hex(TK)]),
    {KCK, KEK, TK, PMKR0Name, PMKR1Name}.

   %% Inputs:  Plaintext, n 64-bit values {P1, P2, ..., Pn}, and
   %%          Key, K (the KEK).
   %% Outputs: Ciphertext, (n+1) 64-bit values {C0, C1, ..., Cn}.

   %% 1) Initialize variables.

   %%     Set A = IV, an initial value (see 2.2.3)
   %%     For i = 1 to n
   %%         R[i] = P[i]

   %% 2) Calculate intermediate values.

   %%     For j = 0 to 5
   %%         For i=1 to n
   %%             B = AES(K, A | R[i])
   %%             A = MSB(64, B) ^ t where t = (n*j)+i
   %%             R[i] = LSB(64, B)

   %% 3) Output the results.

   %%     Set C[0] = A
   %%     For i = 1 to n
   %%         C[i] = R[i]

aes_key_wrap(KEK, PlainText) ->
    IV = binary:copy(<<16#A6>>, 8),
    Text = [X || <<X:8/bytes>> <= PlainText],
    Algo = case byte_size(KEK) of
	       16 -> aes_128_ecb;
	       24 -> aes_192_ecb;
	       32 -> aes_256_ecb
	   end,
    aes_key_wrap({Algo, KEK}, IV, Text, 1, 0).

aes_key_wrap(_KEK, IV, Text, _Cnt, 6) ->
    iolist_to_binary([IV | Text]);
aes_key_wrap(KEK, IV0, Text0, Cnt0, Round) ->
    {IV1, Text1, Cnt1} = aes_key_wrap0(KEK, IV0, Text0, [], Cnt0),
    aes_key_wrap(KEK, IV1, Text1, Cnt1, Round + 1).

aes_key_wrap0(_KEK, IV, [], Wrapped, Cnt) ->
    {IV, lists:reverse(Wrapped), Cnt};
aes_key_wrap0({Algo, Key} = KEK, IV0, [Text | Next], Wrapped, Cnt) ->
    <<MSB:8/bytes, LSB:8/bytes, _/binary>> = crypto:crypto_one_time(Algo, Key, [IV0, Text], true),
    IV1 = crypto:exor(MSB, <<Cnt:64>>),
    aes_key_wrap0(KEK, IV1, Next, [LSB | Wrapped], Cnt + 1).
