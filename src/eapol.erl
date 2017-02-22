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
-export([phrase2psk/2, prf/4, pmk2ptk/6, aes_key_wrap/2, key_len/1]).

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

mic_len(#ccmp{}) -> 16;
mic_len('AES-HMAC-SHA1') -> 16.

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

cipher_suite('AES-HMAC-SHA1') -> 2;
cipher_suite(X) when is_atom(X) -> 0;

cipher_suite(2) -> 'AES-HMAC-SHA1';
cipher_suite(X) when is_integer(X) -> unknown.

hash('AES-HMAC-SHA1') ->
    sha.

calc_hmac(#ccmp{cipher_suite = CipherSuite, kck = KCK}, EAPOL, Data, MICLen) ->
    Hash = hash(CipherSuite),
    C1 = crypto:hmac_init(Hash, KCK),
    C2 = crypto:hmac_update(C1, EAPOL),
    C3 = crypto:hmac_update(C2, binary:copy(<<0>>, MICLen)),
    C4 = crypto:hmac_update(C3, Data),
    crypto:hmac_final_n(C4, MICLen).

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
key(Flags, KeyData, #ccmp{cipher_suite = CipherSuite,
			  replay_counter = ReplayCounter,
			  nonce = Nonce} = CCMP) ->
    KeyInfo = lists:foldl(fun keyinfo/2, 0, Flags)
	bor cipher_suite(CipherSuite),
    KeyLen = key_len(CCMP),
    MICLen = mic_len(CipherSuite),
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
	    lager:debug("Head: ~s", [pbkdf2:to_hex(Head)]),
	    lager:debug("MIC: ~s", [pbkdf2:to_hex(MIC)]),
	    lager:debug("Tail: ~s", [pbkdf2:to_hex(Tail)]),
	    lager:debug("invalid MIC: expected: ~s, got: ~s", [pbkdf2:to_hex(MIC), pbkdf2:to_hex(V)]),
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
	CipherSuite = cipher_suite(KeyInfo band 16#07),
	Flags = keyinfo(KeyInfo),
	lager:debug("KeyInfo: ~p", [Flags]),
	MICLen = mic_len(CipherSuite),

	<< ?EAPOL_KEY_802_11, _:16, _KeyLen:16, ReplayCounter:64,
	   Nonce:32/bytes, 0:128, 0:64, 0:64, _:MICLen/bytes,
	   KeyDataLen:16, KeyData:KeyDataLen/bytes>> = EAPOLData,

	<< Head:81/bytes, MIC:MICLen/bytes, Tail/bytes>> = Data,

	{key, Flags, CipherSuite, ReplayCounter, Nonce, KeyData, {Head, MIC, Tail}}
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

hmac_sha1(Key, Label, Data, Count) ->
    crypto:hmac(sha, Key, [Label, 0, Data, Count]).

prf(Key, Label, Data, WantedLength) ->
    prf(Key, Label, Data, WantedLength, 0, []).

prf(_Key, _Label, _Data, WantedLength, _N, [Last | Acc])
  when WantedLength =< 0 ->
    Keep = byte_size(Last) + WantedLength,
    <<B:Keep/binary, _/binary>> = Last,
    list_to_binary(lists:reverse(Acc, [B]));

prf(Key, Label, Data, WantedLength, N, Acc) ->
    Bin = hmac_sha1(Key, Label, Data, N),
    prf(Key, Label, Data, WantedLength - byte_size(Bin), N + 1, [Bin|Acc]).

phrase2psk(Phrase, SSID)
  when is_binary(Phrase), is_binary(SSID) ->
    pbkdf2:pbkdf2(sha, Phrase, SSID, 4096, 32);
phrase2psk(Phrase, SSID)
  when is_list(Phrase) ->
    phrase2psk(iolist_to_binary(Phrase), SSID);
phrase2psk(Phrase, SSID)
  when is_list(SSID) ->
    phrase2psk(Phrase, iolist_to_binary(SSID)).

pmk2ptk(PMK, AA, SPA, ANonce, SNonce, PRFLen) ->
    <<KCK:16/bytes, KEK:16/bytes, TK/binary>> =
	prf(PMK, "Pairwise key expansion", [min(AA, SPA), max(AA, SPA),
					    min(ANonce, SNonce), max(SNonce, ANonce)], PRFLen),
    {KCK, KEK, TK}.



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
    aes_key_wrap(KEK, IV, Text, 1, 0).

aes_key_wrap(_KEK, IV, Text, _Cnt, 6) ->
    iolist_to_binary([IV | Text]);
aes_key_wrap(KEK, IV0, Text0, Cnt0, Round) ->
    {IV1, Text1, Cnt1} = aes_key_wrap0(KEK, IV0, Text0, [], Cnt0),
    aes_key_wrap(KEK, IV1, Text1, Cnt1, Round + 1).

aes_key_wrap0(_KEK, IV, [], Wrapped, Cnt) ->
    {IV, lists:reverse(Wrapped), Cnt};
aes_key_wrap0(KEK, IV0, [Text | Next], Wrapped, Cnt) ->
    <<MSB:8/bytes, LSB:8/bytes, _/binary>> = crypto:block_encrypt(aes_ecb, KEK, [IV0, Text]),
    IV1 = crypto:exor(MSB, <<Cnt:64>>),
    aes_key_wrap0(KEK, IV1, Next, [LSB | Wrapped], Cnt + 1).

