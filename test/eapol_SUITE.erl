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

-module(eapol_SUITE).

-compile(export_all).

-include_lib("common_test/include/ct.hrl").

-define(equal(Expected, Actual),
    (fun (Expected@@@, Expected@@@) -> true;
         (Expected@@@, Actual@@@) ->
             ct:pal("MISMATCH(~s:~b, ~s)~nExpected: ~p~nActual:   ~p~n",
                    [?FILE, ?LINE, ??Actual, Expected@@@, Actual@@@]),
             false
     end)(Expected, Actual) orelse error(badmatch)).


% hexstr2bin
hexstr2bin(S) ->
    list_to_binary(hexstr2list(S)).

hexstr2list([X,Y|T]) ->
    [mkint(X)*16 + mkint(Y) | hexstr2list(T)];
hexstr2list([]) ->
    [].

mkint(C) when $0 =< C, C =< $9 ->
    C - $0;
mkint(C) when $A =< C, C =< $F ->
    C - $A + 10;
mkint(C) when $a =< C, C =< $f ->
    C - $a + 10.

%%--------------------------------------------------------------------
%% @spec suite() -> Info
%% Info = [tuple()]
%% @end
%%--------------------------------------------------------------------
suite() ->
	[{timetrap,{seconds,30}}].

do_prf([]) ->
    ok;
do_prf([{Key, Label, Data, Expected} | Next]) ->
    Len = bit_size(Expected),
    ?equal(Expected, eapol:prf(sha, Key, Label, Data, Len)),
    do_prf(Next).

test_prf(_Config) ->
    Cases = [{hexstr2bin("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
	      "prefix",
	      "Hi There",
	      hexstr2bin("bcd4c650b30b9684951829e0d75f9d54"
			 "b862175ed9f00606e17d8da35402ffee"
			 "75df78c3d31e0f889f012120c0862beb"
			 "67753e7439ae242edb8373698356cf5a")},
	     {"Jefe",
	      "prefix",
	      "what do ya want for nothing?",
	      hexstr2bin("51f4de5b33f249adf81aeb713a3c20f4"
			 "fe631446fabdfa58244759ae58ef9009"
			 "a99abf4eac2ca5fa87e692c440eb4002"
			 "3e7babb206d61de7b92f41529092b8fc")},
	     {hexstr2bin("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
	      "prefix",
	      binary:copy(<<16#dd>>, 50),
	      hexstr2bin("e1ac546ec4cb636f9976487be5c86be1"
			 "7a0252ca5d8d8df12cfb0473525249ce"
			 "9dd8d177ead710bc9b590547239107ae"
			 "f7b4abd43d87f0a68f1cbd9e2b6f7607")},
	    {binary:copy(<<16#aa>>, 80),
	     "prefix-3",
	     "Test Using Larger Than Block-Size Key - Hash Key First",
	     hexstr2bin("0ab6c33ccf70d0d736f4b04c8a737325"
			"5511abc5073713163bd0b8c9eeb7e195"
			"6fa066820a73ddee3f6d3bd407e0682a")}],

    do_prf(Cases).

do_kdf([]) ->
    ok;
do_kdf([{Key, Label, Data, Expected} | Next]) ->
    Len = bit_size(Expected),
    ?equal(Expected, eapol:kdf(sha256, Key, Label, Data, Len)),
    do_kdf(Next).

test_kdf(_Config) ->
    Cases = [{hexstr2bin("e3a83dee5b300abdd0801562089d22be012b0f"
			 "eab5cef8b320ea85e5fdf931f0"),
	      <<"FT-R0">>,
	      hexstr2bin("0f54657374574c414e2d534347312d47dead0d"
			 "736367342e747069702e6e6574f81a67210767"),
	      hexstr2bin("a6d6a60cf34c0cb7113421d14078b7b467a074"
			 "6ec887c874c2e71cf2f46876be238e3bd6400a"
			 "0f7f013e65814ff1500d")}],
    do_kdf(Cases).

do_psk_hashing([]) ->
    ok;
do_psk_hashing([{Phrase, SSID, Expected} | Next]) ->
    PSK = eapol:phrase2psk(Phrase, SSID),
    ?equal(Expected, PSK),
    do_psk_hashing(Next).

test_psk_hashing(_Config) ->
    Cases = [{"password", "IEEE",
	      hexstr2bin("f42c6fc52df0ebef9ebb4b90b38a5f90"
			 "2e83fe1b135a70e23aed762e9710a12e")},
	     {"ThisIsAPassword", "ThisIsASSID",
	      hexstr2bin("0dc0d6eb90555ed6419756b9a15ec3e3"
			 "209b63df707dd508d14581f8982721af")},
	     {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	      "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",
	      hexstr2bin("becb93866bb8c3832cb777c2f559807c"
			 "8c59afcb6eae734885001300a981cc62")}],
    do_psk_hashing(Cases).

test_ptk(_Config) ->
    PMK = hexstr2bin("0dc0d6eb90555ed6419756b9a15ec3e3"
		     "209b63df707dd508d14581f8982721af"),
    AA = hexstr2bin("a0a1a1a3a4a5"),
    SPA = hexstr2bin("b0b1b2b3b4b5"),
    SNonce = hexstr2bin("c0c1c2c3c4c5c6c7c8c9d0d1d2d3d4d5"
			"d6d7d8d9dadbdcdddedfe0e1e2e3e4e5"),
    ANonce = hexstr2bin("e0e1e2e3e4e5e6e7e8e9f0f1f2f3f4f5"
			"f6f7f8f9fafbfcfdfeff000102030405"),
    ExpectedTK = hexstr2bin("b2360c79e9710fdd58bea93deaf06599"),

    {_KCK, _KEK, TK} =  eapol:pmk2ptk(PMK, AA, SPA, ANonce, SNonce, 384),
    ?equal(ExpectedTK, TK).

do_aes_key_wrap([]) ->
    ok;
do_aes_key_wrap([{KEK, Key, Expected} | Next]) ->
    Wrapped = eapol:aes_key_wrap(KEK, Key),
    ?equal(Expected, Wrapped),
    do_aes_key_wrap(Next).

test_aes_key_wrap(_Config) ->
    Cases = [{hexstr2bin("000102030405060708090A0B0C0D0E0F"),
	      hexstr2bin("00112233445566778899AABBCCDDEEFF"),
	      hexstr2bin("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5")},
	     {hexstr2bin("000102030405060708090A0B0C0D0E0F1011121314151617"),
	      hexstr2bin("00112233445566778899AABBCCDDEEFF"),
	      hexstr2bin("96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D")},
	     {hexstr2bin("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
	      hexstr2bin("00112233445566778899AABBCCDDEEFF"),
	      hexstr2bin("64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7")},
	     {hexstr2bin("000102030405060708090A0B0C0D0E0F1011121314151617"),
	      hexstr2bin("00112233445566778899AABBCCDDEEFF0001020304050607"),
	      hexstr2bin("031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2")},
	     {hexstr2bin("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
	      hexstr2bin("00112233445566778899AABBCCDDEEFF0001020304050607"),
	      hexstr2bin("A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1")},
	     {hexstr2bin("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
	      hexstr2bin("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F"),
	      hexstr2bin("28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326"
			 "CBC7F0E71A99F43BFB988B9B7A02DD21")}],
    do_aes_key_wrap(Cases).

all() ->
    [test_prf, test_kdf, test_psk_hashing, test_ptk, test_aes_key_wrap].

init_per_suite(Config) ->
	Config.

end_per_suite(_Config) ->
	ok.

