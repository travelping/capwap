%% Copyright (C) 2023, Travelping GmbH <info@travelping.com>

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

-module(test_loc_handler).

-export([init/2, content/0]).

init(Req0 = #{path_info := [<<"location">> | _]}, State) ->
    ct:pal("Receiving request in test_loc_handler: ~p~n", [Req0]),
    Resp = cowboy_req:reply(200,
                            #{<<"content-type">> => <<"application/json">>},
                            test_loc_handler:content(),
                            Req0),
    ct:pal("Sending response in test_loc_handler: ~p~n", [Resp]),
    {ok, Resp, State}.

%% Hook for meck
content() ->
    jsx:encode(#{<<"latitude">> => <<"11111.1">>,  <<"longitude">> => <<"22222.2">>}).
