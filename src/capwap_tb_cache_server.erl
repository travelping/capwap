-module(capwap_tb_cache_server).

-behavior(gen_server).

%% API
-export([start_link/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

%% user api
-export([flush_id_cache/0, flush_loc_cache/0, get_id/1, get_loc/1]).

-include_lib("kernel/include/logger.hrl").

-define(CW_DEV_CACHE_ID, capwap_tb_cache_server_id).
-define(CW_DEV_CACHE_LOC, capwap_tb_cache_server_loc).
-define(VALUE_KEY, <<"value"/utf8>>).

-record(tb_cache, {id_tab, loc_tab, timeout, refresh, uri, token, keys}).

%% user api

start_link(Opts) ->
  gen_server:start_link({local, ?MODULE}, ?MODULE, Opts, []).

flush_id_cache() ->
  gen_server:call(?MODULE, flush_id_cache).

flush_loc_cache() ->
  gen_server:call(?MODULE, flush_loc_cache).

get_id(Device) ->
  case ets:lookup(?CW_DEV_CACHE_ID, Device) of
    [{Device, Id}] -> Id;
    % [{Device, error}] -> error;
    []   -> gen_server:call(?MODULE, {cache_dev_id, Device})
  end.

get_loc(Device) ->
  case get_id(Device) of
    error -> error;
    Id ->
      case ets:lookup(?CW_DEV_CACHE_LOC, Id) of
        [{Id, Loc = {location, Lat, Long}}] -> {Lat, Long};
        % [{Id, error}] -> error;
        [] -> gen_server:call(?MODULE, {cache_dev_loc, Id})
      end
  end.

%% gen_server impl

init(#{timeout := Timeout,
       refresh := RefreshTime,
       uri := URI,
       keys := #{lat_key := LatKey, long_key := LongKey},
       token := Token}) ->
  ?LOG(debug, "cache started"),
  TabOpts = [set, protected, named_table],
  IdTab = ets:new(?CW_DEV_CACHE_ID, TabOpts ++ [{read_concurrency,true}]),
  LocTab = ets:new(?CW_DEV_CACHE_LOC, TabOpts),
  {ok, #tb_cache{
    id_tab = IdTab, loc_tab = LocTab, timeout = Timeout,
    refresh = RefreshTime, uri = uri_string:parse(URI), token = Token,
    keys = #{lat_key => LatKey, long_key => LongKey}}}.

handle_call(flush_id_cache, From, State = #tb_cache{id_tab = IdTab}) ->
  ?LOG(debug, "Flush id cache"),
  ets:delete_all_objects(IdTab),
  {reply,ok,State};
handle_call(flush_loc_cache, From, State = #tb_cache{loc_tab = LocTab}) ->
  ?LOG(debug, "Flush location cache"),
  ets:delete_all_objects(LocTab),
  {reply,ok,State};
handle_call({cache_dev_id, Device}, From, State = #tb_cache{id_tab = IdTab, loc_tab = LocTab, timeout = Timeout,
    uri = URI, token = Token}) ->
  ?LOG(debug, "get id for device: ~p", [Device]),
  Id = local_get_id(URI, Token, Device, IdTab),
  {reply,Id,State};
handle_call({cache_dev_loc, Id}, From, State = #tb_cache{
    loc_tab = LocTab, uri = URI, token = Token, refresh = RefreshTime,
    keys = #{lat_key := LatKey, long_key := LongKey}}) ->
  ?LOG(debug, "get location for device id: ~p", [Id]),
  Loc = local_get_loc(URI, Token, RefreshTime, LatKey, LongKey, Id, LocTab),
  {reply,Loc,State}.

handle_cast(_, State) ->
  ?LOG(error, "Unexpected cast"),
  {noreply,State}.

handle_info({refresh, Id}, State = #tb_cache{id_tab = IdTab, loc_tab = LocTab, timeout = Timeout,
    refresh = RefreshTime, uri = URI, token = Token,
    keys = #{lat_key := LatKey, long_key := LongKey}}) ->
  ?LOG(debug, "refresh location for device id: ~p", [Id]),
  case send_location_req(URI, Token, LatKey, LongKey, Id) of
    error -> error;
    Loc -> ets:insert(LocTab, {Id, Loc})
  end,
  erlang:send_after(RefreshTime, ?MODULE, {refresh, Id}),
  {noreply,State}.

terminate() ->
  ?LOG(debug, "terminating"),
  ok.

%% Internal functions

local_get_id(URI, Token, Device, IdTab) ->
  case ets:lookup(IdTab, Device) of
    [{Device, Id}] -> Id;
    []   ->
      case send_devid_req(URI, Token, Device) of
        error -> error;
        Id ->
          ets:insert(IdTab, {Device, Id}),
          Id
      end
  end.

local_get_loc(URI, Token, RefreshTime, LatKey, LongKey, Id, LocTab) ->
  case ets:lookup(LocTab, Id) of
    [{Id, Loc = {location, Lat, Long}}] -> {Lat, Long};
    [] -> 
      case send_location_req(URI, Token, LatKey, LongKey, Id) of
        error -> error;
        Loc -> 
          ets:insert(LocTab, {Id, Loc}),
          erlang:send_after(RefreshTime, ?MODULE, {refresh, Id}),
          Loc
      end
  end.

refresh_loc(URI, Token, RefreshTime, LatKey, LongKey, Id, LocTab) ->
  case send_location_req(URI, Token, LatKey, LongKey, Id) of
    error -> error;
    Loc -> 
      ets:insert(LocTab, {Id, Loc})
  end,
  erlang:send_after(RefreshTime, ?MODULE, {refresh, Id}).

send_devid_req(URI, Token, DevName) ->
    #{path := UriPath} = URI,
    JsonHeader = {<<"Content-Type">>, <<"application/json">>},
    AuthHeader = {<<"x-authorization">>, <<"Bearer ", Token/binary>>},
    UriPathBin = unicode:characters_to_binary(UriPath),
    DevNamePath = <<UriPathBin/binary, "/tenant/devices">>,
    DevNameQuery = uri_string:compose_query([{"deviceName", DevName}]),
    DevNameUri = URI#{path => DevNamePath, query => DevNameQuery},
    case http_request(uri_string:recompose(DevNameUri), [JsonHeader, AuthHeader], []) of
      {ok, {#{<<"id">> := #{<<"entityType">> := <<"DEVICE">>, <<"id">> := Id}}, _ClientRef}} ->
        Id;
      {error, Error} ->
        ?LOG(error, "Internal error: ~p", [Error]),
        error
    end.
      
send_location_req(URI, Token, LatKey, LongKey, DevId) ->
    #{path := UriPath} = URI,
    JsonHeader = {<<"Content-Type">>, <<"application/json">>},
    AuthHeader = {<<"x-authorization">>, <<"Bearer ", Token/binary>>},
    UriPathBin = unicode:characters_to_binary(UriPath),
    TelemetryPath = <<UriPathBin/binary, "/plugins/telemetry/DEVICE/", DevId/binary, "/values/timeseries">>,
    TelemetryUri = URI#{path => TelemetryPath},
    LatKeyBin = unicode:characters_to_binary(LatKey),
    LongKeyBin = unicode:characters_to_binary(LongKey),
    case http_request(uri_string:recompose(TelemetryUri), [JsonHeader, AuthHeader], []) of
        {ok, {Response = #{LatKeyBin := [#{?VALUE_KEY := LatVal}], LongKeyBin := [#{?VALUE_KEY := LongVal}]}, _LocReqState}} ->
            ?LOG(debug, "Got response: ~p", [Response]),
            {location, LatVal, LongVal};
        {ok, {Response, _LocReqState}} ->
            ?LOG(error, "Got non-matching response: ~p", [Response]),
            error;
        {error, Error} ->
            ?LOG(error, "Error retrieving location: ~p", [Error]),
            error
    end.


http_request(Http, Headers, Opts) ->
  case hackney:request(get, Http, Headers, <<>>, Opts) of
    {ok, 200, _RespHeaders, ClientRef} ->
      {ok, Body} = hackney:body(ClientRef),
      {ok, {jsx:decode(Body, [return_maps]), ClientRef}};
    Error ->
      % exometer:update([capwap, ac, error_wtp_http_config_count], 1),
      {error, Error}
  end.

