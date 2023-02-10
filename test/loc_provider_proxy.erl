-module(loc_provider_proxy).

-behavior(gen_server).

%% API
-export([start/1, start_link/1]).

%% gen_server callbacks
-export([init/1, handle_call/3]).

%% user api
-export([flush_loc_cache/0, get_loc/1, get_loc/2, load_config/1]).

start_link(Config) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, Config, []).

start(Config) ->
    gen_server:start({local, ?MODULE}, ?MODULE, Config, []).

init(_) ->
    {ok, undefined}.

flush_loc_cache() ->
    gen_server:call(?MODULE, flush_loc_cache).

load_config(Config) ->
    gen_server:call(?MODULE, {load_config, Config}).

get_loc(Name) ->
    get_loc(Name, true).

get_loc(Name, CheckCache) ->
    gen_server:call(?MODULE, {get_loc, Name, CheckCache}, 20000).

handle_call(flush_loc_cache, _, S) ->
    {reply, capwap_loc_provider:flush_loc_cache(), S};
handle_call({get_loc, Name, CheckCache}, _, S) ->
    {reply, capwap_loc_provider:get_loc(Name, CheckCache), S};
handle_call({load_config, Config}, _, S) ->
    {reply, capwap_loc_provider:load_config(Config), S}.
