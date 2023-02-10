-module(capwap_dummy_sup).

-behaviour(supervisor).

%% API
-export([start_link/1]).

%% Supervisor callbacks
-export([init/1]).

-include_lib("kernel/include/logger.hrl").

%% API functions

start_link(Config) ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, [Config]).

%% Supervisor callbacks

init([Config]) ->
    ?LOG(debug, "Init'ed supervisor with config: ~p", [Config]),
    ProviderServer = #{id => capwap_loc_provider,
		       start => {capwap_loc_provider, start_link, [Config]},
		       restart => permanent,
		       significant => false,
		       shutdown => 500,
		       type => worker},
    LocProxy = #{id => loc_provider_proxy,
		 start => {loc_provider_proxy, start_link, [undefined]},
		 restart => permanent,
		 significant => false,
		 shutdown => 500,
		 type => worker},

    {ok, {#{strategy => one_for_one, intensity => 30, period => 60}, [
	    ProviderServer,
	    LocProxy
    ]}}.
