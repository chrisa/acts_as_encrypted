%% @author author <author@example.com>
%% @copyright YYYY author.

%% @doc Callbacks for the encserver application.

-module(encserver_app).
-author('author <author@example.com>').

-behaviour(application).
-export([start/2,stop/1]).


%% @spec start(_Type, _StartArgs) -> ServerRet
%% @doc application start callback for encserver.
start(_Type, _StartArgs) ->
    encserver_deps:ensure(),
    encserver_sup:start_link().

%% @spec stop(_State) -> ServerRet
%% @doc application stop callback for encserver.
stop(_State) ->
    ok.
