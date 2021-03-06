%% @author author <author@example.com>
%% @copyright YYYY author.

%% @doc TEMPLATE.

-module(encserver).
-author('author <author@example.com>').
-export([start/0, stop/0]).

ensure_started(App) ->
    case application:start(App) of
	ok ->
	    ok;
	{error, {already_started, App}} ->
	    ok
    end.
	
%% @spec start() -> ok
%% @doc Start the encserver server.
start() ->
    encserver_deps:ensure(),
    ensure_started(crypto),
    application:start(encserver).

%% @spec stop() -> ok
%% @doc Stop the encserver server.
stop() ->
    Res = application:stop(encserver),
    application:stop(crypto),
    Res.
