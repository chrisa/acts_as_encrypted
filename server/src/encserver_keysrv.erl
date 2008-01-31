%% @author author <author@example.com>
%% @copyright YYYY author.

%% @doc Web server for encserver.

-module(encserver_keysrv).
-author('author <author@example.com>').

-export([start/0, init/1, addkey/2, getkey/1]).

%% External API

start() ->
    Keys = [],
    gen_server:start_link({local, ?MODULE}, ?MODULE, Keys, []).
    
init(Keys) ->
    loop(Keys).

addkey(KeyId, Key) ->
    ?MODULE ! { addkey, KeyId, Key, self() }.

getkey(KeyId) ->
    ?MODULE ! { getkey, KeyId, self() },
    receive
	{ key, Key } ->
	    { _, KeyMaterial } = Key,
	    KeyMaterial;
	_ ->
	    { error }
	end.

%% Internal API
loop(Keys) ->
    receive
	{ addkey, KeyId, Key, Sender } ->
	    Sender ! ok,
	    loop([ { KeyId, Key } | Keys ]);
	{ getkey, KeyId, Sender } ->
	    Sender ! { key, find_current_key(Keys, KeyId) },
	    loop(Keys)
    end.

%% fake find_key, returns first
find_current_key(Keys, KeyId) -> 
    [ Key | Others ] = Keys,
    Key.

