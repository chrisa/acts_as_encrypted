%% @author author <author@example.com>
%% @copyright YYYY author.

%% @doc Web server for encserver.

-module(encserver_web).
-author('author <author@example.com>').

-export([start/1, stop/0, loop/2]).

%% External API

start(Options) ->
    {DocRoot, Options1} = get_option(docroot, Options),
    Loop = fun (Req) ->
		   ?MODULE:loop(Req, DocRoot)
	   end,
    mochiweb_http:start([{name, ?MODULE}, {loop, Loop} | Options1]).

stop() ->
    mochiweb_http:stop(?MODULE).

loop(Req, DocRoot) ->
    "/" ++ Path = Req:get(path),
    case Req:get(method) of
	'POST' ->
	    case Path of
		"encrypt" -> 
		    Reply = crypto_op(encrypt, Req),
		    Req:ok(Reply);
		"decrypt" -> 
		    Reply = crypto_op(decrypt, Req),
		    Req:ok(Reply);
		_ -> 
		    Req:respond({501, [], ""})
	    end;
	_ ->
	    Req:respond({501, [], []})
    end.

%% Internal API

get_option(Option, Options) ->
    {proplists:get_value(Option, Options), proplists:delete(Option, Options)}.

crypto_op(Op, Req) ->
    { struct, Struct } = mochijson2:decode(Req:recv_body()),

    case Op of

	encrypt ->
	    IVec = crypto:rand_bytes(16),
	    [
	     { <<"plaintext">>, Plaintext }, 
	     { <<"keyid">>,     KeyId },
	     { <<"family">>,    Family }
	    ] = Struct,

	    KeyMaterial = encserver_keysrv:getkey(KeyId),
	    Ciphertext = crypto:aes_cbc_256_encrypt(KeyMaterial, IVec, Plaintext),
	    Res = {struct, [ 
			     { <<"ciphertext">>, base64:encode(Ciphertext) },
			     { <<"iv">>,         base64:encode(IVec) },
			     { <<"keyid">>,      <<"1">>} 
			    ] 
		  },
	    {"text/json", mochijson2:encode(Res)};

	decrypt ->
	    [
	     { <<"iv">>,         IVec }, 
	     { <<"ciphertext">>, Ciphertext }, 
	     { <<"keyid">>,      KeyId },
	     { <<"family">>,     Family } 
	    ] = Struct,

	    KeyMaterial = encserver_keysrv:getkey(KeyId),
	    Plaintext = crypto:aes_cbc_256_decrypt(KeyMaterial, base64:decode(IVec), base64:decode(Ciphertext)),
	    Res = {struct, [ 
			     { <<"plaintext">>, Plaintext }
			    ] 
		  },
	    {"text/json", mochijson2:encode(Res)}
    end.

