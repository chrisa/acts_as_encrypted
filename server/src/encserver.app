{application, encserver,
 [{description, "encserver"},
  {vsn, "0.01"},
  {modules, [
    encserver,
    encserver_app,
    encserver_sup,
    encserver_web,
    encserver_deps,
    encserver_keysrv
  ]},
  {registered, [keysrv]},
  {mod, {encserver_app, []}},
  {env, []},
  {applications, [kernel, stdlib, crypto]}]}.
