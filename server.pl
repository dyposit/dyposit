:- use_module(library(http/thread_httpd)).
:- use_module(library(http/http_dispatch)).
:- use_module(library(http/http_parameters)).

% Start a server running on a specific port
server(PORT) :-
  http_server(http_dispatch, [port(PORT)]).

:- http_handler('/permit', do_permit, []).
:- http_handler('/assert', do_assert, []).
:- http_handler('/retract', do_retract, []).

do_permit(REQUEST) :-
  format('Content-type: text/plain~n~n', []),
  http_parameters(REQUEST, [ principal(PRINCIPAL, [])
                           , action(ACTION, [])
                           ]),
  permit(PRINCIPAL, ACTION, OBLIGATIONS) 
    -> do_permit_success(OBLIGATIONS)
     ; do_permit_failure().

do_permit_success(OBLIGATIONS) :-
  format("okay~n", []),
  print_obligations(OBLIGATIONS).

do_permit_failure() :-
  format("nope~n").
  
print_obligations([]).
print_obligations([H|T]) :- 
  format('~w~n', H),
  print_obligations(T).

do_assert(REQUEST) :-
  format('Content-type: text/plain~n~n', []),
  http_parameters(REQUEST, [ that(That, []) ]),
  % FIXME: arbitrary code loading ahoy!
  term_to_atom(Term, That),
  assertz(Term),
  format('okay~n').

do_retract(REQUEST) :-
  format('Content-type: text/plain~n~n', []),
  http_parameters(REQUEST, [ that(That, []) ]),
  % FIXME: arbitrary code loading ahoy!
  term_to_atom(Term, That),
  retract(Term),
  format('okay~n').
