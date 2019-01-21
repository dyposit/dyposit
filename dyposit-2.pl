:- consult('server').

% Dyposit predicates are dynamic---they can be redefined over the course of a
% program run.
:- dynamic mitigate/4.
:- dynamic posture/2.
:- dynamic responsible/2.
:- dynamic says/4.
:- dynamic threat/3.
:- dynamic test/1.

% A PRINCIPAL will only permit an ACTION if any threats in the principal's risk
% posture that could affect the action are mitigated.
permit(PRINCIPAL, ACTION, OBLIGATIONS) :-
  ( responsible(PRINCIPAL, ACTION),
    forall(
      ( posture(PRINCIPAL, THREAT),
        threat(PRINCIPAL, ACTION, THREAT)
      ),
      mitigate(PRINCIPAL, ACTION, THREAT, _)
    )
  ) 
  -> 
  (
    findall(
      O,
      ( posture(PRINCIPAL, THREAT), 
        threat(PRINCIPAL, ACTION, THREAT), 
        once(mitigate(PRINCIPAL, ACTION, THREAT, O))
      ),
      OS
    ), 
    flatten(OS, OBLIGATIONS)
  )
  ; fail.

% Initial policy begins here...
:- discontiguous mitigate/4.
:- discontiguous posture/2.
:- discontiguous responsible/2.
:- discontiguous says/4.
:- discontiguous threat/3.

posture(engineer, bad_reg).
posture(engineer, break_in).

threat(engineer, integrity, break_in) :-
  threat(guard, integrity, break_in).

threat(engineer, valve_operation, bad_reg) :-
  says(senami, test_result, true, []).

mitigate(engineer, valve_operation, bad_reg, [obligation(update_refresh(1))]) :-
  says(senami, test_result, true, []),
  \+ threat(engineer, operations, _).

mitigate(engineer, integrity, break_in, [ obligation(call_repairman)
                                        , add(threat(engineer, operations, sabotage))
                                        ]).

responsible(engineer, integrity).
responsible(engineer, valve_operation).

says(senami, test_result, false, []).

% Dynamic statements added via API
says(senami, test_result, true, []).
threat(engineer, valve_operation, bad_reg).
threat(guard, integrity, break_in).
threat(engineer, operations, sabotage).

mitigate(engineer, valve_operation, bad_reg, [ obligation(shutdown)
                                             , alert(water_shortage)
                                             ]) :-
  says(senami, test_result, true, []),
  threat(engineer, operations, sabotage).

