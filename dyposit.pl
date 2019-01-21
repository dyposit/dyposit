:- consult('server').

% Dyposit predicates are dynamic---they can be redefined over the course of a
% program run.
:- dynamic posture/2.
:- dynamic threat/3.
:- dynamic mitigate/4.
:- dynamic says/4.
:- dynamic responsible/2.
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

% Policy begins here...

% The public authority believes that the threat from foul water should be dealt
% with (i.e. is in their risk posture).
posture(public_authority, foul_water).
posture(public_authority, aliens).

% The public authority believes there is a threat to the operation of the valve
% from fouled water.
threat(public_authority, valve_operation, foul_water).
threat(public_authority, valve_operation, aliens).

% The public authority believes that a threat to the operation of the valve can
% be mitigated if the public authority belives that a recognized authority says
% the water has been purified.
mitigate(public_authority, valve_operation, foul_water, OBLIGATION) :-
  says(public_authority, recognized, purified, OBLIGATION).

mitigate(public_authority, valve_operation, aliens, [obligation(tin_foil_hat)]).
mitigate(public_authority, valve_operation, aliens, [obligation(firing_solution)]).

% The public authority believes that if an operator says something, then a
% recognized authority has said it.
says(public_authority, recognized, X, OBLIGATION) :-
  says(public_authority, operator, X, OBLIGATION).

% The public authority believes the operator has said the water has been purified.
says(public_authority, operator, purified, [obligation(do_purify)]).

% The public authority is the only person who is responsible for whether the
% valve is allowed to open or not.
responsible(public_authority, valve_operation).

