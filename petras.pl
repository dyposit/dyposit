% Dyposit policy for the Petras Demonstation

% Dyposit predicates are dynamic---they can be redefined over the course of a
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

% Utility
says(X, Y, Z, []) :- says(X, Y, Z).
mitigate(X, Y, Z, []) :- mitigate(X, Y, Z).

% Policy begins here...
% If the pressure sensor is high, then the GUNT should shut down
threat(operator, pump, excess_pressure) :-
    says(operator, pressure_sensor, high_pressure).


% Once the pressure falls back to safe pressure, then the threat is mitigated
% TODO: should remove the above threat?
mitigate(operator, pump, excess_pressure) :-
    says(operator, pressure_sensor, returned_to_safe_pressure).

% If the archivist (Kepware) says that the connection to thingworx is unencrypted and it goes down, then there is a threat of shenanigans(?)
threat(kepware, data_authenticity, attack) :-
    says(kepware, thingworx, unencrypted),
    says(kepware, thingworx, down).

% There's always a threat of malware if the computer isn't running AV
threat(operator, kepware, malware).
mitigate(operator, kepware, malware) :-
    says(operator, kepware_machine, av_installed).

threat(operator, kepware, operation) :-
    says(operator, ids, scanning).

% Masking RTU
threat(operator, pump, communications) :-
    says(operator, modbus, offline).

threat(operator, pump, communications) :-
    says(operator, dnp3, offline).

mitigate(operator, pump, operations, [raise_polling_frequency()]).

threat(operator, pump, attack) :-
    threat(operator, pump, communications),
    says(operator, rtu, high_speed_polling).


% Actions
start_pump.
stop_pump.
set_pump_speed.
open_valve.
close_valve.
disable_alarm.

% Threats/Mitigations
pump_safe_state.
pump_over_pressure.
plc_integrity.


threat(operator, pc, integrity).

mitigate(operator, pc, integrity) :-
    says(operator, pc, av_installed).

threat(operator, archivist, integrity) :-
    says(operator, thinkwork, inconsistent_state). % Thinkwork down, but connection up

mitigate(operator, archivist, integrity, [restart_thinkworx]).

threat(operator, soc, availability) :-
    says(operator, rtu, compromised).

says(operator, rtu, compromised) :-
    says(operator, rtu, reconfigured).

says(operator, rtu, compromised) :-
    says(operator, rtu, modbus_down).


threat(operator, plant_operation, safety) :-
    threat(operator, plc, integrity).

threat(operator, valve_operation, safety) :-
    threat(operator, plc, integrity).

threat(operator, sensors, integrity) :- 
    threat(operator, plc, integrity).

threat(operator, plc, integrity) :-
    threat(operator, pc, integrity).

% Thing is working, put we can't see whats happening.
threat(operator, plant, survivability) :-
    threat(operator, soc, availability).

threat(operator, plant, integrity) :-
    threat(operator, plc, integrity).

threat(operator, hmi, integrity) :-
    threat(operator, plc, integrity).

% Game over
threat(operator, plant, operation) :-
    threat(operator, plant, survivability),
    threat(operator, plc, integrity).

threat(operator, plc, integrity_pre_attack) :-
    says(ids, kepware, port_scanning).

mitigation(operator, plc, integrity_pre_attack, [kepware_ro]).
    
