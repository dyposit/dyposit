# DYPOSIT Policy Framework

Code implementing framework described in the 
_Threat-Centered Dynamic Policies for CPI_
paper.

Two policies are supplied for you to play with, as well as a rudimentary server
which implements the PDP.

## Usage

    $ swipl -l 'dyposit.pl' -g 'server(8080)'
    $ ./dyposit help

## Inventory

- `README.md`: this file
- `dyposit`: allows interaction with the server
- `dyposit.pl`: simple policy (based on example in the paper)
- `dyposit-2.pl`: alternative, more complex policy (based on paper)
- `server.pl`: webserver code to allow remote interaction

