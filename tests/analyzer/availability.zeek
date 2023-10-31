# @TEST-DOC: Check that the SYNCHROPHASOR analyzers are available.
#
# @TEST-EXEC: [ $(zeek -NN | grep -i -c 'ANALYZER__\?SYNCHROPHASOR_..P') -eq 2 ]
