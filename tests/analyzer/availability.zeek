# @TEST-DOC: Check that the SYNCHROPHASOR analyzers are available.
#
# @TEST-EXEC: zeek -NN | grep -qi 'ANALYZER_SPICY__\?SYNCHROPHASOR_UDP'
# @TEST-EXEC: zeek -NN | grep -qi 'ANALYZER_SPICY__\?SYNCHROPHASOR_TCP'