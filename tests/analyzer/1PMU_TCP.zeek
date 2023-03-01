# @TEST-EXEC: zeek -C -r ${TRACES}/C37.118_1PMU_TCP.pcap %INPUT
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff synchrophasor.log
#
# @TEST-DOC: Test synchrophasor analyzer with C37.118_1PMU_TCP.pcap

@load analyzer
