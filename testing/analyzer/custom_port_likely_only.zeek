# @TEST-EXEC: mkdir tcp udp
# @TEST-EXEC: cd tcp && zeek -C -r ${TRACES}/C37.118_1PMU_TCP_minimal_otherport_serverfirst.pcap "likely_server_ports+={ 12345/tcp }" %INPUT
# @TEST-EXEC: test ! -s tcp/synchrophasor.log
# @TEST-EXEC: zeek-cut service < tcp/conn.log > likely_only.out
# @TEST-EXEC: cd udp && zeek -C -r ${TRACES}/C37.118_1PMU_UDP_minimal_otherport_serverfirst.pcap "likely_server_ports+={ 12345/udp }" %INPUT
# @TEST-EXEC: test ! -s udp/synchrophasor.log
# @TEST-EXEC: zeek-cut service < udp/conn.log >> likely_only.out
# @TEST-EXEC: btest-diff likely_only.out
#
# @TEST-DOC: Adding a custom port only to likely_server_ports orients the connection but does not register either Synchrophasor analyzer.

@load analyzer
