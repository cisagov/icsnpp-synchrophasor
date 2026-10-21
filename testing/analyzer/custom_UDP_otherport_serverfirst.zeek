# @TEST-EXEC: zeek -C -r ${TRACES}/C37.118_1PMU_UDP_minimal_otherport_serverfirst.pcap "SYNCHROPHASOR::synchrophasor_ports_udp+={ 12345/udp }" %INPUT > custom_udp.out
# @TEST-EXEC: zeek-cut id.orig_h id.orig_p id.resp_h id.resp_p proto service < conn.log >> custom_udp.out
# @TEST-EXEC: zeek-cut history < synchrophasor.log >> custom_udp.out
# @TEST-EXEC: btest-diff custom_udp.out
#
# @TEST-DOC: A redefined UDP analyzer port is also used for direction detection, allowing a server-first capture on port 12345 to be parsed in both directions.

@load analyzer

event zeek_init() &priority=-5
    {
    print 12345/udp in likely_server_ports;
    }
