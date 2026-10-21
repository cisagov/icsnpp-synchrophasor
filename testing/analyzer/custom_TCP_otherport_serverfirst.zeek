# @TEST-EXEC: zeek -C -r ${TRACES}/C37.118_1PMU_TCP_minimal_otherport_serverfirst.pcap "SYNCHROPHASOR::synchrophasor_ports_tcp+={ 12345/tcp }" %INPUT > custom_tcp.out
# @TEST-EXEC: zeek-cut id.orig_h id.orig_p id.resp_h id.resp_p proto service < conn.log >> custom_tcp.out
# @TEST-EXEC: zeek-cut history < synchrophasor.log >> custom_tcp.out
# @TEST-EXEC: btest-diff custom_tcp.out
#
# @TEST-DOC: A redefined TCP analyzer port is also used for direction detection, allowing a server-first capture on port 12345 to be parsed.

@load analyzer

event zeek_init() &priority=-5
    {
    print 12345/tcp in likely_server_ports;
    }
