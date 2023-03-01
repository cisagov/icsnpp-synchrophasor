# @TEST-DOC: Test Zeek parsing a trace file through the SYNCHROPHASOR analyzer.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/tcp-port-12345.pcap ${PACKAGE} %INPUT >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff synchrophasor.log

# TODO: Adapt as suitable. The example only checks the output of the event
# handlers.

event SYNCHROPHASOR::request(c: connection, is_orig: bool, payload: string)
    {
    print fmt("Testing SYNCHROPHASOR: [request] %s %s", c$id, payload);
    }

event SYNCHROPHASOR::reply(c: connection, is_orig: bool, payload: string)
    {
    print fmt("Testing SYNCHROPHASOR: [reply] %s %s", c$id, payload);
    }
