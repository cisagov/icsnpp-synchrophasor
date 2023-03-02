# @TEST-EXEC: touch synchrophasor_hdr.log
# @TEST-EXEC: zeek -C -r ${TRACES}/C37.118_4in1PMU_TCP.pcap %INPUT
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff synchrophasor.log
# @TEST-EXEC: btest-diff synchrophasor_cmd.log
# @TEST-EXEC: btest-diff synchrophasor_cfg.log
# @TEST-EXEC: btest-diff synchrophasor_hdr.log
# @TEST-EXEC: btest-diff synchrophasor_data.log
#
# @TEST-DOC: Test synchrophasor analyzer with C37.118_4in1PMU_TCP.pcap

@load analyzer
