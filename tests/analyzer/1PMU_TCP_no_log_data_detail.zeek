# @TEST-EXEC: touch synchrophasor.log synchrophasor_cmd.log synchrophasor_cfg.log synchrophasor_cfg_detail.log synchrophasor_hdr.log synchrophasor_data.log synchrophasor_data_detail.log
# @TEST-EXEC: zeek -C -r ${TRACES}/C37.118_1PMU_TCP.pcap SYNCHROPHASOR::log_data_frame=T SYNCHROPHASOR::log_data_detail=F SYNCHROPHASOR::log_cfg_detail=T  %INPUT
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff synchrophasor.log
# @TEST-EXEC: btest-diff synchrophasor_cmd.log
# @TEST-EXEC: btest-diff synchrophasor_cfg.log
# @TEST-EXEC: btest-diff synchrophasor_cfg_detail.log
# @TEST-EXEC: btest-diff synchrophasor_hdr.log
# @TEST-EXEC: btest-diff synchrophasor_data.log
# @TEST-EXEC: btest-diff synchrophasor_data_detail.log
#
# @TEST-DOC: Test synchrophasor analyzer with log_data_detail disabled but log_data_frame enabled

@load analyzer
