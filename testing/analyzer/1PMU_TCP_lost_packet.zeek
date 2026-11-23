# @TEST-EXEC: touch synchrophasor.log synchrophasor_data.log weird.log
# @TEST-EXEC: zeek -C -r ${TRACES}/C37.118_1PMU_TCP_lost_packet.pcap %INPUT
# @TEST-EXEC: zeek-cut id.orig_h id.orig_p id.resp_h id.resp_p proto service < conn.log > conn.tmp && mv conn.tmp conn.log
# @TEST-EXEC: zeek-cut -n uid data_frame_id < synchrophasor_data.log > synchrophasor_data.tmp && mv synchrophasor_data.tmp synchrophasor_data.log
# @TEST-EXEC: zeek-cut name < weird.log | sort | uniq -c > weird.tmp && mv weird.tmp weird.log
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff synchrophasor.log
# @TEST-EXEC: btest-diff synchrophasor_data.log
# @TEST-EXEC: btest-diff weird.log
#
# @TEST-DOC: C37.118_1PMU_TCP.pcap with one TCP segment from the PMU removed (one data frame): the analyzer resumes at the next frame header and logs every other data frame

@load analyzer
