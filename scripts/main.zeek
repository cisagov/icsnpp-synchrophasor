module SYNCHROPHASOR;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;

        version : set[count] &log &optional;
        data_stream_id : set[count] &log &optional;
        data_frame_count : count &log;
    };

    global log_synchrophasor: event(rec: Info);

    const FRAME_TYPE_CODES = {
      [SYNCHROPHASOR::FrameTypeCode_DATA_FRAME] = "Data",
      [SYNCHROPHASOR::FrameTypeCode_HEADER_FRAME] = "Header",
      [SYNCHROPHASOR::FrameTypeCode_CONFIG_1_FRAME] = "Config 1",
      [SYNCHROPHASOR::FrameTypeCode_CONFIG_2_FRAME] = "Config 2",
      [SYNCHROPHASOR::FrameTypeCode_CONFIG_3_FRAME] = "Config 3",
      [SYNCHROPHASOR::FrameTypeCode_COMMAND_FRAME] = "Command",
    } &default = "unknown";

    const COMMAND_CODES = {
      [1] = "Data transmission on",
      [2] = "Data transmission off",
      [3] = "Send HDR frame",
      [4] = "Send CFG-1 frame",
      [5] = "Send CFG-2 frame",
      [6] = "Send CFG-3 frame",
      [8] = "Extended frame",
    } &default = "unknown";

}

redef record connection += {
    synchrophasor: Info &optional;
};

const ports = {
    4712/tcp,
    4713/udp
};

redef likely_server_ports += { ports };

event zeek_init() &priority=5 {
    Log::create_stream(SYNCHROPHASOR::LOG, [$columns=Info, $ev=log_synchrophasor, $path="synchrophasor"]);
}

hook set_session(c: connection) {
    if ( c?$synchrophasor )
        return;

    c$synchrophasor = Info($ts=network_time(), $uid=c$uid, $id=c$id, $data_frame_count=0);
}

function emit_log(c: connection) {
    if ( ! c?$synchrophasor )
        return;

    Log::write(SYNCHROPHASOR::LOG, c$synchrophasor);
    delete c$synchrophasor;
}

event SYNCHROPHASOR::CommandFrame(c: connection,
                                  is_orig: bool,
                                  timeStamp: time,
                                  frameSize: count,
                                  chk: count,
                                  version: count,
                                  dataStreamId: count,
                                  cmd: count) {
    hook set_session(c);

    local info = c$synchrophasor;

    add info$version[version];
    add info$data_stream_id[dataStreamId];
}

event SYNCHROPHASOR::Config3Frame(c: connection,
                                  is_orig: bool,
                                  timeStamp: time,
                                  frameSize: count,
                                  chk: count,
                                  version: count,
                                  dataStreamId: count,
                                  initialized: bool,
                                  contIdx: count,
                                  timeBase: count,
                                  numPMU: count) {
    if (initialized) {
        hook set_session(c);

        local info = c$synchrophasor;

        add info$version[version];
        add info$data_stream_id[dataStreamId];
    }
}

event SYNCHROPHASOR::ConfigFrame(c: connection,
                                 is_orig: bool,
                                 timeStamp: time,
                                 frameSize: count,
                                 chk: count,
                                 version: count,
                                 dataStreamId: count,
                                 initialized: bool,
                                 timeBase: count,
                                 numPMU: count,
                                 dataRate: count) {
    if (initialized) {
        hook set_session(c);

        local info = c$synchrophasor;

        add info$version[version];
        add info$data_stream_id[dataStreamId];
    }
}

event SYNCHROPHASOR::DataFrame(c: connection,
                               is_orig: bool,
                               timeStamp: time,
                               frameSize: count,
                               chk: count,
                               version: count,
                               dataStreamId: count,
                               numPMU: count,
                               phnmr: count,
                               annmr: count,
                               dgnmr: count,
                               triggerReason: count,
                               unlockedTime: count,
                               pmuTimeQuality: count,
                               dataModified: bool,
                               configChange: bool,
                               pmuTriggerPickup: bool,
                               dataSortingType: bool,
                               pmuSyncError: bool,
                               dataErrorIndicator: count) {
    hook set_session(c);

    local info = c$synchrophasor;

    add info$version[version];
    add info$data_stream_id[dataStreamId];

    info$data_frame_count += 1;
}

event SYNCHROPHASOR::HeaderFrame(c: connection,
                                 is_orig: bool,
                                 timeStamp: time,
                                 frameSize: count,
                                 chk: count,
                                 version: count,
                                 dataStreamId: count) {
    hook set_session(c);

    local info = c$synchrophasor;

    add info$version[version];
    add info$data_stream_id[dataStreamId];
}

event connection_state_remove(c: connection) {
    # TODO: For UDP protocols, you may want to do this after every request and/or reply.
    emit_log(c);
}
