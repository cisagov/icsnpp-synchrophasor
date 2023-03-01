module SYNCHROPHASOR;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;

        version : set[count] &log &optional;
        data_stream_id : set[count] &log &optional;
        history : string &log &optional;
        frame_size_min : count &log &optional;
        frame_size_max : count &log &optional;
        data_frame_count : count &log &optional;
        data_rate : set[count] &log &optional;
    };

    global log_synchrophasor: event(rec: Info);

    const COMMAND_CODES_INITIALS = {
      [1] = "d", # turn off transmission of data frames
      [2] = "D", # turn on transmission of data frames
      [3] = "h", # send HDR frame
      [4] = "1", # send CFG-1 frame
      [5] = "2", # send CFG-2 frame
      [6] = "3", # send CFG-3 frame
      [8] = "e", # extended frame
    } &default = "u"; # unknown

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

    c$synchrophasor = Info($ts=network_time(),
                           $uid=c$uid,
                           $id=c$id,
                           $version=set(),
                           $history="",
                           $data_stream_id=set(),
                           $data_rate=set(),
                           $frame_size_min=0,
                           $frame_size_max=0,
                           $data_frame_count=0);
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

    if (frameSize > 0) {
        if ((frameSize < info$frame_size_min) || (info$frame_size_min == 0))
            info$frame_size_min = frameSize;
        if (frameSize > info$frame_size_max)
            info$frame_size_max = frameSize;
    }

    info$history += COMMAND_CODES_INITIALS[cmd];
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

        if (frameSize > 0) {
            if ((frameSize < info$frame_size_min) || (info$frame_size_min == 0))
                info$frame_size_min = frameSize;
            if (frameSize > info$frame_size_max)
                info$frame_size_max = frameSize;
        }
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
        add info$data_rate[dataRate];

        if (frameSize > 0) {
            if ((frameSize < info$frame_size_min) || (info$frame_size_min == 0))
                info$frame_size_min = frameSize;
            if (frameSize > info$frame_size_max)
                info$frame_size_max = frameSize;
        }
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
                               dgnmr: count) {
    hook set_session(c);

    local info = c$synchrophasor;

    add info$version[version];
    add info$data_stream_id[dataStreamId];

    if (frameSize > 0) {
        if ((frameSize < info$frame_size_min) || (info$frame_size_min == 0))
            info$frame_size_min = frameSize;
        if (frameSize > info$frame_size_max)
            info$frame_size_max = frameSize;
    }

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

    if (frameSize > 0) {
        if ((frameSize < info$frame_size_min) || (info$frame_size_min == 0))
            info$frame_size_min = frameSize;
        if (frameSize > info$frame_size_max)
            info$frame_size_max = frameSize;
    }
}

event connection_state_remove(c: connection) {
    # TODO: For UDP protocols, you may want to do this after every request and/or reply.
    emit_log(c);
}
