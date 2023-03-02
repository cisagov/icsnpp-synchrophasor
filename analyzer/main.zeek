module SYNCHROPHASOR;

export {
    redef enum Log::ID += { LOG_SYNCHROPHASOR,
                            LOG_SYNCHROPHASOR_COMMAND,
                            LOG_SYNCHROPHASOR_HEADER,
                            LOG_SYNCHROPHASOR_CONFIG,
                            LOG_SYNCHROPHASOR_DATA };

    type Synchrophasor_Info: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;

        proto : string &log &optional;
        version : set[count] &log &optional;
        data_stream_id : set[count] &log &optional;
        history : string &log &optional;
        frame_size_min : count &log &optional;
        frame_size_max : count &log &optional;
        data_frame_count : count &log &optional;
        data_rate : set[count] &log &optional;
    };

    type Synchrophasor_Command: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;

        proto : string &log &optional;
        command : string &log &optional;
        extframe : vector[count] &log &optional;
    };

    type Synchrophasor_Header: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;

        proto : string &log &optional;
        payload : string &log &optional;
    };

    type Synchrophasor_Config: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;

        proto : string &log &optional;
    };

    type Synchrophasor_Data: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;

        proto : string &log &optional;
    };

    global log_synchrophasor: event(rec: Synchrophasor_Info);
    global log_synchrophasor_command: event(rec: Synchrophasor_Command);
    global log_synchrophasor_header: event(rec: Synchrophasor_Header);
    global log_synchrophasor_config: event(rec: Synchrophasor_Config);
    global log_synchrophasor_data: event(rec: Synchrophasor_Data);

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
    synchrophasor_proto: string &optional;
    synchrophasor: Synchrophasor_Info &optional;
    synchrophasor_cmd: Synchrophasor_Command &optional;
    synchrophasor_hdr: Synchrophasor_Header &optional;
    synchrophasor_cfg: Synchrophasor_Config &optional;
    synchrophasor_data: Synchrophasor_Data &optional;
};

const ports = {
    4712/tcp,
    4713/udp
};

redef likely_server_ports += { ports };

event zeek_init() &priority=5 {
    Log::create_stream(SYNCHROPHASOR::LOG_SYNCHROPHASOR,
                       [$columns=Synchrophasor_Info,
                       $ev=log_synchrophasor,
                       $path="synchrophasor"]);
    Log::create_stream(SYNCHROPHASOR::LOG_SYNCHROPHASOR_COMMAND,
                       [$columns=Synchrophasor_Command,
                       $ev=log_synchrophasor_command,
                       $path="synchrophasor_cmd"]);
    Log::create_stream(SYNCHROPHASOR::LOG_SYNCHROPHASOR_HEADER,
                       [$columns=Synchrophasor_Header,
                       $ev=log_synchrophasor_header,
                       $path="synchrophasor_hdr"]);
    Log::create_stream(SYNCHROPHASOR::LOG_SYNCHROPHASOR_CONFIG,
                       [$columns=Synchrophasor_Config,
                       $ev=log_synchrophasor_config,
                       $path="synchrophasor_cfg"]);
    Log::create_stream(SYNCHROPHASOR::LOG_SYNCHROPHASOR_DATA,
                       [$columns=Synchrophasor_Data,
                       $ev=log_synchrophasor_data,
                       $path="synchrophasor_data"]);
}

event analyzer_confirmation(c: connection, atype: Analyzer::Tag, aid: count) &priority=5 {

  if ( atype == Analyzer::ANALYZER_SPICY_SYNCHROPHASOR_TCP ) {
    c$synchrophasor_proto = "tcp";
  } else if ( atype == Analyzer::ANALYZER_SPICY_SYNCHROPHASOR_UDP ) {
    c$synchrophasor_proto = "udp";
  }

}

hook set_session_cmd(c: connection) {
    if ( ! c?$synchrophasor )
        c$synchrophasor = Synchrophasor_Info(
                               $ts=network_time(),
                               $uid=c$uid,
                               $id=c$id,
                               $proto="",
                               $version=set(),
                               $history="",
                               $data_stream_id=set(),
                               $data_rate=set(),
                               $frame_size_min=0,
                               $frame_size_max=0,
                               $data_frame_count=0);

    if ( ! c?$synchrophasor_cmd )
        c$synchrophasor_cmd = Synchrophasor_Command(
                               $ts=network_time(),
                               $uid=c$uid,
                               $id=c$id,
                               $proto="",
                               $command="",
                               $extframe=vector());
}

hook set_session_hdr(c: connection) {
    if ( ! c?$synchrophasor )
        c$synchrophasor = Synchrophasor_Info(
                               $ts=network_time(),
                               $uid=c$uid,
                               $id=c$id,
                               $proto="",
                               $version=set(),
                               $history="",
                               $data_stream_id=set(),
                               $data_rate=set(),
                               $frame_size_min=0,
                               $frame_size_max=0,
                               $data_frame_count=0);

    if ( ! c?$synchrophasor_hdr )
        c$synchrophasor_hdr = Synchrophasor_Header(
                               $ts=network_time(),
                               $uid=c$uid,
                               $id=c$id,
                               $proto="",
                               $payload="");
}

hook set_session_cfg(c: connection) {
    if ( ! c?$synchrophasor )
        c$synchrophasor = Synchrophasor_Info(
                               $ts=network_time(),
                               $uid=c$uid,
                               $id=c$id,
                               $proto="",
                               $version=set(),
                               $history="",
                               $data_stream_id=set(),
                               $data_rate=set(),
                               $frame_size_min=0,
                               $frame_size_max=0,
                               $data_frame_count=0);

    if ( ! c?$synchrophasor_cfg )
        c$synchrophasor_cfg = Synchrophasor_Config(
                               $ts=network_time(),
                               $uid=c$uid,
                               $id=c$id,
                               $proto="");
}

hook set_session_data(c: connection) {
    if ( ! c?$synchrophasor )
        c$synchrophasor = Synchrophasor_Info(
                               $ts=network_time(),
                               $uid=c$uid,
                               $id=c$id,
                               $proto="",
                               $version=set(),
                               $history="",
                               $data_stream_id=set(),
                               $data_rate=set(),
                               $frame_size_min=0,
                               $frame_size_max=0,
                               $data_frame_count=0);

    if ( ! c?$synchrophasor_data )
        c$synchrophasor_data = Synchrophasor_Data(
                               $ts=network_time(),
                               $uid=c$uid,
                               $id=c$id,
                               $proto="");
}

function emit_synchrophasor_log(c: connection) {
    if ( ! c?$synchrophasor )
        return;

    if (c?$synchrophasor_proto)
      c$synchrophasor$proto = c$synchrophasor_proto;

    Log::write(SYNCHROPHASOR::LOG_SYNCHROPHASOR, c$synchrophasor);
    delete c$synchrophasor;
}

function emit_synchrophasor_cmd_log(c: connection) {
    if ( ! c?$synchrophasor_cmd )
        return;

    if (c?$synchrophasor_proto)
      c$synchrophasor_cmd$proto = c$synchrophasor_proto;

    Log::write(SYNCHROPHASOR::LOG_SYNCHROPHASOR_COMMAND, c$synchrophasor_cmd);
    delete c$synchrophasor_cmd;
}

function emit_synchrophasor_hdr_log(c: connection) {
    if ( ! c?$synchrophasor_hdr )
        return;

    if (c?$synchrophasor_proto)
      c$synchrophasor_hdr$proto = c$synchrophasor_proto;

    Log::write(SYNCHROPHASOR::LOG_SYNCHROPHASOR_COMMAND, c$synchrophasor_hdr);
    delete c$synchrophasor_hdr;
}

function emit_synchrophasor_cfg_log(c: connection) {
    if ( ! c?$synchrophasor_cfg )
        return;

    if (c?$synchrophasor_proto)
      c$synchrophasor_cfg$proto = c$synchrophasor_proto;

    Log::write(SYNCHROPHASOR::LOG_SYNCHROPHASOR_COMMAND, c$synchrophasor_cfg);
    delete c$synchrophasor_cfg;
}

function emit_synchrophasor_data_log(c: connection) {
    if ( ! c?$synchrophasor_data )
        return;

    if (c?$synchrophasor_proto)
      c$synchrophasor_data$proto = c$synchrophasor_proto;

    Log::write(SYNCHROPHASOR::LOG_SYNCHROPHASOR_COMMAND, c$synchrophasor_data);
    delete c$synchrophasor_data;
}

function emit_synchrophasor_log_all(c: connection) {
    emit_synchrophasor_log(c);
    emit_synchrophasor_cmd_log(c);
    emit_synchrophasor_hdr_log(c);
    emit_synchrophasor_cfg_log(c);
    emit_synchrophasor_data_log(c);
}

event SYNCHROPHASOR::CommandFrame(c: connection,
                                  is_orig: bool,
                                  timeStamp: time,
                                  frameSize: count,
                                  chk: count,
                                  version: count,
                                  dataStreamId: count,
                                  cmd: count) {
    hook set_session_cmd(c);

    local info = c$synchrophasor;
    local info_cmd = c$synchrophasor_cmd;

    add info$version[version];
    add info$data_stream_id[dataStreamId];

    if (frameSize > 0) {
        if ((frameSize < info$frame_size_min) || (info$frame_size_min == 0))
            info$frame_size_min = frameSize;
        if (frameSize > info$frame_size_max)
            info$frame_size_max = frameSize;
    }

    info$history += COMMAND_CODES_INITIALS[cmd];

    emit_synchrophasor_cmd_log(c);
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
        hook set_session_cfg(c);

        local info = c$synchrophasor;
        local info_cfg = c$synchrophasor_cfg;

        add info$version[version];
        add info$data_stream_id[dataStreamId];

        if (frameSize > 0) {
            if ((frameSize < info$frame_size_min) || (info$frame_size_min == 0))
                info$frame_size_min = frameSize;
            if (frameSize > info$frame_size_max)
                info$frame_size_max = frameSize;
        }

        emit_synchrophasor_cfg_log(c);
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
        hook set_session_cfg(c);

        local info = c$synchrophasor;
        local info_cfg = c$synchrophasor_cfg;

        add info$version[version];
        add info$data_stream_id[dataStreamId];
        add info$data_rate[dataRate];

        if (frameSize > 0) {
            if ((frameSize < info$frame_size_min) || (info$frame_size_min == 0))
                info$frame_size_min = frameSize;
            if (frameSize > info$frame_size_max)
                info$frame_size_max = frameSize;
        }

        emit_synchrophasor_cfg_log(c);
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
    hook set_session_data(c);

    local info = c$synchrophasor;
    local info_data = c$synchrophasor_data;

    add info$version[version];
    add info$data_stream_id[dataStreamId];

    if (frameSize > 0) {
        if ((frameSize < info$frame_size_min) || (info$frame_size_min == 0))
            info$frame_size_min = frameSize;
        if (frameSize > info$frame_size_max)
            info$frame_size_max = frameSize;
    }

    info$data_frame_count += 1;

    emit_synchrophasor_data_log(c);
}

event SYNCHROPHASOR::HeaderFrame(c: connection,
                                 is_orig: bool,
                                 timeStamp: time,
                                 frameSize: count,
                                 chk: count,
                                 version: count,
                                 dataStreamId: count) {
    hook set_session_hdr(c);

    local info = c$synchrophasor;
    local info_hdr = c$synchrophasor_hdr;

    add info$version[version];
    add info$data_stream_id[dataStreamId];

    if (frameSize > 0) {
        if ((frameSize < info$frame_size_min) || (info$frame_size_min == 0))
            info$frame_size_min = frameSize;
        if (frameSize > info$frame_size_max)
            info$frame_size_max = frameSize;
    }

    emit_synchrophasor_hdr_log(c);
}

event connection_state_remove(c: connection) {
    # TODO: For UDP protocols, you may want to do this after every request and/or reply.
    emit_synchrophasor_log_all(c);
}
