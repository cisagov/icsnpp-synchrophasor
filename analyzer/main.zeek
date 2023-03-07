## main.zeek
##
## ICSNPP-Synchrophasor parser
##
## Zeek script type/record definitions describing the information
## that will be written to the log files.
##
## Author:   Seth Grover
## Contact:  Seth.Grover@inl.gov
##
## Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.

module SYNCHROPHASOR;

export {

    # define log enums for synchrophasor, synchrophasor_cmd, synchrophasor_hdr,
    #   synchrophasor_cfg and synchrophasor_data
    redef enum Log::ID += { LOG_SYNCHROPHASOR,
                            LOG_SYNCHROPHASOR_COMMAND,
                            LOG_SYNCHROPHASOR_HEADER,
                            LOG_SYNCHROPHASOR_CONFIG,
                            LOG_SYNCHROPHASOR_DATA };

    # synchrophasor.log columns
    # summary log file entry (one per synchrophasor session/conn. UID)
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

    # synchrophasor_cmd.log columns
    # command frame logs (one per command frame)
    type Synchrophasor_Command: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;

        proto : string &log &optional;
        frame_type : string &log &optional;
        command : string &log &optional;
        extframe : vector of count &log &optional;
    };

    # synchrophasor_hdr.log columns
    # header frame logs (one per header frame)
    type Synchrophasor_Header: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;

        proto : string &log &optional;
        frame_type : string &log &optional;
        data : string &log &optional;
    };

    # synchrophasor_cfg.log columns
    # config frame logs (one per CFG frame: CFG-1, CFG-2 and CFG-3 frame types)
    #
    # TODO: as described in C37.118.2-2011, 6.4, and parsed with ConfigFrame, PMUConfig and PMUConfig3 unit
    #   types in synchrophasor.spicy, configuration frames can be pretty complicated.
    #   Rather than include every possible field in this log, for now I'm going to observe how this parser
    #   does in the field and expand as needed.
    type Synchrophasor_Config: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;

        proto : string &log &optional;
        frame_type : string &log &optional;
        cont_idx : count &log &optional;
        pmu_count_expected : count &log &optional;
        pmu_count_actual : count &log &optional;
        data_rate : count &log &optional;
        station_names : vector of string &log &optional;
        phasor_names : vector of string &log &optional;
        analog_names : vector of string &log &optional;
        digital_names : vector of string &log &optional;
    };

    # synchrophasor_data.log columns
    # data frame logs (one per data frame)
    #
    # TODO: as described in C37.118.2-2011, 6.3, and parsed with DataFrame and PMUData
    #   types in synchrophasor.spicy, data frames can be pretty complicated and very verbose.
    #   Rather than include every possible field in this log, for now I'm going to observe how this parser
    #   does in the field and expand as needed.
    type Synchrophasor_Data: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;

        proto : string &log &optional;
        frame_type : string &log &optional;
        pmu_count_expected : count &log &optional;
        pmu_count_actual : count &log &optional;
    };

    # global events for logging
    global log_synchrophasor: event(rec: Synchrophasor_Info);
    global log_synchrophasor_command: event(rec: Synchrophasor_Command);
    global log_synchrophasor_header: event(rec: Synchrophasor_Header);
    global log_synchrophasor_config: event(rec: Synchrophasor_Config);
    global log_synchrophasor_data: event(rec: Synchrophasor_Data);

    # command code initials for Synchrophasor_Info::history field
    const COMMAND_CODES_INITIALS = {
      [1] = "d", # turn off transmission of data frames
      [2] = "D", # turn on transmission of data frames
      [3] = "h", # send HDR frame
      [4] = "1", # send CFG-1 frame
      [5] = "2", # send CFG-2 frame
      [6] = "3", # send CFG-3 frame
      [8] = "e", # extended frame
    } &default = "u"; # unknown

    const COMMAND_CODES_STRINGS = {
      [1] = "Data off", # turn off transmission of data frames
      [2] = "Data on", # turn on transmission of data frames
      [3] = "Send HDR", # send HDR frame
      [4] = "Send CFG-1", # send CFG-1 frame
      [5] = "Send CFG-2", # send CFG-2 frame
      [6] = "Send CFG-3", # send CFG-3 frame
      [8] = "Extended frame", # extended frame
    } &default = "unknown"; # unknown

    const FRAME_TYPES = {
      [SYNCHROPHASOR::FrameTypeCode_DATA_FRAME] = "Data",
      [SYNCHROPHASOR::FrameTypeCode_HEADER_FRAME] = "Header",
      [SYNCHROPHASOR::FrameTypeCode_CONFIG_1_FRAME] = "CFG1",
      [SYNCHROPHASOR::FrameTypeCode_CONFIG_2_FRAME] = "CFG2",
      [SYNCHROPHASOR::FrameTypeCode_COMMAND_FRAME] = "Command",
      [SYNCHROPHASOR::FrameTypeCode_CONFIG_3_FRAME] = "CFG3"
    } &default = "unknown";
}

# redefine connection record to contain one of each of the synchrophasor records
redef record connection += {
    synchrophasor_proto: string &optional;
    synchrophasor: Synchrophasor_Info &optional;
    synchrophasor_cmd: Synchrophasor_Command &optional;
    synchrophasor_hdr: Synchrophasor_Header &optional;
    synchrophasor_cfg: Synchrophasor_Config &optional;
    synchrophasor_data: Synchrophasor_Data &optional;
};

# C37.118.2-2011, E.2, Network communications using Internet protocol (IP)
# "Default port numbers shall be 4712 for TCP and 4713 for UDP, but in all cases,
#  the user shall be provided the means to set port numbers as desired."
const ports = {
    4712/tcp,
    4713/udp
};
redef likely_server_ports += { ports };

event zeek_init() &priority=5 {
    # initialize logging streams for all synchrophasor logs
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

# triggered by SYNCHROPHASOR::FrameHeader::%done, set synchrophasor_proto according to analyzer
event analyzer_confirmation(c: connection, atype: Analyzer::Tag, aid: count) &priority=5 {

  if ( atype == Analyzer::ANALYZER_SPICY_SYNCHROPHASOR_TCP ) {
    c$synchrophasor_proto = "tcp";
  } else if ( atype == Analyzer::ANALYZER_SPICY_SYNCHROPHASOR_UDP ) {
    c$synchrophasor_proto = "udp";
  }

}

# set_session_* functions for each of the synchrophasor frame events
# these functions initialize empty synchrophasor records of the
# appropriate types within the connection record

# command frame
hook set_session_cmd(c: connection) {
    if ( ! c?$synchrophasor )
        c$synchrophasor = Synchrophasor_Info(
            $ts=network_time(),
            $uid=c$uid,
            $id=c$id,
            $proto="",
            $version=set(),
            $data_stream_id=set(),
            $history="",
            $frame_size_min=0,
            $frame_size_max=0,
            $data_frame_count=0,
            $data_rate=set());

    if ( ! c?$synchrophasor_cmd )
        c$synchrophasor_cmd = Synchrophasor_Command(
            $ts=network_time(),
            $uid=c$uid,
            $id=c$id,
            $proto="",
            $frame_type="",
            $command="",
            $extframe=vector());
}

# header frame
hook set_session_hdr(c: connection) {
    if ( ! c?$synchrophasor )
        c$synchrophasor = Synchrophasor_Info(
            $ts=network_time(),
            $uid=c$uid,
            $id=c$id,
            $proto="",
            $version=set(),
            $data_stream_id=set(),
            $history="",
            $frame_size_min=0,
            $frame_size_max=0,
            $data_frame_count=0,
            $data_rate=set());

    if ( ! c?$synchrophasor_hdr )
        c$synchrophasor_hdr = Synchrophasor_Header(
            $ts=network_time(),
            $uid=c$uid,
            $id=c$id,
            $proto="",
            $frame_type="",
            $data="");
}

# cfg frame
hook set_session_cfg(c: connection) {
    if ( ! c?$synchrophasor )
        c$synchrophasor = Synchrophasor_Info(
            $ts=network_time(),
            $uid=c$uid,
            $id=c$id,
            $proto="",
            $version=set(),
            $data_stream_id=set(),
            $history="",
            $frame_size_min=0,
            $frame_size_max=0,
            $data_frame_count=0,
            $data_rate=set());

    if ( ! c?$synchrophasor_cfg )
        c$synchrophasor_cfg = Synchrophasor_Config(
            $ts=network_time(),
            $uid=c$uid,
            $id=c$id,
            $proto="",
            $frame_type="",
            $cont_idx=0,
            $pmu_count_expected=0,
            $pmu_count_actual=0,
            $data_rate=0,
            $station_names=vector(),
            $phasor_names=vector(),
            $analog_names=vector(),
            $digital_names=vector());
}

# data frame
hook set_session_data(c: connection) {
    if ( ! c?$synchrophasor )
        c$synchrophasor = Synchrophasor_Info(
            $ts=network_time(),
            $uid=c$uid,
            $id=c$id,
            $proto="",
            $version=set(),
            $data_stream_id=set(),
            $history="",
            $frame_size_min=0,
            $frame_size_max=0,
            $data_frame_count=0,
            $data_rate=set());

    if ( ! c?$synchrophasor_data )
        c$synchrophasor_data = Synchrophasor_Data(
            $ts=network_time(),
            $uid=c$uid,
            $id=c$id,
            $proto="",
            $frame_type="",
            $pmu_count_expected=0,
            $pmu_count_actual=0);
}

# emit_synchrophasor*log functions generate log entries for their
# respective record types then delete the record logged

# synchrophasor.log
function emit_synchrophasor_log(c: connection) {
    if ( ! c?$synchrophasor )
        return;

    if (c?$synchrophasor_proto)
      c$synchrophasor$proto = c$synchrophasor_proto;

    Log::write(SYNCHROPHASOR::LOG_SYNCHROPHASOR, c$synchrophasor);
    delete c$synchrophasor;
}

# synchrophasor_cmd.log
function emit_synchrophasor_cmd_log(c: connection) {
    if ( ! c?$synchrophasor_cmd )
        return;

    if (c?$synchrophasor_proto)
      c$synchrophasor_cmd$proto = c$synchrophasor_proto;

    Log::write(SYNCHROPHASOR::LOG_SYNCHROPHASOR_COMMAND, c$synchrophasor_cmd);
    delete c$synchrophasor_cmd;
}

# synchrophasor_hdr.log
function emit_synchrophasor_hdr_log(c: connection) {
    if ( ! c?$synchrophasor_hdr )
        return;

    if (c?$synchrophasor_proto)
      c$synchrophasor_hdr$proto = c$synchrophasor_proto;

    Log::write(SYNCHROPHASOR::LOG_SYNCHROPHASOR_HEADER, c$synchrophasor_hdr);
    delete c$synchrophasor_hdr;
}

# synchrophasor_cfg.log
function emit_synchrophasor_cfg_log(c: connection) {
    if ( ! c?$synchrophasor_cfg )
        return;

    if (c?$synchrophasor_proto)
      c$synchrophasor_cfg$proto = c$synchrophasor_proto;

    Log::write(SYNCHROPHASOR::LOG_SYNCHROPHASOR_CONFIG, c$synchrophasor_cfg);
    delete c$synchrophasor_cfg;
}

# synchrophasor_data.log
function emit_synchrophasor_data_log(c: connection) {
    if ( ! c?$synchrophasor_data )
        return;

    if (c?$synchrophasor_proto)
      c$synchrophasor_data$proto = c$synchrophasor_proto;

    Log::write(SYNCHROPHASOR::LOG_SYNCHROPHASOR_DATA, c$synchrophasor_data);
    delete c$synchrophasor_data;
}

# log all synchrophasor log types (to be used on connection close)
function emit_synchrophasor_log_all(c: connection) {
    emit_synchrophasor_log(c);
    emit_synchrophasor_cmd_log(c);
    emit_synchrophasor_hdr_log(c);
    emit_synchrophasor_cfg_log(c);
    emit_synchrophasor_data_log(c);
}

##
## Synchrophasor message frame events
##

event SYNCHROPHASOR::CommandFrame(
    c: connection,
    is_orig: bool,
    frameType : SYNCHROPHASOR::FrameTypeCode,
    timeStamp: time,
    frameSize: count,
    chk: count,
    version: count,
    dataStreamId: count,
    cmd: count,
    extframe: vector of count) {

    hook set_session_cmd(c);

    local info = c$synchrophasor;
    local info_cmd = c$synchrophasor_cmd;

    info_cmd$frame_type = FRAME_TYPES[frameType];

    add info$version[version];
    add info$data_stream_id[dataStreamId];

    if (frameSize > 0) {
        if ((frameSize < info$frame_size_min) || (info$frame_size_min == 0))
            info$frame_size_min = frameSize;
        if (frameSize > info$frame_size_max)
            info$frame_size_max = frameSize;
    }

    info$history += COMMAND_CODES_INITIALS[cmd];
    info_cmd$command = COMMAND_CODES_STRINGS[cmd];
    info_cmd$extframe = extframe;

    emit_synchrophasor_cmd_log(c);
}

event SYNCHROPHASOR::ConfigFrame(
    c: connection,
    is_orig: bool,
    frameType : SYNCHROPHASOR::FrameTypeCode,
    timeStamp: time,
    frameSize: count,
    chk: count,
    version: count,
    dataStreamId: count,
    initialized: bool,
    timeBase: count,
    contIdx: count,
    numPMUExpected: count,
    numPMUActual: count,
    dataRate: count,
    allStationNames: vector of string,
    allPhasorNames: vector of string,
    allAnalogNames: vector of string,
    allDigitalNames: vector of string) {

    hook set_session_cfg(c);

    local info = c$synchrophasor;
    local info_cfg = c$synchrophasor_cfg;

    info_cfg$frame_type = FRAME_TYPES[frameType];

    add info$version[version];
    add info$data_stream_id[dataStreamId];
    add info$data_rate[dataRate];

    if (frameSize > 0) {
        if ((frameSize < info$frame_size_min) || (info$frame_size_min == 0))
            info$frame_size_min = frameSize;
        if (frameSize > info$frame_size_max)
            info$frame_size_max = frameSize;
    }

    info_cfg$cont_idx = contIdx;
    info_cfg$pmu_count_expected = numPMUExpected;
    info_cfg$pmu_count_actual = numPMUActual;
    info_cfg$data_rate = dataRate;

    for (i, val in allStationNames)
        info_cfg$station_names += strip(val);
    for (i, val in allPhasorNames)
        info_cfg$phasor_names += strip(val);
    for (i, val in allAnalogNames)
        info_cfg$analog_names += strip(val);
    for (i, val in allDigitalNames)
        info_cfg$digital_names += strip(val);

    emit_synchrophasor_cfg_log(c);
}

event SYNCHROPHASOR::DataFrame(
    c: connection,
    is_orig: bool,
    frameType : SYNCHROPHASOR::FrameTypeCode,
    timeStamp: time,
    frameSize: count,
    chk: count,
    version: count,
    dataStreamId: count,
    initialized: bool,
    numPMUExpected: count,
    numPMUActual: count) {

    hook set_session_data(c);

    local info = c$synchrophasor;
    local info_data = c$synchrophasor_data;

    info_data$frame_type = FRAME_TYPES[frameType];
    info_data$pmu_count_expected = numPMUExpected;
    info_data$pmu_count_actual = numPMUActual;

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

event SYNCHROPHASOR::HeaderFrame(
    c: connection,
    is_orig: bool,
    frameType : SYNCHROPHASOR::FrameTypeCode,
    timeStamp: time,
    frameSize: count,
    chk: count,
    version: count,
    dataStreamId: count,
    data: string) {

    hook set_session_hdr(c);

    local info = c$synchrophasor;
    local info_hdr = c$synchrophasor_hdr;

    info_hdr$frame_type = FRAME_TYPES[frameType];

    add info$version[version];
    add info$data_stream_id[dataStreamId];

    if (frameSize > 0) {
        if ((frameSize < info$frame_size_min) || (info$frame_size_min == 0))
            info$frame_size_min = frameSize;
        if (frameSize > info$frame_size_max)
            info$frame_size_max = frameSize;
    }

    info_hdr$data = data;

    emit_synchrophasor_hdr_log(c);
}

event connection_state_remove(c: connection) {
    # TODO: For UDP protocols, you may want to do this after every request and/or reply.
    emit_synchrophasor_log_all(c);
}
