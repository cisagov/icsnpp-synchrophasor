##! main.zeek
##!
##! ICSNPP-Synchrophasor parser
##!
##! Zeek script type/record definitions describing the information
##! that will be written to the log files.
##!
##! Author:   Seth Grover
##! Contact:  Seth.Grover@inl.gov
##!
##! Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.

module SYNCHROPHASOR;

export {

    # define log enums for synchrophasor, synchrophasor_cmd, synchrophasor_hdr,
    #   synchrophasor_cfg, synchrophasor_cfg_detail, synchrophasor_data and synchrophasor_data_detail
    redef enum Log::ID += { LOG_SYNCHROPHASOR,
                            LOG_SYNCHROPHASOR_COMMAND,
                            LOG_SYNCHROPHASOR_HEADER,
                            LOG_SYNCHROPHASOR_CONFIG,
                            LOG_SYNCHROPHASOR_CONFIG_DETAIL,
                            LOG_SYNCHROPHASOR_DATA,
                            LOG_SYNCHROPHASOR_DATA_DETAIL };

    # synchrophasor.log columns
    # summary log file entry (one per synchrophasor session/conn. UID)
    type Synchrophasor_Info: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;

        proto : transport_proto &log &optional;
        version : set[count] &log &optional;
        data_stream_id : set[count] &log &optional;
        history : string &log &optional;
        frame_size_min : count &log &optional;
        frame_size_max : count &log &optional;
        frame_size_tot : count &log &optional;
        data_frame_count : count &log &optional;
        data_rate : set[count] &log &optional;
    };

    # synchrophasor_cmd.log columns
    # command frame logs (one per command frame)
    type Synchrophasor_Command: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;

        proto : transport_proto &log &optional;
        frame_type : string &log &optional;
        frame_size : count &log &optional;
        header_time_stamp : time &log &optional;
        command : string &log &optional;
        extframe : vector of count &log &optional;
    };

    # synchrophasor_hdr.log columns
    # header frame logs (one per header frame)
    type Synchrophasor_Header: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;

        proto : transport_proto &log &optional;
        frame_type : string &log &optional;
        frame_size : count &log &optional;
        header_time_stamp : time &log &optional;
        data : string &log &optional;
    };

    # synchrophasor_cfg.log columns
    # config frame logs (one per CFG frame: CFG-1, CFG-2 and CFG-3 frame types)
    type Synchrophasor_Config: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;

        proto : transport_proto &log &optional;
        frame_type : string &log &optional;
        frame_size : count &log &optional;
        header_time_stamp : time &log &optional;
        cont_idx : count &log &optional;
        pmu_count_expected : count &log &optional;
        pmu_count_actual : count &log &optional;
        data_rate : count &log &optional;
        cfg_frame_id : string &log &optional;
    };

    # synchrophasor_cfg_detail.log columns
    # config frame log details
    # one log line per PMU config, i.e., there could be up to
    #   Synchrophasor_Config.pmu_count_actual logs lines per
    #   ConfigFrame event.
    #
    type Synchrophasor_Config_Detail: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;

        proto : transport_proto &log &optional;
        frame_type : string &log &optional;
        header_time_stamp : time &log &optional;
        cfg_frame_id : string &log &optional;

        pmu_idx : count &log &optional;
        svc_class : string &log &optional;
        station_name : string &log &optional;
        data_source_id : count &log &optional;
        global_pmuid : string &log &optional;
        phasor_shape : bool &log &optional;
        phasor_format : bool &log &optional;
        analog_format : bool &log &optional;
        freq_format : bool &log &optional;
        phnmr : count &log &optional;
        annmr : count &log &optional;
        dgnmr : count &log &optional;
        phnam : vector of string &log &optional;
        annam : vector of string &log &optional;
        dgnam : vector of string &log &optional;
        phasor_conv_phunit : vector of count &log &optional;
        phasor_conv_phvalue : vector of count &log &optional;
        phasor_conv_upsampled_interpolation : vector of bool &log &optional;
        phasor_conv_upsampled_extrapolation : vector of bool &log &optional;
        phasor_conv_downsampled_reselection : vector of bool &log &optional;
        phasor_conv_downsampled_fir_filter : vector of bool &log &optional;
        phasor_conv_downsampled_no_fir_filter : vector of bool &log &optional;
        phasor_conv_filtered_without_changing_sampling : vector of bool &log &optional;
        phasor_conv_calibration_mag_adj : vector of bool &log &optional;
        phasor_conv_calibration_phas_adj : vector of bool &log &optional;
        phasor_conv_rotation_phase_adj : vector of bool &log &optional;
        phasor_conv_pseudo_phasor_val : vector of bool &log &optional;
        phasor_conv_mod_appl : vector of bool &log &optional;
        phasor_conv_phasor_component : vector of count &log &optional;
        phasor_conv_phasor_type : vector of bool &log &optional;
        phasor_conv_user_def : vector of count &log &optional;
        phasor_conv_scale_factor : vector of double &log &optional;
        phasor_conv_angle_adj : vector of double &log &optional;
        analog_conv_analog_flags : vector of count &log &optional;
        analog_conv_user_defined_scaling : vector of int &log &optional;
        analog_conv_mag_scale : vector of double &log &optional;
        analog_conv_offset : vector of double &log &optional;
        digital_conv_normal_status_mask : vector of count &log &optional;
        digital_conv_valid_inputs_mask : vector of count &log &optional;
        pmu_lat : double &log &optional;
        pmu_lon : double &log &optional;
        pmu_elev : double &log &optional;
        window : int &log &optional;
        group_delay : int &log &optional;
        fnom : count &log &optional;
        cfgcnt : count &log &optional;
    };

    # synchrophasor_data.log columns
    # data frame logs (one per data frame)
    type Synchrophasor_Data: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;

        proto : transport_proto &log &optional;
        frame_type : string &log &optional;
        frame_size : count &log &optional;
        header_time_stamp : time &log &optional;
        pmu_count_expected : count &log &optional;
        pmu_count_actual : count &log &optional;
        data_frame_id : string &log &optional;
    };

    # synchrophasor_data_detail.log columns
    # config frame log details
    # one log line per PMU config, i.e., there could be up to
    #   Synchrophasor_Data.pmu_count_actual logs lines per
    #   DataFrame event.
    #
    type Synchrophasor_Data_Detail: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;

        proto : transport_proto &log &optional;
        frame_type : string &log &optional;
        header_time_stamp : time &log &optional;
        data_frame_id : string &log &optional;

        pmu_idx : count &log &optional;
        trigger_reason : count &log &optional;
        unlocked_time : count &log &optional;
        pmu_time_quality : count &log &optional;
        data_modified : bool &log &optional;
        config_change : bool &log &optional;
        pmu_trigger_pickup : bool &log &optional;
        data_sorting_type : bool &log &optional;
        pmu_sync_error : bool &log &optional;
        data_error_indicator : count &log &optional;
        est_rectangular_real : vector of double &log &optional;
        est_rectangular_imaginary : vector of double &log &optional;
        est_polar_magnitude : vector of double &log &optional;
        est_polar_angle : vector of double &log &optional;
        freq_dev_mhz : double &log &optional;
        rocof : double &log &optional;
        analog_data : vector of double &log &optional;
        digital : vector of count &log &optional;
    };

    # global events for logging
    global log_synchrophasor: event(rec: Synchrophasor_Info);
    global log_policy_sychrophasor: Log::PolicyHook;
    global log_synchrophasor_command: event(rec: Synchrophasor_Command);
    global log_policy_sychrophasor_command: Log::PolicyHook;
    global log_synchrophasor_header: event(rec: Synchrophasor_Header);
    global log_policy_sychrophasor_header: Log::PolicyHook;
    global log_synchrophasor_config: event(rec: Synchrophasor_Config);
    global log_policy_sychrophasor_config: Log::PolicyHook;
    global log_synchrophasor_config_detail: event(rec: Synchrophasor_Config_Detail);
    global log_policy_sychrophasor_config_detail: Log::PolicyHook;
    global log_synchrophasor_data: event(rec: Synchrophasor_Data);
    global log_policy_sychrophasor_data: Log::PolicyHook;
    global log_synchrophasor_data_detail: event(rec: Synchrophasor_Data_Detail);
    global log_policy_sychrophasor_data_detail: Log::PolicyHook;

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
    synchrophasor: Synchrophasor_Info &optional;
    synchrophasor_cmd: Synchrophasor_Command &optional;
    synchrophasor_hdr: Synchrophasor_Header &optional;
    synchrophasor_cfg: Synchrophasor_Config &optional;
    synchrophasor_data: Synchrophasor_Data &optional;
};

# C37.118.2-2011, E.2, Network communications using Internet protocol (IP)
# "Default port numbers shall be 4712 for TCP and 4713 for UDP, but in all cases,
#  the user shall be provided the means to set port numbers as desired."

export {
    const synchrophasor_ports_tcp: set[port] = { 4712/tcp } &redef;
    const synchrophasor_ports_udp: set[port] = { 4713/udp } &redef;
}
redef likely_server_ports += { synchrophasor_ports_tcp, synchrophasor_ports_udp };

event zeek_init() &priority=5 {
    Analyzer::register_for_ports(Analyzer::ANALYZER_SYNCHROPHASOR_TCP, synchrophasor_ports_tcp);
    Analyzer::register_for_ports(Analyzer::ANALYZER_SYNCHROPHASOR_UDP, synchrophasor_ports_udp);

    # initialize logging streams for all synchrophasor logs
    Log::create_stream(SYNCHROPHASOR::LOG_SYNCHROPHASOR,
                       [$columns=Synchrophasor_Info,
                       $ev=log_synchrophasor,
                       $path="synchrophasor",
                       $policy=log_policy_sychrophasor]);
    Log::create_stream(SYNCHROPHASOR::LOG_SYNCHROPHASOR_COMMAND,
                       [$columns=Synchrophasor_Command,
                       $ev=log_synchrophasor_command,
                       $path="synchrophasor_cmd",
                       $policy=log_policy_sychrophasor_command]);
    Log::create_stream(SYNCHROPHASOR::LOG_SYNCHROPHASOR_HEADER,
                       [$columns=Synchrophasor_Header,
                       $ev=log_synchrophasor_header,
                       $path="synchrophasor_hdr",
                       $policy=log_policy_sychrophasor_header]);
    Log::create_stream(SYNCHROPHASOR::LOG_SYNCHROPHASOR_CONFIG,
                       [$columns=Synchrophasor_Config,
                       $ev=log_synchrophasor_config,
                       $path="synchrophasor_cfg",
                       $policy=log_policy_sychrophasor_config]);
    Log::create_stream(SYNCHROPHASOR::LOG_SYNCHROPHASOR_CONFIG_DETAIL,
                       [$columns=Synchrophasor_Config_Detail,
                       $ev=log_synchrophasor_config_detail,
                       $path="synchrophasor_cfg_detail",
                       $policy=log_policy_sychrophasor_config_detail]);
    Log::create_stream(SYNCHROPHASOR::LOG_SYNCHROPHASOR_DATA,
                       [$columns=Synchrophasor_Data,
                       $ev=log_synchrophasor_data,
                       $path="synchrophasor_data",
                       $policy=log_policy_sychrophasor_data]);
    Log::create_stream(SYNCHROPHASOR::LOG_SYNCHROPHASOR_DATA_DETAIL,
                       [$columns=Synchrophasor_Data_Detail,
                       $ev=log_synchrophasor_data_detail,
                       $path="synchrophasor_data_detail",
                       $policy=log_policy_sychrophasor_data_detail]);
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
            $proto=get_conn_transport_proto(c$id),
            $version=set(),
            $data_stream_id=set(),
            $history="",
            $frame_size_min=0,
            $frame_size_max=0,
            $frame_size_tot=0,
            $data_frame_count=0,
            $data_rate=set());

    if ( ! c?$synchrophasor_cmd )
        c$synchrophasor_cmd = Synchrophasor_Command(
            $ts=network_time(),
            $uid=c$uid,
            $id=c$id,
            $proto=get_conn_transport_proto(c$id),
            $frame_type="",
            $frame_size=0,
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
            $proto=get_conn_transport_proto(c$id),
            $version=set(),
            $data_stream_id=set(),
            $history="",
            $frame_size_min=0,
            $frame_size_max=0,
            $frame_size_tot=0,
            $data_frame_count=0,
            $data_rate=set());

    if ( ! c?$synchrophasor_hdr )
        c$synchrophasor_hdr = Synchrophasor_Header(
            $ts=network_time(),
            $uid=c$uid,
            $id=c$id,
            $proto=get_conn_transport_proto(c$id),
            $frame_type="",
            $frame_size=0,
            $data="");
}

# cfg frame
hook set_session_cfg(c: connection) {
    if ( ! c?$synchrophasor )
        c$synchrophasor = Synchrophasor_Info(
            $ts=network_time(),
            $uid=c$uid,
            $id=c$id,
            $proto=get_conn_transport_proto(c$id),
            $version=set(),
            $data_stream_id=set(),
            $history="",
            $frame_size_min=0,
            $frame_size_max=0,
            $frame_size_tot=0,
            $data_frame_count=0,
            $data_rate=set());

    if ( ! c?$synchrophasor_cfg )
        c$synchrophasor_cfg = Synchrophasor_Config(
            $ts=network_time(),
            $uid=c$uid,
            $id=c$id,
            $proto=get_conn_transport_proto(c$id),
            $frame_type="",
            $frame_size=0,
            $cont_idx=0,
            $pmu_count_expected=0,
            $pmu_count_actual=0,
            $data_rate=0,
            $cfg_frame_id="");
}

# data frame
hook set_session_data(c: connection) {
    if ( ! c?$synchrophasor )
        c$synchrophasor = Synchrophasor_Info(
            $ts=network_time(),
            $uid=c$uid,
            $id=c$id,
            $proto=get_conn_transport_proto(c$id),
            $version=set(),
            $data_stream_id=set(),
            $history="",
            $frame_size_min=0,
            $frame_size_max=0,
            $frame_size_tot=0,
            $data_frame_count=0,
            $data_rate=set());

    if (! c?$synchrophasor_data )
        c$synchrophasor_data = Synchrophasor_Data(
            $ts=network_time(),
            $uid=c$uid,
            $id=c$id,
            $proto=get_conn_transport_proto(c$id),
            $frame_type="",
            $frame_size=0,
            $pmu_count_expected=0,
            $pmu_count_actual=0);
}

# emit_synchrophasor*log functions generate log entries for their
# respective record types then delete the record logged

# synchrophasor.log
function emit_synchrophasor_log(c: connection) {
    if ( ! c?$synchrophasor )
        return;

    Log::write(SYNCHROPHASOR::LOG_SYNCHROPHASOR, c$synchrophasor);
    delete c$synchrophasor;
}

# synchrophasor_cmd.log
function emit_synchrophasor_cmd_log(c: connection) {
    if ( ! c?$synchrophasor_cmd )
        return;

    Log::write(SYNCHROPHASOR::LOG_SYNCHROPHASOR_COMMAND, c$synchrophasor_cmd);
    delete c$synchrophasor_cmd;
}

# synchrophasor_hdr.log
function emit_synchrophasor_hdr_log(c: connection) {
    if ( ! c?$synchrophasor_hdr )
        return;

    Log::write(SYNCHROPHASOR::LOG_SYNCHROPHASOR_HEADER, c$synchrophasor_hdr);
    delete c$synchrophasor_hdr;
}

# synchrophasor_cfg.log
function emit_synchrophasor_cfg_log(c: connection) {
    if ( ! c?$synchrophasor_cfg )
        return;

    Log::write(SYNCHROPHASOR::LOG_SYNCHROPHASOR_CONFIG, c$synchrophasor_cfg);
    delete c$synchrophasor_cfg;
}

# synchrophasor_data.log
function emit_synchrophasor_data_log(c: connection) {
    if ( ! c?$synchrophasor_data )
        return;

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

# Synchrophasor message frame events
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
    info_cmd$frame_size = frameSize;

    add info$version[version];
    add info$data_stream_id[dataStreamId];

    if (frameSize > 0) {
        info$frame_size_tot += frameSize;
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
    pmuCfgs : vector of PMUConfigRec) {

    hook set_session_cfg(c);

    local info = c$synchrophasor;
    local info_cfg = c$synchrophasor_cfg;

    info_cfg$frame_type = FRAME_TYPES[frameType];
    info_cfg$frame_size = frameSize;

    add info$version[version];
    add info$data_stream_id[dataStreamId];
    add info$data_rate[dataRate];

    if (frameSize > 0) {
        info$frame_size_tot += frameSize;
        if ((frameSize < info$frame_size_min) || (info$frame_size_min == 0))
            info$frame_size_min = frameSize;
        if (frameSize > info$frame_size_max)
            info$frame_size_max = frameSize;
    }

    info_cfg$cont_idx = contIdx;
    info_cfg$pmu_count_expected = numPMUExpected;
    info_cfg$pmu_count_actual = numPMUActual;
    info_cfg$data_rate = dataRate;

    info_cfg$cfg_frame_id = unique_id("c");

    if (|pmuCfgs| > 0) {
      for (pmuCfgIdx in pmuCfgs) {
        local detail = Synchrophasor_Config_Detail($ts=info_cfg$ts,
                                                   $uid=c$uid,
                                                   $id=c$id,
                                                   $phnam = vector(),
                                                   $annam = vector(),
                                                   $dgnam = vector(),
                                                   $phasor_conv_phunit = vector(),
                                                   $phasor_conv_phvalue = vector(),
                                                   $phasor_conv_upsampled_interpolation = vector(),
                                                   $phasor_conv_upsampled_extrapolation = vector(),
                                                   $phasor_conv_downsampled_reselection = vector(),
                                                   $phasor_conv_downsampled_fir_filter = vector(),
                                                   $phasor_conv_downsampled_no_fir_filter = vector(),
                                                   $phasor_conv_filtered_without_changing_sampling = vector(),
                                                   $phasor_conv_calibration_mag_adj = vector(),
                                                   $phasor_conv_calibration_phas_adj = vector(),
                                                   $phasor_conv_rotation_phase_adj = vector(),
                                                   $phasor_conv_pseudo_phasor_val = vector(),
                                                   $phasor_conv_mod_appl = vector(),
                                                   $phasor_conv_phasor_component = vector(),
                                                   $phasor_conv_phasor_type = vector(),
                                                   $phasor_conv_user_def = vector(),
                                                   $phasor_conv_scale_factor = vector(),
                                                   $phasor_conv_angle_adj = vector(),
                                                   $analog_conv_analog_flags = vector(),
                                                   $analog_conv_user_defined_scaling = vector(),
                                                   $analog_conv_mag_scale = vector(),
                                                   $analog_conv_offset = vector(),
                                                   $digital_conv_normal_status_mask = vector(),
                                                   $digital_conv_valid_inputs_mask = vector());

        detail$proto=get_conn_transport_proto(c$id);
        detail$frame_type = info_cfg$frame_type;
        detail$cfg_frame_id=info_cfg$cfg_frame_id;
        detail$header_time_stamp=timeStamp;

        detail$pmu_idx = pmuCfgs[pmuCfgIdx]$pmuIdx;
        detail$svc_class = pmuCfgs[pmuCfgIdx]$svcClass;
        detail$station_name = strip(pmuCfgs[pmuCfgIdx]$stationName);
        detail$data_source_id = pmuCfgs[pmuCfgIdx]$dataSourceId;
        detail$global_pmuid = pmuCfgs[pmuCfgIdx]$globalPMUID;
        detail$phasor_shape = pmuCfgs[pmuCfgIdx]$phasorShape;
        detail$phasor_format = pmuCfgs[pmuCfgIdx]$phasorFormat;
        detail$analog_format = pmuCfgs[pmuCfgIdx]$analogFormat;
        detail$freq_format = pmuCfgs[pmuCfgIdx]$freqFormat;
        detail$phnmr = pmuCfgs[pmuCfgIdx]$phnmr;
        detail$annmr = pmuCfgs[pmuCfgIdx]$annmr;
        detail$dgnmr = pmuCfgs[pmuCfgIdx]$dgnmr;
        if (|pmuCfgs[pmuCfgIdx]$phnam| > 0) {
            for (nameIdx in pmuCfgs[pmuCfgIdx]$phnam) {
                detail$phnam += strip(pmuCfgs[pmuCfgIdx]$phnam[nameIdx]);
            }
        }
        if (|pmuCfgs[pmuCfgIdx]$annam| > 0) {
            for (nameIdx in pmuCfgs[pmuCfgIdx]$annam) {
                detail$annam += strip(pmuCfgs[pmuCfgIdx]$annam[nameIdx]);
            }
        }
        if (|pmuCfgs[pmuCfgIdx]$dgnam| > 0) {
            for (nameIdx in pmuCfgs[pmuCfgIdx]$dgnam) {
                detail$dgnam += strip(pmuCfgs[pmuCfgIdx]$dgnam[nameIdx]);
            }
        }
        detail$pmu_lat = pmuCfgs[pmuCfgIdx]$pmuLat;
        detail$pmu_lon = pmuCfgs[pmuCfgIdx]$pmuLon;
        detail$pmu_elev = pmuCfgs[pmuCfgIdx]$pmuElev;
        detail$window = pmuCfgs[pmuCfgIdx]$window;
        detail$group_delay = pmuCfgs[pmuCfgIdx]$groupDelay;
        detail$fnom = pmuCfgs[pmuCfgIdx]$fnom;
        detail$cfgcnt = pmuCfgs[pmuCfgIdx]$cfgcnt;

        if (|pmuCfgs[pmuCfgIdx]$phunit| > 0) {
            for (phconvIdx in pmuCfgs[pmuCfgIdx]$phunit) {
                detail$phasor_conv_phunit += pmuCfgs[pmuCfgIdx]$phunit[phconvIdx]$phunit;
                detail$phasor_conv_phvalue += pmuCfgs[pmuCfgIdx]$phunit[phconvIdx]$phvalue;
                detail$phasor_conv_upsampled_interpolation += pmuCfgs[pmuCfgIdx]$phunit[phconvIdx]$upsampledInterpolation;
                detail$phasor_conv_upsampled_extrapolation += pmuCfgs[pmuCfgIdx]$phunit[phconvIdx]$upsampledExtrapolation;
                detail$phasor_conv_downsampled_reselection += pmuCfgs[pmuCfgIdx]$phunit[phconvIdx]$downsampledReselection;
                detail$phasor_conv_downsampled_fir_filter += pmuCfgs[pmuCfgIdx]$phunit[phconvIdx]$downsampledFIRFilter;
                detail$phasor_conv_downsampled_no_fir_filter += pmuCfgs[pmuCfgIdx]$phunit[phconvIdx]$downsampledNoFIRFilter;
                detail$phasor_conv_filtered_without_changing_sampling += pmuCfgs[pmuCfgIdx]$phunit[phconvIdx]$filteredWithoutChangingSampling;
                detail$phasor_conv_calibration_mag_adj += pmuCfgs[pmuCfgIdx]$phunit[phconvIdx]$calibrationMagAdj;
                detail$phasor_conv_calibration_phas_adj += pmuCfgs[pmuCfgIdx]$phunit[phconvIdx]$calibrationPhasAdj;
                detail$phasor_conv_rotation_phase_adj += pmuCfgs[pmuCfgIdx]$phunit[phconvIdx]$rotationPhaseAdj;
                detail$phasor_conv_pseudo_phasor_val += pmuCfgs[pmuCfgIdx]$phunit[phconvIdx]$pseudoPhasorVal;
                detail$phasor_conv_mod_appl += pmuCfgs[pmuCfgIdx]$phunit[phconvIdx]$modAppl;
                detail$phasor_conv_phasor_component += pmuCfgs[pmuCfgIdx]$phunit[phconvIdx]$phasorComponent;
                detail$phasor_conv_phasor_type += pmuCfgs[pmuCfgIdx]$phunit[phconvIdx]$phasorType;
                detail$phasor_conv_user_def += pmuCfgs[pmuCfgIdx]$phunit[phconvIdx]$userDef;
                detail$phasor_conv_scale_factor += pmuCfgs[pmuCfgIdx]$phunit[phconvIdx]$scaleFactor;
                detail$phasor_conv_angle_adj += pmuCfgs[pmuCfgIdx]$phunit[phconvIdx]$angleAdj;
            }
        }

        if (|pmuCfgs[pmuCfgIdx]$anunit| > 0) {
            for (anconvIdx in pmuCfgs[pmuCfgIdx]$anunit) {
                detail$analog_conv_analog_flags += pmuCfgs[pmuCfgIdx]$anunit[anconvIdx]$analogFlags;
                detail$analog_conv_user_defined_scaling += pmuCfgs[pmuCfgIdx]$anunit[anconvIdx]$userDefinedScaling;
                detail$analog_conv_mag_scale += pmuCfgs[pmuCfgIdx]$anunit[anconvIdx]$magScale;
                detail$analog_conv_offset += pmuCfgs[pmuCfgIdx]$anunit[anconvIdx]$offset;
            }
        }

        if (|pmuCfgs[pmuCfgIdx]$digunit| > 0) {
            for (digconvIdx in pmuCfgs[pmuCfgIdx]$digunit) {
                detail$digital_conv_normal_status_mask += pmuCfgs[pmuCfgIdx]$digunit[digconvIdx]$normalStatusMask;
                detail$digital_conv_valid_inputs_mask += pmuCfgs[pmuCfgIdx]$digunit[digconvIdx]$validInputsMask;
            }
        }

        Log::write(SYNCHROPHASOR::LOG_SYNCHROPHASOR_CONFIG_DETAIL, detail);
      }
    }

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
    numPMUActual: count,
    pmuData: vector of PMUDataRec) {

    hook set_session_data(c);

    local info = c$synchrophasor;
    local info_data : Synchrophasor_Data;

    info_data = c$synchrophasor_data;

    info_data$frame_type = FRAME_TYPES[frameType];
    info_data$frame_size = frameSize;

    add info$version[version];
    add info$data_stream_id[dataStreamId];

    if (frameSize > 0) {
        info$frame_size_tot += frameSize;
        if ((frameSize < info$frame_size_min) || (info$frame_size_min == 0))
            info$frame_size_min = frameSize;
        if (frameSize > info$frame_size_max)
            info$frame_size_max = frameSize;
    }

    info$data_frame_count += 1;


    # if the data frame didn't get "initialized" that means that the analyzer
    # never saw the config frame used to parse it. in other words, it's garbage.
    # we can note the stuff from the frameheader (like we just did) but that's it.

    if (initialized) {
        info_data$pmu_count_expected = numPMUExpected;
        info_data$pmu_count_actual = numPMUActual;
        info_data$data_frame_id = unique_id("d");

        if (|pmuData| > 0) {
            for (pmuDataIdx in pmuData) {
                local detail = Synchrophasor_Data_Detail($ts=info_data$ts,
                                                         $uid=c$uid,
                                                         $id=c$id,
                                                         $est_rectangular_real=vector(),
                                                         $est_rectangular_imaginary=vector(),
                                                         $est_polar_magnitude=vector(),
                                                         $est_polar_angle=vector(),
                                                         $analog_data=vector(),
                                                         $digital=vector());

                detail$proto=get_conn_transport_proto(c$id);
                detail$data_frame_id=info_data$data_frame_id;
                detail$frame_type = info_data$frame_type;
                detail$header_time_stamp=timeStamp;

                detail$pmu_idx = pmuData[pmuDataIdx]$pmuIdx;
                detail$trigger_reason = pmuData[pmuDataIdx]$triggerReason;
                detail$unlocked_time = pmuData[pmuDataIdx]$unlockedTime;
                detail$pmu_time_quality = pmuData[pmuDataIdx]$pmuTimeQuality;
                detail$data_modified = pmuData[pmuDataIdx]$dataModified;
                detail$config_change = pmuData[pmuDataIdx]$configChange;
                detail$pmu_trigger_pickup = pmuData[pmuDataIdx]$pmuTriggerPickup;
                detail$data_sorting_type = pmuData[pmuDataIdx]$dataSortingType;
                detail$pmu_sync_error = pmuData[pmuDataIdx]$pmuSyncError;
                detail$data_error_indicator = pmuData[pmuDataIdx]$dataErrorIndicator;
                detail$digital = pmuData[pmuDataIdx]$digital;

                if ((pmuData[pmuDataIdx]$freq?$freqDevMhzFloat) && (pmuData[pmuDataIdx]$freq$freqDevMhzFloat != 0.0)) {
                    detail$freq_dev_mhz = pmuData[pmuDataIdx]$freq$freqDevMhzFloat;
                } else if ((pmuData[pmuDataIdx]$freq?$freqDevMhzInt) && (pmuData[pmuDataIdx]$freq$freqDevMhzInt != 0)) {
                    detail$freq_dev_mhz = pmuData[pmuDataIdx]$freq$freqDevMhzInt;
                } else {
                    detail$freq_dev_mhz = 0.0;
                }

                if ((pmuData[pmuDataIdx]$dfreq?$rocofFloat) && (pmuData[pmuDataIdx]$dfreq$rocofFloat != 0.0)) {
                    detail$rocof = pmuData[pmuDataIdx]$dfreq$rocofFloat;
                } else if ((pmuData[pmuDataIdx]$dfreq?$rocofInt) && (pmuData[pmuDataIdx]$dfreq$rocofInt != 0)) {
                    detail$rocof = pmuData[pmuDataIdx]$dfreq$rocofInt;
                } else {
                    detail$rocof = 0.0;
                }

                if (|pmuData[pmuDataIdx]$phasors| > 0) {
                    for (phasorIdx in pmuData[pmuDataIdx]$phasors) {

                        if ((pmuData[pmuDataIdx]$phasors[phasorIdx]?$rectangularRealValFloat) && (pmuData[pmuDataIdx]$phasors[phasorIdx]$rectangularRealValFloat != 0.0)) {
                            detail$est_rectangular_real += pmuData[pmuDataIdx]$phasors[phasorIdx]$rectangularRealValFloat;
                        } else if ((pmuData[pmuDataIdx]$phasors[phasorIdx]?$rectangularRealValInt) && (pmuData[pmuDataIdx]$phasors[phasorIdx]$rectangularRealValInt != 0)) {
                            detail$est_rectangular_real += pmuData[pmuDataIdx]$phasors[phasorIdx]$rectangularRealValInt;
                        } else {
                            detail$est_rectangular_real += 0.0;
                        }

                        if ((pmuData[pmuDataIdx]$phasors[phasorIdx]?$rectangularImaginaryValFloat) && (pmuData[pmuDataIdx]$phasors[phasorIdx]$rectangularImaginaryValFloat != 0.0)) {
                            detail$est_rectangular_imaginary += pmuData[pmuDataIdx]$phasors[phasorIdx]$rectangularImaginaryValFloat;
                        } else if ((pmuData[pmuDataIdx]$phasors[phasorIdx]?$rectangularImaginaryValInt) && (pmuData[pmuDataIdx]$phasors[phasorIdx]$rectangularImaginaryValInt != 0)) {
                            detail$est_rectangular_imaginary += pmuData[pmuDataIdx]$phasors[phasorIdx]$rectangularImaginaryValInt;
                        } else {
                            detail$est_rectangular_imaginary += 0.0;
                        }

                        if ((pmuData[pmuDataIdx]$phasors[phasorIdx]?$polarMagnitudeValFloat) && (pmuData[pmuDataIdx]$phasors[phasorIdx]$polarMagnitudeValFloat != 0.0)) {
                            detail$est_polar_magnitude += pmuData[pmuDataIdx]$phasors[phasorIdx]$polarMagnitudeValFloat;
                        } else if ((pmuData[pmuDataIdx]$phasors[phasorIdx]?$polarMagnitudeValInt) && (pmuData[pmuDataIdx]$phasors[phasorIdx]$polarMagnitudeValInt != 0)) {
                            detail$est_polar_magnitude += pmuData[pmuDataIdx]$phasors[phasorIdx]$polarMagnitudeValInt;
                        } else {
                            detail$est_polar_magnitude += 0.0;
                        }

                        if ((pmuData[pmuDataIdx]$phasors[phasorIdx]?$polarAngleValFloat) && (pmuData[pmuDataIdx]$phasors[phasorIdx]$polarAngleValFloat != 0.0)) {
                            detail$est_polar_angle += pmuData[pmuDataIdx]$phasors[phasorIdx]$polarAngleValFloat;
                        } else if ((pmuData[pmuDataIdx]$phasors[phasorIdx]?$polarAngleValInt) && (pmuData[pmuDataIdx]$phasors[phasorIdx]$polarAngleValInt != 0)) {
                            detail$est_polar_angle += pmuData[pmuDataIdx]$phasors[phasorIdx]$polarAngleValInt;
                        } else {
                            detail$est_polar_angle += 0.0;
                        }

                    }
                }

                if (|pmuData[pmuDataIdx]$analog| > 0) {
                    for (analogIdx in pmuData[pmuDataIdx]$analog) {

                        if ((pmuData[pmuDataIdx]$analog[analogIdx]?$analogDataFloat) && (pmuData[pmuDataIdx]$analog[analogIdx]$analogDataFloat != 0.0)) {
                            detail$analog_data += pmuData[pmuDataIdx]$analog[analogIdx]$analogDataFloat;
                        } else if ((pmuData[pmuDataIdx]$analog[analogIdx]?$analogDataInt) && (pmuData[pmuDataIdx]$analog[analogIdx]$analogDataInt != 0)) {
                            detail$analog_data += pmuData[pmuDataIdx]$analog[analogIdx]$analogDataInt;
                        } else {
                            detail$analog_data += 0.0;
                        }

                    }
                }

                Log::write(SYNCHROPHASOR::LOG_SYNCHROPHASOR_DATA_DETAIL, detail);
            }
        }
    }
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
    info_hdr$frame_size = frameSize;

    add info$version[version];
    add info$data_stream_id[dataStreamId];

    if (frameSize > 0) {
        info$frame_size_tot += frameSize;
        if ((frameSize < info$frame_size_min) || (info$frame_size_min == 0))
            info$frame_size_min = frameSize;
        if (frameSize > info$frame_size_max)
            info$frame_size_max = frameSize;
    }

    info_hdr$data = data;

    emit_synchrophasor_hdr_log(c);
}

event connection_state_remove(c: connection) {
    emit_synchrophasor_log_all(c);
}
