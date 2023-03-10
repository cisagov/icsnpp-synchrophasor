# ICSNPP-Synchrophasor

Industrial Control Systems Network Protocol Parsers (ICSNPP) - Synchrophasor Data Transfer for Power Systems (C37.118) over TCP and UDP.

## Overview

ICSNPP-Synchrophasor is a Zeek plugin (written in [Spicy](https://docs.zeek.org/projects/spicy/en/latest/)) for parsing and logging fields used by the Synchrophasor protocol as presented in the IEEE standard C37.118, defining a transmission format for reporting synchronized phasor measurements in power systems.

This parser produces the following log files, defined in [analyzer/main.zeek](analyzer/main.zeek):

* `synchrophasor.log`
* `synchrophasor_cmd.log`
* `synchrophasor_hdr.log`
* `synchrophasor_cfg.log`
* `synchrophasor_cfg_detail.log`
* `synchrophasor_data.log`
* `synchrophasor_data_detail.log`

For additional information on this log file, see the *Logging Capabilities* section below.

## Installation

### Package Manager

This script is available as a package for [Zeek Package Manager](https://docs.zeek.org/projects/package-manager/en/stable/index.html). It requires [Spicy](https://docs.zeek.org/projects/spicy/en/latest/) and the [Zeek Spicy plugin](https://docs.zeek.org/projects/spicy/en/latest/zeek.html).

```bash
$ zkg refresh
$ zkg install icsnpp-synchrophasor
```

If this package is installed from `zkg` it will be added to the available plugins. This can be tested by running `zeek -NN`. If installed correctly you will see `ANALYZER_SPICY_SYNCHROPHASOR_TCP` and `ANALYZER_SPICY_SYNCHROPHASOR_UDP` under the list of `Zeek::Spicy` analyzers.

If you have `zkg` configured to load packages (see `@load packages` in the [`zkg` Quickstart Guide](https://docs.zeek.org/projects/package-manager/en/stable/quickstart.html)), this plugin and scripts will automatically be loaded and ready to go.

## Logging Capabilities

### Synchrophasor Log (synchrophasor.log)

#### Overview

This log summarizes, by connection, Synchrophasor frames transmitted over 4712/tcp or 4713/udp to `synchrophasor.log`.

#### Fields Captured

| Field             | Type           | Description                                               |
| ----------------- |----------------|-----------------------------------------------------------| 
| ts                | time           | Timestamp (network time)                                  |
| uid               | string         | Unique ID for this connection                             |
| id                | conn_id        | Default Zeek connection info (IP addresses, ports)        |
| proto             | string         | Transport protocol                                        |
| version           | set<count>     | Protocol version number(s) observed                       |
| data_stream_id    | set<count>     | Data stream ID(s) observed                                |
| history           | string         | Command history (see below)                               |
| frame_size_min    | count          | Smallest frame size observed, in bytes                    |
| frame_size_max    | count          | Largest frame size observed, in bytes                     |
| frame_size_tot    | count          | Sum of frame sizes observed, in bytes                     |
| data_frame_count  | count          | Count of data frames observed                             |
| data_rate         | set<count>     | Data rate values(s) observed                              |

* The **`history`** field is comprised of letters representing commands specified in observed command frames in the order they were transmitted (e.g., `2Dd`, etc.):
    - `d` - turn off transmission of data frames
    - `D` - turn on transmission of data frames
    - `h` - send HDR frame
    - `1` - send CFG-1 frame
    - `2` - send CFG-2 frame
    - `3` - send CFG-3 frame
    - `e` - extended frame

### Synchrophasor Command Frame Log (synchrophasor_cmd.log)

#### Overview

This log summarizes synchrophasor Command frames.

#### Fields Captured

| Field             | Type           | Description                                               |
| ----------------- |----------------|-----------------------------------------------------------|
| ts                | time           | Timestamp (network time)                                  |
| uid               | string         | Unique ID for this connection                             |
| id                | conn_id        | Default Zeek connection info (IP addresses, ports)        |
| proto             | string         | Transport protocol                                        |
| frame_type        | string         | Frame type from synchrophasor frame synchronization word  |
| frame_size        | count          | Frame size (in bytes)                                     |
| header_time_stamp | time           | Timestamp from frame header                               |
| command           | string         | String represetnation of the command                      |
| extframe          | vector<count>  | Extended frame data (user-defined)                        |

### Synchrophasor Header Frame Log (synchrophasor_hdr.log)

#### Overview

This log summarizes synchrophasor Header frames.

#### Fields Captured

| Field             | Type           | Description                                               |
| ----------------- |----------------|-----------------------------------------------------------|
| ts                | time           | Timestamp (network time)                                  |
| uid               | string         | Unique ID for this connection                             |
| id                | conn_id        | Default Zeek connection info (IP addresses, ports)        |
| proto             | string         | Transport protocol                                        |
| frame_type        | string         | Frame type from synchrophasor frame synchronization word  |
| frame_size        | count          | Frame size (in bytes)                                     |
| header_time_stamp | time           | Timestamp from frame header                               |
| command           | string         | String represetnation of the command                      |
| data              | string         | Human-readable header data (user-defined)                 |

### Synchrophasor Configuration Frame Log (synchrophasor_cfg.log)

#### Overview

This log summarizes synchrophasor Configuration (CFG-1, CFG-2, and CFG-3) frames.

#### Fields Captured

| Field              | Type           | Description                                               |
| -------------------|----------------|-----------------------------------------------------------|
| ts                 | time           | Timestamp (network time)                                  |
| uid                | string         | Unique ID for this connection                             |
| id                 | conn_id        | Default Zeek connection info (IP addresses, ports)        |
| proto              | string         | Transport protocol                                        |
| frame_type         | string         | Frame type from synchrophasor frame synchronization word  |
| frame_size         | count          | Frame size (in bytes)                                     |
| header_time_stamp  | time           | Timestamp from frame header                               |
| cont_idx           | count          | Continuation index for fragmented frames                  |
| pmu_count_expected | count          | The number of PMUs expected in the configuration frame    |
| pmu_count_actual   | count          | The number of PMUs included in the configuration frame    |
| cfg_frame_id       | string         | Unique string to correlate with synchrophasor_cfg_detail  |

### Synchrophasor Configuration PMU Details (synchrophasor_cfg_detail.log)

#### Overview

This log lists the per-PMU details from synchrophasor Configuration (CFG-1, CFG-2, and CFG-3) frames. As this can be very verbose, this log file is **disabled** by default. You can enable it by appending `SYNCHROPHASOR::log_cfg_detail=T` to your `zeek` command on the command line or by adding `redef SYNCHROPHASOR::log_cfg_detail = T;` to your `local.zeek` file.

#### Fields Captured

Most of the fields listed here are optional. Many may be unused during communication depending on device configuration. See IEEE Std C37.118.2-2011 for more details.


| Field                                          | Type           | Description                                                                  |
| -----------------------------------------------|----------------|------------------------------------------------------------------------------|
| ts                                             | time           | Timestamp (network time)                                                     |
| uid                                            | string         | Unique ID for this connection                                                |
| id                                             | conn_id        | Default Zeek connection info (IP addresses, ports)                           |
| proto                                          | string         | Transport protocol                                                           |
| header_time_stamp                              | time           | Timestamp from frame header                                                  |
| cfg_frame_id                                   | string         | Unique string to correlate with synchrophasor_cfg                            |
| pmu_idx                                        | count          | 0-based index of PMU configuration within the CFG frame                      |
| svc_class                                      | string         | Service class as defined in IEEE Std C37.118.1                               |
| station_name                                   | string         | Station name                                                                 |
| data_source_id                                 | count          | Data source id                                                               |
| global_pmuid                                   | string         | Global PMU ID                                                                |
| phasor_shape                                   | bool           | F = phasor real and imaginary (rectangular), T = magnitude and angle (polar) |
| phasor_format                                  | bool           | F = phasors 16-bit integer, T = floating point                               |
| analog_format                                  | bool           | F = analogs 16-bit integer, T = floating point                               |
| freq_format                                    | bool           | 0 = FREQ/DFREQ 16-bit integer, 1 = floating point                            |
| phnmr                                          | count          | Number of phasors                                                            |
| annmr                                          | count          | Number of analog values                                                      |
| dgnmr                                          | count          | Number of digital status words                                               |
| phnam                                          | vector<string> | Phasor channel names                                                         |
| annam                                          | vector<string> | Analog channel names                                                         |
| dgnam                                          | vector<string> | Digital channel names                                                        |
| phasor_conv_phunit                             | vector<count>  | Phasor conversion factor format unit                                         |
| phasor_conv_phvalue                            | vector<count>  | Phasor conversion factor format value                                        |
| phasor_conv_upsampled_interpolation            | vector<bool>   | Up sampled with interpolation                                                |
| phasor_conv_upsampled_extrapolation            | vector<bool>   | Upsampled with extrapolation                                                 |
| phasor_conv_downsampled_reselection            | vector<bool>   | Down sampled by reselection (selecting every Nth sample)                     |
| phasor_conv_downsampled_fir_filter             | vector<bool>   | Down sampled with FIR filter                                                 |
| phasor_conv_downsampled_no_fir_filter          | vector<bool>   | Down sampled with non-FIR filter                                             |
| phasor_conv_filtered_without_changing_sampling | vector<bool>   | Filtered without changing sampling                                           |
| phasor_conv_calibration_mag_adj                | vector<bool>   | Phasor magnitude adjusted for calibration                                    |
| phasor_conv_calibration_phas_adj               | vector<bool>   | Phasor phase adjusted for calibration                                        |
| phasor_conv_rotation_phase_adj                 | vector<bool>   | Phasor phase adjusted for rotation ( ±30o, ±120o, etc.)                      |
| phasor_conv_pseudo_phasor_val                  | vector<bool>   | Pseudo-phasor value (combined from other phasors)                            |
| phasor_conv_mod_appl                           | vector<bool>   | Modification applied, type not here defined                                  |
| phasor_conv_phasor_component                   | vector<count>  | Phasor component (see std. spec)                                             |
| phasor_conv_phasor_type                        | vector<bool>   | F = voltage, T = current                                                     |
| phasor_conv_user_def                           | vector<count>  | User-defined                                                                 |
| phasor_conv_scale_factor                       | vector<double> | Scale factor Y                                                               |
| phasor_conv_angle_adj                          | vector<double> | Phasor angle adjustment θ                                                    |
| analog_conv_analog_flags                       | vector<count>  | Analog flags                                                                 |
| analog_conv_user_defined_scaling               | vector<int>    | User-defined scaling                                                         |
| analog_conv_mag_scale                          | vector<double> | Magnitude scale factor                                                       |
| analog_conv_offset                             | vector<double> | Angle offset                                                                 |
| digital_conv_normal_status_mask                | vector<count>  | Digital input normal status mask                                             |
| digital_conv_valid_inputs_mask                 | vector<count>  | Digital input valid inputs status mask                                       |
| pmu_lat                                        | double         | PMU latitude in degrees                                                      |
| pmu_lon                                        | double         | PMU longitude in degrees                                                     |
| pmu_elev                                       | double         | PMU elevation in meters                                                      |
| window                                         | int            | Phasor measurement window length                                             |
| group_delay                                    | int            | Phasor measurement group delay                                               |
| fnom                                           | count          | Nominal line frequency code                                                  |
| cfgcnt                                         | count          | Configuration change count                                                   |

### Synchrophasor Data Frame Log (synchrophasor_data.log)

#### Overview

This log summarizes synchrophasor Data frames. As this can be very verbose, this log file is **disabled** by default. You can enable it by appending `SYNCHROPHASOR::log_data_frame=T` to your `zeek` command on the command line or by adding `redef SYNCHROPHASOR::log_data_frame = T;` to your `local.zeek` file.

#### Fields Captured

| Field              | Type           | Description                                               |
| -------------------|----------------|-----------------------------------------------------------|
| ts                 | time           | Timestamp (network time)                                  |
| uid                | string         | Unique ID for this connection                             |
| id                 | conn_id        | Default Zeek connection info (IP addresses, ports)        |
| proto              | string         | Transport protocol                                        |
| frame_type         | string         | Frame type from synchrophasor frame synchronization word  |
| frame_size         | count          | Frame size (in bytes)                                     |
| header_time_stamp  | time           | Timestamp from frame header                               |
| pmu_count_expected | count          | The number of PMUs expected in the data frame             |
| pmu_count_actual   | count          | The number of PMUs included in the data frame             |
| data_frame_id      | string         | Unique string to correlate with synchrophasor_data_detail |

### Synchrophasor Data PMU Details Log (synchrophasor_data_detail.log)

#### Overview

This log lists the per-PMU details from synchrophasor Data frames. As this can be very verbose, this log file is **disabled** by default. You can enable it by appending `SYNCHROPHASOR::log_data_detail=T` to your `zeek` command on the command line or by adding `redef SYNCHROPHASOR::log_data_detail = T;` to your `local.zeek` file. Note that `log_data_frame` described above must also be set to `T` for `log_data_detail` to take effect.

Most of the fields listed here are optional. Many may be unused during communication depending on device configuration. See IEEE Std C37.118.2-2011 for more details.

#### Fields Captured

| Field                           | Type           | Description                                                  |
| --------------------------------|----------------|--------------------------------------------------------------|
| ts                              | time           | Timestamp (network time)                                     |
| uid                             | string         | Unique ID for this connection                                |
| id                              | conn_id        | Default Zeek connection info (IP addresses, ports)           |
| proto                           | string         | Transport protocol                                           |
| header_time_stamp               | time           | Timestamp from frame header                                  |
| data_frame_id                   | string         | Unique string to correlate with synchrophasor_data_detail    |
| pmu_idx                         | count          | 0-based index of PMU data within the data frame              |
| trigger_reason                  | count          | Trigger reason                                               |
| unlocked_time                   | count          | Unlocked time                                                |
| pmu_time_quality                | count          | PMU time quality                                             |
| data_modified                   | bool           | T = data made by post-processing, F = otherwise              |
| config_change                   | bool           | T = confiuration change advised, F = change effected         |
| pmu_trigger_pickup              | bool           | T = PMU trigger detected, F = no trigger                     |
| data_sorting_type               | bool           | F = sort by time stamp, T = sort by arrival                  |
| pmu_sync_error                  | bool           | T = time sync error, F = PMU in sync with time source        |
| data_error_indicator            | count          | Data error indicator                                         |
| est_rectangular_real_int        | vector<int>    | Phasor estimate: rectangular real value, integer             |
| est_rectangular_real_float      | vector<double> | Phasor estimate: rectangular real value, floating-point      |
| est_rectangular_imaginary_int   | vector<int>    | Phasor estimate: rectangular imaginary value, integer        |
| est_rectangular_imaginary_float | vector<double> | Phasor estimate: rectangular imaginary value, floating-point |
| est_polar_magnitude_int         | vector<count>  | Phasor estimate: polar magnitude value, integer              |
| est_polar_magnitude_float       | vector<double> | Phasor estimate: polar magnitude value, floating-point       |
| est_polar_angle_int             | vector<int>    | Phasor estimate: polar angle radians, integer                |
| est_polar_angle_float           | vector<double> | Phasor estimate: polar angle radians, floating-point         |
| freq_dev_mhz_int                | int            | Frequency deviation from nominal, in mHz, integer            |
| freq_dev_mhz_float              | double         | Frequency deviation from nominal, in mHz, floating-point     |
| rocof_int                       | int            | ROCOF, in hertz per second times 100, integer                |
| rocof_float                     | double         | ROCOF, in hertz per second times 100, floating-point         |
| analog_data_int                 | vector<int>    | User-defined analog data value, integer                      |
| analog_data_float               | vector<double> | User-defined analog data value, floating-point               |
| digital                         | vector<count>  | User-defined digital status word                             |

## ICSNPP Packages

All ICSNPP Packages:

* [ICSNPP](https://github.com/cisagov/icsnpp)

Full ICS Protocol Parsers:

* [BACnet](https://github.com/cisagov/icsnpp-bacnet)
    * Full Zeek protocol parser for BACnet (Building Control and Automation)
* [BSAP](https://github.com/cisagov/ICSNPP-BSAP)
    * Full Zeek protocol parser for BSAP (Bristol Standard Asynchronous Protocol) over IP
    * Full Zeek protocol parser for BSAP Serial comm converted using serial tap device
* [Ethercat](https://github.com/cisagov/icsnpp-ethercat)
    * Full Zeek protocol parser for Ethercat
* [Ethernet/IP and CIP](https://github.com/cisagov/icsnpp-enip)
    * Full Zeek protocol parser for Ethernet/IP and CIP
* [Genisys](https://github.com/cisagov/icsnpp-genisys)
    * Full Zeek protocol parser for Genisys
* [OPCUA-Binary](https://github.com/cisagov/icsnpp-opcua-binary)
    * Full Zeek protocol parser for OPC UA (OPC Unified Architecture) - Binary
* [S7Comm](https://github.com/cisagov/icsnpp-s7comm)
    * Full Zeek protocol parser for S7comm, S7comm-plus, and COTP
* [Synchrophasor](https://github.com/cisagov/icsnpp-synchrophasor)
    * Full Zeek protocol parser for Synchrophasor

Updates to Zeek ICS Protocol Parsers:

* [DNP3](https://github.com/cisagov/icsnpp-dnp3)
    * DNP3 Zeek script extending logging capabilities of Zeek's default DNP3 protocol parser
* [Modbus](https://github.com/cisagov/icsnpp-modbus)
    * Modbus Zeek script extending logging capabilities of Zeek's default Modbus protocol parser

### Other Software
Idaho National Laboratory is a cutting edge research facility which is a constantly producing high quality research and software. Feel free to take a look at our other software and scientific offerings at:

[Primary Technology Offerings Page](https://www.inl.gov/inl-initiatives/technology-deployment)

[Supported Open Source Software](https://github.com/idaholab)

[Raw Experiment Open Source Software](https://github.com/IdahoLabResearch)

[Unsupported Open Source Software](https://github.com/IdahoLabCuttingBoard)

### License

Copyright 2023 Battelle Energy Alliance, LLC. Released under the terms of the 3-Part BSD license (see [`LICENSE`](./LICENSE)).
