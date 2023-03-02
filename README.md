# ICSNPP-Synchrophasor

Industrial Control Systems Network Protocol Parsers (ICSNPP) - Synchrophasor Data Transfer for Power Systems (C37.118) over TCP and UDP.

## Overview

ICSNPP-Synchrophasor is a Zeek plugin (written in [Spicy](https://docs.zeek.org/projects/spicy/en/latest/)) for parsing and logging fields used by the Synchrophasor protocol as presented in the IEEE standard C37.118, defining a transmission format for reporting synchronized phasor measurements in power systems.

This parser produces one log file, `synchrophasor.log`, defined in [analyzer/main.zeek](analyzer/main.zeek).

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

This log captures and summarizes, by connection, Synchrophasor frames transmitted over 4712/tcp or 4713/udp to `synchrophasor.log`.

#### Fields Captured

| Field             | Type           | Description                                               |
| ----------------- |----------------|-----------------------------------------------------------| 
| ts                | time           | Timestamp                                                 |
| uid               | string         | Unique ID for this connection                             |
| id                | conn_id        | Default Zeek connection info (IP addresses, ports)        |
| proto             | string         | Transport protocol                                        |
| version           | set<count>     | Protocol version number(s) observed                       |
| data_stream_id    | set<count>     | Data stream ID(s) observed                                |
| history           | string         | Command history (see below)                               |
| frame_size_min    | count          | Smallest frame size observed, in bytes                    |
| frame_size_max    | count          | Largest frame size observed, in bytes                     |
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
