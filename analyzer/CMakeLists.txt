spicy_add_analyzer(
    NAME SYNCHROPHASOR
    PACKAGE_NAME icsnpp-synchrophasor
    SOURCES synchrophasor.spicy synchrophasor.evt zeek_synchrophasor.spicy
    SCRIPTS __load__.zeek main.zeek
)
