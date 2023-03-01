spicy_add_analyzer(
    NAME SYNCHROPHASOR_TCP
    PACKAGE_NAME icsnpp-synchrophasor
    SOURCES synchrophasor.spicy synchrophasor.evt zeek_synchrophasor.spicy
    SCRIPTS __load__.zeek main.zeek dpd.sig
)

spicy_add_analyzer(
    NAME SYNCHROPHASOR_UDP
    PACKAGE_NAME icsnpp-synchrophasor
    SOURCES synchrophasor.spicy synchrophasor.evt zeek_synchrophasor.spicy
    SCRIPTS __load__.zeek main.zeek dpd.sig
)