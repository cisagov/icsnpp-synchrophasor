signature dpd_synchrophasor {
    payload /^\xaa/
}

signature dpd_synchrophasor_tcp {
    ip-proto == tcp
    requires-signature dpd_synchrophasor
    enable "spicy_SYNCHROPHASOR_TCP"
}

signature dpd_synchrophasor_udp {
    ip-proto == udp
    requires-signature dpd_synchrophasor
    enable "spicy_SYNCHROPHASOR_UDP"
}
