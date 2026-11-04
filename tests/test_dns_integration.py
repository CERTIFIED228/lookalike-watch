"""Runs DnsLookup against a tiny real DNS server on localhost.

The unit tests use a fake resolver; this makes sure the real dnspython
objects (and the real wire format) parse the way we expect.
"""
import socket
import threading

import dns.message
import dns.rcode
import dns.resolver
import dns.rrset
import pytest

from lookalike_watch.resolver import DnsLookup

ZONE = {
    ("paypa1.com.", "NS"): ["ns1.evil-host.net."],
    ("paypa1.com.", "A"): ["203.0.113.7"],
    ("paypa1.com.", "MX"): ["10 mail.paypa1.com."],
    ("parked.com.", "NS"): ["ns1.sedoparking.com."],
    ("nomail.com.", "NS"): ["ns1.x.net."],
    ("nomail.com.", "MX"): ["0 ."],
}
EXISTING = {name for name, _ in ZONE}


def _serve(sock: socket.socket, stop: threading.Event) -> None:
    sock.settimeout(0.2)
    while not stop.is_set():
        try:
            data, addr = sock.recvfrom(4096)
        except TimeoutError:
            continue
        query = dns.message.from_wire(data)
        q = query.question[0]
        name, rdtype = q.name.to_text(), dns.rdatatype.to_text(q.rdtype)
        response = dns.message.make_response(query)
        if name not in EXISTING:
            response.set_rcode(dns.rcode.NXDOMAIN)
        elif (name, rdtype) in ZONE:
            response.answer.append(
                dns.rrset.from_text_list(name, 300, "IN", rdtype, ZONE[(name, rdtype)])
            )
        sock.sendto(response.to_wire(), addr)


@pytest.fixture(scope="module")
def local_dns():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    stop = threading.Event()
    thread = threading.Thread(target=_serve, args=(sock, stop), daemon=True)
    thread.start()

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ["127.0.0.1"]
    resolver.port = sock.getsockname()[1]
    yield DnsLookup(timeout=2, resolver=resolver)

    stop.set()
    thread.join()
    sock.close()


def test_real_lookup_of_registered_lookalike(local_dns):
    record = local_dns("paypa1.com")
    assert record.ns == ["ns1.evil-host.net"]
    assert record.a == ["203.0.113.7"]
    assert record.mx == ["mail.paypa1.com"]


def test_real_lookup_of_missing_domain(local_dns):
    assert local_dns("paypa2.com") is None


def test_real_lookup_of_parked_domain(local_dns):
    record = local_dns("parked.com")
    assert record.ns == ["ns1.sedoparking.com"]
    assert not record.live


def test_real_null_mx(local_dns):
    assert local_dns("nomail.com").mx == []
