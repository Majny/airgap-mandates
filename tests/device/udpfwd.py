"""UDP relay run inside the trezor-user-env container (tests/device/tenv.sh).

The emulator binds 127.0.0.1 inside the container, which Docker cannot publish. For each port P given on the
command line this relays 0.0.0.0:(P+10000) <-> 127.0.0.1:P; the host publishes those on 127.0.0.1 only.
"""
import selectors
import socket
import sys


def main(ports: list[int]) -> None:
    sel = selectors.DefaultSelector()
    for port in ports:
        pub = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        pub.bind(("0.0.0.0", port + 10000))
        up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        up.connect(("127.0.0.1", port))
        peer: dict = {"addr": None}
        sel.register(pub, selectors.EVENT_READ, ("pub", pub, up, peer))
        sel.register(up, selectors.EVENT_READ, ("up", pub, up, peer))
    while True:
        for key, _ in sel.select():
            kind, pub, up, peer = key.data
            try:
                if kind == "pub":
                    data, peer["addr"] = pub.recvfrom(65536)
                    up.send(data)
                elif peer["addr"]:
                    pub.sendto(up.recv(65536), peer["addr"])
                else:
                    up.recv(65536)
            except OSError:
                pass


if __name__ == "__main__":
    main([int(p) for p in sys.argv[1:]])
