#!/usr/bin/env python3

import argparse
import sys
from typing import List

from implementations import IMPLEMENTATIONS, Role
from interop import InteropRunner

implementations = {
    name: {"image": value["image"], "url": value["url"]}
    for name, value in IMPLEMENTATIONS.items()
}
client_implementations = [
    name
    for name, value in IMPLEMENTATIONS.items()
    if value["role"] == Role.BOTH or value["role"] == Role.CLIENT
]
server_implementations = [
    name
    for name, value in IMPLEMENTATIONS.items()
    if value["role"] == Role.BOTH or value["role"] == Role.SERVER
]


def main():
    def get_args():
        parser = argparse.ArgumentParser()
        parser.add_argument(
            "-d",
            "--debug",
            action="store_const",
            const=True,
            default=False,
            help="turn on debug logs",
        )
        parser.add_argument(
            "-s", "--server", help="server implementations (comma-separated)"
        )
        parser.add_argument(
            "-c", "--client", help="client implementations (comma-separated)"
        )
        parser.add_argument(
            "-l",
            "--log-dir",
            help="log directory",
            default="",
        )
        parser.add_argument(
            "-r", "--rtt", help="RTT for ns3 simulated network", default="20",
        )

        parser.add_argument(
            "-i", "--interface", help="docker network interface used for injection and pcap collection", default="",
        )
        parser.add_argument(
            "-m",
            "--markdown",
            help="output the matrix in Markdown format",
            action="store_const",
            const=True,
            default=False,
        )
        parser.add_argument(
            "-i",
            "--must-include",
            help="implementation that must be included",
        )
        return parser.parse_args()

    def get_impls(arg, availableImpls, role) -> List[str]:
        if not arg:
            return availableImpls
        impls = []
        for s in arg.split(","):
            if s not in availableImpls:
                sys.exit(role + " implementation " + s + " not found.")
            impls.append(s)
        return impls

    return InteropRunner(
        implementations=implementations,
        servers=get_impls(get_args().server, server_implementations, "Server"),
        clients=get_impls(get_args().client, client_implementations, "Client"),
        debug=get_args().debug,
        log_dir=get_args().log_dir,
        rtt=int(get_args().rtt),
        iface=get_args().interface,
    ).run()


if __name__ == "__main__":
    sys.exit(main())
