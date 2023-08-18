import abc
import logging
import os
import random
import string
import subprocess
import sys
import tempfile
from enum import Enum, IntEnum
from typing import List

from Crypto.Cipher import AES

KB = 1 << 10
QUIC_VERSION = hex(0x1)


class Perspective(Enum):
    SERVER = "server"
    CLIENT = "client"


def random_string(length: int):
    """Generate a random string of fixed length"""
    letters = string.ascii_lowercase
    return "".join(random.choice(letters) for i in range(length))


def generate_cert_chain(directory: str, length: int = 1):
    cmd = "./certs.sh " + directory + " " + str(length)
    r = subprocess.run(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )
    logging.debug("%s", r.stdout.decode("utf-8"))
    if r.returncode != 0:
        logging.info("Unable to create certificates")
        sys.exit(1)


class TestCase(abc.ABC):
    _files = []
    _www_dir = None
    _client_keylog_file = None
    _server_keylog_file = None
    _download_dir = None
    _cert_dir = None

    def __init__(
        self,
        client_keylog_file: str,
        server_keylog_file: str,
    ):
        self._server_keylog_file = server_keylog_file
        self._client_keylog_file = client_keylog_file
        self._files = []

    @abc.abstractmethod
    def name(self):
        pass

    @abc.abstractmethod
    def desc(self):
        pass

    def __str__(self):
        return self.name()

    def testname(self, p: Perspective):
        """The name of testcase presented to the endpoint Docker images"""
        return self.name()

    @staticmethod
    def scenario() -> str:
        """Scenario for the ns3 simulator"""
        return "simple-p2p --delay=15ms --bandwidth=10Mbps --queue=25"

    @staticmethod
    def timeout() -> int:
        """timeout in s"""
        return 60

    @staticmethod
    def urlprefix() -> str:
        """URL prefix"""
        return "https://server4:443/"

    @staticmethod
    def additional_envs() -> List[str]:
        return [""]

    @staticmethod
    def additional_containers() -> List[str]:
        return [""]

    def www_dir(self):
        if not self._www_dir:
            self._www_dir = tempfile.TemporaryDirectory(dir="/tmp", prefix="www_")
        return self._www_dir.name + "/"

    def download_dir(self):
        if not self._download_dir:
            self._download_dir = tempfile.TemporaryDirectory(
                dir="/tmp", prefix="download_"
            )
        return self._download_dir.name + "/"

    def certs_dir(self):
        if not self._cert_dir:
            self._cert_dir = tempfile.TemporaryDirectory(dir="/tmp", prefix="certs_")
            generate_cert_chain(self._cert_dir.name)
        return self._cert_dir.name + "/"

    # see https://www.stefanocappellini.it/generate-pseudorandom-bytes-with-python/ for benchmarks
    def _generate_random_file(self, size: int, filename_len=10) -> str:
        filename = random_string(filename_len)
        enc = AES.new(os.urandom(32), AES.MODE_OFB, b"a" * 16)
        f = open(self.www_dir() + filename, "wb")
        f.write(enc.encrypt(b" " * size))
        f.close()
        logging.debug("Generated random file: %s of size: %d", filename, size)
        return filename

    def cleanup(self):
        if self._www_dir:
            self._www_dir.cleanup()
            self._www_dir = None
        if self._download_dir:
            self._download_dir.cleanup()
            self._download_dir = None

    @abc.abstractmethod
    def get_paths(self):
        pass

class TestCaseHTTP3(TestCase):
    @staticmethod
    def name():
        return "http3"

    @staticmethod
    def abbreviation():
        return "3"

    @staticmethod
    def desc():
        return "An H3 transaction succeeded."

    def get_paths(self):
        self._files = [
            self._generate_random_file(5 * KB),
            self._generate_random_file(10 * KB),
            self._generate_random_file(500 * KB),
        ]
        return self._files
