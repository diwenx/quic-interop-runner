import logging
import os
import random
import re
import shutil
import string
import subprocess
import sys
import tempfile
import atexit
import signal
import time
import threading
from datetime import datetime
from typing import Callable, List

import testcases
import middlebox
from testcases import Perspective
from testcases import TestCaseHTTP3


def start_tcpdump(interface="any", pcap_file="log.pcap"):
    command = ["tcpdump", "-i", interface, "-w", pcap_file]
    tcpdump_process = subprocess.Popen(command)
    time.sleep(1)
    return tcpdump_process

def stop_tcpdump(tcpdump_process):
    if tcpdump_process:
        tcpdump_process.terminate()
        tcpdump_process.wait()

def signal_handler(signum, frame, tcpdump_process):
    stop_tcpdump(tcpdump_process)
    exit(0)

def random_string(length: int):
    """Generate a random string of fixed length"""
    letters = string.ascii_lowercase
    return "".join(random.choice(letters) for i in range(length))


class LogFileFormatter(logging.Formatter):
    def format(self, record):
        msg = super(LogFileFormatter, self).format(record)
        # remove color control characters
        return re.compile(r"\x1B[@-_][0-?]*[ -/]*[@-~]").sub("", msg)


class InteropRunner:
    _start_time = 0
    compliant = {}
    _implementations = {}
    _servers = []
    _clients = []
    _log_dir = ""
    _rtt = 0
    _iface = ""

    def __init__(
        self,
        implementations: dict,
        servers: List[str],
        clients: List[str],
        debug: bool,
        rtt:int,
        log_dir="",
        iface="",
    ):
        logger = logging.getLogger()
        logger.setLevel(logging.DEBUG)
        console = logging.StreamHandler(stream=sys.stderr)
        if debug:
            console.setLevel(logging.DEBUG)
        else:
            console.setLevel(logging.INFO)
        logger.addHandler(console)
        self._start_time = datetime.now()
        self._servers = servers
        self._clients = clients
        self._implementations = implementations
        self._log_dir = log_dir
        self._rtt = rtt
        self._iface = iface
        if len(self._log_dir) == 0:
            self._log_dir = "logs_{:%Y-%m-%dT%H:%M:%S}".format(self._start_time)
        if os.path.exists(self._log_dir):
            sys.exit("Log dir " + self._log_dir + " already exists.")
        logging.info("Saving logs to %s.", self._log_dir)

    def _is_unsupported(self, lines: List[str]) -> bool:
        return any("exited with code 127" in str(line) for line in lines) or any(
            "exit status 127" in str(line) for line in lines
        )

    def _check_impl_is_compliant(self, name: str) -> bool:
        """check if an implementation return UNSUPPORTED for unknown test cases"""
        if name in self.compliant:
            logging.debug(
                "%s already tested for compliance: %s", name, str(self.compliant)
            )
            return self.compliant[name]

        client_log_dir = tempfile.TemporaryDirectory(dir="/tmp", prefix="logs_client_")
        www_dir = tempfile.TemporaryDirectory(dir="/tmp", prefix="compliance_www_")
        certs_dir = tempfile.TemporaryDirectory(dir="/tmp", prefix="compliance_certs_")
        downloads_dir = tempfile.TemporaryDirectory(
            dir="/tmp", prefix="compliance_downloads_"
        )

        testcases.generate_cert_chain(certs_dir.name)

        # check that the client is capable of returning UNSUPPORTED
        logging.debug("Checking compliance of %s client", name)
        cmd = (
            "CERTS=" + certs_dir.name + " "
            "TESTCASE_CLIENT=" + random_string(6) + " "
            "SERVER_LOGS=/dev/null "
            "CLIENT_LOGS=" + client_log_dir.name + " "
            "WWW=" + www_dir.name + " "
            "DOWNLOADS=" + downloads_dir.name + " "
            'SCENARIO="simple-p2p --delay=15ms --bandwidth=10Mbps --queue=25" '
            "CLIENT=" + self._implementations[name]["image"] + " "
            "SERVER="
            + self._implementations[name]["image"]
            + " "  # only needed so docker compose doesn't complain
            "docker compose --env-file empty.env up --timeout 0 --abort-on-container-exit -V sim client"
        )
        output = subprocess.run(
            cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
        )
        if not self._is_unsupported(output.stdout.splitlines()):
            logging.error("%s client not compliant.", name)
            logging.debug("%s", output.stdout.decode("utf-8", errors="replace"))
            self.compliant[name] = False
            return False
        logging.debug("%s client compliant.", name)

        # check that the server is capable of returning UNSUPPORTED
        logging.debug("Checking compliance of %s server", name)
        server_log_dir = tempfile.TemporaryDirectory(dir="/tmp", prefix="logs_server_")
        cmd = (
            "CERTS=" + certs_dir.name + " "
            "TESTCASE_SERVER=" + random_string(6) + " "
            "SERVER_LOGS=" + server_log_dir.name + " "
            "CLIENT_LOGS=/dev/null "
            "WWW=" + www_dir.name + " "
            "DOWNLOADS=" + downloads_dir.name + " "
            "CLIENT="
            + self._implementations[name]["image"]
            + " "  # only needed so docker compose doesn't complain
            "SERVER=" + self._implementations[name]["image"] + " "
            "docker compose --env-file empty.env up -V server"
        )
        output = subprocess.run(
            cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
        )
        if not self._is_unsupported(output.stdout.splitlines()):
            logging.error("%s server not compliant.", name)
            logging.debug("%s", output.stdout.decode("utf-8", errors="replace"))
            self.compliant[name] = False
            return False
        logging.debug("%s server compliant.", name)

        # remember compliance test outcome
        self.compliant[name] = True
        return True

    def _print_results(self):
        logging.info("Run took %s", datetime.now() - self._start_time)

    def _copy_logs(self, container: str, dir: tempfile.TemporaryDirectory):
        cmd = (
            "docker cp \"$(docker ps -a --format '{{.ID}} {{.Names}}' | awk '/^.* "
            + container
            + "$/ {print $1}')\":/logs/. "
            + dir.name
        )
        r = subprocess.run(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        if r.returncode != 0:
            logging.info(
                "Copying logs from %s failed: %s",
                container,
                r.stdout.decode("utf-8", errors="replace"),
            )

    def _run_test(
        self,
        server: str,
        client: str,
        test: Callable[[], testcases.TestCase],
        iface: str,
        injection: bool,
    ):
        start_time = datetime.now()
        server_log_dir = tempfile.TemporaryDirectory(dir="/tmp", prefix="logs_server_")
        client_log_dir = tempfile.TemporaryDirectory(dir="/tmp", prefix="logs_client_")
        log_file = tempfile.NamedTemporaryFile(dir="/tmp", prefix="output_log_")
        pcap_file = tempfile.NamedTemporaryFile(dir="/tmp", prefix="output_pcap_")
        log_handler = logging.FileHandler(log_file.name)
        log_handler.setLevel(logging.DEBUG)

        formatter = LogFileFormatter("%(asctime)s %(message)s")
        log_handler.setFormatter(formatter)
        logging.getLogger().addHandler(log_handler)

        testcase = test(
            client_keylog_file=client_log_dir.name + "/keys.log",
            server_keylog_file=server_log_dir.name + "/keys.log",
        )
        print(
            "Server: "
            + server
            + ". Client: "
            + client
            + ". Running test case: "
            + str(testcase)
        )

        tcpdump_process = start_tcpdump(interface=iface, pcap_file=pcap_file.name)

        # Register the stop_tcpdump function to be called at exit
        atexit.register(stop_tcpdump, tcpdump_process)
        signal.signal(signal.SIGINT, lambda s, f: signal_handler(s, f, tcpdump_process))
        signal.signal(signal.SIGTERM, lambda s, f: signal_handler(s, f, tcpdump_process))

        reqs = " ".join([testcase.urlprefix() + p for p in testcase.get_paths()])
        logging.debug("Requests: %s", reqs)
        scenario = "'simple-p2p --delay=" + str(self._rtt) + "ms --bandwidth=10Mbps --queue=25'"
        params = (
            "WAITFORSERVER=server:443 "
            "CERTS=" + testcase.certs_dir() + " "
            "TESTCASE_SERVER=" + testcase.testname(Perspective.SERVER) + " "
            "TESTCASE_CLIENT=" + testcase.testname(Perspective.CLIENT) + " "
            "WWW=" + testcase.www_dir() + " "
            "DOWNLOADS=" + testcase.download_dir() + " "
            "SERVER_LOGS=" + server_log_dir.name + " "
            "CLIENT_LOGS=" + client_log_dir.name + " "
            "SCENARIO=" + scenario + " "
            "CLIENT=" + self._implementations[client]["image"] + " "
            "SERVER=" + self._implementations[server]["image"] + " "
            'REQUESTS="' + reqs + '" '
            'VERSION="' + testcases.QUIC_VERSION + '" '
        )
        params += " ".join(testcase.additional_envs())
        containers = "sim client server " + " ".join(testcase.additional_containers())
        cmd = (
            params
            + " docker compose --env-file empty.env up --abort-on-container-exit --timeout 1 "
            + containers
        )
        logging.debug("Command: %s", cmd)

        output = ""
        expired = False
        try:
            r = subprocess.run(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=testcase.timeout(),
            )
            output = r.stdout
        except subprocess.TimeoutExpired as ex:
            output = ex.stdout
            expired = True

        logging.debug("%s", output.decode("utf-8", errors="replace"))

        if expired:
            logging.debug("Test timeout: took longer than %ds.", testcase.timeout())
            r = subprocess.run(
                "docker compose --env-file empty.env stop " + containers,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=60,
            )
            logging.debug("%s", r.stdout.decode("utf-8", errors="replace"))

        stop_tcpdump(tcpdump_process)

        # copy the pcaps from the simulator
        self._copy_logs("client", client_log_dir)
        self._copy_logs("server", server_log_dir)

        # save logs
        logging.getLogger().removeHandler(log_handler)
        log_handler.close()
        log_dir = ''
        if injection:
            log_dir = self._log_dir + "/" + server + "_" + client + "/injection"
        else:
            log_dir = self._log_dir + "/" + server + "_" + client + "/control"
        shutil.copytree(server_log_dir.name, log_dir + "/server")
        shutil.copytree(client_log_dir.name, log_dir + "/client")
        shutil.copyfile(log_file.name, log_dir + "/output.txt")
        shutil.copyfile(pcap_file.name, log_dir + "/output.pcap")

        testcase.cleanup()
        server_log_dir.cleanup()
        client_log_dir.cleanup()
        logging.debug("Test took %ss", (datetime.now() - start_time).total_seconds())
    

    def run(self):

        for server in self._servers:
            for client in self._clients:
                logging.debug(
                    "Running with server %s (%s) and client %s (%s)",
                    server,
                    self._implementations[server]["image"],
                    client,
                    self._implementations[client]["image"],
                )
                if not (
                    self._check_impl_is_compliant(server)
                    and self._check_impl_is_compliant(client)
                ):
                    logging.info("Not compliant, skipping")
                    continue

                if len(self._iface) == 0:
                    logging.info("No interface specified, skipping")
                    continue

                # run the control case
                print("Running Control case...")
                self._run_test(server, client, TestCaseHTTP3, self._iface, False)

                time.sleep(5)

                # run the test case
                print("Running Injection case...")
                sniffing_thread = threading.Thread(target=middlebox.start_sniffing, args=(self._iface, ))
                sniffing_thread.start()
                self._run_test(server, client, TestCaseHTTP3, self._iface, True)

