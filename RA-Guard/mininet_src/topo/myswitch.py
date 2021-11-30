from .switch import P4RuntimeSwitch
from pathlib import Path
from mininet.log import info


class MySwitch(P4RuntimeSwitch):
    def __init__(self, name, *opts, **kwargs):
        Path("logs/").mkdir(exist_ok=True)
        Path("pcaps/").mkdir(exist_ok=True)
        P4RuntimeSwitch.__init__(self, name, *opts,
                                 sw_path="simple_switch_grpc",
                                 log_file=f"logs/{name}.log",
                                 log_console=True,
                                 pcap_dump="pcaps/",
                                 cpu_port=255,
                                 enable_debugger=True,
                                 **kwargs)
