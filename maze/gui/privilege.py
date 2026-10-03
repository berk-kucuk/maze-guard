"""
Connection to the Maze Guard privileged helper.

The helper runs as a root systemd service (daemon mode); the GUI always stays
in the normal user session and simply connects to the helper's socket. No sudo
password is ever requested, which keeps credential handling out of the GUI and
removes that privilege-escalation surface entirely. If the daemon is not
running/reachable, the GUI falls back to limited (detection-only) mode.
"""
import os

from maze.helper_client import HelperClient, _SOCK_PATH


def helper_socket_path() -> str:
    return _SOCK_PATH


async def connect_helper(iface: str = "eth0"):
    """
    Connect to the running helper daemon.

    Always returns a HelperClient, connected or not. A GUI autostarted at login
    routinely beats the daemon to it, and returning None then meant nothing
    ever retried: the whole session ran in limited mode. The engine keeps
    reconnecting an unconnected client (see MazeEngine._helper_loop).
    """
    client = HelperClient(uid=os.getuid())
    await client.connect()
    return client
