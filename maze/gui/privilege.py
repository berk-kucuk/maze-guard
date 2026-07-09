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
    Returns a connected HelperClient, or None if the daemon is unavailable.
    """
    client = HelperClient(uid=os.getuid())
    if await client.connect():
        return client
    return None
