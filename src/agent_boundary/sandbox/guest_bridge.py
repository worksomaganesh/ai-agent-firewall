"""Guest-side loopback TCP to host UNIX-socket bridge."""

from __future__ import annotations

import argparse
import asyncio
import os
import signal
import sys
from collections.abc import Sequence


async def _pump(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    while True:
        data = await reader.read(65536)
        if not data:
            try:
                writer.write_eof()
                await writer.drain()
            except (AttributeError, OSError, RuntimeError):
                pass
            return
        writer.write(data)
        await writer.drain()


async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, socket_path: str) -> None:
    remote_writer: asyncio.StreamWriter | None = None
    tasks: list[asyncio.Task[None]] = []
    try:
        remote_reader, connected_writer = await asyncio.wait_for(asyncio.open_unix_connection(socket_path), timeout=5)
        remote_writer = connected_writer
        tasks = [
            asyncio.create_task(_pump(reader, connected_writer)),
            asyncio.create_task(_pump(remote_reader, writer)),
        ]
        await asyncio.wait_for(asyncio.gather(*tasks), timeout=600)
    except (OSError, asyncio.TimeoutError, ConnectionError):
        pass
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        if remote_writer is not None:
            remote_writer.close()
            try:
                await remote_writer.wait_closed()
            except (OSError, RuntimeError):
                pass
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, RuntimeError):
            pass


async def _run(command: Sequence[str], socket_path: str, port: int) -> int:
    server = await asyncio.start_server(
        lambda reader, writer: _handle(reader, writer, socket_path),
        host="127.0.0.1", port=port, limit=65536, start_serving=True,
    )
    env = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": "/tmp", "TMPDIR": "/tmp", "LANG": "C.UTF-8",
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0",
        "HTTP_PROXY": f"http://127.0.0.1:{port}",
        "HTTPS_PROXY": f"http://127.0.0.1:{port}",
        "ALL_PROXY": f"http://127.0.0.1:{port}",
        "http_proxy": f"http://127.0.0.1:{port}",
        "https_proxy": f"http://127.0.0.1:{port}",
        "all_proxy": f"http://127.0.0.1:{port}",
        "NO_PROXY": "", "no_proxy": "",
    }
    process: asyncio.subprocess.Process | None = None
    try:
        process = await asyncio.create_subprocess_exec(*command, env=env, start_new_session=True)
        return await process.wait()
    finally:
        if process is not None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            if process.returncode is None:
                try:
                    await asyncio.wait_for(process.wait(), timeout=2)
                except asyncio.TimeoutError:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
        server.close()
        await server.wait_closed()


def main() -> int:
    parser = argparse.ArgumentParser(description="Guest-side policy proxy bridge")
    parser.add_argument("--proxy-socket", required=True)
    parser.add_argument("--listen-port", required=True, type=int)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    if not command or any("\x00" in item for item in command):
        parser.error("a command is required after --")
    if not 1024 <= args.listen_port <= 65535:
        parser.error("listen port must be in 1024..65535")
    return asyncio.run(_run(command, args.proxy_socket, args.listen_port))


if __name__ == "__main__":
    sys.exit(main())
