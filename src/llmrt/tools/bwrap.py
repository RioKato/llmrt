"""Thin Python wrapper for bubblewrap (bwrap)."""

import asyncio
import os
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Self

PathArg = str | os.PathLike[str]


class Bwrap:
    def __init__(self, *options: PathArg) -> None:
        self._options: list[PathArg] = list(options)

    def _add(self, option: str, *args: PathArg) -> Self:
        self._options.extend((option, *args))
        return self

    # Namespaces

    def unshare_all(self) -> Self:
        return self._add("--unshare-all")

    def unshare_user(self) -> Self:
        return self._add("--unshare-user")

    def unshare_user_try(self) -> Self:
        return self._add("--unshare-user-try")

    def unshare_ipc(self) -> Self:
        return self._add("--unshare-ipc")

    def unshare_pid(self) -> Self:
        return self._add("--unshare-pid")

    def unshare_net(self) -> Self:
        return self._add("--unshare-net")

    def share_net(self) -> Self:
        return self._add("--share-net")

    def unshare_uts(self) -> Self:
        return self._add("--unshare-uts")

    def unshare_cgroup(self) -> Self:
        return self._add("--unshare-cgroup")

    def unshare_cgroup_try(self) -> Self:
        return self._add("--unshare-cgroup-try")

    def userns(self, fd: int) -> Self:
        return self._add("--userns", str(fd))

    def userns2(self, fd: int) -> Self:
        return self._add("--userns2", str(fd))

    def pidns(self, fd: int) -> Self:
        return self._add("--pidns", str(fd))

    def disable_userns(self) -> Self:
        return self._add("--disable-userns")

    def assert_userns_disabled(self) -> Self:
        return self._add("--assert-userns-disabled")

    def uid(self, uid: int) -> Self:
        return self._add("--uid", str(uid))

    def gid(self, gid: int) -> Self:
        return self._add("--gid", str(gid))

    def hostname(self, name: str) -> Self:
        return self._add("--hostname", name)

    # Filesystem. Option order is significant (mounts, overlay sources, permissions).

    def bind(self, source: PathArg, destination: PathArg) -> Self:
        return self._add("--bind", source, destination)

    def bind_try(self, source: PathArg, destination: PathArg) -> Self:
        return self._add("--bind-try", source, destination)

    def ro_bind(self, source: PathArg, destination: PathArg) -> Self:
        return self._add("--ro-bind", source, destination)

    def ro_bind_try(self, source: PathArg, destination: PathArg) -> Self:
        return self._add("--ro-bind-try", source, destination)

    def dev_bind(self, source: PathArg, destination: PathArg) -> Self:
        return self._add("--dev-bind", source, destination)

    def dev_bind_try(self, source: PathArg, destination: PathArg) -> Self:
        return self._add("--dev-bind-try", source, destination)

    def remount_ro(self, destination: PathArg) -> Self:
        return self._add("--remount-ro", destination)

    def overlay_src(self, source: PathArg) -> Self:
        return self._add("--overlay-src", source)

    def overlay(self, upper: PathArg, work: PathArg, destination: PathArg) -> Self:
        return self._add("--overlay", upper, work, destination)

    def tmp_overlay(self, destination: PathArg) -> Self:
        return self._add("--tmp-overlay", destination)

    def ro_overlay(self, destination: PathArg) -> Self:
        return self._add("--ro-overlay", destination)

    def proc(self, destination: PathArg) -> Self:
        return self._add("--proc", destination)

    def dev(self, destination: PathArg) -> Self:
        return self._add("--dev", destination)

    def tmpfs(self, destination: PathArg) -> Self:
        return self._add("--tmpfs", destination)

    def mqueue(self, destination: PathArg) -> Self:
        return self._add("--mqueue", destination)

    def dir(self, destination: PathArg) -> Self:
        return self._add("--dir", destination)

    def symlink(self, source: PathArg, destination: PathArg) -> Self:
        return self._add("--symlink", source, destination)

    def file(self, fd: int, destination: PathArg) -> Self:
        return self._add("--file", str(fd), destination)

    def bind_data(self, fd: int, destination: PathArg) -> Self:
        return self._add("--bind-data", str(fd), destination)

    def ro_bind_data(self, fd: int, destination: PathArg) -> Self:
        return self._add("--ro-bind-data", str(fd), destination)

    def perms(self, mode: str) -> Self:
        return self._add("--perms", mode)

    def size(self, bytes_: int) -> Self:
        return self._add("--size", str(bytes_))

    def chmod(self, mode: str, path: PathArg) -> Self:
        return self._add("--chmod", mode, path)

    # Environment

    def chdir(self, directory: PathArg) -> Self:
        return self._add("--chdir", directory)

    def clearenv(self) -> Self:
        return self._add("--clearenv")

    def setenv(self, name: str, value: str) -> Self:
        return self._add("--setenv", name, value)

    def unsetenv(self, name: str) -> Self:
        return self._add("--unsetenv", name)

    # Execution and monitoring

    def argv0(self, value: str) -> Self:
        return self._add("--argv0", value)

    def args(self, fd: int) -> Self:
        return self._add("--args", str(fd))

    def level_prefix(self) -> Self:
        return self._add("--level-prefix")

    def lock_file(self, path: PathArg) -> Self:
        return self._add("--lock-file", path)

    def sync_fd(self, fd: int) -> Self:
        return self._add("--sync-fd", str(fd))

    def block_fd(self, fd: int) -> Self:
        return self._add("--block-fd", str(fd))

    def userns_block_fd(self, fd: int) -> Self:
        return self._add("--userns-block-fd", str(fd))

    def info_fd(self, fd: int) -> Self:
        return self._add("--info-fd", str(fd))

    def json_status_fd(self, fd: int) -> Self:
        return self._add("--json-status-fd", str(fd))

    def new_session(self) -> Self:
        return self._add("--new-session")

    def die_with_parent(self) -> Self:
        return self._add("--die-with-parent")

    def as_pid_1(self) -> Self:
        return self._add("--as-pid-1")

    # Lockdown

    def seccomp(self, fd: int) -> Self:
        return self._add("--seccomp", str(fd))

    def add_seccomp_fd(self, fd: int) -> Self:
        return self._add("--add-seccomp-fd", str(fd))

    def exec_label(self, label: str) -> Self:
        return self._add("--exec-label", label)

    def file_label(self, label: str) -> Self:
        return self._add("--file-label", label)

    def cap_add(self, capability: str) -> Self:
        return self._add("--cap-add", capability)

    def cap_drop(self, capability: str) -> Self:
        return self._add("--cap-drop", capability)

    def not_a_security_boundary(self) -> Self:
        return self._add("--not-a-security-boundary")

    def run(self, command: Sequence[PathArg], **kwargs: Any) -> subprocess.CompletedProcess[Any]:
        return subprocess.run(["bwrap", *self._options, "--", *command], **kwargs)

    # Convenience presets

    def sandbox(self) -> Self:
        """Configure an isolated environment with host command-line tools."""
        (
            self.die_with_parent()
            .unshare_all()
            .new_session()
            .clearenv()
            .setenv("PATH", "/usr/bin:/bin")
            .setenv("HOME", "/tmp")
            .setenv("TMPDIR", "/tmp")
            .setenv("LC_ALL", "C.UTF-8")
            .ro_bind("/usr", "/usr")
            .dev("/dev")
            .proc("/proc")
            .tmpfs("/tmp")
        )

        for alias in ("/bin", "/sbin", "/lib", "/lib64"):
            path = Path(alias)
            if not path.exists():
                continue

            resolved = path.resolve(strict=True)
            if resolved.is_relative_to(Path("/usr")):
                self.symlink(str(resolved).lstrip("/"), alias)
            else:
                self.ro_bind(alias, alias)

        return self

    def workspace(
        self,
        source: PathArg,
        destination: PathArg,
        *,
        overlay_dir: PathArg | None = None,
    ) -> Self:
        """Mount source at destination, optionally with a writable overlay."""
        self.dir(destination)
        if overlay_dir is None:
            self.ro_bind(source, destination)
        else:
            directory = Path(overlay_dir)
            self.overlay_src(source).overlay(directory / "upper", directory / "work", destination)
        return self.chdir(destination)


class Shell(Bwrap):
    description = {
        "type": "function",
        "function": {
            "name": "shell",
            "description": "Execute a shell command.",
            "parameters": {
                "type": "object",
                "properties": {"command": {"type": "string"}},
                "required": ["command"],
                "additionalProperties": False,
            },
        },
    }

    async def call(self, arguments: dict[str, Any]) -> dict[str, Any]:
        command = arguments["command"]
        if not isinstance(command, str):
            raise TypeError("command must be a string")
        result = await asyncio.to_thread(
            self.run,
            ["/bin/sh", "-c", command],
            capture_output=True,
            text=True,
            errors="replace",
        )
        return {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
        }
