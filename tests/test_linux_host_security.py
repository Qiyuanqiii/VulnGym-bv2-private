from __future__ import annotations

from pathlib import Path
import stat
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

import vulngym_agent.linux_host_security as host_security


_MOUNTINFO = (
    b"24 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n"
    b"25 24 8:1 /protected /mnt/bind rw,relatime - ext4 /dev/sda1 rw\n"
    b"26 24 9:2 / /separate rw,relatime - xfs /dev/sdb2 rw\n"
)


def _node(kind: int, mode: int, *, inode: int, uid: int = 0, gid: int = 0):
    return SimpleNamespace(
        st_mode=kind | mode,
        st_dev=8,
        st_ino=inode,
        st_uid=uid,
        st_gid=gid,
        st_mtime_ns=100 + inode,
        st_ctime_ns=200 + inode,
    )


class LinuxHostSecurityTests(unittest.TestCase):
    def test_bind_mount_alias_maps_to_same_physical_path(self) -> None:
        table = host_security.parse_linux_mountinfo_v1(_MOUNTINFO)
        self.assertEqual(
            host_security.linux_physical_path_v1(
                table, "/protected/sub/task"
            ),
            ("8:1", "/protected/sub/task"),
        )
        self.assertEqual(
            host_security.linux_physical_path_v1(
                table, "/mnt/bind/sub/task"
            ),
            ("8:1", "/protected/sub/task"),
        )
        self.assertTrue(
            host_security.linux_paths_overlap_v1(
                table,
                "/protected/sub",
                "/mnt/bind",
            )
        )
        self.assertFalse(
            host_security.linux_paths_overlap_v1(
                table, "/mnt/bind/sub", "/separate/data"
            )
        )

    def test_mountinfo_rejects_decoded_control_characters(self) -> None:
        for field in ("root", "mount_point"):
            with self.subTest(field=field):
                root = b"/protected\\000name" if field == "root" else b"/"
                mount_point = (
                    b"/mnt/control\\011name"
                    if field == "mount_point"
                    else b"/mnt/bind"
                )
                payload = (
                    b"24 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n"
                    + b"25 24 8:1 "
                    + root
                    + b" "
                    + mount_point
                    + b" rw,relatime - ext4 /dev/sda1 rw\n"
                )
                with self.assertRaises(
                    host_security.LinuxHostSecurityError
                ) as captured:
                    host_security.parse_linux_mountinfo_v1(payload)
                self.assertEqual(captured.exception.code, "mountinfo_invalid")

    def test_mount_snapshot_change_is_rejected(self) -> None:
        table = host_security.parse_linux_mountinfo_v1(_MOUNTINFO)
        with (
            mock.patch.object(
                host_security,
                "_read_mountinfo_v1",
                return_value=_MOUNTINFO + b"27 24 8:1 /new /new rw - ext4 /dev/sda1 rw\n",
            ),
            self.assertRaises(host_security.LinuxHostSecurityError) as captured,
        ):
            host_security.assert_linux_mount_table_stable_v1(table)
        self.assertEqual(captured.exception.code, "mountinfo_changed")

    @unittest.skipUnless(sys.platform == "linux", "requires Linux path semantics")
    def test_socket_requires_private_parent_socket_and_safe_ancestors(self) -> None:
        socket_path = Path("/run/vulngym/docker.sock")

        def states(*, parent_mode: int = 0o700, socket_mode: int = 0o600):
            return {
                Path("/"): _node(stat.S_IFDIR, 0o755, inode=1),
                Path("/run"): _node(stat.S_IFDIR, 0o755, inode=2),
                Path("/run/vulngym"): _node(
                    stat.S_IFDIR, parent_mode, inode=3
                ),
                socket_path: _node(stat.S_IFSOCK, socket_mode, inode=4),
            }

        for parent_mode, socket_mode in ((0o750, 0o600), (0o700, 0o660)):
            with self.subTest(parent_mode=parent_mode, socket_mode=socket_mode):
                values = states(parent_mode=parent_mode, socket_mode=socket_mode)
                with (
                    mock.patch.object(host_security, "_require_native_linux"),
                    mock.patch.object(
                        host_security.os,
                        "geteuid",
                        return_value=0,
                        create=True,
                    ),
                    mock.patch.object(
                        host_security.os, "lstat", side_effect=lambda path: values[Path(path)]
                    ),
                    mock.patch.object(
                        host_security,
                        "_directory_members_v1",
                        return_value=(socket_path.name,),
                    ),
                    mock.patch.object(Path, "resolve", lambda self, strict=True: self),
                    self.assertRaises(host_security.LinuxHostSecurityError),
                ):
                    host_security.bind_docker_socket_guard_v1(socket_path)

        values = states()
        with (
            mock.patch.object(host_security, "_require_native_linux"),
            mock.patch.object(
                host_security.os, "geteuid", return_value=0, create=True
            ),
            mock.patch.object(
                host_security.os, "lstat", side_effect=lambda path: values[Path(path)]
            ),
            mock.patch.object(
                host_security,
                "_directory_members_v1",
                return_value=(socket_path.name,),
            ),
            mock.patch.object(Path, "resolve", lambda self, strict=True: self),
        ):
            guard = host_security.bind_docker_socket_guard_v1(socket_path)
        self.assertEqual(guard.socket_identity[4], 0o600)
        self.assertEqual(guard.directory_guard.chain[-1][-1], 0o700)

        with (
            mock.patch.object(host_security, "_require_native_linux"),
            mock.patch.object(
                host_security.os, "geteuid", return_value=0, create=True
            ),
            mock.patch.object(
                host_security.os,
                "lstat",
                side_effect=lambda path: values[Path(path)],
            ),
            mock.patch.object(
                host_security,
                "_directory_members_v1",
                return_value=(socket_path.name, "daemon.pid"),
            ),
            mock.patch.object(Path, "resolve", lambda self, strict=True: self),
            self.assertRaises(host_security.LinuxHostSecurityError) as captured,
        ):
            host_security.bind_docker_socket_guard_v1(socket_path)
        self.assertEqual(captured.exception.code, "docker_socket_unsafe")

    @unittest.skipUnless(sys.platform == "linux", "requires Linux path semantics")
    def test_docker_root_chain_must_be_root_owned_and_not_writable(self) -> None:
        docker_root = Path("/var/lib/docker")
        values = {
            Path("/"): _node(stat.S_IFDIR, 0o755, inode=1),
            Path("/var"): _node(stat.S_IFDIR, 0o755, inode=2),
            Path("/var/lib"): _node(stat.S_IFDIR, 0o755, inode=3),
            docker_root: _node(stat.S_IFDIR, 0o710, inode=4),
        }
        with (
            mock.patch.object(host_security, "_require_native_linux"),
            mock.patch.object(
                host_security.os, "lstat", side_effect=lambda path: values[Path(path)]
            ),
            mock.patch.object(Path, "resolve", lambda self, strict=True: self),
        ):
            guard = host_security.bind_root_owned_directory_chain_v1(docker_root)
        self.assertEqual(guard.path, docker_root)

        values[Path("/var/lib")] = _node(
            stat.S_IFDIR, 0o775, inode=3
        )
        with (
            mock.patch.object(host_security, "_require_native_linux"),
            mock.patch.object(
                host_security.os, "lstat", side_effect=lambda path: values[Path(path)]
            ),
            mock.patch.object(Path, "resolve", lambda self, strict=True: self),
            self.assertRaises(host_security.LinuxHostSecurityError) as captured,
        ):
            host_security.bind_root_owned_directory_chain_v1(docker_root)
        self.assertEqual(captured.exception.code, "directory_permissions_unsafe")


if __name__ == "__main__":
    unittest.main()
