"""Small architecture-aware classic BPF filter for Bubblewrap.

The filter denies a conservative set of kernel-management and introspection
syscalls, and denies TIOCSTI specifically rather than blocking all ioctl calls.
It is not a complete syscall allowlist and must be used alongside namespaces
and filesystem isolation.
"""

from __future__ import annotations

import errno
import platform
import struct
from collections.abc import Iterable

# classic BPF instruction codes
_BPF_LD_W_ABS = 0x20
_BPF_JMP_JEQ_K = 0x15
_BPF_RET_K = 0x06
_SECCOMP_RET_KILL_PROCESS = 0x80000000
_SECCOMP_RET_ALLOW = 0x7FFF0000
_SECCOMP_RET_ERRNO = 0x00050000
_TIOCSTI = 0x5412

# syscall values are from Linux's asm-generic and x86-64 syscall tables.
# Unsupported architectures are rejected instead of using guessed values.
_ARCHES: dict[str, tuple[int, int, tuple[int, ...]]] = {
    "x86_64": (
        0xC000003E, 16,
        (101, 165, 166, 175, 176, 246, 248, 249, 250, 272, 298, 304, 308, 313, 321, 323),
    ),
    "amd64": (
        0xC000003E, 16,
        (101, 165, 166, 175, 176, 246, 248, 249, 250, 272, 298, 304, 308, 313, 321, 323),
    ),
    "aarch64": (
        0xC00000B7, 29,
        (39, 40, 104, 105, 106, 117, 217, 218, 219, 241, 265, 268, 273, 280, 282),
    ),
    "arm64": (
        0xC00000B7, 29,
        (39, 40, 104, 105, 106, 117, 217, 218, 219, 241, 265, 268, 273, 280, 282),
    ),
}


def supported_architecture(machine: str | None = None) -> str:
    """Return the normalized supported architecture, or fail closed."""
    value = (machine or platform.machine()).lower()
    if value not in _ARCHES:
        raise ValueError(
            f"Seccomp filter is not defined for architecture {value!r}; "
            "supported architectures are x86_64 and aarch64"
        )
    return value


def _insn(code: int, jt: int = 0, jf: int = 0, k: int = 0) -> tuple[int, int, int, int]:
    return (code, jt, jf, k)


def _pack_program(program: Iterable[tuple[int, int, int, int]]) -> bytes:
    return b"".join(struct.pack("=HBBI", code, jt, jf, k) for code, jt, jf, k in program)


def build_seccomp_filter(machine: str | None = None) -> bytes:
    """Compile a cBPF filter understood by bwrap's --seccomp FD option.

    An architecture mismatch kills the calling process. Listed syscalls return
    EPERM. Other syscalls are allowed, so this is defense-in-depth rather than
    a complete syscall allowlist.
    """
    arch = supported_architecture(machine)
    audit_arch, ioctl_nr, denied_syscalls = _ARCHES[arch]
    program: list[tuple[int, int, int, int]] = [
        _insn(_BPF_LD_W_ABS, k=4),  # seccomp_data.arch
        _insn(_BPF_JMP_JEQ_K, jt=1, jf=0, k=audit_arch),
        _insn(_BPF_RET_K, k=_SECCOMP_RET_KILL_PROCESS),
        _insn(_BPF_LD_W_ABS, k=0),  # seccomp_data.nr
    ]
    for syscall_nr in denied_syscalls:
        program.append(_insn(_BPF_JMP_JEQ_K, jt=0, jf=1, k=syscall_nr))
        program.append(_insn(_BPF_RET_K, k=_SECCOMP_RET_ERRNO | errno.EPERM))

    # If this is not ioctl, skip the following four instructions to RET ALLOW.
    # Otherwise, load args[0], deny only TIOCSTI, then restore syscall nr.
    program.extend(
        [
            _insn(_BPF_JMP_JEQ_K, jt=0, jf=4, k=ioctl_nr),
            _insn(_BPF_LD_W_ABS, k=16),  # low 32 bits of seccomp_data.args[0]
            _insn(_BPF_JMP_JEQ_K, jt=0, jf=1, k=_TIOCSTI),
            _insn(_BPF_RET_K, k=_SECCOMP_RET_ERRNO | errno.EPERM),
            _insn(_BPF_LD_W_ABS, k=0),
            _insn(_BPF_RET_K, k=_SECCOMP_RET_ALLOW),
        ]
    )
    return _pack_program(program)
