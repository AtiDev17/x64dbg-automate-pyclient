"""MCP server for x64dbg-automate. Exposes x64dbg automation as MCP tools."""

from __future__ import annotations

import base64
import ctypes
import json
import os
import struct
import sys
import time
from pathlib import Path

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:
    print("MCP dependency not installed. Install with: pip install x64dbg_automate[mcp]", file=sys.stderr)
    sys.exit(1)

from x64dbg_automate import X64DbgClient
from x64dbg_automate.events import EventType
from x64dbg_automate.models import (
    BreakpointType,
    HardwareBreakpointType,
    MEM_COMMIT,
    MEM_FREE,
    MEM_IMAGE,
    MEM_MAPPED,
    MEM_PRIVATE,
    MEM_RESERVE,
    MemoryBreakpointType,
    PAGE_GUARD,
)

try:
    # Windows-only bindings (ctypes.windll). Imported lazily-safe: on non-Windows
    # platforms every tool that needs them reports a clear error.
    from x64dbg_automate import win32 as _win32
except Exception:  # pragma: no cover - non-Windows import guard
    _win32 = None

mcp = FastMCP(
    "x64dbg-automate",
    instructions=(
        "MCP server for controlling the x64dbg debugger via x64dbg-automate. "
        "Use list_sessions or start_session first, then connect before using other tools. "
        "Addresses are hex strings (e.g. '0x7FF6A0001000'). Memory reads return hex dumps "
        "by default; pass format='hex' or 'base64' for compact output and a larger "
        "per-call limit, size=0 to read as much as fits, and read_memory_many to batch "
        "scattered struct-field reads. "
        "ALL debugger waits are hard-capped at 5 seconds: trace_into/trace_over/run_until "
        "clamp larger wait_timeout values (and tag the result '[clamped to 5 s]'), and "
        "wait_for_event refuses timeout > 5 — see x64dbg_help('timeout caps')."
    ),
)

_client: X64DbgClient | None = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _require_client() -> X64DbgClient:
    """Return the active client or raise a clear error."""
    if _client is None:
        raise RuntimeError("Not connected to x64dbg. Use connect_to_session or start_session first.")
    return _client


def _parse_address_or_expression(s: str) -> int:
    """Parse an address string to int.

    Accepts hex literals ('0x7FF6...', '7FF6...'), and falls back to
    x64dbg's expression evaluator so registers ('RIP'), symbols
    ('kernel32:CreateFileA'), and arithmetic ('rsp+0x20') all work.
    """
    s = s.strip()
    if s.startswith("0x") or s.startswith("0X"):
        return int(s, 16)
    try:
        return int(s, 16)
    except ValueError:
        pass
    # Fall back to x64dbg expression evaluator
    client = _require_client()
    _assert_expression_evaluable(client, s)
    val, success = client.eval_sync(s)
    if not success:
        raise ValueError(f"Cannot resolve address: {s}")
    return val


def _format_address(addr: int) -> str:
    """Format an integer address as a hex string."""
    return f"0x{addr:X}"


def _format_memory(data: bytes, base: int) -> str:
    """Format bytes as a standard hex dump with ASCII sidebar."""
    lines = []
    for offset in range(0, len(data), 16):
        chunk = data[offset:offset + 16]
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        ascii_part = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        lines.append(f"{_format_address(base + offset)}  {hex_part:<48s}  {ascii_part}")
    return "\n".join(lines)


# Ceiling on the encoded response, in characters. Only the MCP layer caps reads: the
# plugin issues an unbounded DbgMemRead and the transport is msgpack bytes. The limit
# applies to encoded output rather than raw bytes because encoding expands input by
# 1.33x (base64) to 5.19x (dump), so one byte cap cannot suit all three formats.
#
# The default targets Claude Code's 25k-token result limit at roughly 2 characters per
# token for binary data. Raise it via the env var for clients with a larger budget.
MAX_RESPONSE_CHARS = int(os.getenv("X64DBG_MCP_MAX_RESPONSE_CHARS", "48000"))

# Held back from a batch's budget so read_memory_many's closing summary and
# no-debuggee suffix always fit.
_BATCH_TAIL_RESERVE = 256

# Hard cap on every debugger wait, per AGENTS.md rule 4. Larger values are clamped
# (trace_into/trace_over/run_until) or refused (wait_for_event) — never honored.
MAX_DEBUGGER_WAIT_SECONDS = 5

# wait_for_event's no-progress horizon: if the debuggee stays running with zero
# events and zero state change for this long, the tool bails with a status message
# instead of draining the whole timeout on a silent/looping target (rule 5: "bail on
# the first empty/unchanged result"). Lanes re-poll and classify the stage.
WAIT_EVENT_NO_PROGRESS_SECONDS = 1.0

NO_DEBUGGEE_MSG = (
    "No debuggee: nothing is attached (not started, or exited/terminated). "
    "This is not a bad address — use get_debugger_status to confirm."
)


_STATE_NAMES = {MEM_COMMIT: "commit", MEM_RESERVE: "reserve", MEM_FREE: "free"}
_TYPE_NAMES = {MEM_PRIVATE: "private", MEM_MAPPED: "mapped", MEM_IMAGE: "image"}

# Low byte of PAGE_* protection -> rwx triplet. "C" is copy-on-write, which counts
# as writable for filtering purposes.
_PROTECT_NAMES = {
    0x01: "---",  # PAGE_NOACCESS
    0x02: "R--",  # PAGE_READONLY
    0x04: "RW-",  # PAGE_READWRITE
    0x08: "RC-",  # PAGE_WRITECOPY
    0x10: "--X",  # PAGE_EXECUTE
    0x20: "R-X",  # PAGE_EXECUTE_READ
    0x40: "RWX",  # PAGE_EXECUTE_READWRITE
    0x80: "RCX",  # PAGE_EXECUTE_WRITECOPY
}


def _decode_protect(protect: int) -> str:
    """Render a PAGE_* protection constant as an 'RW-' style triplet.

    A trailing '+G' marks PAGE_GUARD. Free regions report protect 0 and render '---'.
    """
    base = protect & 0xFF
    text = _PROTECT_NAMES.get(base, "---" if base == 0 else f"?{base:02X}")
    if protect & PAGE_GUARD:
        text += "+G"
    return text


def _protect_matches(protect: int, required: str) -> bool:
    """Check a region's protection against a filter.

    `required` is either a hex literal ('0x04') matched exactly against the low byte,
    or a subset of 'rwx' meaning the region must grant at least those permissions.
    """
    required = required.strip().lower()
    if not required:
        return True
    if required.startswith("0x"):
        return (protect & 0xFF) == int(required, 16)
    if set(required) - set("rwx"):
        raise ValueError(f"Invalid protect filter '{required}': expected a hex literal or a subset of 'rwx'")
    triplet = _PROTECT_NAMES.get(protect & 0xFF, "---")
    for perm in required:
        if perm == "r" and triplet[0] != "R":
            return False
        # Copy-on-write regions are writable.
        if perm == "w" and triplet[1] not in ("W", "C"):
            return False
        if perm == "x" and triplet[2] != "X":
            return False
    return True


def _named_filter_value(value: str, names: dict[int, str], label: str) -> int | None:
    """Resolve a friendly filter name (or hex literal) to its numeric constant."""
    value = value.strip().lower()
    if not value:
        return None
    if value.startswith("0x"):
        return int(value, 16)
    for num, name in names.items():
        if name == value:
            return num
    raise ValueError(f"Invalid {label} filter '{value}': expected one of {sorted(names.values())} or a hex literal")


def _assert_expression_evaluable(client, expression: str) -> None:
    """Raise if there is no debuggee to evaluate the expression against.

    With nothing attached, x64dbg resolves registers, flags and memory dereferences to
    0 and reports SUCCESS, and expression functions such as peb() and mod.base() either
    do the same or return values cached from the exited process. Which expressions are
    affected cannot be decided from the string — the evaluator's grammar is open and
    plugins extend it — so nothing is evaluated without a debuggee.

    Raises:
        ValueError: When no debuggee is attached.
    """
    if not client.is_debugging():
        raise ValueError(f"Cannot evaluate '{expression}': no debuggee attached")


def _no_debuggee_hint(client) -> str:
    """Return a no-debuggee suffix for failed memory access, else an empty string.

    The plugin reports XERROR_READ_FAILED both for a bad address and for a dead
    debuggee, so disambiguate on the error path only — no cost when reads succeed.
    """
    try:
        return "" if client.is_debugging() else f" — {NO_DEBUGGEE_MSG}"
    except Exception:
        return ""


def _encoded_len(nbytes: int, addr: int, format: str) -> int:
    """Exact length of the encoded output, computed without performing the read.

    A short read yields fewer bytes than requested, so this only ever over-estimates.
    """
    if format == "hex":
        return nbytes * 2
    if format == "base64":
        return 4 * ((nbytes + 2) // 3)
    if format == "dump":
        # Every dump line costs more than one character per byte, so a byte count
        # already past the budget cannot fit — skip the per-line walk.
        if nbytes > MAX_RESPONSE_CHARS:
            return nbytes
        total = 0
        for offset in range(0, nbytes, 16):
            n = min(16, nbytes - offset)
            total += len(_format_address(addr + offset)) + 2 + max(48, n * 3 - 1) + 2 + n
        return total + max(0, (nbytes + 15) // 16 - 1)  # newlines between lines
    raise ValueError(f"Invalid format '{format}': expected 'dump', 'hex', or 'base64'")


def _max_bytes_for(format: str, addr: int, budget: int | None = None) -> int:
    """Largest byte count whose encoded form fits the response budget."""
    budget = MAX_RESPONSE_CHARS if budget is None else budget
    if budget <= 0:
        return 0
    if format == "hex":
        return budget // 2
    if format == "base64":
        return (budget // 4) * 3
    if format == "dump":
        # address + 2 spaces + 48-char hex column + 2 spaces + 16 ASCII + newline
        per_line = len(_format_address(addr)) + 2 + 48 + 2 + 16 + 1
        nbytes = (budget // per_line) * 16
        # An address gains a digit at each power-of-16 boundary, lengthening every
        # line past it, so confirm against the exact cost and shrink if needed.
        while nbytes > 0 and _encoded_len(nbytes, addr, format) > budget:
            nbytes -= 16
        return nbytes
    raise ValueError(f"Invalid format '{format}': expected 'dump', 'hex', or 'base64'")


def _batch_exhausted(remaining: int) -> str:
    """Closing line for a batch that ran out of response budget."""
    return (f"[{remaining} more read(s) skipped: response budget exhausted. "
            f"Request them in smaller batches.]")


def _readable_span(client, addr: int) -> int:
    """Readable bytes from addr to the end of its region, or 0 if that is unknown.

    DbgMemRead is all-or-nothing across a region boundary: a read running past the end
    of a region fails rather than returning a short read.
    """
    try:
        for page in client.memmap():
            if page.base_address <= addr < page.base_address + page.region_size:
                # Committed alone is not enough — a NOACCESS region is unreadable.
                # PAGE_GUARD stays eligible: x64dbg reports a stack's guard page as
                # part of the whole region, and ReadProcessMemory does not trip guard
                # semantics, so excluding it would rule out most stacks.
                if page.state != MEM_COMMIT or not _protect_matches(page.protect, "r"):
                    return 0
                return page.base_address + page.region_size - addr
    except Exception:
        return 0
    return 0


def _encode_memory(data: bytes, addr: int, format: str) -> str:
    """Render read bytes in the requested output format."""
    if format == "dump":
        return _format_memory(data, addr)
    if format == "hex":
        return data.hex().upper()
    if format == "base64":
        return base64.b64encode(data).decode("ascii")
    raise ValueError(f"Invalid format '{format}': expected 'dump', 'hex', or 'base64'")


def _render_registers(client) -> str:
    """Render the full general-purpose register dump + flags as text."""
    regs = client.get_regs()
    ctx = regs.context
    lines = []
    for field_name in type(ctx).model_fields:
        val = getattr(ctx, field_name)
        if isinstance(val, int):
            lines.append(f"{field_name:8s} = {_format_address(val)}")
    flags = regs.flags
    flag_strs = [f"{k}={int(v)}" for k, v in flags.model_dump().items()]
    lines.append(f"flags    = {' '.join(flag_strs)}")
    return "\n".join(lines)


def _parse_external_address(s: str) -> int:
    """Parse a plain hex address for processes outside the debugger session.

    External reads (read_memory_external) have no x64dbg expression evaluator to
    resolve registers or symbols against, so only hex literals are accepted.
    """
    s = s.strip()
    try:
        return int(s, 16)
    except ValueError:
        raise ValueError(
            f"Cannot parse external address '{s}': expected a hex literal (e.g. '0x401000')"
        )


def _pe_bitness(exe_path: str) -> int:
    """Read the PE Machine field to determine if an executable is 32-bit or 64-bit."""
    with open(exe_path, "rb") as f:
        mz = f.read(2)
        if mz != b"MZ":
            raise ValueError(f"Not a valid PE file: {exe_path}")
        f.seek(0x3C)
        pe_offset = struct.unpack("<I", f.read(4))[0]
        f.seek(pe_offset)
        sig = f.read(4)
        if sig != b"PE\x00\x00":
            raise ValueError(f"Invalid PE signature in: {exe_path}")
        machine = struct.unpack("<H", f.read(2))[0]
    if machine == 0x8664:
        return 64
    if machine == 0x14C:
        return 32
    raise ValueError(f"Unknown PE machine type 0x{machine:X} in: {exe_path}")


def _resolve_x64dbg_path_with_env(x64dbg_path: str) -> str:
    """Resolve x64dbg path from parameter, falling back to X64DBG_PATH env var.

    Args:
        x64dbg_path: Explicit path from tool parameter (may be empty).

    Returns:
        Resolved path string.

    Raises:
        FileNotFoundError: If neither parameter nor env var provides a path.
    """
    path = x64dbg_path.strip() if x64dbg_path else ""
    if not path:
        path = os.environ.get("X64DBG_PATH", "").strip()
    if not path:
        raise FileNotFoundError(
            "x64dbg path not provided and X64DBG_PATH environment variable is not set."
        )
    return path


def _resolve_debugger_path(x64dbg_path: str, target_exe: str = "") -> str:
    """Resolve x96dbg.exe to the correct x64dbg.exe or x32dbg.exe based on target bitness.

    If the path already points to x64dbg.exe or x32dbg.exe, it is returned as-is.
    """
    p = Path(x64dbg_path)
    name_lower = p.name.lower()
    if name_lower not in ("x96dbg.exe", "x96dbg"):
        return x64dbg_path
    # x96dbg launcher — resolve to the correct binary
    if target_exe.strip():
        bitness = _pe_bitness(target_exe.strip())
    else:
        bitness = 64  # default when no target specified
    arch_dir = "x64" if bitness == 64 else "x32"
    dbg_name = "x64dbg.exe" if bitness == 64 else "x32dbg.exe"
    candidates = [
        p.parent / arch_dir / dbg_name,        # release/x64/x64dbg.exe (standard layout)
        p.parent / dbg_name,                    # release/x64dbg.exe (flat layout)
        p.parent / "release" / dbg_name,        # alongside release/ folder
        p.parent / "release" / arch_dir / dbg_name,
    ]
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    raise FileNotFoundError(
        f"Cannot find {dbg_name} relative to {x64dbg_path}. "
        f"Pass the path to {dbg_name} directly instead of x96dbg.exe."
    )


# ---------------------------------------------------------------------------
# Session Management
# ---------------------------------------------------------------------------

@mcp.tool()
def list_sessions() -> str:
    """List all active x64dbg debugger instances. Does not require an active connection."""
    try:
        sessions = X64DbgClient.list_sessions()
        if not sessions:
            return "No active x64dbg sessions found."
        lines = []
        for s in sessions:
            exe_path = s.cmdline[0].strip() if s.cmdline and s.cmdline[0].strip() else "unknown"
            lines.append(
                f"PID: {s.pid}  |  Path: {exe_path}  |  Window: {s.window_title}  |  "
                f"REQ port: {s.sess_req_rep_port}  |  SUB port: {s.sess_pub_sub_port}"
            )
        return "\n".join(lines)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def start_session(x64dbg_path: str = "", target_exe: str = "", cmdline: str = "", current_dir: str = "") -> str:
    """Launch a new x64dbg instance and optionally load an executable.

    If x96dbg.exe (the launcher) is given, the correct x64dbg.exe or x32dbg.exe is
    selected automatically based on the target executable's PE bitness.

    Args:
        x64dbg_path: Path to x64dbg installation (x96dbg.exe, x64dbg.exe, or x32dbg.exe). Falls back to X64DBG_PATH env var if not provided.
        target_exe: Path to executable to debug (optional)
        cmdline: Command-line arguments for the target (optional)
        current_dir: Working directory for the target (optional)
    """
    global _client
    try:
        path = _resolve_x64dbg_path_with_env(x64dbg_path)
        resolved = _resolve_debugger_path(path, target_exe)
        _client = X64DbgClient(resolved)
        pid = _client.start_session(target_exe, cmdline, current_dir)
        return f"Session started with {Path(resolved).name}. Debugger PID: {pid}"
    except Exception as e:
        _client = None
        return f"Error: {e}"


@mcp.tool()
def connect_to_session(x64dbg_path: str = "", session_pid: int = 0) -> str:
    """Connect to an already-running x64dbg instance.

    If x96dbg.exe is given, it is resolved to x64dbg.exe (default).
    The actual debugger binary must already be running.

    Args:
        x64dbg_path: Path to x64dbg installation (x96dbg.exe, x64dbg.exe, or x32dbg.exe). Falls back to X64DBG_PATH env var if not provided.
        session_pid: PID of the x64dbg process to attach to
    """
    if not session_pid:
        return "Error: session_pid is required."
    global _client
    try:
        path = _resolve_x64dbg_path_with_env(x64dbg_path)
        resolved = _resolve_debugger_path(path)
        _client = X64DbgClient(resolved)
        _client.attach_session(session_pid)
        return f"Connected to session PID {session_pid}."
    except Exception as e:
        _client = None
        return f"Error: {e}"


@mcp.tool()
def connect_remote(host: str, req_rep_port: int, pub_sub_port: int) -> str:
    """Connect to a remote x64dbg instance running on another machine or VM.

    Bypasses local session discovery (lockfiles). The x64dbg plugin on the
    remote machine must be configured to bind to an accessible address
    (e.g. 0.0.0.0) via the [XAutomate] section in x64dbg.ini.

    Args:
        host: Remote hostname or IP address (e.g. '192.168.1.100')
        req_rep_port: The REQ/REP port the plugin is listening on
        pub_sub_port: The PUB/SUB port the plugin is listening on
    """
    global _client
    try:
        _client = X64DbgClient.connect_remote(host, req_rep_port, pub_sub_port)
        return f"Connected to remote x64dbg at {host}:{req_rep_port}."
    except Exception as e:
        _client = None
        return f"Error: {e}"


@mcp.tool()
def disconnect() -> str:
    """Disconnect from the current x64dbg session without terminating the debugger."""
    global _client
    if _client is None:
        return "No active connection."
    try:
        _client.detach_session()
        _client = None
        return "Disconnected."
    except Exception as e:
        _client = None
        return f"Error: {e}"


@mcp.tool()
def terminate_session() -> str:
    """Terminate the connected x64dbg debugger process."""
    global _client
    try:
        client = _require_client()
        client.terminate_session()
        _client = None
        return "Session terminated."
    except Exception as e:
        _client = None
        return f"Error: {e}"


@mcp.tool()
def attach(target: str) -> str:
    """Attach the debugger to a running process for live dynamic analysis.

    Connects to the target process via dbgeng (WinDbg engine). After attaching,
    use get_memory_map() to see loaded DLLs, set_breakpoint() to set breakpoints,
    and get_debugger_status() to confirm the attach (pid, bitness, run state).

    Args:
        target: Process name (e.g. "Game.exe") or PID.
    """
    global _client
    try:
        client = _require_client()
        if isinstance(target, int) or (isinstance(target, str) and target.isdigit()):
            pid = int(target)
        else:
            import subprocess
            result = subprocess.run(
                ["tasklist", "/FI", f"IMAGENAME eq {target}", "/FO", "CSV", "/NH"],
                capture_output=True, text=True, timeout=5,
            )
            lines = [line for line in result.stdout.strip().splitlines() if line]
            if not lines:
                return f"Process '{target}' not found."
            pid = int(lines[0].split(",")[1].strip('"'))
        success = client.attach(pid, wait_timeout=10)
        return f"Attached to PID {pid}." if success else f"Failed to attach to PID {pid}."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def load_executable(target_exe: str, cmdline: str = "", current_dir: str = "") -> str:
    """Load a new executable into the debugger.

    Imports the file, opens it in the CodeBrowser, and optionally starts auto-analysis.
    When analysis is enabled, sends a log notification when analysis completes.

    Args:
        target_exe: Absolute path to the executable file on disk
        cmdline: Command-line arguments for the target (optional)
        current_dir: Working directory for the target (optional)
    """
    global _client
    try:
        client = _require_client()
        success = client.load_executable(target_exe, cmdline, current_dir, wait_timeout=10)
        return f"Loaded {Path(target_exe).name}." if success else f"Failed to load {target_exe}."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def is_process_alive() -> str:
    """Check if the debuggee process is still running.

    Returns the debuggee PID, run state, and whether it is still alive.
    Useful for quick status checks after go() or when unsure if the process crashed.
    """
    try:
        client = _require_client()
        debugging = client.is_debugging()
        if not debugging:
            return "No debuggee loaded (process exited or not started)."
        running = client.is_running()
        pid = client.debugee_pid()
        state = "running" if running else "paused/stopped"
        return f"Debuggee PID {pid} is {state}."
    except Exception as e:
        return f"Error: {e}"


# ---------------------------------------------------------------------------
# Debug Control
# ---------------------------------------------------------------------------

@mcp.tool()
def get_debugger_status() -> str:
    """Get consolidated debugger status: debuggee presence, run state, PID, bitness, elevated."""
    try:
        client = _require_client()
        debugging = client.is_debugging()
        # DbgIsRunning() is !waitislocked(WAITID_RUN) — it means "not paused at a
        # breakpoint", not "a process exists". With no debuggee it reports True, which
        # reads as a bridge fault, so only report it when there is something to run.
        running = client.is_running()
        elevated = client.debugger_is_elevated()
        parts = [f"Has debuggee: {debugging}"]
        if debugging:
            parts.append(f"State: {'running' if running else 'paused'}")
            parts.append(f"Debuggee PID: {client.debugee_pid()}")
            parts.append(f"Bitness: {client.debugee_bitness()}")
        else:
            parts.append("State: no debuggee (not started, or exited/terminated)")
            parts.append("Debuggee PID: n/a")
            parts.append("Bitness: n/a")
        parts.append(f"Elevated: {elevated}")
        return "\n".join(parts)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def go(pass_exceptions: bool = False, swallow_exceptions: bool = False) -> str:
    """Resume debuggee execution.

    Args:
        pass_exceptions: Pass exceptions to the debuggee
        swallow_exceptions: Swallow exceptions
    """
    try:
        client = _require_client()
        result = client.go(pass_exceptions=pass_exceptions, swallow_exceptions=swallow_exceptions)
        return "Resumed." if result else "Failed to resume."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def pause() -> str:
    """Pause the debuggee."""
    try:
        client = _require_client()
        result = client.pause()
        return "Paused." if result else "Failed to pause."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def step_into(count: int = 1) -> str:
    """Step into one or more instructions.

    Args:
        count: Number of instructions to step into
    """
    try:
        client = _require_client()
        result = client.stepi(step_count=count)
        return f"Stepped into {count} instruction(s)." if result else "Step into failed."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def step_over(count: int = 1) -> str:
    """Step over one or more instructions.

    Args:
        count: Number of instructions to step over
    """
    try:
        client = _require_client()
        result = client.stepo(step_count=count)
        return f"Stepped over {count} instruction(s)." if result else "Step over failed."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def skip_instruction(count: int = 1) -> str:
    """Skip instructions without executing them.

    Args:
        count: Number of instructions to skip
    """
    try:
        client = _require_client()
        result = client.skip(skip_count=count)
        return f"Skipped {count} instruction(s)." if result else "Skip failed."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def run_to_return(frames: int = 1) -> str:
    """Run until a return instruction is encountered.

    Args:
        frames: Number of return frames to seek
    """
    try:
        client = _require_client()
        result = client.ret(frames=frames)
        return "Ran to return." if result else "Run to return failed."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def detach() -> str:
    """Detach the debugger from the debuggee without killing it.

    The debuggee process continues running normally after detach.
    """
    try:
        client = _require_client()
        result = client.detach(wait_timeout=10)
        return "Detached." if result else "Failed to detach."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def terminate_debuggee() -> str:
    """Kill the debuggee process."""
    try:
        client = _require_client()
        result = client.unload_executable(wait_timeout=5)
        return "Debuggee terminated." if result else "Failed to terminate debuggee."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def trace_into(
    break_condition: str,
    max_steps: int = 50000,
    log_text: str | None = None,
    log_condition: str | None = None,
    command_text: str | None = None,
    command_condition: str | None = None,
    log_file: str | None = None,
    pass_exceptions: bool = False,
    swallow_exceptions: bool = False,
    wait_timeout: int = 5,
) -> str:
    """Trace into (single-step into calls) until a condition is met.

    Steps one instruction at a time, following into calls, until break_condition
    evaluates to non-zero or max_steps is reached. Optionally logs each step.

    Args:
        break_condition: x64dbg expression that stops the trace when non-zero (e.g. 'cip == 0x401000')
        max_steps: Maximum steps before giving up (default 50000)
        log_text: Formatted text to log each step (e.g. '{p:cip} {i:cip}')
        log_condition: Expression controlling when log_text is printed
        command_text: x64dbg command to execute each step
        command_condition: Expression controlling when command_text runs
        log_file: Path to redirect trace log output to a file
        pass_exceptions: Pass exceptions to the debuggee
        swallow_exceptions: Swallow exceptions
        wait_timeout: Max seconds to wait for trace completion (hard-capped at 5)
    """
    try:
        client = _require_client()
        clamped = wait_timeout > MAX_DEBUGGER_WAIT_SECONDS
        if clamped:
            wait_timeout = MAX_DEBUGGER_WAIT_SECONDS
        result = client.trace_into(
            break_condition=break_condition,
            max_steps=max_steps,
            log_text=log_text,
            log_condition=log_condition,
            command_text=command_text,
            command_condition=command_condition,
            log_file=log_file,
            pass_exceptions=pass_exceptions,
            swallow_exceptions=swallow_exceptions,
            wait_timeout=wait_timeout,
        )
        msg = "Trace into completed." if result else "Trace into failed."
        return f"{msg} [clamped to 5 s]" if clamped else msg
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def trace_over(
    break_condition: str,
    max_steps: int = 50000,
    log_text: str | None = None,
    log_condition: str | None = None,
    command_text: str | None = None,
    command_condition: str | None = None,
    log_file: str | None = None,
    pass_exceptions: bool = False,
    swallow_exceptions: bool = False,
    wait_timeout: int = 5,
) -> str:
    """Trace over (single-step over calls) until a condition is met.

    Steps one instruction at a time, stepping over calls, until break_condition
    evaluates to non-zero or max_steps is reached. Optionally logs each step.

    Args:
        break_condition: x64dbg expression that stops the trace when non-zero (e.g. 'cip == 0x401000')
        max_steps: Maximum steps before giving up (default 50000)
        log_text: Formatted text to log each step (e.g. '{p:cip} {i:cip}')
        log_condition: Expression controlling when log_text is printed
        command_text: x64dbg command to execute each step
        command_condition: Expression controlling when command_text runs
        log_file: Path to redirect trace log output to a file
        pass_exceptions: Pass exceptions to the debuggee
        swallow_exceptions: Swallow exceptions
        wait_timeout: Max seconds to wait for trace completion (hard-capped at 5)
    """
    try:
        client = _require_client()
        clamped = wait_timeout > MAX_DEBUGGER_WAIT_SECONDS
        if clamped:
            wait_timeout = MAX_DEBUGGER_WAIT_SECONDS
        result = client.trace_over(
            break_condition=break_condition,
            max_steps=max_steps,
            log_text=log_text,
            log_condition=log_condition,
            command_text=command_text,
            command_condition=command_condition,
            log_file=log_file,
            pass_exceptions=pass_exceptions,
            swallow_exceptions=swallow_exceptions,
            wait_timeout=wait_timeout,
        )
        msg = "Trace over completed." if result else "Trace over failed."
        return f"{msg} [clamped to 5 s]" if clamped else msg
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def run_until(condition: str, address: str = "", timeout: int = 5) -> str:
    """Run at full speed until a condition holds, then return regs.

    Fast alternative to trace_into for far targets: x64dbg has no 'runtocond'
    command, so this arms a temporary conditional breakpoint and runs until it
    fires (or the timeout elapses). The temporary breakpoint is removed either way.

    The condition is only ever evaluated at the target address — that is how
    x64dbg break conditions work — so the design expects a condition of the form
    'cip == 0x401000' (which also supplies the address). If the address can't be
    derived from the condition, pass it explicitly via `address`.

    Args:
        condition: x64dbg expression that stops the run when non-zero, evaluated
            when the target is reached (e.g. 'cip == 0x401000', '[0x76C30000] == 0x232')
        address: Optional target address where the condition is evaluated. Derived
            automatically from 'cip == <hex>' / 'eip == <hex>' or a bare hex condition.
        timeout: Max seconds to wait (hard-capped at 5). A condition that never
            becomes true returns TIMEOUT under the cap — never hangs.

    Returns:
        On hit: 'Condition met: cip == 0x...' plus the full register snapshot.
        On timeout: 'TIMEOUT: condition not met within N s' plus the current cip.
    """
    try:
        client = _require_client()
        if not client.is_debugging():
            return NO_DEBUGGEE_MSG
        clamped = timeout > MAX_DEBUGGER_WAIT_SECONDS
        if clamped:
            timeout = MAX_DEBUGGER_WAIT_SECONDS

        # Derive the target address: explicit > 'cip/eip == 0x...' > bare hex.
        target: int | None = None
        if address.strip():
            target = _parse_address_or_expression(address)
        else:
            import re
            m = re.search(r"(?:cip|eip)\s*==\s*(0x[0-9a-fA-F]+)", condition)
            if m:
                target = int(m.group(1), 16)
            else:
                bare = condition.strip()
                if re.fullmatch(r"0x[0-9a-fA-F]+", bare):
                    target = int(bare, 16)
        if target is None:
            return (
                f"Error: cannot derive a target address from condition '{condition}'. "
                "Pass address=<hex> explicitly, or use a 'cip == 0x...' style condition."
            )

        # Arm a single-shot conditional breakpoint, run, then poll for the stop.
        if not client.set_breakpoint(target, name="mcp_run_until", singleshoot=True):
            return f"Error: failed to arm temporary breakpoint at {_format_address(target)}."
        if not client.set_breakpoint_condition(target, condition):
            client.clear_breakpoint(target)
            return f"Error: failed to set condition '{condition}' on the temporary breakpoint."
        try:
            client.go()
            stopped = client.wait_until_stopped(timeout)
            if not stopped:
                cur = 0
                try:
                    cur = client.get_reg("cip")
                except Exception:
                    pass
                tag = " [clamped to 5 s]" if clamped else ""
                return (
                    f"TIMEOUT: condition never became true within {timeout}s{tag}. "
                    f"Current cip = {_format_address(cur)}."
                )
            if not client.is_debugging():
                return "Debuggee exited before the condition became true."
            cur = client.get_reg("cip")
            hit = cur == target
            head = (
                f"Condition met: cip == {_format_address(target)}"
                if hit else
                f"Stopped at cip == {_format_address(cur)} (condition not qualified "
                f"to the target — the temporary breakpoint fired on the address)"
            )
            tag = " [clamped to 5 s]" if clamped else ""
            return f"{head}{tag}\n{_render_registers(client)}"
        finally:
            try:
                client.clear_breakpoint(target)
            except Exception:
                pass
    except Exception as e:
        return f"Error: {e}"


# ---------------------------------------------------------------------------
# Memory
# ---------------------------------------------------------------------------

@mcp.tool()
def read_memory(address: str, size: int = 256, format: str = "dump") -> str:
    """Read memory from the debuggee.

    Results are never truncated. A read too large to encode is refused before it is
    issued, naming the limit for the chosen format.

    Args:
        address: Address — hex ('0x7FF6A0001000'), register ('RSP'), symbol, or expression ('rsp+0x20')
        size: Number of bytes to read, or 0 for the largest readable run that fits in
              one response, stopping at the end of the containing memory region.
        format: Output encoding, which also sets how many bytes fit per response:
            'dump'   — hex dump with ASCII sidebar (default; human-readable, ~9 KB)
            'hex'    — contiguous uppercase hex, no separators (~24 KB)
            'base64' — most compact, best for bulk reads (~36 KB)
    """
    try:
        client = _require_client()
        addr = _parse_address_or_expression(address)
        cap = _max_bytes_for(format, addr)
        if size <= 0:
            # Bounded by the region as well as the budget — see _readable_span.
            span = _readable_span(client, addr)
            size = min(cap, span) if span else cap
        elif _encoded_len(size, addr, format) > MAX_RESPONSE_CHARS:
            alt = ""
            if format != "base64":
                alt = f", or format='base64' to fit {_max_bytes_for('base64', addr):,}"
            return (
                f"Error: {size:,} bytes as '{format}' would exceed the response limit. "
                f"Read at most {cap:,} bytes in this format{alt}. "
                f"Pass size=0 for the largest read that fits."
            )
        try:
            data = client.read_memory(addr, size)
        except Exception as e:
            return f"Error: {e}{_no_debuggee_hint(client)}"
        return _encode_memory(data, addr, format)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def read_memory_many(reads: list[str], format: str = "hex") -> str:
    """Read several memory ranges in one call — for walking scattered struct fields.

    Each read is resolved and reported independently: one failing address does not
    abort the others, so a partially-mapped structure still yields its readable fields.

    The batch shares one response budget. A read that does not fit in what remains is
    skipped whole and reported as such — every returned read is complete.

    Args:
        reads: Ranges as '<address>:<size>' strings, e.g. ['0x1000:16', 'esi+0x10:4'].
               The address accepts the same forms as read_memory. Sizes are literal
               here; the size=0 shorthand is read_memory only.
        format: Output encoding per read — 'hex' (default), 'base64', or 'dump'.

    Returns:
        One line per read: '<spec> @<resolved address> = <encoded bytes>',
        '<spec> ERROR: <reason>' for reads that could not be satisfied, or
        '<spec> SKIPPED: ...' for reads dropped to stay within the response budget.
    """
    try:
        client = _require_client()
    except Exception as e:
        return f"Error: {e}"

    if not reads:
        return "No reads requested."

    lines = []
    failed = False
    # Every emitted line counts against the budget — payloads, labels, skip notices and
    # error notices alike — with a reserve kept back for the tail.
    budget = MAX_RESPONSE_CHARS - _BATCH_TAIL_RESERVE
    for index, spec in enumerate(reads):
        try:
            addr_part, _, size_part = spec.rpartition(":")
            if not addr_part:
                raise ValueError("expected '<address>:<size>'")
            addr = _parse_address_or_expression(addr_part)
            size = max(0, int(size_part, 0))
            prefix = f"{spec} @{_format_address(addr)} ="
            overhead = len(prefix) + 2  # separator + newline
            if _encoded_len(size, addr, format) + overhead > budget:
                room = _max_bytes_for(format, addr, max(0, budget - overhead))
                note = (
                    f"{spec} SKIPPED: {size:,} bytes exceeds the remaining response "
                    f"budget (room for {room:,} more bytes). Request it separately."
                )
                if len(note) + 1 > budget:
                    lines.append(_batch_exhausted(len(reads) - index))
                    break
                lines.append(note)
                budget -= len(note) + 1
                continue
            data = client.read_memory(addr, size)
            encoded = _encode_memory(data, addr, format)
            separator = "\n" if format == "dump" else " "
            line = f"{prefix}{separator}{encoded}"
            lines.append(line)
            budget -= len(line) + 1
        except Exception as e:
            failed = True
            note = f"{spec} ERROR: {e}"
            if len(note) + 1 > budget:
                lines.append(_batch_exhausted(len(reads) - index))
                break
            lines.append(note)
            budget -= len(note) + 1

    # Probe for a debuggee once, and only if something failed, so a fully
    # successful batch costs no extra round trip — same rule as read_memory.
    suffix = _no_debuggee_hint(client).lstrip(" —") if failed else ""
    return "\n".join(lines) + (f"\n{suffix}" if suffix else "")


@mcp.tool()
def write_memory(address: str, hex_data: str) -> str:
    """Write bytes to debuggee memory.

    Args:
        address: Hex address to write to
        hex_data: Hex string of bytes to write (e.g. '90 90 90' or '909090')
    """
    try:
        client = _require_client()
        addr = _parse_address_or_expression(address)
        cleaned = hex_data.replace(" ", "").replace("\n", "")
        data = bytes.fromhex(cleaned)
        result = client.write_memory(addr, data)
        return f"Wrote {len(data)} bytes to {_format_address(addr)}." if result else "Write failed."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def allocate_memory(size: int = 4096, address: str = "0") -> str:
    """Allocate memory in the debuggee's address space (VirtualAlloc).

    Args:
        size: Number of bytes to allocate
        address: Preferred address (0 for any)
    """
    try:
        client = _require_client()
        addr = _parse_address_or_expression(address)
        result = client.virt_alloc(n=size, addr=addr)
        return f"Allocated {size} bytes at {_format_address(result)}."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def free_memory(address: str) -> str:
    """Free memory in the debuggee's address space (VirtualFree).

    Args:
        address: Address of memory to free
    """
    try:
        client = _require_client()
        addr = _parse_address_or_expression(address)
        client.virt_free(addr)
        return f"Freed memory at {_format_address(addr)}."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def get_memory_map(
    state: str = "commit",
    protect: str = "",
    mem_type: str = "",
    min_size: int = 0,
    offset: int = 0,
    limit: int = 200,
    as_json: bool = False,
) -> str:
    """List memory regions in the debuggee's address space, filtered and paginated.

    Defaults to committed regions only — a full map is typically ~1000 regions and
    too large for a single response. Pass state='' to include reserved and free ones.

    Args:
        state:    'commit' (default), 'reserve', 'free', a hex literal, or '' for all.
        protect:  Permission filter — a subset of 'rwx' meaning the region must grant at
                  least those (e.g. 'rw'), or a hex literal ('0x04') matched exactly.
                  Copy-on-write counts as writable. Empty means no filter.
        mem_type: 'private', 'mapped', 'image', a hex literal, or '' for all.
        min_size: Skip regions smaller than this many bytes.
        offset:   Index of the first matching region to return (for paging).
        limit:    Maximum regions to return (0 = no limit).
        as_json:  Return a JSON array of objects instead of the text table.

    Returns:
        One line per region — address, size, decoded rwx protection, state, type, info —
        followed by a summary stating how many regions matched, were hidden by filters,
        and remain beyond `limit`.
    """
    try:
        client = _require_client()

        # DbgMemMap copies x64dbg's memoryPages cache with no debuggee check, and that
        # cache is only refreshed on debug events. With nothing attached it returns the
        # dead process's map, which looks like a successful result. Fail loudly instead.
        # Checked before the filters are parsed so a detached session reports the
        # absence rather than a complaint about the filter arguments.
        if not client.is_debugging():
            return NO_DEBUGGEE_MSG

        want_state = _named_filter_value(state, _STATE_NAMES, "state")
        want_type = _named_filter_value(mem_type, _TYPE_NAMES, "mem_type")

        pages = client.memmap()
        total = len(pages)
        if not pages:
            return "No memory regions found."

        matched = [
            p for p in pages
            if (want_state is None or p.state == want_state)
            and (want_type is None or p.type == want_type)
            and p.region_size >= min_size
            and _protect_matches(p.protect, protect)
        ]

        offset = max(0, offset)
        window = matched[offset:] if limit <= 0 else matched[offset:offset + limit]
        remaining = len(matched) - offset - len(window)

        if as_json:
            payload = [
                {
                    "base_address": _format_address(p.base_address),
                    "allocation_base": _format_address(p.allocation_base),
                    "region_size": p.region_size,
                    "protect": _decode_protect(p.protect),
                    "protect_raw": p.protect,
                    "state": _STATE_NAMES.get(p.state, f"0x{p.state:X}"),
                    "type": _TYPE_NAMES.get(p.type, f"0x{p.type:X}"),
                    "info": p.info,
                }
                for p in window
            ]
            body = json.dumps(payload, indent=2)
        elif window:
            body = "\n".join(
                f"{_format_address(p.base_address)}  Size: {_format_address(p.region_size):>12s}  "
                f"{_decode_protect(p.protect):<5s}  {_STATE_NAMES.get(p.state, f'0x{p.state:X}'):<7s}  "
                f"{_TYPE_NAMES.get(p.type, f'0x{p.type:X}'):<7s}  {p.info}"
                for p in window
            )
        else:
            body = "No regions matched the filters."

        summary = f"[{len(matched)}/{total} regions matched, {total - len(matched)} hidden by filters"
        if remaining > 0:
            summary += f"; {remaining} more — call again with offset={offset + len(window)}"
        return f"{body}\n{summary}]"
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def get_modules() -> str:
    """List loaded modules (image regions) with base address and total size.

    Wraps the raw x64dbg 'modules' command. Built from get_memory_map's image
    regions: each module's size is the sum of its contiguous image regions, so
    the listing stays a single coherent table.

    Returns:
        One line per module: '<base>  Size: <size>  <name>'.
    """
    try:
        client = _require_client()
        pages = [p for p in client.memmap() if p.type == MEM_IMAGE]
        if not pages:
            return "No modules (no image regions found)."
        modules: dict[str, tuple[int, int]] = {}  # name -> (first base, total size)
        for p in sorted(pages, key=lambda p: p.base_address):
            name = p.info or f"image_{_format_address(p.base_address)}"
            if name in modules:
                base, size = modules[name]
                modules[name] = (base, size + p.region_size)
            else:
                modules[name] = (p.base_address, p.region_size)
        lines = [
            f"{_format_address(base)}  Size: {_format_address(size):>12s}  {name}"
            for name, (base, size) in sorted(modules.items(), key=lambda kv: kv[1][0])
        ]
        return f"[{len(modules)} modules]\n" + "\n".join(lines)
    except Exception as e:
        return f"Error: {e}"


# ---------------------------------------------------------------------------
# Window Stage & External Reads (text-only, non-pausing)
# ---------------------------------------------------------------------------

@mcp.tool()
def enumerate_windows(pid: int | None = None, all_top_level: bool = False) -> str:
    """Enumerate top-level windows and classify the GUI stage — as text.

    Replacement for screenshots: every lane must snapshot window class/title/rect
    and classify the stage (protector dialog, game window, error dialog) before
    touching target state. Output matches the Winprobe schema used in lane docs.

    Args:
        pid: Owner process id to filter windows to. Defaults to the current
            debuggee pid (from get_debugger_status) — the same anchor a lane
            would use for external reads.
        all_top_level: If False (default), only windows owned by the debuggee pid
            are listed (forms, game windows, error dialogs). If True, every
            top-level window on the desktop is listed.

    Returns:
        One line per window: 'hwnd  class  "title"  (left,top,right,bottom)  pid=...'
    """
    if _win32 is None:
        return "Error: window enumeration requires Windows (x64dbg-automate win32 bindings)."
    try:
        client = _require_client()
        if pid is None:
            pid = client.debugee_pid()
            if pid is None:
                return (
                    "No debuggee pid to scope windows to. Pass pid=<int> explicitly "
                    "or set all_top_level=True."
                )

        found: list[tuple[int, str, str, int, int, int, int, int]] = []

        def callback(hwnd, _lparam):
            owner_pid = ctypes.c_ulong(0)
            owner_pid_p = ctypes.cast(ctypes.byref(owner_pid), ctypes.POINTER(ctypes.c_ulong))
            _win32.GetWindowThreadProcessId(hwnd, owner_pid_p)
            owner = owner_pid.value
            if not all_top_level and owner != pid:
                return True
            title_buf = ctypes.create_unicode_buffer(512)
            _win32.GetWindowTextW(hwnd, title_buf, 512)
            class_buf = ctypes.create_unicode_buffer(256)
            _win32.GetClassNameW(hwnd, class_buf, 256)
            rect = ctypes.wintypes.RECT()
            rect_p = ctypes.cast(ctypes.byref(rect), ctypes.POINTER(ctypes.wintypes.RECT))
            _win32.GetWindowRect(hwnd, rect_p)
            found.append((hwnd, class_buf.value, title_buf.value,
                          rect.left, rect.top, rect.right, rect.bottom, owner))
            return True

        cb = _win32.EnumWindows.argtypes[0](callback)
        _win32.EnumWindows(cb, None)
        if not found:
            return f"No windows owned by pid {pid}."
        lines = [
            f"{hwnd:#x}  {cls}  \"{title}\"  ({l},{t},{r},{b})  pid={owner}"
            for hwnd, cls, title, l, t, r, b, owner in found
        ]
        scope = "all top-level" if all_top_level else f"owned by pid {pid}"
        return f"[{len(lines)} windows ({scope})]\n" + "\n".join(lines)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def read_memory_external(pid: int, address: str, size: int = 256, format: str = "hex") -> str:
    """Read a process's memory WITHOUT pausing it or touching the debuggee.

    Uses a bare OpenProcess + ReadProcessMemory (safe/tamper-invisible: no
    breakpoints, no debug events, no state change). Use it to sample buffers on a
    running/protected target, or any separate process.

    **Pid anchoring is mandatory**: the MCP holds ONE shared session, so reads can
    silently land on another lane's debuggee. This tool reports the pid it acted
    on in every result and only ever touches the pid you pass.

    Args:
        pid: Target process id — pass the exact debuggee pid from
            get_debugger_status (or any process you intend to sample).
        address: Plain hex address in the target process (no registers/symbols —
            there is no x64dbg evaluator for foreign processes).
        size: Number of bytes to request (bounded by the response budget for the
            format, like read_memory).
        format: Output encoding per read — 'hex' (default), 'base64', or 'dump'.

    Returns:
        '<pid> @0x<addr> (<n> bytes): <encoded>' — the resolved pid and the byte
        count actually read are always reported.
    """
    if _win32 is None:
        return "Error: external reads require Windows (x64dbg-automate win32 bindings)."
    try:
        addr = _parse_external_address(address)
        cap = _max_bytes_for(format, addr)
        size = min(max(1, size), cap) if size > 0 else cap
        data = _win32.read_process_memory(pid, addr, size)
        encoded = _encode_memory(data, addr, format)
        return f"{pid} @0x{addr:X} ({len(data)} bytes): {encoded}"
    except Exception as e:
        return f"Error: {e}"


# ---------------------------------------------------------------------------
# Registers
# ---------------------------------------------------------------------------

@mcp.tool()
def get_register(register: str) -> str:
    """Read a single register value.

    Args:
        register: Register name (e.g. 'rax', 'eip', 'rsp', 'eflags')
    """
    try:
        client = _require_client()
        val = client.get_reg(register)
        return f"{register} = {_format_address(val)}"
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def set_register(register: str, value: str) -> str:
    """Write a value to a register.

    Args:
        register: Register name (e.g. 'rax', 'eip')
        value: Hex value to set
    """
    try:
        client = _require_client()
        val = _parse_address_or_expression(value)
        result = client.set_reg(register, val)
        return f"Set {register} = {_format_address(val)}." if result else "Failed to set register."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def get_all_registers() -> str:
    """Dump all general-purpose registers and flags."""
    try:
        client = _require_client()
        return _render_registers(client)
    except Exception as e:
        return f"Error: {e}"


# ---------------------------------------------------------------------------
# Expressions & Commands
# ---------------------------------------------------------------------------

@mcp.tool()
def eval_expression(expression: str) -> str:
    """Evaluate an x64dbg expression. Supports symbols, registers, arithmetic.

    Requires a debuggee. With nothing attached x64dbg resolves registers, flags and
    memory reads to 0 and reports success, which is indistinguishable from a real zero.

    Args:
        expression: Expression to evaluate (e.g. 'kernel32:CreateFileA', 'rax+0x10')
    """
    try:
        client = _require_client()
        _assert_expression_evaluable(client, expression)
        val, success = client.eval_sync(expression)
        if not success:
            return f"Evaluation failed for: {expression}"
        return f"{expression} = {_format_address(val)}"
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def execute_command(command: str) -> str:
    """Execute a raw x64dbg command.

    See https://help.x64dbg.com/en/latest/commands/ for available commands.

    Args:
        command: x64dbg command string
    """
    try:
        client = _require_client()
        result = client.cmd_sync(command)
        return f"Command executed. Success: {result}"
    except Exception as e:
        return f"Error: {e}"


_X64DBG_COMMANDS = {
    "breakpoint creation": [
        ("bp addr", "Set software breakpoint at address"),
        ("bph addr, type, size", "Set hardware breakpoint at address (type: r/w/x, size: 1/2/4/8)"),
        ("bpm addr", "Set memory breakpoint at address"),
        ("bpd addr", "Set memory breakpoint on data"),
        ("bp addr, condition", "Set conditional software breakpoint"),
    ],
    "breakpoint control": [
        ("be addr", "Enable breakpoint"),
        ("bd addr", "Disable breakpoint"),
        ("bc addr", "Clear/delete breakpoint"),
        ("bce", "Clear ALL breakpoints (no address argument)"),
        ("bphwe addr", "Enable hardware breakpoint"),
        ("bphwd addr", "Disable hardware breakpoint"),
        ("bphc [addr]", "Clear hardware breakpoint (no addr = clear all hardware)"),
    ],
    "hardware breakpoints": [
        ("bph addr, type, size", "Arm a debug-register watch (4 slots total; r/w/x; size 1/2/4/8)"),
        ("bphwcond addr, cond", "Set HARDWARE breakpoint condition (bphwc family) — works on protected pages"),
        ("bphwlog addr, text", "Set HARDWARE breakpoint log text"),
        ("SetHardwareBreakpointCommand addr, cmd", "Run cmd when a HARDWARE breakpoint hits"),
        ("SetHardwareBreakpointSilent addr, 1/0", "Silent flag for a hardware breakpoint (log without breaking)"),
        ("get_hardware_slots", "MCP tool: which of the 4 debug-register slots are occupied"),
        ("set_breakpoint(bp_type='hardware', hardware_size=N)", "MCP tool: arm + verify-after-set"),
        ("set_breakpoint_condition(..., bp_type='hardware')", "MCP tool: hardware condition via bphwcond"),
    ],
    "breakpoint settings": [
        ("SetBreakpointCondition addr, expr", "Set condition expression (software BP)"),
        ("SetBreakpointLog addr, text", "Set log text (software BP)"),
        ("SetBreakpointLogCondition addr, expr", "Set log condition"),
        ("SetBreakpointCommand addr, cmd", "Set command to execute on hit (software BP)"),
        ("SetBreakpointCommandCondition addr, expr", "Set command condition"),
        ("SetBreakpointSilent addr, 1/0", "Make breakpoint silent (no log window)"),
        ("SetBreakpointFastResume addr, 1/0", "Skip exception handling on resume"),
    ],
    "execution control": [
        ("run", "Resume execution (F9)"),
        ("pause", "Pause execution (F12)"),
        ("singlestep", "Step into one instruction (F7)"),
        ("stepover", "Step over one instruction (F8)"),
        ("till addr", "Run until address"),
        ("ret", "Run until return"),
        ("skip", "Skip current instruction (NOP)"),
    ],
    "timeout caps": [
        ("wait_timeout on trace_into/trace_over", "Hard-capped at 5 s; larger values are clamped and tagged '[clamped to 5 s]'"),
        ("wait_for_event(timeout=N)", "Refuses N > 5 s with an immediate error naming the cap"),
        ("run_until(condition, timeout=N)", "Capped at 5 s; returns TIMEOUT under the cap, never hangs"),
        ("MAX_DEBUGGER_WAIT_SECONDS", "Server-wide cap constant (AGENTS.md rule 4)"),
    ],
    "register manipulation": [
        ("r eax=1", "Set EAX to 1"),
        ("r rax=0x1000", "Set RAX to 0x1000"),
        ("r eflags|=0x40", "Set zero flag"),
        ("r eflags&=~0x40", "Clear zero flag"),
    ],
    "memory operations": [
        ("dump addr", "Hex dump at address"),
        ("db addr", "Dump bytes"),
        ("dw addr", "Dump words"),
        ("dd addr", "Dump dwords"),
        ("dq addr", "Dump qwords"),
        ("disasm addr", "Disassemble at address"),
        ("asm addr, instruction", "Assemble instruction at address"),
        ("fill addr, size, value", "Fill memory with value"),
        ("memcpy dest, src, size", "Copy memory"),
        ("strlen addr", "Get null-terminated string length"),
    ],
    "search": [
        ("find addr, data", "Search memory for data"),
        ("findall addr, data", "Find all occurrences"),
        ("findasm addr, instruction", "Search for assembly instruction"),
        ("findmemall addr, data", "Find in all memory regions"),
    ],
    "information": [
        ("modules", "List loaded modules"),
        ("memmap", "Show memory map"),
        ("threads", "List threads"),
        ("handles", "List open handles"),
        ("log", "Show log messages"),
        ("stack", "Show stack dump"),
        ("dump addr expr", "Show address expression"),
    ],
    "trace": [
        ("TraceIntoConditional cond", "Trace into until condition"),
        ("TraceOverConditional cond", "Trace over until condition"),
        ("traceenable 1/0", "Enable/disable trace recording"),
    ],
    "conditional logging": [
        ("SetBreakpointLog addr, \"{msg}\"", "Log message on hit"),
        ("SetBreakpointLog addr, \"{msg} {reg}\"", "Log with register value"),
        ("SetBreakpointSilent addr, 1", "Log without breaking"),
    ],
    "useful patterns": [
        ("r al=1", "Force auth check to pass (set return value)"),
        ("r eax=0", "Force function to return 0/success"),
        ("r eax=1", "Force function to return 1"),
        ("ret", "Skip current function (return immediately)"),
        ("skip", "NOP current instruction"),
        ("jmp addr", "Unconditional jump to address"),
    ],
}


@mcp.tool()
def x64dbg_help(category: str = "") -> str:
    """Reference guide for x64dbg commands.

    Use this to look up the correct command syntax before calling execute_command.
    Covers breakpoint creation, control, settings, hardware breakpoints, execution
    control, register manipulation, memory operations, search, tracing, timeout
    caps, and common patterns.

    Args:
        category: Optional category filter (e.g. 'breakpoint creation', 'hardware breakpoints',
                  'timeout caps', 'memory operations', 'register manipulation', 'execution control',
                  'search', 'trace', 'conditional logging', 'useful patterns'). Leave empty for all categories.
    """
    if category:
        cat_lower = category.lower()
        matches = {k: v for k, v in _X64DBG_COMMANDS.items() if cat_lower in k.lower()}
        if not matches:
            available = ", ".join(_X64DBG_COMMANDS.keys())
            return f"Unknown category '{category}'. Available: {available}"
    else:
        matches = _X64DBG_COMMANDS

    lines = []
    for cat, cmds in matches.items():
        lines.append(f"\n== {cat.upper()} ==")
        for cmd, desc in cmds:
            lines.append(f"  {cmd:50s} {desc}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Breakpoints
# ---------------------------------------------------------------------------

@mcp.tool()
def set_breakpoint(
    address_or_symbol: str,
    bp_type: str = "software",
    name: str | None = None,
    hardware_mode: str = "x",
    hardware_size: int = 1,
    memory_mode: str = "a",
    singleshot: bool = False,
) -> str:
    """Set a breakpoint (software, hardware, or memory).

    Hardware breakpoints are verified after arming: the result reports the actual
    debug-register arm (slot + size) instead of a bare "Breakpoint set.", so a
    silent software fallback or exhausted-slot failure is never mistaken for success.

    Args:
        address_or_symbol: Hex address or symbol name
        bp_type: 'software', 'hardware', or 'memory'
        name: Optional breakpoint name (software only)
        hardware_mode: Hardware BP mode: 'r' (read), 'w' (write), 'x' (execute)
        hardware_size: Hardware BP watch size, one of 1, 2, 4, 8 bytes (e.g. 4 to
            watch a full dword; 8 for a qword). Only with bp_type='hardware'.
        memory_mode: Memory BP mode: 'r', 'w', 'x', 'a' (access)
        singleshot: Single-shot breakpoint
    """
    try:
        client = _require_client()
        # Parse address; if it fails, treat as symbol name
        try:
            addr: int | str = _parse_address_or_expression(address_or_symbol)
        except (ValueError, TypeError):
            addr = address_or_symbol

        if bp_type == "hardware":
            if hardware_size not in (1, 2, 4, 8):
                raise ValueError(
                    f"Invalid hardware_size {hardware_size}: expected 1, 2, 4, or 8 bytes"
                )
            hw = HardwareBreakpointType(hardware_mode)
            result = client.set_hardware_breakpoint(addr, bp_type=hw, size=hardware_size)
            if not result:
                return (
                    f"Failed to set hardware BP at {address_or_symbol} [{hardware_mode}] — "
                    "all 4 debug slots may be exhausted or the address is unsupported."
                )
            # Verify-after-set: report the ACTUAL arm so a SW fallback or lost slot
            # is visible instead of a bare success.
            try:
                hw_bps = client.get_breakpoints(BreakpointType.BpHardware)
            except Exception:
                hw_bps = []
            match_target = addr if isinstance(addr, int) else None
            hit = None
            for bp in hw_bps or []:
                if bp.enabled and (match_target is None or bp.addr == match_target):
                    hit = bp
                    break
            if hit is not None:
                return (
                    f"Hardware BP set at {_format_address(hit.addr)} [{hardware_mode}] "
                    f"size={hit.hwSize} confirmed (slot {hit.slot})"
                )
            return (
                f"Hardware BP set at {address_or_symbol} [{hardware_mode}] size={hardware_size} "
                "but NOT verified — no enabled hardware breakpoint listed at that address "
                "(may have fallen back to a software BP)."
            )
        elif bp_type == "memory":
            mm = MemoryBreakpointType(memory_mode)
            result = client.set_memory_breakpoint(addr, bp_type=mm, singleshoot=singleshot)
        else:
            result = client.set_breakpoint(addr, name=name, singleshoot=singleshot)

        return f"Breakpoint set at {address_or_symbol}." if result else "Failed to set breakpoint."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def clear_breakpoint(address: str | None = None, bp_type: str = "software") -> str:
    """Clear breakpoint(s).

    Args:
        address: Hex address or symbol (None clears all of this type)
        bp_type: 'software', 'hardware', or 'memory'
    """
    try:
        client = _require_client()
        target: int | str | None = None
        if address is not None:
            try:
                target = _parse_address_or_expression(address)
            except (ValueError, TypeError):
                target = address

        if bp_type == "hardware":
            result = client.clear_hardware_breakpoint(target)
        elif bp_type == "memory":
            result = client.clear_memory_breakpoint(target)
        else:
            result = client.clear_breakpoint(target)

        return "Breakpoint(s) cleared." if result else "Failed to clear breakpoint(s)."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def toggle_breakpoint(address: str | None = None, bp_type: str = "software", enable: bool = True) -> str:
    """Enable or disable breakpoint(s).

    Args:
        address: Hex address or symbol (None toggles all of this type)
        bp_type: 'software', 'hardware', or 'memory'
        enable: True to enable, False to disable
    """
    try:
        client = _require_client()
        target: int | str | None = None
        if address is not None:
            try:
                target = _parse_address_or_expression(address)
            except (ValueError, TypeError):
                target = address

        if bp_type == "hardware":
            result = client.toggle_hardware_breakpoint(target, on=enable)
        elif bp_type == "memory":
            result = client.toggle_memory_breakpoint(target, on=enable)
        else:
            result = client.toggle_breakpoint(target, on=enable)

        action = "Enabled" if enable else "Disabled"
        return f"{action} breakpoint(s)." if result else f"Failed to {action.lower()} breakpoint(s)."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def list_breakpoints(bp_type: str = "software") -> str:
    """List all breakpoints of a given type.

    Args:
        bp_type: 'software', 'hardware', or 'memory'
    """
    try:
        client = _require_client()
        type_map = {
            "software": BreakpointType.BpNormal,
            "hardware": BreakpointType.BpHardware,
            "memory": BreakpointType.BpMemory,
        }
        bt = type_map.get(bp_type, BreakpointType.BpNormal)
        bps = client.get_breakpoints(bt)
        if not bps:
            return f"No {bp_type} breakpoints set."
        lines = []
        for bp in bps:
            status = "ON" if bp.enabled else "OFF"
            extra = f"  Slot: {bp.slot}  Size: {bp.hwSize}" if bt == BreakpointType.BpHardware else ""
            lines.append(
                f"{_format_address(bp.addr)}  [{status}]  Name: {bp.name}  "
                f"Module: {bp.mod}  Hits: {bp.hitCount}  Singleshot: {bp.singleshoot}{extra}"
            )
        return "\n".join(lines)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def get_hardware_slots() -> str:
    """Report which of the 4 debug-register slots are occupied (and by what).

    Diagnoses hardware-breakpoint exhaustion at a glance: x64dbg only has 4 DRx
    slots, and set_breakpoint(bp_type='hardware') fails or falls back when they
    are full. Run this before arming a watch if slots may already be taken.

    Returns:
        One line per slot 0-3: '<slot>: <address> mode=<r/w/x> size=<N> name=<N>'
        or '<slot>: free'. Also lists any reported hardware BPs without a valid slot.
    """
    try:
        client = _require_client()
        bps = client.get_breakpoints(BreakpointType.BpHardware) or []
        occupied: dict[int, object] = {}
        extras = []
        for bp in bps:
            if bp.enabled and bp.slot >= 0 and bp.slot < 4:
                occupied.setdefault(bp.slot, bp)
            else:
                extras.append(bp)
        lines = ["Hardware breakpoint slots (4 total):"]
        for slot in range(4):
            bp = occupied.get(slot)
            if bp is None:
                lines.append(f"  Slot {slot}: free")
            else:
                lines.append(
                    f"  Slot {slot}: {_format_address(bp.addr)} size={bp.hwSize} "
                    f"name={bp.name or '-'}"
                )
        if extras:
            lines.append("[note: %d hardware BP(s) reported without a valid slot]" % len(extras))
        return "\n".join(lines)
    except Exception as e:
        return f"Error: {e}"


# ---------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------

@mcp.tool()
def disassemble(address: str, count: int = 10) -> str:
    """Disassemble instructions at an address.

    Args:
        address: Address — hex ('0x401000'), register ('RIP'), symbol, or expression
        count: Number of instructions to disassemble (max 100)
    """
    try:
        client = _require_client()
        addr = _parse_address_or_expression(address)
        count = min(count, 100)
        lines = []
        current = addr
        for _ in range(count):
            ins = client.disassemble_at(current)
            if ins is None:
                lines.append(f"{_format_address(current)}  ???")
                break
            lines.append(f"{_format_address(current)}  {ins.symbolized_instruction}")
            current += ins.instr_size
        return "\n".join(lines)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def assemble(address: str, instruction: str) -> str:
    """Assemble a single instruction at an address.

    Args:
        address: Hex address to assemble at
        instruction: Assembly instruction (e.g. 'nop', 'mov eax, 1')
    """
    try:
        client = _require_client()
        addr = _parse_address_or_expression(address)
        size = client.assemble_at(addr, instruction)
        if size is None:
            return f"Failed to assemble '{instruction}' at {_format_address(addr)}."
        return f"Assembled '{instruction}' at {_format_address(addr)} ({size} bytes)."
    except Exception as e:
        return f"Error: {e}"


# ---------------------------------------------------------------------------
# Annotations & Symbols
# ---------------------------------------------------------------------------

@mcp.tool()
def set_label(address: str, text: str) -> str:
    """Set a label at an address.

    Args:
        address: Hex address
        text: Label text
    """
    try:
        client = _require_client()
        addr = _parse_address_or_expression(address)
        result = client.set_label_at(addr, text)
        return f"Label set at {_format_address(addr)}." if result else "Failed to set label."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def get_label(address: str) -> str:
    """Get the label at an address.

    Args:
        address: Hex address
    """
    try:
        client = _require_client()
        addr = _parse_address_or_expression(address)
        label = client.get_label_at(addr)
        if not label:
            return f"No label at {_format_address(addr)}."
        return f"{_format_address(addr)}: {label}"
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def set_comment(address: str, text: str) -> str:
    """Set a comment at an address.

    Args:
        address: Hex address
        text: Comment text
    """
    try:
        client = _require_client()
        addr = _parse_address_or_expression(address)
        result = client.set_comment_at(addr, text)
        return f"Comment set at {_format_address(addr)}." if result else "Failed to set comment."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def get_comment(address: str) -> str:
    """Get the comment at an address.

    Args:
        address: Hex address
    """
    try:
        client = _require_client()
        addr = _parse_address_or_expression(address)
        comment = client.get_comment_at(addr)
        if not comment:
            return f"No comment at {_format_address(addr)}."
        return f"{_format_address(addr)}: {comment}"
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def get_symbol(address: str) -> str:
    """Look up the symbol at an address.

    Args:
        address: Hex address
    """
    try:
        client = _require_client()
        addr = _parse_address_or_expression(address)
        sym = client.get_symbol_at(addr)
        if sym is None:
            return f"No symbol at {_format_address(addr)}."
        return (
            f"Address: {_format_address(sym.addr)}\n"
            f"Decorated: {sym.decoratedSymbol}\n"
            f"Undecorated: {sym.undecoratedSymbol}\n"
            f"Type: {sym.type}  Ordinal: {sym.ordinal}"
        )
    except Exception as e:
        return f"Error: {e}"


# ---------------------------------------------------------------------------
# Threads
# ---------------------------------------------------------------------------

@mcp.tool()
def create_thread(entry_address: str, argument: str = "0") -> str:
    """Create a new thread in the debuggee.

    Args:
        entry_address: Hex address of the thread entry point
        argument: Hex value passed as thread argument
    """
    try:
        client = _require_client()
        addr = _parse_address_or_expression(entry_address)
        arg = _parse_address_or_expression(argument)
        tid = client.thread_create(addr, arg)
        if tid is None:
            return "Failed to create thread."
        return f"Thread created. TID: {tid}"
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def terminate_thread(tid: int) -> str:
    """Terminate a thread in the debuggee.

    Args:
        tid: Thread ID to terminate
    """
    try:
        client = _require_client()
        result = client.thread_terminate(tid)
        return f"Thread {tid} terminated." if result else f"Failed to terminate thread {tid}."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def pause_resume_thread(tid: int, action: str = "pause") -> str:
    """Pause or resume a thread.

    Args:
        tid: Thread ID
        action: 'pause' or 'resume'
    """
    try:
        client = _require_client()
        if action == "resume":
            result = client.thread_resume(tid)
            return f"Thread {tid} resumed." if result else f"Failed to resume thread {tid}."
        else:
            result = client.thread_pause(tid)
            return f"Thread {tid} paused." if result else f"Failed to pause thread {tid}."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def switch_thread(tid: int) -> str:
    """Switch the debugger's active thread context.

    Args:
        tid: Thread ID to switch to
    """
    try:
        client = _require_client()
        result = client.switch_thread(tid)
        return f"Switched to thread {tid}." if result else f"Failed to switch to thread {tid}."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def get_thread_list() -> str:
    """List all threads in the debuggee.

    Shows thread ID, start address, local base, and name for each thread.
    """
    try:
        client = _require_client()
        threads = client.get_threads()
        if not threads:
            return "No threads found."
        lines = []
        for t in threads:
            lines.append(
                f"TID: {t.thread_id}  |  Start: 0x{t.start_address:x}  |  "
                f"LocalBase: 0x{t.local_base:x}  |  Name: {t.thread_name or '(unnamed)'}"
            )
        return "\n".join(lines)
    except Exception as e:
        return f"Error: {e}"


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------

@mcp.tool()
def get_latest_event() -> str:
    """Pop the latest debug event from the event queue."""
    try:
        client = _require_client()
        event = client.get_latest_debug_event()
        if event is None:
            return "No events in queue."
        data_str = ""
        if event.event_data is not None:
            data_str = "\n" + "\n".join(
                f"  {k}: {v}" for k, v in event.event_data.model_dump().items()
            )
        return f"Event: {event.event_type}{data_str}"
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def wait_for_event(event_type: str, timeout: int = 5) -> str:
    """Wait for a specific debug event type — state-aware, never blocks on a silent target.

    This is a SHORT poll probe, not a long block. It returns on the first cycle
    where the debugger state says nothing can (or will) arrive:

    * Already-queued event            -> returned instantly;
    * Debuggee paused/stopped/idle    -> 'NOT WAITING: paused...' (events only fire
      while running — classify the stage instead of blocking, AGENTS.md rule 5);
    * Running, no event, no state     -> 'STILL RUNNING: no <EVENT> in ~1 s...' (loop
      change for ~1 s                  or bp never reached): re-poll or classify;
    * Debuggee stops, no event queued -> 'STOPPED...' (other stop reason / bp wiped).

    The full timeout is only ever consumed while the debugger is actively running,
    and even then the no-progress bail fires after ~1 s of silence. This is what
    prevents the classic hang: `go()` on a target that never hits the breakpoint
    (or is sitting at a form) no longer burns the entire timeout for nothing.

    Hard-capped: timeout > 5 s is refused immediately (never honored).

    Args:
        event_type: Event type name (e.g. 'EVENT_BREAKPOINT', 'EVENT_LOAD_DLL')
        timeout: Max seconds to wait (must be <= 5)
    """
    try:
        if timeout > MAX_DEBUGGER_WAIT_SECONDS:
            raise ValueError(
                f"wait_for_event timeout {timeout}s exceeds the {MAX_DEBUGGER_WAIT_SECONDS} s "
                f"hard cap (AGENTS.md rule 4). Pass timeout <= {MAX_DEBUGGER_WAIT_SECONDS}."
            )
        client = _require_client()
        et = EventType(event_type)

        if not client.is_debugging():
            return NO_DEBUGGEE_MSG

        def _fmt(event) -> str:
            data_str = ""
            if event.event_data is not None:
                data_str = "\n" + "\n".join(
                    f"  {k}: {v}" for k, v in event.event_data.model_dump().items()
                )
            return f"Event: {event.event_type}{data_str}"

        # Already-queued event -> return instantly. timeout=0 still scans the queue
        # once (events.py), so this costs nothing and never blocks.
        event = client.wait_for_debug_event(et, timeout=0)
        if event is not None:
            return _fmt(event)

        # Paused/idle: no debug event can fire until go()/step. Burn nothing.
        if not client.is_running():
            return (
                f"NOT WAITING: debuggee is paused/stopped, so {event_type} can only "
                "fire after go()/step. Classify the stage via enumerate_windows() or "
                "get_debugger_status() and decide — never block on a paused target."
            )

        start = time.monotonic()
        deadline = start + timeout
        while time.monotonic() < deadline:
            event = client.wait_for_debug_event(et, timeout=0.25)
            if event is not None:
                return _fmt(event)
            if not client.is_running():
                # State changed — the target stopped. One grace tick for the in-flight
                # SUB event, then report instead of waiting out the cap.
                event = client.wait_for_debug_event(et, timeout=0.25)
                if event is not None:
                    return _fmt(event)
                if not client.is_debugging():
                    return "Debuggee exited while waiting; no event arrived."
                return (
                    f"STOPPED: debuggee paused but no {event_type} was queued (stopped "
                    "for another reason, or the breakpoint was wiped). Read "
                    "get_debugger_status()/enumerate_windows() to classify."
                )
            if time.monotonic() - start >= WAIT_EVENT_NO_PROGRESS_SECONDS:
                return (
                    f"STILL RUNNING: no {event_type} in ~{WAIT_EVENT_NO_PROGRESS_SECONDS:g} s "
                    "with no state change (loop, or the breakpoint is never reached). "
                    "Re-poll, check get_debugger_status()/enumerate_windows(), or re-arm."
                )
        return f"Timed out waiting for {event_type} after {timeout}s."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def peek_latest_event() -> str:
    """Peek at the latest debug event without removing it from the queue.

    Unlike get_latest_event() which pops the event, this lets you check
    what happened without consuming it. Useful for polling while waiting
    for a specific condition.
    """
    try:
        client = _require_client()
        event = client.peek_latest_debug_event()
        if event is None:
            return "No events in queue."
        data_str = ""
        if event.event_data is not None:
            data_str = "\n" + "\n".join(
                f"  {k}: {v}" for k, v in event.event_data.model_dump().items()
            )
        return f"Event: {event.event_type}{data_str}"
    except Exception as e:
        return f"Error: {e}"


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

@mcp.tool()
def get_setting(section: str, name: str, type: str = "string") -> str:
    """Read an x64dbg setting.

    Args:
        section: Settings section name
        name: Setting name
        type: 'string' or 'int'
    """
    try:
        client = _require_client()
        if type == "int":
            val = client.get_setting_int(section, name)
        else:
            val = client.get_setting_str(section, name)
        if val is None:
            return f"Setting [{section}]{name} not found."
        return f"[{section}]{name} = {val}"
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def set_setting(section: str, name: str, value: str, type: str = "string") -> str:
    """Write an x64dbg setting.

    Args:
        section: Settings section name
        name: Setting name
        value: Setting value
        type: 'string' or 'int'
    """
    try:
        client = _require_client()
        if type == "int":
            result = client.set_setting_int(section, name, int(value))
        else:
            result = client.set_setting_str(section, name, value)
        return f"Setting [{section}]{name} updated." if result else "Failed to update setting."
    except Exception as e:
        return f"Error: {e}"


# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------

@mcp.tool()
def log_message(message: str) -> str:
    """Log a message to the x64dbg log window.

    Args:
        message: Message text to log
    """
    try:
        client = _require_client()
        result = client.log(message)
        return "Message logged." if result else "Failed to log message."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def get_log(since_index: int = 0, limit: int = 0, filter: str = "") -> str:
    """Read log messages from the current debug session.

    Returns all messages captured since the session started, or only new messages
    when since_index from a previous call is provided. Head semantics: when limit
    is set, the first `limit` matching entries are returned. Call again with the
    returned next_index to fetch the next page.

    Args:
        since_index: Index returned by a previous get_log call (0 for full session log)
        limit:       Maximum number of log lines to return (0 = unlimited). When set,
                     the first `limit` matching lines are returned (head semantics).
                     If remaining > 0, call again with next_index to get the next page.
        filter:      Substring to match against each log line — only matching lines are
                     returned. Empty string means no filtering.

    Returns:
        Log lines followed by metadata:
        - [next_index=N] always present; pass as since_index on the next call.
        - [remaining=N, call again with next_index=N] when more entries exist.
        - [WARNING: evicted=N entries lost before oldest available] when buffer cap
          was hit and the requested since_index is older than the oldest entry.
    """
    try:
        client = _require_client()
        next_index, messages, remaining, evicted = client.get_log(since_index, limit, filter)
        parts = []
        if evicted:
            parts.append(f"[WARNING: evicted={evicted} entries lost before oldest available]")
        if not messages:
            parts.append(f"No new log messages. next_index={next_index}")
            return "\n".join(parts)
        parts.append("\n".join(m.rstrip("\n") for m in messages))
        if remaining:
            parts.append(f"[remaining={remaining}, call again with next_index={next_index}]")
        parts.append(f"[next_index={next_index}]")
        return "\n".join(parts)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def refresh_gui() -> str:
    """Refresh all x64dbg GUI views."""
    try:
        client = _require_client()
        result = client.gui_refresh_views()
        return "GUI refreshed." if result else "Failed to refresh GUI."
    except Exception as e:
        return f"Error: {e}"


# ---------------------------------------------------------------------------
# Breakpoint Conditions & Logging
# ---------------------------------------------------------------------------

@mcp.tool()
def set_breakpoint_condition(address: str, condition: str, bp_type: str = "software") -> str:
    """Set a condition on a breakpoint.

    With bp_type='hardware' this uses x64dbg's bphwcond (SetHardwareBreakpointCondition)
    — no software breakpoint involved, so it works on pages where a SW BP would be
    wiped or detected (e.g. PAGECRYPT-protected regions).

    Args:
        address: Hex address of the breakpoint
        condition: x64dbg condition expression (e.g. 'eax == 1', '[0x76C30000] == 0x232')
        bp_type: 'software' (default) or 'hardware'
    """
    try:
        client = _require_client()
        addr = _parse_address_or_expression(address)
        if bp_type == "hardware":
            result = client.set_hardware_breakpoint_condition(addr, condition)
        else:
            result = client.set_breakpoint_condition(addr, condition)
        return f"Breakpoint condition set at {_format_address(addr)}." if result else "Failed to set condition."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def set_breakpoint_log(address: str, log_text: str, silent: bool = False, bp_type: str = "software") -> str:
    """Set log text on a breakpoint.

    With bp_type='hardware' this uses x64dbg's bphwlog (SetHardwareBreakpointLog)
    plus SetHardwareBreakpointSilent when silent=True — no software breakpoint
    involved, so log-without-breaking works on protected pages too.

    Args:
        address: Hex address of the breakpoint
        log_text: Text to log when the breakpoint is hit
        silent: If True, the breakpoint will not break execution
        bp_type: 'software' (default) or 'hardware'
    """
    try:
        client = _require_client()
        addr = _parse_address_or_expression(address)
        if bp_type == "hardware":
            result = client.set_hardware_breakpoint_log(addr, log_text, silent)
        else:
            result = client.set_breakpoint_log(addr, log_text, silent)
        return f"Breakpoint log set at {_format_address(addr)}." if result else "Failed to set log."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def set_breakpoint_command(address: str, command: str, bp_type: str = "software") -> str:
    """Set a command to execute automatically when a breakpoint is hit.

    With bp_type='hardware' this uses x64dbg's SetHardwareBreakpointCommand — no
    software breakpoint involved, so command-on-hit works on protected pages too.

    Args:
        address: Hex address of the breakpoint
        command: x64dbg command to execute on hit (e.g. 'r al=1' to set al to 1)
        bp_type: 'software' (default) or 'hardware'
    """
    try:
        client = _require_client()
        addr = _parse_address_or_expression(address)
        if bp_type == "hardware":
            result = client.set_hardware_breakpoint_command(addr, command)
        else:
            result = client.set_breakpoint_command(addr, command)
        return f"Breakpoint command set at {_format_address(addr)}." if result else "Failed to set command."
    except Exception as e:
        return f"Error: {e}"


# ---------------------------------------------------------------------------
# Stack Trace
# ---------------------------------------------------------------------------

@mcp.tool()
def get_stack_trace() -> str:
    """Get the current call stack."""
    try:
        client = _require_client()
        frames = client.get_stack_trace()
        if not frames:
            return "No stack frames."
        lines = []
        for i, frame in enumerate(frames):
            lines.append(f"#{i} {_format_address(frame.addr)} from {_format_address(frame.from_addr)}  {frame.comment}")
        return "\n".join(lines)
    except Exception as e:
        return f"Error: {e}"


# ---------------------------------------------------------------------------
# Memory Search
# ---------------------------------------------------------------------------

@mcp.tool()
def search_memory(address: str, size: int, pattern: str) -> str:
    """Search memory for a byte pattern.

    Args:
        address: Start address to search from
        size: Number of bytes to search
        pattern: Hex pattern to search for (e.g. '48 89 5C' or '48895C')
    """
    try:
        client = _require_client()
        addr = _parse_address_or_expression(address)
        cleaned = pattern.replace(" ", "").replace("\n", "")
        pat_bytes = bytes.fromhex(cleaned)
        results = client.search_memory(addr, size, pat_bytes)
        if not results:
            return "Pattern not found."
        lines = [f"{_format_address(a)}" for a in results[:100]]
        if len(results) > 100:
            lines.append(f"... and {len(results) - 100} more")
        return f"Found {len(results)} match(es):\n" + "\n".join(lines)
    except Exception as e:
        return f"Error: {e}"


# ---------------------------------------------------------------------------
# Threads
# ---------------------------------------------------------------------------

@mcp.tool()
def get_threads() -> str:
    """List all threads in the debuggee."""
    try:
        client = _require_client()
        threads = client.get_threads()
        if not threads:
            return "No threads found."
        lines = []
        for t in threads:
            name = f"  ({t.thread_name})" if t.thread_name else ""
            lines.append(
                f"TID: {t.thread_id}  Start: {_format_address(t.start_address)}  "
                f"LocalBase: {_format_address(t.local_base)}{name}"
            )
        return "\n".join(lines)
    except Exception as e:
        return f"Error: {e}"


# ---------------------------------------------------------------------------
# String Reading
# ---------------------------------------------------------------------------

@mcp.tool()
def read_string(address: str, max_len: int = 512) -> str:
    """Read a null-terminated string from debuggee memory.

    Args:
        address: Hex address to read from
        max_len: Maximum number of bytes to read
    """
    try:
        client = _require_client()
        addr = _parse_address_or_expression(address)
        text = client.read_string_at(addr, max_len)
        if not text:
            return f"No string at {_format_address(addr)}."
        return f"{_format_address(addr)}: \"{text}\""
    except Exception as e:
        return f"Error: {e}"


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    """Run the MCP server with stdio transport."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
