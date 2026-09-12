import ctypes
from ctypes import wintypes


K32 = ctypes.windll.kernel32
U32 = ctypes.windll.user32

CloseHandle = K32.CloseHandle
CloseHandle.argtypes = [ctypes.c_void_p]

OpenProcess = K32.OpenProcess
OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_bool, ctypes.c_uint32]

CreateRemoteThread = K32.CreateRemoteThread
CreateRemoteThread.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p]

WaitForSingleObject = K32.WaitForSingleObject
WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]

SetConsoleCtrlHandler = K32.SetConsoleCtrlHandler
SetConsoleCtrlHandler.argtypes = [ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_int), ctypes.c_bool]

GetTempPathW = K32.GetTempPathW
GetTempPathW.argtypes = [ctypes.c_uint32, ctypes.c_wchar_p]

# External, non-pausing process reads (see read_process_memory below).
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400

# Memory region states/protections for read_memory_external's size=0 region
# measurement (VirtualQueryEx). Same values as in models.py.
MEM_COMMIT = 0x1000
PAGE_NOACCESS = 0x01
PAGE_EXECUTE = 0x10


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    """_MEMORY_BASIC_INFORMATION — what VirtualQueryEx reports about one region."""

    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("PartitionId", wintypes.WORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


VirtualQueryEx = K32.VirtualQueryEx
VirtualQueryEx.argtypes = [
    ctypes.c_void_p,                              # hProcess
    ctypes.c_void_p,                              # lpBaseAddress
    ctypes.POINTER(MEMORY_BASIC_INFORMATION),     # lpBuffer
    ctypes.c_size_t,                              # dwLength
]
VirtualQueryEx.restype = ctypes.c_size_t

ReadProcessMemory = K32.ReadProcessMemory
ReadProcessMemory.argtypes = [
    ctypes.c_void_p,     # hProcess
    ctypes.c_void_p,     # lpBaseAddress
    ctypes.c_void_p,     # lpBuffer
    ctypes.c_size_t,     # nSize
    ctypes.POINTER(ctypes.c_size_t),  # lpNumberOfBytesRead
]
ReadProcessMemory.restype = ctypes.c_bool

EnumWindows = U32.EnumWindows
EnumWindows.argtypes = [ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p), ctypes.c_void_p]

GetWindowTextW = U32.GetWindowTextW
GetWindowTextW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_int]

GetClassNameW = U32.GetClassNameW
GetClassNameW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_int]

GetWindowRect = U32.GetWindowRect
GetWindowRect.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.RECT)]

GetWindowThreadProcessId = U32.GetWindowThreadProcessId
GetWindowThreadProcessId.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

EnumChildWindows = U32.EnumChildWindows
EnumChildWindows.argtypes = [ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p), ctypes.c_void_p, ctypes.c_void_p]

IsWindowVisible = U32.IsWindowVisible
IsWindowVisible.argtypes = [ctypes.c_void_p]
IsWindowVisible.restype = ctypes.c_bool


def read_process_memory(pid: int, address: int, size: int) -> bytes:
    """Read ``size`` bytes from an external process's address space without pausing it.

    Uses a bare ``OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION)`` +
    ``ReadProcessMemory`` — never touches the debugger or the target's execution
    state, so it is safe to sample a running (even protected) process.

    Args:
        pid: Target process id.
        address: Base address to read from.
        size: Number of bytes to request.

    Returns:
        The bytes actually read (may be shorter than requested if the readable
        region ends early).

    Raises:
        ProcessLookupError: OpenProcess failed (pid not running or access denied).
        OSError: ReadProcessMemory failed (bad address or unreadable region).
    """
    handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not handle:
        raise ProcessLookupError(
            f"Cannot open PID {pid} for reading (process may not exist or access is denied)"
        )
    try:
        buf = ctypes.create_string_buffer(size)
        nread = ctypes.c_size_t(0)
        ok = ReadProcessMemory(handle, ctypes.c_void_p(address), buf, size, ctypes.byref(nread))
        if not ok:
            # A failing read that still copied bytes is a partial read: the region
            # shrank between sizing and this read (a running target mutates its own
            # memory). Return the readable prefix rather than discarding it.
            if nread.value > 0:
                return buf.raw[:nread.value]
            raise OSError(
                f"ReadProcessMemory failed for PID {pid} at 0x{address:X} "
                "(bad address or unreadable region)"
            )
        return buf.raw[:nread.value]
    finally:
        CloseHandle(handle)


def readable_region_size(pid: int, address: int) -> int:
    """Bytes readable from ``address`` to the end of its region, or 0.

    Measures the containing region with ``VirtualQueryEx`` (no debugger, no pause)
    so a caller can size a read that stays entirely inside committed, readable
    memory. Mirrors the in-debugger region rules: MEM_COMMIT with a readable
    protection is required; PAGE_GUARD stays eligible because ReadProcessMemory
    does not trip guard semantics.

    Args:
        pid: Target process id.
        address: Base address to measure from.

    Returns:
        The number of readable bytes from ``address`` to the end of its region, or
        0 when the address is not in a readable MEM_COMMIT region.

    Raises:
        ProcessLookupError: OpenProcess failed (pid not running or access denied).
        OSError: VirtualQueryEx failed.
    """
    handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not handle:
        raise ProcessLookupError(
            f"Cannot open PID {pid} for reading (process may not exist or access is denied)"
        )
    try:
        mbi = MEMORY_BASIC_INFORMATION()
        written = VirtualQueryEx(
            handle,
            ctypes.c_void_p(address),
            ctypes.byref(mbi),
            ctypes.sizeof(MEMORY_BASIC_INFORMATION),
        )
        if not written:
            raise OSError(
                f"VirtualQueryEx failed for PID {pid} at 0x{address:X} (bad address)"
            )
        if mbi.State != MEM_COMMIT:
            return 0
        # Readable = anything but PROTECT_NONE, PAGE_NOACCESS, or PAGE_EXECUTE-only.
        if (mbi.Protect & 0xFF) in (0x00, PAGE_NOACCESS, PAGE_EXECUTE):
            return 0
        offset = address - (mbi.BaseAddress or 0)
        if offset < 0 or offset >= (mbi.RegionSize or 0):
            return 0
        return mbi.RegionSize - offset
    finally:
        CloseHandle(handle)