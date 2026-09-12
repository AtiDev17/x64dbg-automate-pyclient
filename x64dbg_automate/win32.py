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
            raise OSError(
                f"ReadProcessMemory failed for PID {pid} at 0x{address:X} "
                "(bad address or unreadable region)"
            )
        return buf.raw[:nread.value]
    finally:
        CloseHandle(handle)