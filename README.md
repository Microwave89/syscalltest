# syscalltest
PoC for Bypassing UM Hooks By Bruteforcing Intel Syscalls (finished)

For a detailed description see: http://www.kernelmode.info/forum/viewtopic.php?f=15&t=3997.
NOTE: Due to only minimum information retrieval of the on-disk ntdll.dll file the change of the x64 system call stubs occurred in Windows 10 10525+ luckily do NOT affect the function of this project.

Notes...:
We may find further syscalls by iterating over the syscall numbers previous to creation of the lookup table by breaking the iteration after we got telltale and unique NTSTATUS values returned. Interesting APIs (not tested) might include:
- NtUnmapViewOfSection (STATUS_NOT_MAPPED_VIED)
- ...
