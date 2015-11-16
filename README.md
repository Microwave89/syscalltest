# syscalltest
PoC for Bypassing UM Hooks By Bruteforcing Intel Syscalls (finished)

For a detailed description see: http://www.kernelmode.info/forum/viewtopic.php?f=15&t=3997.

Notes...:
We may find further syscalls by iterating over the syscall numbers previous to creation of the lookup table by breaking the iteration after we got telltale and unique NTSTATUS values returned. Interesting APIs (not tested) might include:
- NtUnmapViewOfSection (STATUS_NOT_MAPPED_VIED)
- ...
