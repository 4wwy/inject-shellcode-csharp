using System;
using System.Runtime.InteropServices;

namespace TaskManagerLoader
{
    [StructLayout(LayoutKind.Sequential)]
    public struct OBJECT_ATTRIBUTES
    {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CLIENT_ID
    {
        public IntPtr UniqueProcess;
        public IntPtr UniqueThread;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 16)]
    public struct CONTEXT64
    {
        public ulong P1Home;
        public ulong P2Home;
        public ulong P3Home;
        public ulong P4Home;
        public ulong P5Home;
        public ulong P6Home;
        public uint ContextFlags;
        public uint MxCsr;
        public ushort SegCs;
        public ushort SegDs;
        public ushort SegEs;
        public ushort SegFs;
        public ushort SegGs;
        public ushort SegSs;
        public uint EFlags;
        public ulong Dr0;
        public ulong Dr1;
        public ulong Dr2;
        public ulong Dr3;
        public ulong Dr6;
        public ulong Dr7;
        public ulong Rax;
        public ulong Rcx;
        public ulong Rdx;
        public ulong Rbx;
        public ulong Rsp;
        public ulong Rbp;
        public ulong Rsi;
        public ulong Rdi;
        public ulong R8;
        public ulong R9;
        public ulong R10;
        public ulong R11;
        public ulong R12;
        public ulong R13;
        public ulong R14;
        public ulong R15;
        public ulong Rip;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_DOS_HEADER
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
        public char[] e_magic;
        public ushort e_cblp;
        public ushort e_cp;
        public ushort e_crlc;
        public ushort e_cparhdr;
        public ushort e_minalloc;
        public ushort e_maxalloc;
        public ushort e_ss;
        public ushort e_sp;
        public ushort e_csum;
        public ushort e_ip;
        public ushort e_cs;
        public ushort e_lfarlc;
        public ushort e_ovno;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public ushort[] e_res1;
        public ushort e_oemid;
        public ushort e_oeminfo;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
        public ushort[] e_res2;
        public int e_lfanew;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_FILE_HEADER
    {
        public ushort Machine;
        public ushort NumberOfSections;
        public uint TimeDateStamp;
        public uint PointerToSymbolTable;
        public uint NumberOfSymbols;
        public ushort SizeOfOptionalHeader;
        public ushort Characteristics;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct IMAGE_SECTION_HEADER
    {
        [FieldOffset(0)]
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public char[] Name;
        [FieldOffset(8)]
        public uint VirtualSize;
        [FieldOffset(12)]
        public uint VirtualAddress;
        [FieldOffset(16)]
        public uint SizeOfRawData;
        [FieldOffset(20)]
        public uint PointerToRawData;
        [FieldOffset(24)]
        public uint PointerToRelocations;
        [FieldOffset(28)]
        public uint PointerToLinenumbers;
        [FieldOffset(32)]
        public ushort NumberOfRelocations;
        [FieldOffset(34)]
        public ushort NumberOfLinenumbers;
        [FieldOffset(36)]
        public uint Characteristics;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_EXPORT_DIRECTORY
    {
        public uint Characteristics;
        public uint TimeDateStamp;
        public ushort MajorVersion;
        public ushort MinorVersion;
        public uint Name;
        public uint Base;
        public uint NumberOfFunctions;
        public uint NumberOfNames;
        public uint AddressOfFunctions;
        public uint AddressOfNames;
        public uint AddressOfNameOrdinals;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct VX_TABLE_ENTRY
    {
        public IntPtr pAddress;
        public ulong dwHash;
        public ushort wSystemCall;
        public IntPtr upSysAddress;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct VX_TABLE
    {
        public VX_TABLE_ENTRY NtOpenProcess;
        public VX_TABLE_ENTRY NtAllocateVirtualMemory;
        public VX_TABLE_ENTRY NtWriteVirtualMemory;
        public VX_TABLE_ENTRY NtProtectVirtualMemory;
        public VX_TABLE_ENTRY NtOpenThread;
        public VX_TABLE_ENTRY NtSuspendThread;
        public VX_TABLE_ENTRY NtResumeThread;
        public VX_TABLE_ENTRY NtQuerySystemInformation;
        public VX_TABLE_ENTRY NtDuplicateObject;
        public VX_TABLE_ENTRY NtQueryInformationThread;
        public VX_TABLE_ENTRY NtQueryInformationProcess;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct THREAD_BASIC_INFORMATION
    {
        public int ExitStatus;
        public IntPtr TebBaseAddress;
        public CLIENT_ID ClientId;
        public IntPtr AffinityMask;
        public int Priority;
        public int BasePriority;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SYSTEM_HANDLE_TABLE_ENTRY_INFO
    {
        public ushort ProcessId;
        public ushort CreatorBackTraceIndex;
        public byte ObjectTypeNumber;
        public byte Flags;
        public ushort Handle;
        public IntPtr Object;
        public uint GrantedAccess;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SYSTEM_HANDLE_INFORMATION
    {
        public uint NumberOfHandles;
        public SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles;
    }

    public enum SYSTEM_INFORMATION_CLASS : uint
    {
        SystemHandleInformation = 16,
        SystemProcessInformation = 5
    }

    public static class NativeConstants
    {
        public const uint PROCESS_ALL_ACCESS = 0x001F0FFF;
        public const uint THREAD_ALL_ACCESS = 0x001F03FF;
        public const uint MEM_COMMIT = 0x1000;
        public const uint MEM_RESERVE = 0x2000;
        public const uint PAGE_EXECUTE_READ = 0x20;
        public const uint PAGE_READWRITE = 0x04;
        public const uint CONTEXT_FULL = 0x10007;
        public const uint PROCESS_DUP_HANDLE = 0x00000040;
        public const ushort IMAGE_DOS_SIGNATURE = 0x5A4D;
        public const int IMAGE_NT_SIGNATURE = 0x00004550;
    }
}

