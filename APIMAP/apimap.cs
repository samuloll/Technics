using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

public unsafe class RealPEParsing
{
    // =============================================================
    // PART 1: NATIVE IMPORTS
    // =============================================================

    [DllImport("ntdll.dll")]
    public static extern int NtQueryInformationProcess(
        IntPtr ProcessHandle,
        int ProcessInformationClass,
        ref PROCESS_BASIC_INFORMATION ProcessInformation,
        int ProcessInformationLength,
        out int ReturnLength);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
    public static extern IntPtr GetModuleHandle(string lpModuleName);


    // =============================================================
    // PART 2: LOW-LEVEL STRUCTS (FIXED FOR POINTER SAFETY)
    // =============================================================

    // 1. DOS HEADER (Using Explicit Layout to safely skip the junk)
    [StructLayout(LayoutKind.Explicit)]
    public struct IMAGE_DOS_HEADER
    {
        [FieldOffset(0)]
        public ushort e_magic;      // Magic number (MZ)
        
        // We skip the 'e_res' array entirely!
        
        [FieldOffset(0x3C)]
        public int e_lfanew;        // Offset to NT Header
    }

    // 2. EXPORT DIRECTORY (Sequential is fine here, no arrays)
    [StructLayout(LayoutKind.Sequential)]
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

    // 3. PEB & LDR (The Critical Fixes)
    
    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_BASIC_INFORMATION
    {
        public IntPtr ExitStatus;
        public IntPtr PebBaseAddress; // <--- The Goal
        public IntPtr AffinityMask;
        public IntPtr BasePriority;
        public IntPtr UniqueProcessId;
        public IntPtr InheritedFromUniqueProcessId;
    }

    // FIX: Use Explicit Layout to ensure 'Ldr' is at exactly offset 0x18 (x64)
    [StructLayout(LayoutKind.Explicit)]
    public struct PEB
    {
        // We don't need the Reserved arrays, just the Ldr pointer at the right spot
        [FieldOffset(0x18)]
        public IntPtr Ldr; 
    }


    [StructLayout(LayoutKind.Sequential)]
    public struct LIST_ENTRY
    {
        public IntPtr Flink; // Next
        public IntPtr Blink; // Previous
    }

    // FIX: Use Explicit Layout to ensure 'InMemoryOrderModuleList' is at 0x20
    [StructLayout(LayoutKind.Explicit)]
    public struct PEB_LDR_DATA
    {
        [FieldOffset(0x10)]
        public LIST_ENTRY InLoadOrderModuleList;
        
        [FieldOffset(0x20)]
        public LIST_ENTRY InMemoryOrderModuleList; // <--- The list we walk
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer; 
    }

    [StructLayout(LayoutKind.Explicit, Size = 0x80)]
    public struct LDR_DATA_TABLE_ENTRY
    {
        // Offset 0x10 is critical for the "Magic Math" subtraction
        [FieldOffset(0x10)]
        public LIST_ENTRY InMemoryOrderLinks;

        [FieldOffset(0x30)]
        public IntPtr DllBase; 

        [FieldOffset(0x58)]
        public UNICODE_STRING BaseDllName; 
    }


    // =============================================================
    // PART 3: THE MANUAL LOGIC
    // =============================================================

    public static IntPtr GetModuleHandleManual(string moduleName)
    {
        PROCESS_BASIC_INFORMATION pbi = new PROCESS_BASIC_INFORMATION();
        int returnLength;
        // 0 = ProcessBasicInformation
        int status = NtQueryInformationProcess(Process.GetCurrentProcess().Handle, 0, ref pbi, Marshal.SizeOf(pbi), out returnLength);

        if (status != 0 || pbi.PebBaseAddress == IntPtr.Zero) 
        {
            Console.WriteLine("[-] Failed to get PEB address.");
            return IntPtr.Zero;
        }

        PEB* pPeb = (PEB*)pbi.PebBaseAddress;
        
        // Safety Check: Is Ldr null?
        if (pPeb->Ldr == IntPtr.Zero) 
        {
             Console.WriteLine("[-] Ldr pointer is null.");
             return IntPtr.Zero;
        }

        PEB_LDR_DATA* pLdr = (PEB_LDR_DATA*)pPeb->Ldr;

        LIST_ENTRY* pListHead = &pLdr->InMemoryOrderModuleList;
        LIST_ENTRY* pCurrentEntry = (LIST_ENTRY*)pListHead->Flink;

        // Loop protection to prevent infinite loops if memory is corrupted
        int maxIterations = 100; 
        int i = 0;

        while (pCurrentEntry != pListHead && i < maxIterations)
        {
            i++;
            
            // MAGIC MATH: Go back 0x10 bytes to find the start of the Entry
            LDR_DATA_TABLE_ENTRY* pEntry = (LDR_DATA_TABLE_ENTRY*)((byte*)pCurrentEntry - 0x10);

            // Safety Check: Is the name buffer valid?
            if (pEntry->BaseDllName.Buffer != IntPtr.Zero && pEntry->BaseDllName.Length > 0)
            {
                try {
                    string currentDllName = Marshal.PtrToStringUni(pEntry->BaseDllName.Buffer, pEntry->BaseDllName.Length / 2);
                    
                    if (!string.IsNullOrEmpty(currentDllName) && 
                        currentDllName.Equals(moduleName, StringComparison.OrdinalIgnoreCase))
                    {
                        Console.WriteLine($"[+] PEB Walk: Found {moduleName} at 0x{pEntry->DllBase:X}");
                        return pEntry->DllBase;
                    }
                } 
                catch 
                {
                    // Swallow string errors (rare memory access issue)
                }
            }

            // Move Next
            pCurrentEntry = (LIST_ENTRY*)pCurrentEntry->Flink;
            
            // Safety: If Flink is null, stop
            if (pCurrentEntry == null) break; 
        }

        return IntPtr.Zero;
    }

    public static IntPtr GetFunctionAddress(string moduleName, string functionName)
    {
        IntPtr baseAddress = GetModuleHandleManual(moduleName);
        
        if (baseAddress == IntPtr.Zero) {
            Console.WriteLine($"[-] Could not find module: {moduleName}");
            return IntPtr.Zero;
        }

        byte* pBase = (byte*)baseAddress;

        // DOS -> NT
        int e_lfanew = *(int*)(pBase + 0x3C);
        byte* pNtHeaders = pBase + e_lfanew;

        // Export Directory RVA (0x88 is offset for x64)
        uint exportDirRva = *(uint*)(pNtHeaders + 0x18 + 0x70);

        if (exportDirRva == 0) return IntPtr.Zero;

        IMAGE_EXPORT_DIRECTORY* pExportDir = (IMAGE_EXPORT_DIRECTORY*)(pBase + exportDirRva);

        uint* pAddressOfFunctions = (uint*)(pBase + pExportDir->AddressOfFunctions);
        uint* pAddressOfNames     = (uint*)(pBase + pExportDir->AddressOfNames);
        ushort* pAddressOfOrdinals= (ushort*)(pBase + pExportDir->AddressOfNameOrdinals);

        for (uint i = 0; i < pExportDir->NumberOfNames; i++)
        {
            string currentFuncName = Marshal.PtrToStringAnsi((IntPtr)(pBase + pAddressOfNames[i]));

            if (currentFuncName == functionName)
            {
                ushort ordinal = pAddressOfOrdinals[i];
                uint functionRva = pAddressOfFunctions[ordinal];
                IntPtr finalAddress = (IntPtr)(pBase + functionRva);

                Console.WriteLine($"[+] Export Parse: Found {functionName} at 0x{finalAddress:X}");
                return finalAddress;
            }
        }

        return IntPtr.Zero;
    }

    // =============================================================
    // PART 4: EXECUTION
    // =============================================================
    public static void Main()
    {
        Console.WriteLine("--- LOW LEVEL VALIDATION TEST ---");

        string targetDll = "kernel32.dll";
        string targetFunc = "WinExec";

        IntPtr manualAddr = GetFunctionAddress(targetDll, targetFunc);

        // Verify with OS
        IntPtr osHandle = GetModuleHandle(targetDll);
        IntPtr osAddr = GetProcAddress(osHandle, targetFunc);

        Console.WriteLine("\n--- RESULTS ---");
        Console.WriteLine($"Manual Address: 0x{manualAddr:X}");
        Console.WriteLine($"OS API Address: 0x{osAddr:X}");

        if (manualAddr == osAddr && manualAddr != IntPtr.Zero)
        {
            Console.WriteLine("[SUCCESS] The addresses match exactly!");
        }
        else
        {
            Console.WriteLine("[FAIL] Mismatch or not found.");
        }

        Console.ReadKey();
    }
}