# PE Export Directory Parsing and Custom API Resolution
![NetVersion](https://img.shields.io/badge/.NET-8.0-purple)
![Platform](https://img.shields.io/badge/Platform-x64-lightgrey)
![Status](https://img.shields.io/badge/Status-PoC%20Working-brightgreen)


> [!CAUTION]
> Only use this on a system where you have permission.
> This is for educational purposes only.


### Functions of kernel32.dll  and ntdll.dll used here

```csharp
[DllImport("ntdll.dll")]
    public static extern int NtQueryInformationProcess(
        IntPtr ProcessHandle,
        int ProcessInformationClass,
        ref PROCESS_BASIC_INFORMATION ProcessInformation,
        int ProcessInformationLength,
        out int ReturnLength);
```
* We are bypassing the friendly Win32 API layer and talking directly to the Native API
* int return
    * NTSTATUS
        * 0x00000000 (STATUS_SUCCES) &rarr; worked
        * Any other is a kernel-level failure
* `IntPtr ProcessHandle`
    * Which process we want to check
* `int ProcessInformationClass`
    * What do we want to know
    * We pass an enum
* `ref PROCESS_BASIC_INFORMATION ProcessInformation`
    * put the answer into this struct
* `int ProcessInformationLength`
    * Size of the searched information
* `out ReturnLength`
    * How much bytes did you give actually
```csharp
[DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
```
* `CharSet.Ansi`
    * This is critical 
    * C# uses for string UTF-16, 2 bytes per character, but GetProcAddress is an old one, which only accepts ANSI strings (1 byte per character)
* Gives back the Procedure address in the provided module
```csharp
    [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
    public static extern IntPtr GetModuleHandle(string lpModuleName);
```
* `CharSet.Auto`
    * Because this function is follows the Modern Standard, so C# can decide, what charset to use
* Gives back the module handle(Start-up address), so we can use it in the function above mentioned

### Struct used
##### IMAGE_DOS_HEADER
```csharp
[StructLayout(LayoutKind.Explicit)]
public struct IMAGE_DOS_HEADER
{
    [FieldOffset(0)]
    public ushort e_magic;  
    
    // We skip the 'e_res' array entirely!
    
    [FieldOffset(0x3C)]
    public int e_lfanew;
}
```
* Every Windows program Starts with this header
* `[StructLayout(LayoutKind.Explicit)]`
    * This turns off the automatic organization. The compiler will now wait for your specific coordinates for every single field.
* `[FieldOffset(0)]`
    * Coordinate: Start at byte 0.
* `public ushort e_magic`
    * First 2 bytes of the header
    * If the program valid, it reads `MZ` in ASCII values
> [!NOTE]
> `[MarshalAs(UnmanagedType.ByValArray, SizeConst = 60)]`
> * in C# arrays are dynamic, this line is telling the program to treat this array as a constant size of 60 byte
* `public byte[] e_res`
    * empty code, or code used by MS-DOS
> [!NOTE]
> MS-DOS (Microsoft Disk Operating System)
> The Era: It was dominant in the 1980s and early 90s.
* `public int e_lfanew`
    * Holds an offset to how far is the NT (New Technology) header
    * From the start address (Handle + offset)
##### IMAGE_EXPORT_DIRECTORY
```csharp
[StructLayout(LayoutKind.Sequential)]
public struct IMAGE_EXPORT_DIRECTORY {
    public uint Characteristics;
    public uint TimeDateStamp;
    public ushort MajorVersion;
    public ushort MinorVersion;
    public uint Name;
    public uint Base;
    public uint NumberOfFunctions;
    public uint NumberOfNames;
    public uint AddressOfFunctions;     // The array of Function Addresses
    public uint AddressOfNames;         // The array of Name Strings
    public uint AddressOfNameOrdinals;  // The "Brid
}
```
* This structure is the Public Menu of the DLL
* `public uint Characteristics`
    * Reserved/Unused (usually 0)
* `public uint TimeDateStamp`
    * The exact second the DLL was compiled. Could be used to spot fake DLLs
* `public ushort MajorVersion / MinorVersion`
    * User-defined version numbers (rarely used today)
* `public uint Name`
    * Points to the name of the DLL itself
* `public uint Base`
    * The starting number for the Ordinals (usually 1)
* `public uint AddressOfNames`
    * Contains an offset of 4 bytes
    * Handle + offset &rarr; An array, which contains RVAs (Relative Virtual Addresses)
    * searched function('WinExec')
        * Handle + Offset &rarr; array
        * array[0] = An offset aswell
            * handle + array[0] == "WinExec"
* `public uint AddressOfFunctions`
    * Points to an array of memory addresses where the actual executable code begins
* `public uint AddressOfNameOrdinals`
    * The "Name List" and the "Function List" are not perfectly aligned
    * This array connects them. You find the index of the Name, look up the Ordinal at that same index, and that number tells you which Function to pick
* Lookup
    * Searched function is "WinExec" &rarr; AddressOfNames gives back the number 4 &rarr; You check the number at index 4 in AddressOfNameOrdinals, which gives back 10 &rarr; You go to the 10th index in AddressOfFunction &rarr; You go to the address
* `public uint NumberOfNames`
    * Items in AddressOfNames array
* `public uint NumberOfFunctions`
    * The total number of functions exported
##### PROCESS_BASIC_INFORMATION
```csharp
[StructLayout(LayoutKind.Sequential)]
public struct PROCESS_BASIC_INFORMATION
{
    public IntPtr ExitStatus;
    public IntPtr PebBaseAddress; 
    public IntPtr AffinityMask;
    public IntPtr BasePriority;
    public IntPtr UniqueProcessId;
    public IntPtr InheritedFromUniqueProcessId;
}
```
* `public IntPtr ExitStatus`
    * for checking if the process still running
* `public IntPtr PebBaseAddress`
    * For our case this is the most important
    * A pointer to the Process Enviroment Block(<b>PEB</b>)
    * PEB contains the list of the loaded DLL-s, enviroment variables, and command line arguments
* `public IntPtr AffinityMask`
    * CPU Core permission slip
    * which CPU cores the process allowed to use
* `public IntPtr BasePriority`
    * The scheduling rank
* `public IntPtr UniqueProcessId`
    * PID (Process ID)
* `public IntPtr InheritedFromUniqueProcessId`
    * PPID (Parent Process ID)
    * The ID of the process which started this one
##### PEB (Process Enviroment Block)
```csharp
[StructLayout(LayoutKind.Explicit, Size = 0x380)] // Set explicit size to prevent overflow
public struct PEB
{
    //Undocumented
    [FieldOffset(0x00)]
    public byte InheritedAddressSpace;
    //Undocumented
    [FieldOffset(0x01)]
    public byte ReadImageFileExecOptions;
    //Documented
    [FieldOffset(0x02)]
    public byte BeingDebugged;
    //Undocumented
    [FieldOffset(0x03)]
    public byte BitField;
    //Undocumented
    [FieldOffset(0x08)]
    public IntPtr Mutant;
    //Undocumented
    [FieldOffset(0x10)]
    public IntPtr ImageBaseAddress; 
    //Documented
    [FieldOffset(0x18)]
    public IntPtr Ldr;
    //Undocumented
    [FieldOffset(0x20)]
    public IntPtr ProcessParameters;
    //Undocumented
    [FieldOffset(0x30)]
    public IntPtr ProcessHeap;
    //Undocumented
    [FieldOffset(0x60)]
    public IntPtr ApiSetMap;
    //Undocumented
    [FieldOffset(0x118)]
    public uint OSMajorVersion;
    //Undocumented
    [FieldOffset(0x11C)]
    public uint OSMinorVersion;
    //Undocumented
    [FieldOffset(0x120)]
    public ushort OSBuildNumber;
    //Documented
    [FieldOffset(0x2C0)]
    public uint SessionId;
}
```
> [!NOTE]
> Undocumented means, that it is for now compatible for Windows 10/11 nbut it can change
* A Data Structure containing the global variables for the process
* `[FieldOffset(0x02)]`
    * `public byte BeingDebugged`
        * boolean flag (0/1)
        * When a debugger attaches to a process Windows automaticly sets this to 1
        * Can used to avoid being analyzed
* `[FieldOffset(0x10)]`
    * `public IntPtr ImageBaseAddress`
    * The exact memory address where your main executable (.exe) was loaded
    * If you want to parse your own headers (DOS/NT Headers), you start reading from here
* `[FieldOffset(0x18)]`
    * `public IntPtr Ldr`
    * This offset is hardcoded for the x64 Architecture
    * Pointer to the PEB_LDR_DATA data structure
        * lists all of the DLL-s loaded into the process
* `[FieldOffset(0x30)]`
    * `public IntPtr ProcessHeap`
    * The default location where new or mallowc allocates memory
* `[FieldOffset(0x2C0)]`
    * `public uint SessionId`
    * ID of the user session
        * 0 &rarr; Reserved for System and Services (High Privilige)
        * 1+ &rarr; Standard logged-in users 
```csharp

##### LIST_ENTRY
```csharp
[StructLayout(LayoutKind.Sequential)]
public struct LIST_ENTRY
{
    public IntPtr Flink; // Next
    public IntPtr Blink; // Previous
}
```
* Double Linked List
    * `public IntPtr Flink`
        * Forward link
    * `public IntPtr Blink`
        * Backward Link
##### PEB_LDR_DATA
```csharp
[StructLayout(LayoutKind.Explicit)]
public struct PEB_LDR_DATA
{
    [FieldOffset(0x10)]
    public LIST_ENTRY InLoadOrderModuleList;
    
    [FieldOffset(0x20)]
    public LIST_ENTRY InMemoryOrderModuleList;
}
```
* `public LIST_ENTRY InLoadOrderModuleList`
    * The order represents how did the DLLs been loaded
* `public LIST_ENTRY InMemoryOrderModuleList`
    * It links modules based on their memory adresses

##### UNICODE_STRING
```csharp
[StructLayout(LayoutKind.Sequential)]
public struct UNICODE_STRING
{
    public ushort Length;
    public ushort MaximumLength;
    public IntPtr Buffer; 
}
```
* Windows kernel does not use C-style string
* `public ushort Length`
    * string length in bytes
    * Windows uses UTF-16 as encoding, so each letter is 2 byte
* `public IntPtr Buffer`
    * pointer to where the letters live in the memory
##### LDR_DATA_TABLE_ENTRY
```csharp
[StructLayout(LayoutKind.Explicit, Size = 0x80)]
public struct LDR_DATA_TABLE_ENTRY
{
    [FieldOffset(0x10)]
    public LIST_ENTRY InMemoryOrderLinks;

    [FieldOffset(0x30)]
    public IntPtr DllBase; 

    [FieldOffset(0x58)]
    public UNICODE_STRING BaseDllName; 
}
```
* `public LIST_ENTRY InMemoryOrderLinks`
    * This field correspond the list we walking
* `public IntPtr DllBase`
    *  This is the HMODULE
    * The exact adress where the DLL starts
* `public UNICODE_STRING BaseDllName`
    * The Unicode structure containing the name of the DLL
### Functions
##### GetModuleHandleManual
```csharp
 public static IntPtr GetModuleHandleManual(string moduleName)
```
* gives back the Handle for the dll we search
```csharp
int status = NtQueryInformationProcess(Process.GetCurrentProcess().Handle, 0, ref pbi, Marshal.SizeOf(pbi), out returnLength);
```
* 0 means basic informations
```csharp
PEB* pPeb = (PEB*)pbi.PebBaseAddress;
```
* From the basic infromations we got we get the PEB struct adress for this process

```csharp
PEB_LDR_DATA* pLdr = (PEB_LDR_DATA*)pPeb->Ldr;
LIST_ENTRY* pListHead = &pLdr->InMemoryOrderModuleList;
LIST_ENTRY* pCurrentEntry = (LIST_ENTRY*)pListHead->Flink;
```
* for our iteration we prepare
```csharp
while (pCurrentEntry != pListHead && i < maxIterations)
```
* The InmemoryOrderModuleList is a circualal double linked list, so we stop if we did a circle
```csharp
LDR_DATA_TABLE_ENTRY* pEntry = (LDR_DATA_TABLE_ENTRY*)((byte*)pCurrentEntry - 0x10);
```
* If we remember, the lsit located offset + 0x10 than our base address
```csharp
if (!string.IsNullOrEmpty(currentDllName) && 
    currentDllName.Equals(moduleName, StringComparison.OrdinalIgnoreCase))
    {
        Console.WriteLine($"[+] PEB Walk: Found {moduleName} at 0x{pEntry->DllBase:X}");
        return pEntry->DllBase;
    }
```
* we return the Handle of the DLL what we searched

##### GetFunctionAddress
```csharp
 public static IntPtr GetFunctionAddress(string moduleName, string functionName)
```
```csharp
int e_lfanew = *(int*)(pBase + 0x3C);
byte* pNtHeaders = pBase + e_lfanew;
```
* we calculate the pNtheaders adress so we can calculate the 