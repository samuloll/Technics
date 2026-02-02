# JIT (Just In Time)
![NetVersion](https://img.shields.io/badge/.NET-8.0-purple)
![Platform](https://img.shields.io/badge/Platform-x64-lightgrey)
![Status](https://img.shields.io/badge/Status-PoC%20Working-brightgreen)

> [!CAUTION]
> Only use this on a system where you have permission.
> This is for educational purposes only.

```csharp
using System;
```
* allows you to reference fundamental classes found in the root System Class
    * eg. System.Console
```csharp
using System.Runtime.InteropServices;
```
* It provides the bridge between .NET and the low-level, unmanaged world of the Windows OS raw memory

```csharp
using System.Runtime.CompilerServices;
```
* Essential for how the .NET Runtime (CLR) handles the execution and compilation of your code
```csharp
[DllImport("kernel32.dll")]
```
* Gateway to Windows OS
* Core memory manager of Windows
* Standard C# does not have 'Change Memory Permissions' command; thus, by using this we have control of that

```csharp
[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
```
* By default the compiler wants to make the code faster, so it might change it. But we don't want that so
    * MethodImplOptions.NoInlining
        * If the function is simple the compiler might think, that this doesn't need its own address, and store it in Main
        * With this we say, do not copy it into Main
    * MethodImplOptions.NoOptimization
        * The compiler might think that this function is not important, and change it to  something simpler that does the same, but faster
        * We tell not to do

### Functions of kernel32.dll used here
#### VirtualProtect
* By default executable code  in memory is "Read/Execute" only
* This function forces Windows to change the rule for that specific memory address
```csharp
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
```
* extern
    * Tells the program to import the body of the function from kernel32
*  IntPtr lpAddress
    * IntPtr
        * platform dependent memory address integer
    * Long Pointer To address
        * The starting point of the memory the function wants to change
* UIntPtr dwSize
    * The size of the region whose protection we want to change
    * dwSize
       * Double Word Size
    * UintPtr
        * Size cannot be negative and must match the size of the platform's pointer size
* uint flNewProtect
    * flNewProtect
        * Flags For New Protection
    * Memory constants that we want to apply
<details>
<summary><b>Press to see the Memory Constants</b></summary>

 Name | Value | Description | 
| :--- | :--- | :---: | 
| `PAGE_NOACCESS` | `0x01` | <b>The Void</b>: attempts to read or write or execute will cause an immediate Access Violation crash| 
| `PAGE_READONLY` | `0x02` | You can only read data |
|`PAGE_READWRITE`|`0x04` | <b>Standard data</b>: Used for variables, heap and stack (Prevents buffer OverFlow exploits via DEP/NX bit)
|`PAGE_WRITECOPY`|`0x08` | Allows reading, and if you write, the OS gives you a private copy of the page, so you dont affect other processes sharing it|  
|`PAGE_EXECUTE`|`0x10` | You can only execute nor read or write. Used in rare cases|
|`PAGE_EXECUTE_READ`|`0x20` | You can read and execute. Default for .text sections(compiled code)|  
|`PAGE_EXECUTE_READWRITE`|`0x40` | Highly suspicious for AVs/EDRs, because legitimate programs rarely need this|  
|`PAGE_EXECUTE_WRITECOPY`|`0x80` |Creates a private executable copy when writing |
|`PAGE_GUARD`|`0x100` | The first time the memory is accessed, the OS raises a generic "Guard Page" exception, then removes this flag. Used for growing the stack automatically |
|`PAGE_NOCACHE`|`0x200` |Hardware Direct. Disables CPU caching for this page. Forces the CPU to read/write directly to RAM |
|`PAGE_WRITECOMBINE`|`0x400` |Driver Optimization. Allows writes to be combined/buffered. Mainly for device drivers and video memory|

> [!NOTE]
> DEP/NX bit
>> NX (No-Execute): This is the Hardware implementation. It is a specific bit (literally a 0 or 1 switch) inside the CPU's memory management unit.
>> AMD calls it NX. Intel calls it XD (Execute Disable). They do the exact same thing.
>> DEP (Data Execution Prevention): This is the Windows/Software name for the feature that uses the NX bit. Windows "turns on" DEP by setting the NX bit on all memory pages that shouldn't contain code.
</details>
<br>

* out uint lpflOldProtect
    * Long Pointer to Flags for Old Protection
    * A variable to receive the previous protection value.
    * out
        * Tells C# to pass a pointer to this variable, allowing the external function to write a value back into it.
#### FlushInstructionCache
* Modern CPUs have a cache (L1/L2) to speed up code execution. If you change the memory in the RAM, the program might still execute the code located in the cache
* With this we wipe out the cache content, and forcing it to use the new one
```csharp
public static extern bool FlushInstructionCache(IntPtr hProcess, IntPtr lpBaseAddress, UIntPtr dwSize);
```
* IntPtr hProcess
    * Handle to the Process
        * The ID card of the process whose cache you want to scrub.
* IntPtr lpBaseAddress
    * Same as VirtualProtect
* UIntPtr dwSize
    * Same as VirtualProtect
#### GetCurrentProcess
* Gets the handle for your currently running program so FlushInstructionCache knows which program's cache to clear

### RunExploit Function
* We run SecureFunction once, so JIT compiling happens
```csharp
 var methodInfo = typeof(PoC).GetMethod("SecureFunction");
```
* Gets the information about this function
```csharp
RuntimeHelpers.PrepareMethod(methodInfo.MethodHandle);
```
* Force the CLR (Common Language Runtime) to run the JIT (Just-In-Time) compiler on that specific method immediately, ensuring that the stable, native machine code exists in memory before we try to touch it.
    * It allocates a permanent spot in executable memory for this code.
    * It fixes all internal pointers to point to this final address.
#### What happens if we don't run this
* When you write C# code, it compiles into IL (Intermediate Language), not machine code. When you run the program, the method SecureFunction doesn't actually exist in RAM as executable assembly instructions yet. It only exists as abstract IL data.
* If you try to get the memory address of a method that hasn't been JIT-compiled, one of two things happens
    * You get a null pointer or an error.
    * You get a pointer to a JIT Stub.
        * JIT Stub is a temporary piece of code that says "Hey, this function hasn't been compiled yet. Please pause and compile it now."
```csharp
IntPtr funcAddr = methodInfo.MethodHandle.GetFunctionPointer();
```
* This gives back the pointer to where's the  function located


```csharp
byte b1 = Marshal.ReadByte(funcAddr);
byte b2 = Marshal.ReadByte(funcAddr + 1);
```

* Two possibilities
    * Direct Jump (`0xE9`)
        * The offset is a  32 bit integer
        * int offset = Marshal.ReadInt32(funcAddr + 1);
        * The real Function address is funcAddr + sizeof(Int32) + 1 + offset
    * Indirect Jump (`0xFF` and `0x25`)
        * The offset is 32 bit integer as well
        * The calculation FuncAddr + 6 + offset points to the location where the real function address is stored.
```csharp
VirtualProtect(funcAddr, (UIntPtr)payload.Length, PAGE_EXECUTE_READWRITE, out oldProtect)
```
* Now as we have the function address, we change the permission so we can write our payload.

```csharp
byte[] payload = { 0xB8, 0x37, 0x13, 0x00, 0x00, 0xC3 };
```
* `0xB8`
    * mov EAX, int32
        * when a function returns an int. it always uses EAX, as a container
    * we provide the int as 0x37, 0x13, 0x00, 0x00
        * Little Endian
* `0xC3`
    * RET
```csharp
 Marshal.Copy(payload, 0, funcAddr, payload.Length);
```
* Copies the payload content, starting from the start of the payload array (0)
* Few functions can modify memory in .NET, and Marshal is one of them

```csharp
  VirtualProtect(funcAddr, (UIntPtr)payload.Length, oldProtect, out _);
```

* At the end we set back the old permission, because we are ethical researchers.


