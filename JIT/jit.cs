using System;
using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;
using System.Reflection;

namespace RuntimeInstrumentation
{
    public class FunctionDetour
    {
        // Organize Win32 API calls into a separate 'NativeMethods' class 
        // This is standard C# convention for cleaner code.
        internal static class NativeMethods
        {
            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern bool FlushInstructionCache(IntPtr hProcess, IntPtr lpBaseAddress, UIntPtr dwSize);

            [DllImport("kernel32.dll")]
            public static extern IntPtr GetCurrentProcess();

            // Constant for PAGE_EXECUTE_READWRITE (0x40)
            public const uint PAGE_EXECUTE_READWRITE = 0x40;
        }

        // We use 'NoInlining' to ensure the method exists as a standalone function in memory.
        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        public static int TargetMethod()
        {
            return 0; // Original behavior
        }

        public static void ApplyRuntimePatch()
        {
            Console.WriteLine("--------------------------------------------------");
            Console.WriteLine("[*] Initiating runtime patch sequence...");

            // 1. Force JIT compilation
            // We call the method once to ensure the CLR has compiled it to native machine code.
            TargetMethod();

            // 2. Obtain the raw memory address
            var methodInfo = typeof(FunctionDetour).GetMethod("TargetMethod", BindingFlags.Public | BindingFlags.Static);
            RuntimeHelpers.PrepareMethod(methodInfo.MethodHandle);
            IntPtr funcAddr = methodInfo.MethodHandle.GetFunctionPointer();

            Console.WriteLine($"[Info] Initial MethodHandle Address: 0x{funcAddr:X}");

            // --- ANALYSIS & POINTER RESOLUTION ---
            Console.Write("[Debug] Memory at pointer: ");
            for (int i = 0; i < 6; i++) Console.Write($"{Marshal.ReadByte(funcAddr + i):X2} ");
            Console.WriteLine();

            byte b1 = Marshal.ReadByte(funcAddr);
            byte b2 = Marshal.ReadByte(funcAddr + 1);

            // CASE 1: Direct Relative Jump (0xE9)
            // Common in 32-bit or specific compilation modes.
            if (b1 == 0xE9)
            {
                Console.WriteLine("[Info] Detected: Direct JMP (0xE9). Adjusting offset...");
                int offset = Marshal.ReadInt32(funcAddr + 1);
                // Formula: Current + InstructionLength(5) + Offset
                funcAddr = IntPtr.Add(funcAddr, 5 + offset);
            }
            // CASE 2: Indirect Memory Jump (0xFF 0x25)
            // Standard for x64 .NET JIT (Jump Thunk).
            else if (b1 == 0xFF && b2 == 0x25)
            {
                Console.WriteLine("[Info] Detected: Indirect JMP stub (0xFF 0x25). Resolving real target...");

                // Read the 32-bit offset relative to RIP
                int offset = Marshal.ReadInt32(funcAddr + 2);

                // Calculate RIP (Instruction Pointer) = Address + InstructionLength(6)
                IntPtr rip = IntPtr.Add(funcAddr, 6);

                // The Global Offset Table (GOT) entry location
                IntPtr targetPtrAddress = IntPtr.Add(rip, offset);

                // Dereference: Read the actual 64-bit address stored at that location
                long realTarget = Marshal.ReadInt64(targetPtrAddress);
                funcAddr = (IntPtr)realTarget;
            }

            Console.WriteLine($"[Info] Resolved Native Entry Point: 0x{funcAddr:X}");

            // Verification: Print bytes at the final resolved address
            Console.Write("[Debug] Bytes at Entry Point: ");
            for (int i = 0; i < 6; i++) Console.Write($"{Marshal.ReadByte(funcAddr + i):X2} ");
            Console.WriteLine();
            // -------------------------------

            // 3. Prepare the Assembly Patch
            // Instructions: 
            // MOV EAX, 4919  (B8 37 13 00 00) -> Sets return value to 4919 (0x1337)
            // RET            (C3)             -> Returns control to caller
            byte[] assemblyPatch = { 0xB8, 0x37, 0x13, 0x00, 0x00, 0xC3 };

            // 4. Modify Memory Permissions
            // We need Write permissions on the code segment.
            uint oldProtect;
            if (!NativeMethods.VirtualProtect(funcAddr, (UIntPtr)assemblyPatch.Length, NativeMethods.PAGE_EXECUTE_READWRITE, out oldProtect))
            {
                Console.WriteLine("[Error] Failed to change memory protection constants.");
                return;
            }

            Console.WriteLine("[*] Writing assembly patch...");
            Marshal.Copy(assemblyPatch, 0, funcAddr, assemblyPatch.Length);

            // 5. Cleanup
            // It is best practice to flush the instruction cache after modifying executable code
            // to ensure the CPU doesn't execute stale instructions from its pipeline.
            NativeMethods.FlushInstructionCache(NativeMethods.GetCurrentProcess(), funcAddr, (UIntPtr)assemblyPatch.Length);

            // Restore original permissions (Good hygiene)
            NativeMethods.VirtualProtect(funcAddr, (UIntPtr)assemblyPatch.Length, oldProtect, out _);

            Console.WriteLine("[Success] Runtime patch applied successfully.");
            Console.WriteLine("--------------------------------------------------");
        }

        public static void Main(string[] args)
        {
            Console.WriteLine("Standard execution result: " + TargetMethod());
            
            ApplyRuntimePatch();

            int result = TargetMethod();
            Console.WriteLine("Patched execution result:  " + result);

            if (result == 4919)
            {
                Console.WriteLine("\n[Verified] The method behavior has been dynamically altered.");
            }
            else
            {
                Console.WriteLine("\n[Failed] The method retains original behavior.");
            }

            Console.WriteLine("\nPress any key to exit...");
            Console.ReadKey();
        }
    }
}