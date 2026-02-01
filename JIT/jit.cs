using System;
using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;

public class PoC {
    
    [DllImport("kernel32.dll")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll")]
    public static extern bool FlushInstructionCache(IntPtr hProcess, IntPtr lpBaseAddress, UIntPtr dwSize);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();

    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static int SecureFunction() {
        return 0; 
    }

    public static void MemoryModify() {
        Console.WriteLine("--------------------------------------------------");
        Console.WriteLine("Target acquired");

        // We force JIT to happen
        SecureFunction(); 
        
        var methodInfo = typeof(PoC).GetMethod("SecureFunction");
        RuntimeHelpers.PrepareMethod(methodInfo.MethodHandle);
        IntPtr funcAddr = methodInfo.MethodHandle.GetFunctionPointer();

        Console.WriteLine($"[+] Starting address (MethodHandle): 0x{funcAddr:X}");


        Console.Write("[?] Memory content at the pointer ");
        for(int i=0; i<6; i++) Console.Write($"{Marshal.ReadByte(funcAddr + i):X2} ");
        Console.WriteLine();

        byte b1 = Marshal.ReadByte(funcAddr);
        byte b2 = Marshal.ReadByte(funcAddr + 1);

        //Case 1: Direct JMP (E9) - Relative Jump
        if (b1 == 0xE9) {
            Console.WriteLine("[!] Type: Direct JMP (0xE9)");
            int offset = Marshal.ReadInt32(funcAddr + 1);
            funcAddr = IntPtr.Add(funcAddr, 5 + offset);
        }
        //Case 2: Indirect  JMP (FF 25) - Most often in 64bit .NET!
        else if (b1 == 0xFF && b2 == 0x25) {
            Console.WriteLine("[!] Type: Indirect JMP (FF 25) - JMP [RIP+offset]");
            
            // The instruction is 6 byte long.
            // The offset comes after the FF 25 bytes
            int offset = Marshal.ReadInt32(funcAddr + 2);
            
            // RIP = Current address + 6 bytes
            IntPtr rip = IntPtr.Add(funcAddr, 6);
            
            // The container address
            IntPtr targetPtrAddress = IntPtr.Add(rip, offset);
            
            // We read out the real address
            long realTarget = Marshal.ReadInt64(targetPtrAddress);
            funcAddr = (IntPtr)realTarget;
        }

        Console.WriteLine($"[+] Final target address: 0x{funcAddr:X}");
        

        Console.Write("[?] Memory on the target address: ");
        for(int i=0; i<6; i++) Console.Write($"{Marshal.ReadByte(funcAddr + i):X2} ");
        Console.WriteLine();
        // -------------------------------

        // Payload: MOV EAX, 4919; RET
        byte[] payload = { 0xB8, 0x37, 0x13, 0x00, 0x00, 0xC3 }; 

        uint oldProtect;
        if (!VirtualProtect(funcAddr, (UIntPtr)payload.Length, 0x40, out oldProtect)) {
            Console.WriteLine("[-] VirtualProtect error!");
            return;
        }

        Console.WriteLine("[*] Writing payload ");
        Marshal.Copy(payload, 0, funcAddr, payload.Length);
        FlushInstructionCache(GetCurrentProcess(), funcAddr, (UIntPtr)payload.Length);
        VirtualProtect(funcAddr, (UIntPtr)payload.Length, oldProtect, out _);
        
        Console.WriteLine("--------------------------------------------------");
    }

    public static void Main(string[] args) {
        Console.WriteLine("Original Call: " + SecureFunction());
        MemoryModify();
        
        int result = SecureFunction();
        Console.WriteLine("Modified call: " + result);
        
        if(result == 4919) {
            Console.WriteLine("\nSuccessful.");
        } else {
            Console.WriteLine("\nSomething went wrong.");
        }
        
        Console.ReadKey();
    }
}