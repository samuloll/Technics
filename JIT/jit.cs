using System;
using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;

public class MemoryHack {
    
    [DllImport("kernel32.dll")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll")]
    public static extern bool FlushInstructionCache(IntPtr hProcess, IntPtr lpBaseAddress, UIntPtr dwSize);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();

    //Iderakhatjuk de nem kötelező
    //[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static int SecureFunction() {
        return 0; 
    }

    public static void RunExploit() {
        Console.WriteLine("--------------------------------------------------");
        Console.WriteLine("[*] Célpont bemérése...");

        // 1. Kényszerítjük a JIT fordítást
        SecureFunction(); 
        
        var methodInfo = typeof(MemoryHack).GetMethod("SecureFunction");
        RuntimeHelpers.PrepareMethod(methodInfo.MethodHandle);
        IntPtr funcAddr = methodInfo.MethodHandle.GetFunctionPointer();

        Console.WriteLine($"[+] Kezdeti cím (MethodHandle): 0x{funcAddr:X}");

        // --- DIGANOSZTIKA ÉS KÖVETÉS ---
        // Megnézzük az első 6 bájtot, hogy lássuk mivel állunk szemben
        Console.Write("[?] Memória tartalom a mutatónál: ");
        for(int i=0; i<6; i++) Console.Write($"{Marshal.ReadByte(funcAddr + i):X2} ");
        Console.WriteLine();

        byte b1 = Marshal.ReadByte(funcAddr);
        byte b2 = Marshal.ReadByte(funcAddr + 1);

        // ESET 1: Sima JMP (E9) - Relatív ugrás
        if (b1 == 0xE9) {
            Console.WriteLine("[!] Típus: Direct JMP (0xE9)");
            int offset = Marshal.ReadInt32(funcAddr + 1);
            funcAddr = IntPtr.Add(funcAddr, 5 + offset);
        }
        // ESET 2: Indirekt JMP (FF 25) - Ez a gyakoribb modern x64 .NET-nél!
        else if (b1 == 0xFF && b2 == 0x25) {
            Console.WriteLine("[!] Típus: Indirect JMP (FF 25) - JMP [RIP+offset]");
            
            // Az utasítás hossza 6 bájt.
            // A 4 bájtos offset a következő utasítás címéhez (RIP) képest értendő.
            int offset = Marshal.ReadInt32(funcAddr + 2);
            
            // RIP = Jelenlegi cím + 6 bájt
            IntPtr rip = IntPtr.Add(funcAddr, 6);
            
            // A tároló címe (ahol a valódi célcím lakik)
            IntPtr targetPtrAddress = IntPtr.Add(rip, offset);
            
            // Kiolvassuk a tárolóból a célt (64 bites cím!)
            long realTarget = Marshal.ReadInt64(targetPtrAddress);
            funcAddr = (IntPtr)realTarget;
        }

        Console.WriteLine($"[+] VÉGLEGES célpont címe: 0x{funcAddr:X}");
        
        // Ellenőrzés: Mi van a végleges címen? (Remélhetőleg a függvény bevezetője: 55 48 8B EC... vagy 33 C0...)
        Console.Write("[?] Memória a végleges címen: ");
        for(int i=0; i<6; i++) Console.Write($"{Marshal.ReadByte(funcAddr + i):X2} ");
        Console.WriteLine();
        // -------------------------------

        // Payload: MOV EAX, 4919; RET
        byte[] payload = { 0xB8, 0x37, 0x13, 0x00, 0x00, 0xC3 }; 

        uint oldProtect;
        if (!VirtualProtect(funcAddr, (UIntPtr)payload.Length, 0x40, out oldProtect)) {
            Console.WriteLine("[-] VirtualProtect hiba!");
            return;
        }

        Console.WriteLine("[*] Payload írása...");
        Marshal.Copy(payload, 0, funcAddr, payload.Length);
        //Nem kell ide ez (idk)
        // FlushInstructionCache(GetCurrentProcess(), funcAddr, (UIntPtr)payload.Length);
        VirtualProtect(funcAddr, (UIntPtr)payload.Length, oldProtect, out _);
        
        Console.WriteLine("[SUCCESS] Patch kész.");
        Console.WriteLine("--------------------------------------------------");
    }

    public static void Main(string[] args) {
        Console.WriteLine("Eredeti hívás: " + SecureFunction());
        RunExploit();
        
        int result = SecureFunction();
        Console.WriteLine("Hekkelt hívás: " + result);
        
        if(result == 4919) {
            Console.WriteLine("\n[!!!] BINGO! Sikerült felülírni a natív kódot. [!!!]");
        } else {
            Console.WriteLine("\n[-] Nem sikerült. Valószínűleg még mindig egy stub-ot módosítottunk.");
        }
        
        Console.ReadKey();
    }
}
