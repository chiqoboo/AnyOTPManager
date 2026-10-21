using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using AnyOTPManager.Core;
using Microsoft.Win32;

internal static class Program
{
    private static int _checks;
    private static string _lastCheck = "startup";
    [STAThread]
    private static int Main(string[] args)
    {
        if (args.Length != 2) return 2;
        var root = Path.GetFullPath(args[0]); var output = Path.GetFullPath(args[1]);
        string? scopeName = null; RegistryKey? scope = null;
        IntPtr crypto = IntPtr.Zero, biz = IntPtr.Zero;
        object? instance = null, factoryObject = null;
        IntPtr factoryPointer = IntPtr.Zero, instancePointer = IntPtr.Zero;
        var overridden = false;
        try
        {
            Check(IntPtr.Size == 4, "x86");
            foreach (var (name, hash) in new[] {
                ("AnyOtpDLLwDH.dll", "DB8B864C9F8C25C99F1FAC22803C69EE5DF04FC033625CBB871E9E055F4ACEE7"),
                ("AnyOTPBiz.dll", "1DF04522A294EA58D8088A6441C2655E47BD407915D6D2E1B813B5235FC9281C"),
                ("AnyOtpDLL.dll", "EBC418257CE9112ED2B717D672B43FF9B74CDB107456F6658DF3FBAEF4EA5E3E") })
                Check(Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(Path.Combine(root, name)))) == hash, "binary_hash");
            crypto = Native.LoadLibraryEx(Path.Combine(root, "AnyOtpDLLwDH.dll"), IntPtr.Zero, 0x100 | 0x800);
            Check(crypto != IntPtr.Zero, "load_crypto");
            var generate = Marshal.GetDelegateForFunctionPointer<Native.Generate>(Native.GetProcAddress(crypto, "gen_otp"));
            var derive = Marshal.GetDelegateForFunctionPointer<Native.Derive>(Native.GetProcAddress(crypto, "gen_aes_key"));
            var encrypt = Marshal.GetDelegateForFunctionPointer<Native.Aes>(Native.GetProcAddress(crypto, "aes_enc"));
            var disk = new DiskIdentity("SYNTHETIC\\DISK-IDENTITY-00000001", 0);
            for (var i = 0; i < 32; i++)
            {
                var fixture = SHA1.HashData(Encoding.ASCII.GetBytes("AnyOTPManager native fictional " + i));
                foreach (var counter in new uint[] { 0, 1, 2, 29, 30, 60, 1000000, 0x7fffffff, 0x80000000, 0xffffffff })
                foreach (var digits in new[] { 6, 7, 8 })
                {
                    var bytes = new byte[32]; generate(bytes, digits, counter, fixture);
                    Check(Encoding.ASCII.GetString(bytes, 0, digits) == OtpEngine.GenerateCounter(fixture, counter, digits), "otp_parity");
                }
                CryptographicOperations.ZeroMemory(fixture);
            }
            var pin = "482619";
            var material = Encoding.ASCII.GetBytes(pin + OtpEngine.DiskKey(disk));
            var nativeKey = new byte[16]; var nativeIv = new byte[16];
            derive(material, material.Length, nativeKey, nativeIv);
            var (managedKey, managedIv) = OtpEngine.Derive(pin, disk);
            Check(nativeKey.SequenceEqual(managedKey) && nativeIv.SequenceEqual(managedIv), "derive_parity");
            foreach (var length in new[] { 1, 15, 16, 20, 31, 32, 46, 48, 64, 128 })
            {
                var input = Enumerable.Range(0, length).Select(n => (byte)(n * 17)).ToArray();
                var nativeCipher = new byte[length + 32];
                var count = encrypt(nativeKey, nativeIv, input, input.Length, nativeCipher);
                using var aes = Aes.Create(); aes.Key = managedKey;
                Check(nativeCipher.AsSpan(0, count).SequenceEqual(aes.EncryptCbc(input, managedIv, PaddingMode.PKCS7)), "encrypt_parity");
            }

            // Vendor COM is used only inside this disposable x86 process and a private volatile HKCU.
            // Never call RegisterOTP; never access an account or a real AnyOTP registration.
            scopeName = @"Software\AnyOTPManager.NativeCheck\" + Guid.NewGuid().ToString("N");
            scope = Registry.CurrentUser.CreateSubKey(scopeName, RegistryKeyPermissionCheck.ReadWriteSubTree, RegistryOptions.Volatile);
            var seed = SHA1.HashData(Encoding.ASCII.GetBytes("AnyOTPManager synthetic COM fixture"));
            var env = Enumerable.Repeat((byte)'0', 26).ToArray(); env[12] = (byte)'0'; env[14] = (byte)'0'; env[15] = (byte)'6';
            using (var registration = scope.CreateSubKey(@"Software\AnyOTP", RegistryKeyPermissionCheck.ReadWriteSubTree, RegistryOptions.Volatile))
            { registration.SetValue("SharedKey", seed, RegistryValueKind.Binary); registration.SetValue("EnvInfo", env, RegistryValueKind.Binary); }
            Check(Native.RegOverridePredefKey(new IntPtr(unchecked((int)0x80000001)), scope.Handle.DangerousGetHandle()) == 0, "hkcu_override");
            overridden = true;
            biz = Native.LoadLibraryEx(Path.Combine(root, "AnyOTPBiz.dll"), IntPtr.Zero, 0x100 | 0x800);
            Check(biz != IntPtr.Zero, "load_biz");
            var classObject = Marshal.GetDelegateForFunctionPointer<Native.GetClassObject>(Native.GetProcAddress(biz, "DllGetClassObject"));
            var classId = new Guid("396db50b-d134-430a-a450-5ddb5fbf7b49");
            var factoryId = new Guid("00000001-0000-0000-C000-000000000046");
            Check(classObject(ref classId, ref factoryId, out factoryPointer) >= 0, "class_factory");
            factoryObject = Marshal.GetObjectForIUnknown(factoryPointer);
            var interfaceId = typeof(IOTPLib).GUID;
            Check(((IClassFactory)factoryObject).CreateInstance(IntPtr.Zero, ref interfaceId, out instancePointer) >= 0, "com_instance");
            instance = Marshal.GetObjectForIUnknown(instancePointer);
            var otp = (IOTPLib)instance;
            _ = otp.SetPIN(OtpEngine.DiskKey(disk), pin);
            var template = new List<OtpRegistryValue> {
                new() { Name = "EnvInfo", Kind = OtpRegistryValueKind.Binary, Binary = env },
                new() { Name = "VMData", Kind = OtpRegistryValueKind.Binary, Binary = new byte[48] }
            };
            var managed = OtpEngine.Rewrap(seed, template, disk, pin);
            using (var registration = scope.OpenSubKey(@"Software\AnyOTP"))
                Check(((byte[])registration!.GetValue("VMData")!).SequenceEqual(managed.Single(v => v.Name == "VMData").Binary!), "native_setpin_managed_cipher");
            CheckPublicCode(otp, disk, pin, seed);
            _ = otp.ChangePIN(OtpEngine.DiskKey(disk), Defaults.Pin);
            var changed = OtpEngine.Rewrap(seed, template, disk, Defaults.Pin);
            bool legacyChangePinPreservedSeed;
            using (var registration = scope.OpenSubKey(@"Software\AnyOTP"))
            {
                var legacy = new List<OtpRegistryValue> {
                    new() { Name = "EnvInfo", Kind = OtpRegistryValueKind.Binary, Binary = env },
                    new() { Name = "VMData", Kind = OtpRegistryValueKind.Binary, Binary = (byte[])registration!.GetValue("VMData")! }
                };
                try { legacyChangePinPreservedSeed = OtpEngine.Unlock(legacy, disk, Defaults.Pin).SequenceEqual(seed); }
                catch (OtpException) { legacyChangePinPreservedSeed = false; }
            }
            // The reviewed legacy ChangePIN decrypts with its supplied new PIN and does not preserve
            // the seed in this changed-PIN scenario. Production deliberately uses managed rewrapping.
            Check(!legacyChangePinPreservedSeed, "legacy_changepin_limitation_reproduced");
            using (var registration = scope.OpenSubKey(@"Software\AnyOTP", true))
                registration!.SetValue("SharedKey", seed, RegistryValueKind.Binary);
            _ = otp.SetPIN(OtpEngine.DiskKey(disk), Defaults.Pin);
            using (var registration = scope.OpenSubKey(@"Software\AnyOTP"))
                Check(((byte[])registration!.GetValue("VMData")!).SequenceEqual(changed.Single(v => v.Name == "VMData").Binary!), "managed_pin_change_matches_native_setpin");
            CheckPublicCode(otp, disk, Defaults.Pin, seed);
            // Simulate transfer to a different disk: managed output must be readable by the real COM getter.
            var otherDisk = new DiskIdentity("SYNTHETIC\\DISK-IDENTITY-00000002", 0xABCD1234);
            var rebound = OtpEngine.Rewrap(seed, template, otherDisk, Defaults.Pin);
            using (var registration = scope.OpenSubKey(@"Software\AnyOTP", true))
                registration!.SetValue("VMData", rebound.Single(v => v.Name == "VMData").Binary!, RegistryValueKind.Binary);
            CheckPublicCode(otp, otherDisk, Defaults.Pin, seed);
            Check(OtpEngine.Unlock(rebound, otherDisk, Defaults.Pin).SequenceEqual(seed), "rebound_unlock");

            // Native-created profiles anchor the parser tests independently of managed Rewrap.
            // Real EnvInfo fields may contain a space-padded digit ("6 "), not just "06".
            var environmentCases = 0;
            foreach (var (step, seconds) in new[] { ('0', 60), ('1', 30), ('2', 15) })
            foreach (var digits in new[] { 6, 7, 8 })
            foreach (var field in new[] { $"{digits} ", $" {digits}", $"0{digits}" })
            {
                var caseEnv = Enumerable.Repeat((byte)'0', 26).ToArray();
                caseEnv[12] = (byte)step;
                Encoding.ASCII.GetBytes(field).CopyTo(caseEnv, 14);
                using (var registration = scope.OpenSubKey(@"Software\AnyOTP", true))
                {
                    registration!.SetValue("EnvInfo", caseEnv, RegistryValueKind.Binary);
                    registration.SetValue("SharedKey", seed, RegistryValueKind.Binary);
                }
                _ = otp.SetPIN(OtpEngine.DiskKey(disk), pin);
                var expected = new OtpParameters(seconds, digits);
                CheckPublicCode(otp, disk, pin, seed, expected);
                using var nativeProfile = scope.OpenSubKey(@"Software\AnyOTP");
                var values = new List<OtpRegistryValue> {
                    new() { Name = "EnvInfo", Kind = OtpRegistryValueKind.Binary, Binary = caseEnv },
                    new() { Name = "VMData", Kind = OtpRegistryValueKind.Binary, Binary = (byte[])nativeProfile!.GetValue("VMData")! }
                };
                try
                {
                    _lastCheck = "environment_parameters";
                    Check(OtpEngine.Parameters(values) == expected, "environment_parameters");
                    var recovered = OtpEngine.Unlock(values, disk, pin);
                    try { Check(recovered.SequenceEqual(seed), "native_environment_unlock"); }
                    finally { CryptographicOperations.ZeroMemory(recovered); }
                    environmentCases++;
                }
                finally { SecretBuffers.Clear(values); }
            }

            var result = new { status = "VERIFIED_TEST", processBits = 32, checks = _checks,
                syntheticOtpCases = 960, nativeEnvironmentCases = environmentCases,
                nativeSetPinEqualsManaged = true, managedPinChangeEqualsNativeSetPin = true,
                legacyVendorChangePinPreservedSeed = legacyChangePinPreservedSeed,
                managedRebindAcceptedByPublicCom = true, realProfilesUsed = false, activeAnyOtpRegistryTouched = false,
                network = "NOT RUN", liveAccountAcceptance = "NOT RUN" };
            // Cleanup must succeed before reporting success.
            Release(ref instance); Release(ref factoryObject);
            if (instancePointer != IntPtr.Zero) { Marshal.Release(instancePointer); instancePointer = IntPtr.Zero; }
            if (factoryPointer != IntPtr.Zero) { Marshal.Release(factoryPointer); factoryPointer = IntPtr.Zero; }
            Check(Native.RegOverridePredefKey(new IntPtr(unchecked((int)0x80000001)), IntPtr.Zero) == 0, "hkcu_restore");
            overridden = false; scope.Dispose(); scope = null;
            Registry.CurrentUser.DeleteSubKeyTree(scopeName, false); scopeName = null;
            var completeResult = result with { checks = _checks };
            Directory.CreateDirectory(Path.GetDirectoryName(output)!);
            File.WriteAllText(output, JsonSerializer.Serialize(completeResult, new JsonSerializerOptions { WriteIndented = true }));
            Console.WriteLine(JsonSerializer.Serialize(completeResult)); return 0;
        }
        catch (Exception error)
        {
            Console.Error.WriteLine(JsonSerializer.Serialize(new { status = "FAILED", checksPassed = _checks, lastCheck = _lastCheck, type = error.GetType().Name, error.HResult, secretDetailsOmitted = true }));
            return 1;
        }
        finally
        {
            Release(ref instance); Release(ref factoryObject);
            if (instancePointer != IntPtr.Zero) Marshal.Release(instancePointer);
            if (factoryPointer != IntPtr.Zero) Marshal.Release(factoryPointer);
            var restored = !overridden || Native.RegOverridePredefKey(new IntPtr(unchecked((int)0x80000001)), IntPtr.Zero) == 0;
            scope?.Dispose();
            if (restored && scopeName is not null) Registry.CurrentUser.DeleteSubKeyTree(scopeName, false);
            // Libraries remain mapped until this short-lived process exits.
        }
    }
    private static void CheckPublicCode(IOTPLib otp, DiskIdentity disk, string pin, byte[] seed, OtpParameters? parameters = null)
    {
        parameters ??= new(60, 6);
        var before = DateTimeOffset.UtcNow;
        var result = otp.FetchPasscode(OtpEngine.DiskKey(disk), pin);
        var after = DateTimeOffset.UtcNow;
        Check(result == OtpEngine.Generate(seed, parameters, before).Code ||
              result == OtpEngine.Generate(seed, parameters, after).Code, "public_com_code");
    }
    private static void Check(bool value, string label) { _lastCheck = label; if (!value) throw new InvalidOperationException(label); _checks++; }
    private static void Release(ref object? value) { if (value is not null && Marshal.IsComObject(value)) Marshal.FinalReleaseComObject(value); value = null; }
}

[ComImport, Guid("AC8C24C6-0CD5-4466-AAFA-96C22009456D"), InterfaceType(ComInterfaceType.InterfaceIsDual)]
internal interface IOTPLib
{
    [DispId(1)] int RegisterOTP([MarshalAs(UnmanagedType.BStr)] string id, [MarshalAs(UnmanagedType.BStr)] string auth,
        [MarshalAs(UnmanagedType.BStr)] out string error, [MarshalAs(UnmanagedType.BStr)] out string description);
    [DispId(2)] int SetPIN([MarshalAs(UnmanagedType.BStr)] string key, [MarshalAs(UnmanagedType.BStr)] string pin);
    [DispId(3)] int ChangePIN([MarshalAs(UnmanagedType.BStr)] string key, [MarshalAs(UnmanagedType.BStr)] string pin);
    [DispId(4)] [return: MarshalAs(UnmanagedType.BStr)] string FetchPasscode([MarshalAs(UnmanagedType.BStr)] string key, [MarshalAs(UnmanagedType.BStr)] string pin);
}
[ComImport, Guid("00000001-0000-0000-C000-000000000046"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
internal interface IClassFactory
{
    [PreserveSig] int CreateInstance(IntPtr outer, ref Guid iid, out IntPtr instance);
    [PreserveSig] int LockServer([MarshalAs(UnmanagedType.Bool)] bool locked);
}
internal static class Native
{
    [DllImport("kernel32.dll", EntryPoint = "LoadLibraryExW", CharSet = CharSet.Unicode)] internal static extern IntPtr LoadLibraryEx(string path, IntPtr file, uint flags);
    [DllImport("kernel32.dll", CharSet = CharSet.Ansi)] internal static extern IntPtr GetProcAddress(IntPtr module, string name);
    [DllImport("advapi32.dll")] internal static extern int RegOverridePredefKey(IntPtr key, IntPtr newKey);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate int Generate([Out] byte[] output, int digits, uint counter, [In] byte[] seed);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate int Derive([In] byte[] input, int length, [Out] byte[] key, [Out] byte[] iv);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate int Aes([In] byte[] key, [In] byte[] iv, [In] byte[] input, int length, [Out] byte[] output);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] internal delegate int GetClassObject(ref Guid clsid, ref Guid iid, out IntPtr pointer);
}
