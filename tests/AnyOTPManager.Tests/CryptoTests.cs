using System.Security.Cryptography;
using System.Text;
using AnyOTPManager.Core;

namespace AnyOTPManager.Tests;

public sealed class CryptoTests
{
    [Theory]
    [InlineData('0', 60, 6)] [InlineData('1', 30, 7)] [InlineData('2', 15, 8)] [InlineData('9', 60, 6)]
    public void ProfileUnlockAndTimeSettings(char step, int seconds, int digits)
    {
        var registry = Fixtures.Registry(step: step, digits: digits);
        try { Assert.Equal(Fixtures.Seed(), OtpEngine.Unlock(registry, Fixtures.Disk, Fixtures.Pin)); Assert.Equal(new OtpParameters(seconds, digits), OtpEngine.Parameters(registry)); }
        finally { SecretBuffers.Clear(registry); }
    }

    [Theory]
    [InlineData("06", 6)] [InlineData("6 ", 6)] [InlineData(" 6", 6)]
    [InlineData("07", 7)] [InlineData("7 ", 7)] [InlineData(" 7", 7)]
    [InlineData("08", 8)] [InlineData("8 ", 8)] [InlineData(" 8", 8)]
    public void ParametersAcceptZeroAndSpacePaddingWithoutChangingEnvironment(string field, int digits)
    {
        var registry = Fixtures.Registry();
        try
        {
            var env = registry.Single(v => v.Name == "EnvInfo").Binary!;
            Encoding.ASCII.GetBytes(field).CopyTo(env, 14);
            var original = env.ToArray();
            Assert.Equal(new OtpParameters(60, digits), OtpEngine.Parameters(registry));
            Assert.Equal(original, env);
        }
        finally { SecretBuffers.Clear(registry); }
    }

    [Theory]
    [InlineData("  ")] [InlineData("00")] [InlineData("05")] [InlineData("09")]
    [InlineData("16")] [InlineData("60")] [InlineData("-6")] [InlineData("+6")]
    [InlineData("6x")] [InlineData("x6")] [InlineData("6\0")] [InlineData("\t6")]
    public void InvalidDigitFieldsAreNotGuessed(string field)
    {
        var registry = Fixtures.Registry();
        try
        {
            Encoding.ASCII.GetBytes(field).CopyTo(registry.Single(v => v.Name == "EnvInfo").Binary!, 14);
            Assert.Throws<OtpException>(() => OtpEngine.Parameters(registry));
        }
        finally { SecretBuffers.Clear(registry); }
    }

    [Fact]
    public void ChangingDigitPaddingStillFailsEnvironmentIntegrityCheck()
    {
        var registry = Fixtures.Registry();
        try
        {
            Encoding.ASCII.GetBytes("6 ").CopyTo(registry.Single(v => v.Name == "EnvInfo").Binary!, 14);
            Assert.Equal(new OtpParameters(60, 6), OtpEngine.Parameters(registry));
            Assert.Throws<OtpException>(() => OtpEngine.Unlock(registry, Fixtures.Disk, Fixtures.Pin));
        }
        finally { SecretBuffers.Clear(registry); }
    }

    [Theory]
    [InlineData("000000")] [InlineData("482610")] [InlineData("111111")]
    public void WrongPinIsRejectedBeforeAnyOtp(string pin) =>
        Assert.Throws<OtpException>(() => OtpEngine.Unlock(Fixtures.Registry(), Fixtures.Disk, pin));

    [Fact] public void WrongDiskIsRejected() => Assert.Throws<OtpException>(() => OtpEngine.Unlock(Fixtures.Registry(), Fixtures.OtherDisk, Fixtures.Pin));

    [Fact]
    public void TamperedEnvironmentIsRejected()
    {
        var values = Fixtures.Registry(); values.Single(v => v.Name == "EnvInfo").Binary![0] ^= 1;
        Assert.Throws<OtpException>(() => OtpEngine.Unlock(values, Fixtures.Disk, Fixtures.Pin));
    }

    [Fact]
    public void RewrapChangesPinAndDiskButPreservesCodesAndMetadata()
    {
        using var entry = Fixtures.Entry();
        var changed = OtpEngine.Rewrap(entry.Seed, entry.Registry, Fixtures.OtherDisk, Defaults.Pin);
        try
        {
            var recovered = OtpEngine.Unlock(changed, Fixtures.OtherDisk, Defaults.Pin);
            Assert.Equal(entry.Seed, recovered);
            Assert.Throws<OtpException>(() => OtpEngine.Unlock(changed, Fixtures.OtherDisk, Fixtures.Pin));
            Assert.Equal(0xAABBCCDDu, changed.Single(v => v.Name == "Flags").Dword);
            Assert.Equal("Synthetic only", changed.Single(v => v.Name == "Label").Text);
            foreach (var counter in new uint[] { 0, 1, 1234567, 0x80000000, uint.MaxValue })
                Assert.Equal(OtpEngine.GenerateCounter(entry.Seed, counter, 6), OtpEngine.GenerateCounter(recovered, counter, 6));
        }
        finally { SecretBuffers.Clear(changed); }
    }
    [Fact]
    public void RewrapPreservesUnknownVmTailAndRemovesPlainSharedKey()
    {
        var values = Fixtures.Registry();
        var i = values.FindIndex(v => v.Name == "VMData");
        values[i] = new() { Name = "vmdata", Kind = OtpRegistryValueKind.Binary, Binary = values[i].Binary!.Concat(new byte[] { 55, 66, 77 }).ToArray() };
        values.Add(new() { Name = "SharedKey", Kind = OtpRegistryValueKind.Binary, Binary = Fixtures.Seed() });
        var changed = OtpEngine.Rewrap(Fixtures.Seed(), values, Fixtures.OtherDisk, Defaults.Pin);
        Assert.Equal(new byte[] { 55, 66, 77 }, changed.Single(v => v.Name == "vmdata").Binary![48..]);
        Assert.DoesNotContain(changed, v => v.Name == "SharedKey");
    }
    [Theory]
    [InlineData(15)] [InlineData(30)] [InlineData(60)]
    public void ExactBoundaryRefreshesCounterAndCountdown(int seconds)
    {
        var before = OtpEngine.Generate(Fixtures.Seed(), new(seconds, 6), DateTimeOffset.FromUnixTimeSeconds(OtpEngine.Epoch + seconds - 1));
        var after = OtpEngine.Generate(Fixtures.Seed(), new(seconds, 6), DateTimeOffset.FromUnixTimeSeconds(OtpEngine.Epoch + seconds));
        Assert.Equal(0, before.Counter); Assert.Equal(1, before.SecondsRemaining);
        Assert.Equal(1, after.Counter); Assert.Equal(seconds, after.SecondsRemaining);
        Assert.Equal(1, after.RemainingFraction);
    }
    [Fact] public void RejectsClockBeforeEpoch() => Assert.Throws<OtpException>(() => OtpEngine.Generate(Fixtures.Seed(), new(60, 6), DateTimeOffset.UnixEpoch));
    [Theory] [InlineData("12345")] [InlineData("1234567")] [InlineData("１２３４５６")] [InlineData("12 456")]
    public void PinMustBeSixAsciiDigits(string pin) => Assert.Throws<OtpException>(() => OtpEngine.ValidatePin(pin));

    [Fact]
    public void DiskKeyMatchesObservedCopyOtpFormat()
    {
        Assert.Equal("0000" + Fixtures.Disk.DiskId[^16..], OtpEngine.DiskKey(Fixtures.Disk));
        Assert.Equal("ABCD" + Fixtures.OtherDisk.DiskId[^16..], OtpEngine.DiskKey(Fixtures.OtherDisk));
        Assert.Throws<OtpException>(() => OtpEngine.DiskKey(new(Fixtures.Disk.DiskId, 1)));
    }
    [Fact]
    public void RegistryRoundTripPreservesValuesAndCaseInsensitiveLookup()
    {
        var values = Fixtures.Registry();
        var encoded = ProfileWriter.RegistryFile(values);
        var parsed = ProfileFiles.ParseRegistry(encoded);
        Assert.Equal(Fixtures.Seed(), OtpEngine.Unlock(parsed, ProfileFiles.ParseDisk(ProfileWriter.DiskFile(Fixtures.Disk)), Fixtures.Pin));
    }
    [Theory]
    [InlineData("[HKEY_LOCAL_MACHINE\\Software\\AnyOTP]")]
    [InlineData("[-HKEY_CURRENT_USER\\Software\\AnyOTP]")]
    [InlineData("[HKEY_CURRENT_USER\\Software\\Other]")]
    public void RegistryImportCannotExecuteOrTargetOtherKeys(string header) =>
        Assert.Throws<InvalidDataException>(() => ProfileFiles.ParseRegistry(Encoding.UTF8.GetBytes("Windows Registry Editor Version 5.00\r\n\r\n" + header + "\r\n\"x\"=hex:00\r\n")));
    [Theory]
    [InlineData("\"x\"=hex:00\r\n\"X\"=hex:01")]
    [InlineData("\"x\"=hex:gg")] [InlineData("\"x\"=-")] [InlineData("\"x\"=hex(2):00")]
    public void RejectsAmbiguousOrUnsupportedRegistryValues(string data) => Assert.Throws<InvalidDataException>(() =>
        ProfileFiles.ParseRegistry(Encoding.UTF8.GetBytes("Windows Registry Editor Version 5.00\r\n[HKCU\\Software\\AnyOTP]\r\n" + data)));
    [Fact]
    public void Utf16BigEndianAndUtf8BomAreAccepted()
    {
        var text = Encoding.Unicode.GetString(ProfileWriter.RegistryFile(Fixtures.Registry()).AsSpan(2));
        foreach (var encoding in new Encoding[] { new UnicodeEncoding(true, true, true), new UTF8Encoding(true, true) })
            Assert.Equal(4, ProfileFiles.ParseRegistry(encoding.GetPreamble().Concat(encoding.GetBytes(text)).ToArray()).Count);
    }
}
