using BinSight.Core.Analysis;
using BinSight.Core.Checks;
using BinSight.Core.Config;
using BinSight.Core.PE;
using Xunit;

namespace BinSight.Tests;

public class BaselineAndConfigTests
{
    [Fact]
    public void BaselineDiff_DetectsNewFailure()
    {
        var synth = SyntheticPE.NewHealthyPE32Plus();
        synth.LoadConfig = new SyntheticLoadConfig
        {
            HasSecurityCookie = true,
            GuardCfCheckFunction = 0x1000,
            GuardFlags = PEConstants.GuardCfInstrumented,
        };
        string path = Path.GetTempFileName();
        File.WriteAllBytes(path, synth.Build());
        try
        {
            var report = Analyzer.Default().Analyze(path);
            var batch = new BatchAnalysisReport(path, new[] { report });
            var snap = BaselineComparer.Capture(batch);

            // Force a synthetic "new" failure into current by cloning with an extra fail entry — easier: mutate baseline to remove a fail.
            // Take current as baseline; create "current" with DBCheck forced fail by scanning a broken ASLR binary.
            var bad = SyntheticPE.NewHealthyPE32Plus();
            bad.DllCharacteristics = (ushort)(bad.DllCharacteristics & ~PEConstants.DllCharDynamicBase);
            bad.LoadConfig = synth.LoadConfig;
            string badPath = Path.GetTempFileName();
            File.WriteAllBytes(badPath, bad.Build());
            try
            {
                // Baseline from healthy
                string baseFile = Path.GetTempFileName();
                BaselineComparer.Save(snap, baseFile);

                var badReport = Analyzer.Default().Analyze(badPath);
                var badBatch = new BatchAnalysisReport(badPath, new[] { badReport });
                // Diff keys on full path — normalize by using same logical compare after rewriting baseline target
                foreach (var e in snap.Entries)
                    e.Target = Path.GetFullPath(badPath).Replace('\\', '/');
                BaselineComparer.Save(snap, baseFile);

                var diff = BaselineComparer.Diff(BaselineComparer.Load(baseFile), badBatch);
                Assert.True(diff.NewFailures >= 1);
            }
            finally
            {
                File.Delete(badPath);
            }
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void ScanConfig_LoadsChecksAndFailOn()
    {
        string cfg = Path.GetTempFileName();
        File.WriteAllText(cfg, """
            <?xml version="1.0"?>
            <BinSightConfig>
              <Profile>modern</Profile>
              <Checks>
                <Check name="DBCheck" />
                <Check name="NXCheck" />
              </Checks>
              <FailOn>
                <Check name="DBCheck" />
              </FailOn>
            </BinSightConfig>
            """);
        try
        {
            var loaded = ScanConfig.Load(cfg);
            Assert.Equal(2, loaded.Checks.Count);
            Assert.Contains("DBCheck", loaded.FailOn);
            var checks = loaded.ResolveChecks(null, Array.Empty<string>(), Array.Empty<string>(), out var err);
            Assert.Null(err);
            Assert.Equal(2, checks.Count);
        }
        finally
        {
            File.Delete(cfg);
        }
    }
}
