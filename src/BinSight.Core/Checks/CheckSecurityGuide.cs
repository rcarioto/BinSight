namespace BinSight.Core.Checks;

/// <summary>
/// Educational and triage copy for a check: why it exists, what Pass/Fail mean,
/// when a Fail may be expected noise, what signals a real issue, and what to ask
/// the application team during follow-up.
/// </summary>
public sealed record CheckSecurityGuide(
    string Purpose,
    string WhyItMatters,
    string RoleInBinary,
    string IfPasses,
    string IfFails,
    string WhenFailMayBeExpected,
    string RealIssueSignal,
    IReadOnlyList<string> AskTheTeam,
    string IfNotApplicable = "This check does not apply to this image (wrong architecture, managed runtime, missing feature, or toolchain era). That is informational, not a finding.")
{
    public string MeaningFor(CheckStatus status) => status switch
    {
        CheckStatus.Pass => IfPasses,
        CheckStatus.Fail => IfFails,
        CheckStatus.NotApplicable => IfNotApplicable,
        CheckStatus.Error =>
            "BinSight could not complete this check (truncated, unreadable, or unexpected image data). Treat as incomplete coverage until the underlying issue is resolved.",
        _ => "Unknown status.",
    };
}

/// <summary>Central catalogue of security explanations for every built-in check.</summary>
public static class CheckDocumentation
{
    private static IReadOnlyList<string> Q(params string[] questions) => questions;

    private static readonly Dictionary<string, CheckSecurityGuide> Guides =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["DBCheck"] = new(
                Purpose: "Verify that the image opts in to Address Space Layout Randomization (ASLR) via /DYNAMICBASE.",
                WhyItMatters: "ASLR randomizes the load address of the module each run, making reliable exploitation of memory-corruption bugs much harder because attackers cannot hard-code absolute addresses for ROP gadgets or shellcode.",
                RoleInBinary: "The PE optional-header DllCharacteristics bit IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE tells the Windows loader it may rebase this module. Combined with a relocation table, this is the binary's ASLR opt-in.",
                IfPasses: "ASLR is enabled for this module. The loader can place it at a randomized base, which raises the bar for classic return-oriented and return-to-libc style exploits that depend on fixed addresses.",
                IfFails: "ASLR is not enabled. The module will tend to load at a predictable preferred base, giving attackers stable addresses for gadgets and data. Relink with /DYNAMICBASE (and ensure relocations are not stripped).",
                WhenFailMayBeExpected: "Rare for modern Microsoft toolsets (defaults enable DYNAMICBASE). May appear on very old binaries, intentionally fixed-address firmware/boot helpers, or images deliberately linked /FIXED for a constrained environment.",
                RealIssueSignal: "A user-mode app or DLL shipping without DYNAMICBASE on a supported OS is almost always a real hardening gap—especially if RelocsStrippedCheck also fails.",
                AskTheTeam: Q(
                    "Was this binary linked with an intentional /FIXED or no-/DYNAMICBASE policy, and if so why?",
                    "Can you rebuild with /DYNAMICBASE and confirm the base relocation directory is present?",
                    "Is this image ever loaded at a hard-coded address by a custom loader that would break under ASLR?")),

            ["NXCheck"] = new(
                Purpose: "Verify that the image opts in to Data Execution Prevention (DEP) via /NXCOMPAT.",
                WhyItMatters: "DEP/NX marks data pages non-executable so injected shellcode on the stack or heap cannot run directly. It forces attackers toward more complex ROP/JOP techniques instead of raw code injection.",
                RoleInBinary: "IMAGE_DLLCHARACTERISTICS_NX_COMPAT tells Windows to apply hardware NX (No-eXecute) policy to this process/module's data regions.",
                IfPasses: "DEP is enabled. Stack/heap memory should not be executable under normal loader policy, blocking straightforward shellcode injection.",
                IfFails: "DEP is not enabled. Data regions may remain executable, allowing attackers who gain a write-primitive to run injected code directly. Relink with /NXCOMPAT.",
                WhenFailMayBeExpected: "Uncommon on current VS defaults. Legacy code that self-modifies or relies on executable data (old JIT stubs, some DRM) sometimes cleared NXCOMPAT historically—those cases need explicit risk acceptance, not silent ignore.",
                RealIssueSignal: "Missing NXCOMPAT on a normal application/DLL is a genuine SDL defect unless the team documents a rare requirement for executable data and compensating controls.",
                AskTheTeam: Q(
                    "Do you intentionally require executable data pages, and what feature forces that?",
                    "Can you rebuild with /NXCOMPAT and retest the feature that previously needed executable data?",
                    "If NX must stay off, what compensating controls (CFG, ACG, code signing, sandbox) are in place?")),

            ["HighEntropyVACheck"] = new(
                Purpose: "Verify that 64-bit images opt in to high-entropy ASLR (/HIGHENTROPYVA).",
                WhyItMatters: "On 64-bit Windows, high-entropy ASLR uses far more address bits when randomizing the image base, shrinking the chance that an attacker can guess a useful address even with information leaks of limited precision.",
                RoleInBinary: "IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA (with DYNAMIC_BASE) asks the loader for full 64-bit ASLR entropy for this PE32+ image.",
                IfPasses: "High-entropy ASLR is active. The module benefits from the strongest practical user-mode address randomization Windows offers for PE images.",
                IfFails: "The 64-bit image lacks high-entropy ASLR (or lacks DYNAMIC_BASE). Address guesses and partial pointer leaks are more useful to an attacker. Relink with /DYNAMICBASE and /HIGHENTROPYVA.",
                WhenFailMayBeExpected: "Expected N/A on 32-bit images. On 64-bit, fail is unusual unless the binary is old, or DYNAMICBASE itself is missing (then fix DYNAMICBASE first).",
                RealIssueSignal: "A modern 64-bit user-mode binary without HIGH_ENTROPY_VA (while DYNAMICBASE is set) is a real missed mitigation—easy linker fix.",
                AskTheTeam: Q(
                    "Is the release build using a current 64-bit toolset with /HIGHENTROPYVA (often default when /DYNAMICBASE is on)?",
                    "If HIGHENTROPYVA was disabled, what compatibility constraint required it?",
                    "Does RelocsStrippedCheck / DBCheck also fail on this image?")),

            ["AppContainerCheck"] = new(
                Purpose: "Verify the image is marked for AppContainer isolation (/APPCONTAINER).",
                WhyItMatters: "AppContainer is the sandbox boundary used by Windows Store / UWP-style apps. Without it, Store certification fails and the process will not receive the intended capability-based isolation.",
                RoleInBinary: "IMAGE_DLLCHARACTERISTICS_APPCONTAINER declares that the image is intended to run inside an AppContainer token with restricted capabilities.",
                IfPasses: "The binary declares AppContainer compatibility, matching the isolation model expected for sandboxed Store apps.",
                IfFails: "The binary is not AppContainer-marked. It will not meet Windows Store packaging requirements and will not opt into that sandbox boundary.",
                WhenFailMayBeExpected: "Expected for classic Win32/Win64 desktop, services, drivers, and most line-of-business EXEs. This check is opt-in and is not an SDL fail for non-Store apps.",
                RealIssueSignal: "Only a real issue when the product is supposed to ship as a Store/UWP/AppContainer app (or policy requires AppContainer) and the bit is missing.",
                AskTheTeam: Q(
                    "Is this binary required to run inside an AppContainer or pass Store certification?",
                    "If yes, why is IMAGE_DLLCHARACTERISTICS_APPCONTAINER clear in the release build?",
                    "If no, can this finding be accepted as N/A for desktop packaging?")),

            ["SafeSEHCheck"] = new(
                Purpose: "Verify 32-bit images use Safe Structured Exception Handling (/SAFESEH) or opt out of SEH entirely.",
                WhyItMatters: "On x86, attackers historically overwrote SEH handler pointers on the stack to hijack control flow. SafeSEH restricts dispatch to a linker-registered handler table, blocking many classic SEH exploits.",
                RoleInBinary: "Either IMAGE_DLLCHARACTERISTICS_NO_SEH is set, or the Load Config directory publishes a SafeSEH handler table the OS validates before calling a handler.",
                IfPasses: "Exception dispatch is constrained (SafeSEH table or no-SEH). Overwriting a stack SEH record is much less likely to yield reliable code execution.",
                IfFails: "The x86 image has neither SafeSEH nor NO_SEH. A stack-based SEH overwrite may allow the attacker to point the handler at attacker-controlled code or a gadget. Relink with /SAFESEH.",
                WhenFailMayBeExpected: "N/A on 64-bit (by design). On x86, fail on ancient non-MSVC toolchains may need migration rather than a one-flag fix.",
                RealIssueSignal: "Any still-supported 32-bit native binary without SafeSEH/NO_SEH is a real classic exploitability issue—prioritize rebuild.",
                AskTheTeam: Q(
                    "Is a 32-bit build still required, or can customers move to 64-bit?",
                    "Can you relink with /SAFESEH (or /SAFESEH:NO if SEH is unused) on the current toolset?",
                    "Which modules are still x86 and who owns their build flags?")),

            ["WXCheck"] = new(
                Purpose: "Detect sections that are both writable and executable (W^X violations).",
                WhyItMatters: "Memory that is writable and executable lets an attacker who can write into that section plant and immediately run code. Enforcing W^X (write XOR execute) is a foundational memory-safety mitigation.",
                RoleInBinary: "PE section Characteristics must not combine IMAGE_SCN_MEM_WRITE with IMAGE_SCN_MEM_EXECUTE for the same section.",
                IfPasses: "No section is both writable and executable. Code pages should be non-writable and data pages non-executable at the section level.",
                IfFails: "At least one section is writable and executable. An attacker with a write primitive into that section can inject runnable code without needing a separate DEP bypass for that region. Rebuild so code and writable data are separated.",
                WhenFailMayBeExpected: "Some packers, protectors, or legacy self-modifying loaders ship W+X sections by design. That is still high risk—treat as accepted residual risk only with a strong business reason.",
                RealIssueSignal: "W+X in a normal product binary (not an intentional packer) is a serious real defect. Investigate section names and the linker/post-build step that created them.",
                AskTheTeam: Q(
                    "Which section is W+X, and which build step (linker, packer, post-process) creates it?",
                    "Can the feature be rewritten so code is RX and data is RW without overlap?",
                    "If a packer is required, is there a newer packing mode that avoids persistent W+X?")),

            ["SharedSectionCheck"] = new(
                Purpose: "Detect sections that are both writable and shared across processes.",
                WhyItMatters: "A writable shared section is a cross-process communication channel that any local process mapping the same section can corrupt. That enables privilege escalation and cross-process exploitation when a higher-privilege process trusts shared data.",
                RoleInBinary: "IMAGE_SCN_MEM_SHARED combined with IMAGE_SCN_MEM_WRITE creates a shared writable mapping.",
                IfPasses: "No writable-shared sections were found, reducing a common local privilege-escalation primitive.",
                IfFails: "A writable shared section exists. Another process may alter data this module reads while running, which has historically led to elevation-of-privilege bugs. Remove shared-write sections or make them read-only.",
                WhenFailMayBeExpected: "Legacy IPC designs sometimes used PE shared sections. Prefer replacing with proper IPC (RPC, ALPC, named pipes with ACLs) rather than accepting shared-write PE sections.",
                RealIssueSignal: "Writable shared sections in privileged or multi-user-facing components are a classic real local EoP pattern—treat as high priority.",
                AskTheTeam: Q(
                    "What data is exchanged via the shared section, and which processes map it?",
                    "Is the higher-privilege side validating/copying shared data safely before use?",
                    "Can this be migrated to ACL'd IPC instead of a writable shared PE section?")),

            ["ExecutableImportsCheck"] = new(
                Purpose: "Ensure the Import Address Table (IAT) does not live in an executable section.",
                WhyItMatters: "If the IAT is executable, overwriting a function pointer in the IAT can turn into direct execution of attacker-controlled bytes or ease certain exploitation patterns. Keeping the IAT non-executable limits damage from IAT corruption.",
                RoleInBinary: "The IAT (and import thunks) should reside in a readable data section such as .rdata, not in .text.",
                IfPasses: "Import thunks are in a non-executable section. IAT corruption alone does not create an executable landing pad in that region.",
                IfFails: "The IAT sits in an executable section. Corrupting an import pointer may be easier to turn into code execution. Relink so imports land in non-executable data.",
                WhenFailMayBeExpected: "Unusual with modern MSVC defaults. Custom link scripts, non-MSVC toolchains, or aggressive packing can relocate imports oddly.",
                RealIssueSignal: "IAT in .text (or another executable section) on a production native binary is a real layout defect worth fixing in the link step.",
                AskTheTeam: Q(
                    "Which linker/version and .def/linkerscript produced this layout?",
                    "Can you rebuild so the IAT lands in .rdata (default MSVC behavior)?",
                    "Is a packer or custom post-link tool moving sections after the link?")),

            ["GSCheck"] = new(
                Purpose: "Verify the image publishes a /GS security cookie in the Load Config directory.",
                WhyItMatters: "/GS plants a stack canary (security cookie) before return addresses. Buffer overflows that smash the stack typically overwrite the canary; the runtime detects the mismatch and terminates before returning to attacker-controlled addresses.",
                RoleInBinary: "The Load Config SecurityCookie field points at the module's global cookie storage used by __security_check_cookie / compiler-inserted GS probes.",
                IfPasses: "A /GS security cookie is declared. Instrumentable functions can detect many stack smashing attempts before hijacked returns run.",
                IfFails: "No security cookie is declared. Stack buffer overflows are far more likely to achieve reliable control-flow hijack. Rebuild with /GS and a current CRT.",
                WhenFailMayBeExpected: "Expected N/A for managed (.NET) images. Native binaries built without the MSVC CRT (or with /GS-) may fail—only acceptable with a documented alternate stack-hardening story.",
                RealIssueSignal: "Missing SecurityCookie on a native MSVC-targeted app/DLL is a real SDL gap unless the module is pure assembly with no stack buffers and a written exception.",
                AskTheTeam: Q(
                    "Was /GS disabled (/GS-), or is a non-MSVC toolchain in use?",
                    "Can you rebuild with /GS and the standard CRT and confirm Load Config shows a cookie?",
                    "Which modules are native vs managed in this product family?")),

            ["DefaultGSCookieCheck"] = new(
                Purpose: "Detect whether the on-disk /GS cookie still holds the compiler's well-known default literal.",
                WhyItMatters: "A canary that never becomes process-specific is forgeable. This check reads the cookie bytes in the PE file (or image as scanned). On a static file that is expected to still contain the compile-time default until __security_init_cookie runs at process start.",
                RoleInBinary: "Bytes at the SecurityCookie VA inside the PE image.",
                IfPasses: "Cookie storage does not hold the known default constant. That can indicate a non-default build-time value, a post-processed image, or a dump/snapshot taken after initialization.",
                IfFails: "On-disk (or scanned) cookie storage holds the compiler default (e.g. 0x00002B992DDFA232). For a normal static scan of a /GS binary this is often expected; it becomes a real issue if GS init never runs or a live dump still shows the default after startup.",
                WhenFailMayBeExpected: "Very common and usually benign on static PE scans: the compiler writes the default into the image; randomization happens at runtime via __security_init_cookie. If GSCheck and GSFriendlyInitCheck pass, treat a static default-cookie Fail as likely noise unless you are assessing a memory dump.",
                RealIssueSignal: "Real issue when (a) analyzing a running process/dump after init and the cookie is still the default, or (b) GSCheck/GSFriendlyInitCheck suggest the CRT never seeds the cookie. Do not treat static default alone as proof the canary is weak at runtime.",
                AskTheTeam: Q(
                    "Was this scan against an on-disk EXE/DLL (static) or a process dump after startup?",
                    "Do GSCheck and GSFriendlyInitCheck pass on the same image?",
                    "If this is a dump: has __security_init_cookie run, and is the CRT the standard Microsoft one?",
                    "Can you confirm /GS is enabled and the module is not using a custom CRT that skips cookie init?")),

            ["GSFunctionSafeBuffersCheck"] = new(
                Purpose: "Confirm Load Config does not advertise that the security cookie is unused.",
                WhyItMatters: "GuardFlags can claim the cookie is unused, which signals the /GS contract is inactive even if other fields look populated—effectively disabling canary protection.",
                RoleInBinary: "IMAGE_GUARD_SECURITY_COOKIE_UNUSED in Load Config GuardFlags must be clear when /GS is intended.",
                IfPasses: "Load Config presents an active /GS cookie contract; buffer-security metadata is consistent with protection being on.",
                IfFails: "The image advertises an unused security cookie or lacks cookie metadata. Stack canaries are not protecting this binary as expected. Rebuild with /GS on a current toolset.",
                WhenFailMayBeExpected: "N/A for managed images. Some exotic non-MSVC natives may lack Load Config entirely—then GSCheck already failed.",
                RealIssueSignal: "SECURITY_COOKIE_UNUSED set (or null cookie with GuardFlags claiming GS) on an MSVC binary is a real indication /GS is not active as intended.",
                AskTheTeam: Q(
                    "Was the binary built with /GS- or an option that marks the cookie unused?",
                    "Can you rebuild with default /GS on the current VS toolset?",
                    "Does GSCheck also fail, or only this GuardFlags consistency check?")),

            ["GSFriendlyInitCheck"] = new(
                Purpose: "Heuristically verify the image imports entropy sources used by a /GS-friendly CRT initializer.",
                WhyItMatters: "__security_init_cookie must seed the canary with unpredictable process-specific entropy. Without a proper initializer, the cookie may be weak or static.",
                RoleInBinary: "Typical CRT startup imports helpers such as QueryPerformanceCounter / GetCurrentProcessId from KERNEL32 (or API-set equivalents) to mix into the cookie.",
                IfPasses: "Imports consistent with a GS-friendly CRT initializer were found, supporting strong canary seeding.",
                IfFails: "Could not confirm GS initializer entropy imports. The cookie may be weakly seeded or /GS may be incomplete. Link the standard CRT with /GS enabled.",
                WhenFailMayBeExpected: "Heuristic: delay-load-only imports, API-set renaming BinSight does not recognize, or a custom CRT can produce false fails even when init is correct. Correlate with GSCheck.",
                RealIssueSignal: "Fail plus missing SecurityCookie, or a custom entrypoint that never calls CRT startup, strongly suggests a real weak-/no-canary problem.",
                AskTheTeam: Q(
                    "Are you linking the standard Microsoft CRT, and does startup call __security_init_cookie?",
                    "Are entropy APIs delay-loaded or imported under an API-set name BinSight might not match?",
                    "Can you share the linker CRT choice (/MT, /MD, custom) for this binary?")),

            ["CompilerVersionCheck"] = new(
                Purpose: "Ensure the binary was produced with a sufficiently modern Microsoft linker/toolset.",
                WhyItMatters: "Older toolchains ship weaker defaults (no CFG, weaker GS, vulnerable libraries, missing mitigations). Enforcing a minimum toolset is a policy control that pulls binaries forward onto defended compilers.",
                RoleInBinary: "Optional-header linker version and the Rich header record which compiler/linker components built the image.",
                IfPasses: "The recorded toolset meets policy. The binary was likely built with mitigations and CRT fixes available in that era's toolchain.",
                IfFails: "The image was linked with an older toolset than policy allows. It may lack modern mitigations and may include known-vulnerable library code. Rebuild with a current Visual Studio toolset.",
                WhenFailMayBeExpected: "Third-party redistributables you cannot rebuild will fail until vendors update. Policy may intentionally allow exceptions with compensating controls.",
                RealIssueSignal: "First-party code still shipping on a pre-policy toolset is a real process/security debt issue—especially if CFG/CET/GS-related checks also fail.",
                AskTheTeam: Q(
                    "Is this first-party code or a third-party component you cannot rebuild?",
                    "What VS/build agents produce the release artifact, and can they move to the required toolset?",
                    "If stuck on an old toolset, which mitigations are missing and what is the exception approval?")),

            ["ATLVersionCheck"] = new(
                Purpose: "When ATL is used, verify it came from a modern Visual C++ toolset.",
                WhyItMatters: "Out-of-date ATL has carried serious vulnerabilities. Modern ATL bundles fixes and safer defaults.",
                RoleInBinary: "Imports of ATL*.DLL plus Rich-header compiler entries indicate an ATL-consuming native binary and its build vintage.",
                IfPasses: "ATL usage appears tied to a modern compiler vintage, reducing exposure to historical ATL defects.",
                IfFails: "ATL is present but the toolchain looks old. The process may be exposed to known ATL issues. Rebuild against current ATL headers/libs.",
                WhenFailMayBeExpected: "N/A when ATL is not imported. Vendor binaries may lag; track as dependency risk rather than your app's compiler flags alone.",
                RealIssueSignal: "First-party ATL code on an ancient toolset—especially with ATLVulnCheck also failing—is a real known-vuln concern.",
                AskTheTeam: Q(
                    "Which modules still use ATL, and can they rebuild on current VC++ ATL?",
                    "Is ATL dynamically imported from a shared redistributable you control?",
                    "Does ATLVulnCheck also fail for the CVE-era toolchain window?")),

            ["ATLVulnCheck"] = new(
                Purpose: "Fail ATL-using binaries built with toolchains known to ship CVE-2009-0901 / CVE-2009-2493 vulnerable ATL headers.",
                WhyItMatters: "Those CVEs were widely exploited. Continuing to ship that ATL vintage is an unacceptable known risk.",
                RoleInBinary: "Rich-header compiler build numbers estimate whether pre-fix ATL headers could have been compiled in.",
                IfPasses: "Compiler vintage is past the vulnerable ATL window for those CVEs.",
                IfFails: "Compiler vintage matches the vulnerable ATL era. Treat this binary as carrying a known-dangerous ATL attack surface until rebuilt.",
                WhenFailMayBeExpected: "Only when ATL is present. Heuristic Rich-header dating can mis-estimate exotic build pipelines—confirm with actual ATL headers used.",
                RealIssueSignal: "Fail for an ATL binary in the vulnerable compiler window should be treated as a real, historical high-severity defect until disproven by rebuild evidence.",
                AskTheTeam: Q(
                    "Can you prove the binary was rebuilt with post-fix ATL headers (VS version, build logs)?",
                    "Is this component still exposed to untrusted input that historically triggered those ATL bugs?",
                    "What is the timeline to remove or rebuild this ATL consumer?")),

            ["RSA32Check"] = new(
                Purpose: "Detect linkage against the deprecated RSA32/RSABASE cryptographic libraries.",
                WhyItMatters: "RSA32 is obsolete, unmaintained, and not appropriate for modern cryptography. Its presence signals outdated crypto and likely weak algorithms/protocols.",
                RoleInBinary: "Import or delay-load of RSA32/RSABASE DLLs.",
                IfPasses: "No deprecated RSA32/RSABASE dependency detected.",
                IfFails: "Deprecated RSA crypto libraries are referenced. Replace with supported APIs (CNG/BCrypt, WinCrypt where appropriate) and remove RSA32.",
                WhenFailMayBeExpected: "Almost never 'fine'—only transitional vendor blobs pending replacement. Still track as crypto debt.",
                RealIssueSignal: "Any shipping dependency on RSA32/RSABASE is a real obsolete-crypto finding.",
                AskTheTeam: Q(
                    "Which feature still calls into RSA32/RSABASE?",
                    "What is the migration plan to CNG/BCrypt (or other supported APIs)?",
                    "Are certificates/keys handled with modern algorithms after migration?")),

            ["VB6Check"] = new(
                Purpose: "Detect Visual Basic 6 / MSVBVM60 binaries.",
                WhyItMatters: "VB6 is unsupported, lacks modern exploit mitigations, and pulls in a legacy runtime with a large historical vulnerability surface.",
                RoleInBinary: "Imports of MSVBVM*.DLL or Rich-header Visual Basic product entries.",
                IfPasses: "No evidence of VB6 runtime usage.",
                IfFails: "The image appears to be VB6-based. It will not receive modern compiler mitigations and depends on an unsupported runtime. Migrate off VB6.",
                WhenFailMayBeExpected: "Only if the organization has an explicit, time-bounded exception for a frozen VB6 line-of-business app. It is still unsupported platform risk.",
                RealIssueSignal: "VB6 in any internet-facing or privileged component is a real strategic security/platform issue, not a false positive.",
                AskTheTeam: Q(
                    "Is migration off VB6 already planned, and what is the target stack?",
                    "What is the attack surface (network, local, parsers) of this VB6 component?",
                    "Can compensating controls (isolation, reduced privileges, network filters) be applied until migration?")),

            ["FunctionPointersCheck"] = new(
                Purpose: "Legacy BinScope check for unprotected indirect calls; superseded by CFGCheck.",
                WhyItMatters: "Indirect calls (function pointers, virtuals) are prime hijack targets. Without Control Flow Guard, attackers can redirect them to gadgets after corrupting a pointer.",
                RoleInBinary: "DllCharacteristics GUARD_CF and Load Config CFG fields declare OS-enforced indirect-call validation.",
                IfPasses: "Indirect calls are protected by CFG (or the CLR for managed code).",
                IfFails: "No CFG protection for indirect calls. Corrupting a function pointer can transfer control to attacker-chosen addresses. Enable /GUARD:CF.",
                WhenFailMayBeExpected: "Prefer reading CFGCheck for modern triage. Managed images are N/A. Very old toolchains may need a full rebuild before CFG is available.",
                RealIssueSignal: "Same as CFG missing on a native binary you can rebuild with VS2015+: real mitigation gap.",
                AskTheTeam: Q(
                    "Can you enable /GUARD:CF and confirm CFGCheck passes?",
                    "Are you looking at CFGCheck results for the authoritative modern finding?",
                    "Which modules are still below the CFG-capable toolset?")),

            ["CFGCheck"] = new(
                Purpose: "Verify Control Flow Guard (/GUARD:CF) is enabled and backed by Load Config metadata.",
                WhyItMatters: "CFG is the primary Windows mitigation against indirect call/jump hijacking after memory corruption. It validates call targets against a bitmap of legal addresses before the call proceeds.",
                RoleInBinary: "IMAGE_DLLCHARACTERISTICS_GUARD_CF plus Load Config Guard CF check/dispatch pointers and GuardFlags instrumentation bits.",
                IfPasses: "CFG is enabled and consistent. Indirect call targets are validated by the OS, sharply limiting arbitrary control-flow transfers via corrupted pointers.",
                IfFails: "CFG is missing or inconsistent (flag/metadata mismatch). Attackers who corrupt function pointers have a much easier path to code reuse. Relink with /GUARD:CF on VS2015+.",
                WhenFailMayBeExpected: "N/A for managed (.NET) images—CLR/JIT covers analogous concerns. N/A for pre-CFG-era toolchains. Flag/metadata mismatch (one set without the other) is never 'fine.'",
                RealIssueSignal: "Native image on a CFG-capable toolset without GUARD_CF, or inconsistent CFG metadata, is a real SDL failure for modern Windows software.",
                AskTheTeam: Q(
                    "Is /GUARD:CF enabled in the release project/props for all native modules?",
                    "If CFG is missing, is the toolset older than VS2015, or was the flag turned off?",
                    "Do you see GUARD_CF without Load Config instrumentation (or the reverse)?")),

            ["CETCheck"] = new(
                Purpose: "Verify hardware-enforced stack protection compatibility (/CETCOMPAT).",
                WhyItMatters: "Intel CET shadow stacks (and Windows' enforcement) detect return-address tampering—the core of ROP. /CETCOMPAT marks the module safe for shadow-stack enforcement.",
                RoleInBinary: "Extended DLL characteristics (debug type EX_DLLCHARACTERISTICS) bit IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT.",
                IfPasses: "The image is CET-compatible. On CET-capable Windows/hardware, return-address integrity can be enforced for this module.",
                IfFails: "CET compatibility is not declared. Shadow-stack enforcement cannot fully protect returns in this module. Relink with /CETCOMPAT (VS2019 16.7+) when you control the link.",
                WhenFailMayBeExpected: "Expected for many .NET single-file / apphost stubs (Microsoft-provided native host not rebuilt by your project), older natives, and components you do not link. Managed payloads are N/A—runtime hosts CET differently. Missing CET on a vendor binary you cannot relink is a supply-chain limitation, not your csproj flag.",
                RealIssueSignal: "Real issue when your team owns the native link of this PE and could pass /CETCOMPAT but did not. Less actionable when the PE is a runtime host, third-party closed binary, or pre-CET toolchain.",
                AskTheTeam: Q(
                    "Do you own the linker command line for this exact PE, or is it a runtime/apphost/vendor stub?",
                    "If you own it: can you rebuild with /CETCOMPAT (VS2019 16.7+) and retest on Win10 20H1+ CET hardware?",
                    "If you do not own it: which vendor/runtime version would need to ship a CET-compatible host?",
                    "Are neighboring first-party native DLLs CET-marked even if this host is not?")),

            ["RelocsStrippedCheck"] = new(
                Purpose: "Ensure relocations exist so ASLR can actually rebase the image.",
                WhyItMatters: "/DYNAMICBASE is useless if relocations were stripped (/FIXED or IMAGE_FILE_RELOCS_STRIPPED). The loader cannot move the image, so ASLR silently fails.",
                RoleInBinary: "Absence of IMAGE_FILE_RELOCS_STRIPPED and presence of a base relocation directory.",
                IfPasses: "Relocations are available; ASLR can rebase the module as intended.",
                IfFails: "Relocations are stripped or missing. Even with DYNAMICBASE set, the image may load at a fixed address—ASLR provides little or no benefit. Relink without /FIXED and keep relocs.",
                WhenFailMayBeExpected: "Managed images may have minimal PE reloc directories (CLR handles layout)—often Pass with a managed note. Some embedded/boot EXEs are intentionally fixed.",
                RealIssueSignal: "DYNAMICBASE set but relocs stripped/missing on native user-mode code is a real ASLR bypass condition—high priority with DBCheck.",
                AskTheTeam: Q(
                    "Was /FIXED or /DYNAMICBASE:NO used intentionally?",
                    "Can you relink keeping the base relocation directory?",
                    "Does DBCheck pass while this fails (silent ASLR failure pattern)?")),

            ["AuthenticodeCheck"] = new(
                Purpose: "Report whether an Authenticode certificate table is embedded in the PE.",
                WhyItMatters: "Code signing binds identity to the binary and enables integrity checks (tamper evidence). Unsigned code is harder to trust in enterprise allowlisting and Secure Boot–adjacent workflows.",
                RoleInBinary: "The Certificate Table data directory (file offset) holds WIN_CERTIFICATE / PKCS#7 signature blobs.",
                IfPasses: "An Authenticode certificate table is present (presence only—not a full trust-chain validation). The file carries a signature payload that can be verified with platform tools.",
                IfFails: "No Authenticode table. The binary is unsigned at the PE level; tampering is not detectable via WinVerifyTrust-style checks until it is signed.",
                WhenFailMayBeExpected: "Common and often acceptable for local CI artifacts, unsigned open-source drops, and pre-release builds. Production enterprise distribution usually requires signing by policy—not by PE exploit-mitigation SDL alone.",
                RealIssueSignal: "Real issue for release channels that promise signed updates, SmartScreen reputation, or WDAC/AppLocker allowlisting—absence means those controls cannot work as designed.",
                AskTheTeam: Q(
                    "Is this build supposed to be customer-facing/production signed?",
                    "Which certificate and pipeline (signtool / Azure Signing) should sign it?",
                    "Should AuthenticodeVerifyCheck also be enabled for chain validation on Windows?")),

            ["DelayLoadCheck"] = new(
                Purpose: "When delay-load imports exist, require a guarded delay-load IAT.",
                WhyItMatters: "Delay-load IATs were historically writable and a target for pointer swaps. Modern toolsets can protect them (read-only after bind) via GuardFlags.",
                RoleInBinary: "Delay-import directory plus IMAGE_GUARD_PROTECT_DELAYLOAD_IAT (and optionally own-section) in Load Config.",
                IfPasses: "Delay-load imports are present and the delay-load IAT is marked protected—reducing a writeable function-pointer table attack surface.",
                IfFails: "Delay-load imports exist without IAT protection. An attacker with a write primitive may redirect delay-bound APIs. Link with a current toolset and guarded delay-load support.",
                WhenFailMayBeExpected: "N/A when there are no delay-loads. Older toolsets may delay-load without GuardFlags—rebuild is the fix, not a runtime toggle.",
                RealIssueSignal: "Unprotected delay-load IAT on a modern native binary is a real, fixable linker hardening gap.",
                AskTheTeam: Q(
                    "Which DLLs are delay-loaded and why?",
                    "Can you rebuild with a current VS toolset so IMAGE_GUARD_PROTECT_DELAYLOAD_IAT is set?",
                    "Is delay-load still required, or can those imports be eager?")),

            ["ManifestUACCheck"] = new(
                Purpose: "Ensure EXEs declare a UAC requestedExecutionLevel in an embedded manifest.",
                WhyItMatters: "Without a manifest, older Windows may virtualize the process or apply unexpected elevation behavior. An explicit level documents privilege intent and avoids installer-detection heuristics.",
                RoleInBinary: "RT_MANIFEST resource containing trustInfo/requestedExecutionLevel (asInvoker, highestAvailable, or requireAdministrator).",
                IfPasses: "The EXE declares an explicit UAC execution level, making privilege requirements clear and avoiding ambiguous elevation heuristics.",
                IfFails: "No UAC-aware manifest (or missing requestedExecutionLevel). Windows may apply legacy virtualization or installer-detection elevation unexpectedly. Embed a manifest with an explicit level.",
                WhenFailMayBeExpected: "N/A for DLLs. Some console tools historically shipped without manifests; still better to add asInvoker explicitly.",
                RealIssueSignal: "Missing UAC level on an EXE that writes to Program Files / HKLM, or that unexpectedly elevates, is a real privilege-model bug. requireAdministrator when unnecessary is also a real over-privilege issue to question.",
                AskTheTeam: Q(
                    "What execution level is intended (asInvoker / highestAvailable / requireAdministrator), and why?",
                    "Can you embed a manifest with that level and retest file/registry virtualization behavior?",
                    "If requireAdministrator: which operations truly need elevation?")),

            ["ForceIntegrityCheck"] = new(
                Purpose: "Verify IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY.",
                WhyItMatters: "FORCE_INTEGRITY tells Windows to enforce code-integrity checks on the image (important for drivers and some protected scenarios).",
                RoleInBinary: "DllCharacteristics FORCE_INTEGRITY bit.",
                IfPasses: "FORCE_INTEGRITY is set; the loader/CI path will treat signature integrity as mandatory for this image.",
                IfFails: "FORCE_INTEGRITY is clear. Appropriate for many user apps; required or expected for certain driver/protected-component policies.",
                WhenFailMayBeExpected: "Normal and expected for ordinary user-mode applications. This check is opt-in; do not treat Fail as an SDL bug for typical desktop apps.",
                RealIssueSignal: "Real only when policy (driver, protected process light, CI enforcement) requires FORCE_INTEGRITY and the bit is missing—or when it is set without a valid signature (load failures).",
                AskTheTeam: Q(
                    "Is this component a driver or otherwise required to enforce code integrity at load?",
                    "If yes, is the image signed appropriately for FORCE_INTEGRITY?",
                    "If no, can this opt-in check be left disabled in your scan profile?")),

            ["SymbolsCheck"] = new(
                Purpose: "Report whether PDBs are available and what analysis depth that enables.",
                WhyItMatters: "Symbols do not change runtime exploitability by themselves, but they determine how deeply a reviewer can attribute mitigations (especially /GS) to individual functions. BinSight deliberately does not require them.",
                RoleInBinary: "CodeView debug directory may reference a PDB; /SymPath locates it beside the image or in a symbol store path.",
                IfPasses: "Symbol status was determined. Either analysis proceeded without PDBs (still covering PE-level mitigations) or a PDB was found for enhanced CRT helper confirmation.",
                IfFails: "This check is informational and normally does not fail; a failure would indicate an unexpected internal condition.",
                WhenFailMayBeExpected: "Missing PDBs beside a release EXE is normal. Referenced-but-absent PDB paths (e.g. CI machine paths) are common and do not mean the binary is insecure.",
                RealIssueSignal: "Not a runtime security defect. The 'issue' is reduced auditability—important for deep GS attribution, not for ASLR/DEP/CFG bits.",
                AskTheTeam: Q(
                    "Can matching PDBs be published to a symbol server or passed via /SymPath for deeper review?",
                    "Is the PDB path in the PE expected (private CI path) or a packaging mistake?",
                    "Do PE-level mitigation checks already pass without symbols?")),

            ["GSSymbolsCheck"] = new(
                Purpose: "When a PDB is present, confirm CRT /GS helper symbols; otherwise explain the no-symbol gap.",
                WhyItMatters: "Presence of __security_init_cookie / __security_check_cookie in symbols strongly corroborates that the CRT GS machinery is linked in—beyond what headers alone show.",
                RoleInBinary: "Public PDB content may include CRT GS helper names used at runtime for canary init and checks.",
                IfPasses: "Either helpers were confirmed via PDB probe, or the report clearly states that header-level GS checks still apply without symbols (and what private symbols would add).",
                IfFails: "A PDB was found but no GS helper names were visible—possible missing /GS, stripped publics, or non-MSVC CRT. Investigate before trusting canary coverage.",
                WhenFailMayBeExpected: "Pass-with-advisory when no PDB is present is normal. Stripped public symbols can hide CRT names even when /GS is on—correlate with GSCheck.",
                RealIssueSignal: "PDB present, GS helpers absent, and GSCheck weak/failing together suggest a real missing-/GS problem. Symbols alone missing is not a vulnerability.",
                AskTheTeam: Q(
                    "If a PDB exists: are publics stripped, and can an unstripped PDB be provided under NDA?",
                    "Does GSCheck still show a SecurityCookie in Load Config?",
                    "Are you using a non-Microsoft CRT that names helpers differently?")),

            ["ExtendedMitigationsCheck"] = new(
                Purpose: "Survey extended post-2014 mitigation metadata: hotpatch compatibility, EH continuation, XFG, volatile/Spectre sidecars.",
                WhyItMatters: "These signals show whether a modern toolset applied newer control-flow and Spectre-related protections beyond classic ASLR/DEP/GS.",
                RoleInBinary: "Extended DLL characteristics debug payload, Load Config GuardFlags (EHCont/XFG), and optional volatile metadata sections/debug entries.",
                IfPasses: "Extended mitigation metadata was surveyed; optional bits may still be absent depending on build flags—see details.",
                IfFails: "A modern 64-bit native image lacks all extended mitigation markers. Rebuild with a current VS toolset and enable available /guard and Spectre options.",
                WhenFailMayBeExpected: "Many correctly hardened binaries still omit optional XFG/EHCont/volatile metadata depending on flags and scenario. Read the detail list before treating absence of every optional bit as a defect. N/A for managed/legacy eras.",
                RealIssueSignal: "On a brand-new toolset targeting current Windows, total absence of every extended marker while CFG is also missing is a stronger real signal than missing one optional Spectre sidecar alone.",
                AskTheTeam: Q(
                    "Which extended flags does your SDL policy require (/guard:ehcont, XFG, Spectre mitigations, hotpatch)?",
                    "What VS version and platform toolset built this binary?",
                    "Are missing items optional enhancements or mandatory in your org's baseline?")),

            ["DangerousApiCheck"] = new(
                Purpose: "Heuristically flag imports commonly associated with RWX memory, injection, or legacy risky behaviors.",
                WhyItMatters: "These APIs are not always malicious, but their presence warrants review—especially VirtualProtect/WriteProcessMemory/CreateRemoteThread combinations.",
                RoleInBinary: "The PE import table names functions pulled from system DLLs.",
                IfPasses: "No high-interest injection-style imports were found (medium-interest APIs may still be listed for awareness).",
                IfFails: "High-interest APIs associated with process injection or changing page protections were imported. Confirm this is intentional and constrained.",
                WhenFailMayBeExpected: "Common and often legitimate for .NET single-file/apphost stubs, JITs, installers, packers, graphics/drivers glue, and security products. VirtualProtect alone in a runtime host is usually expected. Medium-only hits (LoadLibrary/GetProcAddress) are ubiquitous.",
                RealIssueSignal: "More concerning when high-interest APIs combine (e.g. VirtualProtect + WriteProcessMemory + CreateRemoteThread/NtCreateThreadEx), appear in a simple app with no stated need, or target other processes. Import presence is capability—not proof of exploit code.",
                AskTheTeam: Q(
                    "Which listed APIs does your feature actually call, and for what user-facing behavior?",
                    "Is this PE a known runtime host, packer, or installer that must change memory protections?",
                    "Do you also import remote-process APIs (WriteProcessMemory, CreateRemoteThread, *Ex on other PIDs)? If yes, why?",
                    "Can risky operations be narrowed (avoid RWX, prefer RX after write, drop unused imports)?")),

            ["AuthenticodeVerifyCheck"] = new(
                Purpose: "Cryptographically verify Authenticode on Windows via WinVerifyTrust.",
                WhyItMatters: "A present certificate table is not enough—expired, untrusted, or tampered signatures should fail policy gates.",
                RoleInBinary: "WinVerifyTrust validates the embedded signature against the Windows trust store.",
                IfPasses: "Windows trusts the signature (presence + chain + integrity for the chosen WinVerifyTrust policy).",
                IfFails: "Verification failed (missing, expired, untrusted root, or bad digest). Do not treat the binary as integrity-protected.",
                WhenFailMayBeExpected: "N/A on non-Windows scanners. Test-signing / private roots fail until the verifying machine trusts that root. Unsigned files fail by design.",
                RealIssueSignal: "Fail on a production-signed release (bad digest, untrusted chain, expired without timestamp) is a real integrity/supply-chain incident until explained.",
                AskTheTeam: Q(
                    "Is this the official signed release artifact, or an unsigned/CI intermediate?",
                    "Does signtool verify /pa succeed on a clean corporate Windows image?",
                    "Was a timestamp used, and has the signing cert been rotated or revoked?")),

            ["SafeSEHSymbolsCheck"] = new(
                Purpose: "Name each SafeSEH handler RVA using exports and/or DbgHelp+PDB (classic BinScope private-symbol depth).",
                WhyItMatters: "Unnamed handler tables are hard to audit; naming handlers shows which exception paths are registered and whether unexpected code is SafeSEH-approved.",
                RoleInBinary: "Load Config SEHandlerTable RVAs resolved through a public symbol map / DbgHelp.",
                IfPasses: "Handlers were enumerated; as many as possible were named. Review the detail list for unexpected entries.",
                IfFails: "This check normally Passes with advisories; a Fail would indicate an unexpected internal condition.",
                WhenFailMayBeExpected: "Unnamed RVAs are common without a matching PDB on Windows. Header SafeSEHCheck still validates the table exists.",
                RealIssueSignal: "Unexpected or attacker-controlled looking handler names in a privileged module warrant investigation.",
                AskTheTeam: Q(
                    "Can you provide the matching PDB via /SymPath on a Windows scan host?",
                    "Do the named handlers match the exception paths you expect in this module?",
                    "Is anyone registering additional SafeSEH handlers at link time that surprise you?")),

            ["GSFunctionCoverageCheck"] = new(
                Purpose: "Attribute functions that call __security_check_cookie (heuristic relative-call scan + symbols).",
                WhyItMatters: "Shows which functions appear /GS-instrumented beyond a single Load Config cookie pointer—the depth BinScope needed private symbols for.",
                RoleInBinary: "Executable-section E8 rel32 calls targeting the resolved __security_check_cookie RVA, named via DbgHelp/exports.",
                IfPasses: "Either call sites were attributed, or the report explains why attribution was limited (no PDB / no E8 sites).",
                IfFails: "This check is advisory Pass-oriented; investigate Error statuses for scan failures.",
                WhenFailMayBeExpected: "Zero call sites can be normal with CFG/indirect GS checks or non-MSVC codegen. Missing PDB limits naming.",
                RealIssueSignal: "Zero call sites plus GSCheck failure suggests /GS is not really active. Large gaps vs expected hot functions may mean stripped symbols.",
                AskTheTeam: Q(
                    "Was this scanned on Windows with the matching PDB beside the image or on /SymPath?",
                    "Do the attributed functions cover your security-sensitive parsers?",
                    "Are you using a non-MSVC toolchain that implements canaries differently?")),

            ["CustomRulesCheck"] = new(
                Purpose: "Evaluate organization-defined JSON rules (/Rules) for banned imports, sections, or byte patterns.",
                WhyItMatters: "Teams often need policy beyond stock SDL checks—banned APIs, packer sections, embedded secrets markers.",
                RoleInBinary: "Rule file matchers against the PE import table, section table, and raw bytes.",
                IfPasses: "All custom rules were satisfied (or only warnings fired).",
                IfFails: "One or more custom rules failed—see rule ids in the details.",
                WhenFailMayBeExpected: "N/A when /Rules is not passed. Warn-severity rules do not fail the check.",
                RealIssueSignal: "A failed ban-list rule on a release binary is a real policy defect unless an exception is documented.",
                AskTheTeam: Q(
                    "Which /Rules file and rule id failed, and is there an approved exception?",
                    "Can the banned import/section/pattern be removed or replaced?",
                    "Should this rule be severity=warn instead of fail for this component?")),

            ["YaraRulesCheck"] = new(
                Purpose: "Run YARA rules (/Yara) via the yara CLI when installed, else a strings-only built-in subset.",
                WhyItMatters: "YARA lets orgs detect packers, malware families, or proprietary forbidden patterns alongside SDL checks.",
                RoleInBinary: "External yara process or embedded string/hex rule evaluation against file bytes.",
                IfPasses: "No YARA/string-subset matches (or /Yara not configured → N/A).",
                IfFails: "One or more YARA rules matched—treat as policy/malware-hunt signal and triage the rule names.",
                WhenFailMayBeExpected: "N/A without /Yara. Built-in subset only understands simple strings/hex rules; full YARA needs the CLI.",
                RealIssueSignal: "A high-confidence org malware/packer rule hit on a production artifact is a real incident until proven false positive.",
                AskTheTeam: Q(
                    "Which YARA rule matched, and is the rule tuned for this product line?",
                    "Is the full yara CLI installed so conditions beyond strings were evaluated?",
                    "Can you provide a clean rebuild that no longer matches?")),
        };

    public static CheckSecurityGuide? TryGet(string checkName) =>
        Guides.TryGetValue(checkName, out var g) ? g : null;

    public static CheckSecurityGuide GetOrFallback(string checkName) =>
        TryGet(checkName) ?? new CheckSecurityGuide(
            Purpose: $"Security check '{checkName}'.",
            WhyItMatters: "See BinSight documentation for this check.",
            RoleInBinary: "See check-specific message.",
            IfPasses: "The check's requirement was satisfied.",
            IfFails: "The check's requirement was not satisfied; remediate per the finding message.",
            WhenFailMayBeExpected: "Compare with related checks and the binary's toolchain/role before treating this as confirmed exploitability.",
            RealIssueSignal: "Treat as a real issue when the team owns the build flags for this PE and no legitimate exception applies.",
            AskTheTeam: Q(
                "Who owns the build/link flags for this binary?",
                "Is this finding reproducible on the official release artifact?",
                "What compensating controls or rebuild plan exist?"));
}
