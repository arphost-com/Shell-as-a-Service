<?php
if (!defined("WHMCS")) {
    die("This file cannot be accessed directly");
}
use Illuminate\Database\Capsule\Manager as Capsule;

function shellasaservice_MetaData()
{
    return array(
        'DisplayName' => 'Shellasaservice',
        'APIVersion' => '1.1',
    );
}


function shellasaservice_ConfigOptions()
{
    return [
        "createbash" => [
            "FriendlyName" => "createbash",
            "Type" => "text", # Text Box
            "Size" => "25", # Defines the Field Width
            "Description" => "",
            "Default" => "",
        ],
        "suspendbash" => [
            "FriendlyName" => "suspendbash",
            "Type" => "text", # Text Box
            "Size" => "25", # Defines the Field Width
            "Description" => "",
            "Default" => "",
        ],
        "unsuspendbash" => [
            "FriendlyName" => "unsuspendbash",
            "Type" => "text", # Text Box
            "Size" => "25", # Defines the Field Width
            "Description" => "",
            "Default" => "",
        ],
        "terminatebash" => [
            "FriendlyName" => "terminatebash",
            "Type" => "text", # Text Box
            "Size" => "25", # Defines the Field Width
            "Description" => "",
            "Default" => "",
        ],
    ];
}

function check_license($licensekey, $localkey='') {

    // -----------------------------------
    //  -- Configuration Values --
    // -----------------------------------

    // Enter the url to your WHMCS installation here
    $whmcsurl = 'https://arphost.com';
    // Must match what is specified in the MD5 Hash Verification field
    // of the licensing product that will be used with this check.

    $licensing_secret_key = '87687681';
    // The number of days to wait between performing remote license checks
    $localkeydays = 1;
    // The number of days to allow failover for after local key expiry
    $allowcheckfaildays = 5;

    // -----------------------------------
    //  -- Do not edit below this line --
    // -----------------------------------

    $check_token = time() . md5(mt_rand(100000000, mt_getrandmax()) . $licensekey);
    $checkdate = date("Ymd");
    $domain = $_SERVER['SERVER_NAME'];
    $usersip = isset($_SERVER['SERVER_ADDR']) ? $_SERVER['SERVER_ADDR'] : $_SERVER['LOCAL_ADDR'];
    $dirpath = dirname(__FILE__);
    $verifyfilepath = 'modules/servers/licensing/verify.php';
    $localkeyvalid = false;
    if ($localkey) {
        $localkey = str_replace("\n", '', $localkey); # Remove the line breaks
        $localdata = substr($localkey, 0, strlen($localkey) - 32); # Extract License Data
        $md5hash = substr($localkey, strlen($localkey) - 32); # Extract MD5 Hash
        if ($md5hash == md5($localdata . $licensing_secret_key)) {
            $localdata = strrev($localdata); # Reverse the string
            $md5hash = substr($localdata, 0, 32); # Extract MD5 Hash
            $localdata = substr($localdata, 32); # Extract License Data
            $localdata = base64_decode($localdata);
            $localkeyresults = json_decode($localdata, true);
            $originalcheckdate = $localkeyresults['checkdate'];
            if ($md5hash == md5($originalcheckdate . $licensing_secret_key)) {
                $localexpiry = date("Ymd", mktime(0, 0, 0, date("m"), date("d") - $localkeydays, date("Y")));
                if ($originalcheckdate > $localexpiry) {
                    $localkeyvalid = true;
                    $results = $localkeyresults;
                    $validdomains = explode(',', $results['validdomain']);
                    if (!in_array($_SERVER['SERVER_NAME'], $validdomains)) {
                        $localkeyvalid = false;
                        $localkeyresults['status'] = "Invalid";
                        $results = array();
                    }
                    $validips = explode(',', $results['validip']);
                    if (!in_array($usersip, $validips)) {
                        $localkeyvalid = false;
                        $localkeyresults['status'] = "Invalid";
                        $results = array();
                    }
                    $validdirs = explode(',', $results['validdirectory']);
                    if (!in_array($dirpath, $validdirs)) {
                        $localkeyvalid = false;
                        $localkeyresults['status'] = "Invalid";
                        $results = array();
                    }
                }
            }
        }
    }
    if (!$localkeyvalid) {
        $responseCode = 0;
        $postfields = array(
            'licensekey' => $licensekey,
            'domain' => $domain,
            'ip' => $usersip,
            'dir' => $dirpath,
        );
        if ($check_token) $postfields['check_token'] = $check_token;
        $query_string = '';
        foreach ($postfields AS $k=>$v) {
            $query_string .= $k.'='.urlencode($v).'&';
        }
        if (function_exists('curl_exec')) {
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $whmcsurl . $verifyfilepath);
            curl_setopt($ch, CURLOPT_POST, 1);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $query_string);
            curl_setopt($ch, CURLOPT_TIMEOUT, 30);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
            $data = curl_exec($ch);
            $responseCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
        } else {
            $responseCodePattern = '/^HTTP\/\d+\.\d+\s+(\d+)/';
            $fp = @fsockopen($whmcsurl, 80, $errno, $errstr, 5);
            if ($fp) {
                $newlinefeed = "\r\n";
                $header = "POST ".$whmcsurl . $verifyfilepath . " HTTP/1.0" . $newlinefeed;
                $header .= "Host: ".$whmcsurl . $newlinefeed;
                $header .= "Content-type: application/x-www-form-urlencoded" . $newlinefeed;
                $header .= "Content-length: ".@strlen($query_string) . $newlinefeed;
                $header .= "Connection: close" . $newlinefeed . $newlinefeed;
                $header .= $query_string;
                $data = $line = '';
                @stream_set_timeout($fp, 20);
                @fputs($fp, $header);
                $status = @socket_get_status($fp);
                while (!@feof($fp)&&$status) {
                    $line = @fgets($fp, 1024);
                    $patternMatches = array();
                    if (!$responseCode
                        && preg_match($responseCodePattern, trim($line), $patternMatches)
                    ) {
                        $responseCode = (empty($patternMatches[1])) ? 0 : $patternMatches[1];
                    }
                    $data .= $line;
                    $status = @socket_get_status($fp);
                }
                @fclose ($fp);
            }
        }
        if ($responseCode != 200) {
            $localexpiry = date("Ymd", mktime(0, 0, 0, date("m"), date("d") - ($localkeydays + $allowcheckfaildays), date("Y")));
            if ($originalcheckdate > $localexpiry) {
                $results = $localkeyresults;
            } else {
                $results = array();
                $results['status'] = "Invalid";
                $results['description'] = "Remote Check Failed";
                return $results;
            }
        } else {
            preg_match_all('/<(.*?)>([^<]+)<\/\\1>/i', $data, $matches);
            $results = array();
            foreach ($matches[1] AS $k=>$v) {
                $results[$v] = $matches[2][$k];
            }
        }
        if (!is_array($results)) {
            die("Invalid License Server Response");
        }
        if ($results['md5hash']) {
            if ($results['md5hash'] != md5($licensing_secret_key . $check_token)) {
                $results['status'] = "Invalid";
                $results['description'] = "MD5 Checksum Verification Failed";
                return $results;
            }
        }
        if ($results['status'] == "Active") {
            $results['checkdate'] = $checkdate;
            $data_encoded = json_encode($results);
            $data_encoded = base64_encode($data_encoded);
            $data_encoded = md5($checkdate . $licensing_secret_key) . $data_encoded;
            $data_encoded = strrev($data_encoded);
            $data_encoded = $data_encoded . md5($data_encoded . $licensing_secret_key);
            $data_encoded = wordwrap($data_encoded, 80, "\n", true);
            $results['localkey'] = $data_encoded;
        }
        $results['remotecheck'] = true;
    }
    unset($postfields,$data,$matches,$whmcsurl,$licensing_secret_key,$checkdate,$usersip,$localkeydays,$allowcheckfaildays,$md5hash);
    return $results;
}
function shellasaservice_CreateAccount(array $params)
{
    try {

        $licensekey="LIC11fae7ea42acaf127b600a2eb7f25d3d72189c5abba3f71e769733268dc97921a11a6ac07440a14a859742f6d0feb08f49ba63ec3985e3a3136aa3b9abf3d0f44a770a5463c363e936139a34f681a76318a062871c860bf4c6c179eb9cffb3778da3c6ad1f4978fb56fc439186d2606b6d39d19a5e31913d90e3b5cf7e34e54b3c5e9c9b9d97cc5d479e8a0c7bd993d92437fced2b93cf1bd2a89c4b053365a92c02562e8da6655da083984807a8ba692e100392c61d47a4ce5b6667083a3be04d5128974c391dd09a7248a8fd015ffecee735574b4624e14e40419eec489b790eebadcbb207461947d8317e5a57a416";

        $localkey = '9tjIxIzNwgDMwIjI6gjOztjIlRXYkt2Ylh2YioTO6M3OicmbpNnblNWasx1cyVmdyV2ccNXZsVHZv1GX
zNWbodHXlNmc192czNWbodHXzN2bkRHacBFUNFEWcNHduVWb1N2bExFd0FWTcNnclNXVcpzQioDM4ozc
7ISey9GdjVmcpRGZpxWY2JiO0EjOztjIx4CMuAjL3ITMioTO6M3OiAXaklGbhZnI6cjOztjI0N3boxWY
j9Gbuc3d3xCdz9GasF2YvxmI6MjM6M3Oi4Wah12bkRWasFmdioTMxozc7ISeshGdu9WTiozN6M3OiUGb
jl3Yn5WasxWaiJiOyEjOztjI3ATL4ATL4ADMyIiOwEjOztjIlRXYkVWdkRHel5mI6ETM6M3OicDMtcDM
tgDMwIjI6ATM6M3OiUGdhR2ZlJnI6cjOztjIlNXYlxEI5xGa052bNByUD1ESXJiO5EjOztjIl1WYuR3Y
1R2byBnI6ETM6M3OicjI6EjOztjIklGdjVHZvJHcioTO6M3Oi02bj5ycj1Ga3BEd0FWbioDNxozc7ICb
pFWblJiO1ozc7IyUD1ESXBCd0FWTioDMxozc7ISZtFmbkVmclR3cpdWZyJiO0EjOztjIlZXa0NWQiojN
6M3OiMXd0FGdzJiO2ozc7pjMxoTY8baca0885830a33725148e94e693f3f073294c0558d38e31f844
c5e399e3c16a';

            $results = check_license($licensekey, $localkey);
print_r($results); exit;
            switch ($results['status']) {
                case "Active":
                    // get new local key and save it somewhere
                    $localkeydata = $results['localkey'];
                    break;
                case "Invalid":
                    die("License key is Invalid");
                    break;
                case "Expired":
                    die("License key is Expired");
                    break;
                case "Suspended":
                    die("License key is Suspended");
                    break;
                default:
                    die("Invalid Response");
                    break;
            }

            $cmd=$params['configoption1']; 
            $output = shell_exec($cmd);
            logModuleCall('shellasaservice',__FUNCTION__,$params,$output);
            if($output)
            {
                return 'success';
            }

    } catch (Exception $e) {
        // Record the error in WHMCS's module log.
        logModuleCall('shellasaservice',__FUNCTION__,$params,$e->getMessage(),$e->getTraceAsString());
        return $e->getMessage();
    }

    return 'success';
}

function shellasaservice_SuspendAccount(array $params)
{
    try {   
            $cmd=$params['configoption2']; 
            $output = shell_exec($cmd);
            logModuleCall('shellasaservice',__FUNCTION__,$params,$output);
            if($output)
            {
                return 'success';
            } 
        
    } catch (Exception $e) {
        // Record the error in WHMCS's module log.
        logModuleCall('shellasaservice',__FUNCTION__,$params,$e->getMessage(),$e->getTraceAsString());
        return $e->getMessage();
    }

    return 'success';
}

function shellasaservice_UnsuspendAccount(array $params)
{
    try {
            $cmd=$params['configoption3']; 
            $output = shell_exec($cmd);
            logModuleCall('shellasaservice',__FUNCTION__,$params,$output);
            if($output)
            {
                return 'success';
            } 
    } catch (Exception $e) {
        // Record the error in WHMCS's module log.
        logModuleCall('shellasaservice',__FUNCTION__,$params,$e->getMessage(),$e->getTraceAsString());

        return $e->getMessage();
    }

    return 'success';
}

function shellasaservice_TerminateAccount(array $params)
{
    try {
            $cmd=$params['configoption4']; 
            $output = shell_exec($cmd);
            logModuleCall('shellasaservice',__FUNCTION__,$params,$output);
            if($output)
            {
                return 'success';
            } 
    } catch (Exception $e) {
        // Record the error in WHMCS's module log.
        logModuleCall('shellasaservice',__FUNCTION__,$params,$e->getMessage(),$e->getTraceAsString());

        return $e->getMessage();
    }

    return 'success';
}