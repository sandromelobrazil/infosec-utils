<?php

$url = $_GET["url"];
getContentByUrl($url);

function getContentByUrl($url) {
	echo "[*] Connecting to " . $url . " ...\n";
	$curlHandle = curl_init();
	curl_setopt($curlHandle, CURLOPT_URL, $url);
	curl_setopt($curlHandle, CURLOPT_SSL_VERIFYPEER, false);
	curl_setopt($curlHandle, CURLOPT_RETURNTRANSFER, 1);
	curl_setopt($curlHandle, CURLOPT_USERAGENT,'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1.13) Gecko/20080311 Firefox/2.0.0.13');
	curl_setopt($curlHandle, CURLOPT_HTTPHEADER, array("Cookie: youaskedfor=cookie"));	
	curl_setopt($curlHandle, CURLOPT_HEADERFUNCTION, "handleHeaderCallback");
	$response = curl_exec($curlHandle);
	curl_close($curlHandle);

	echo $response;
}


function handleHeaderCallback($curl, $header) {
	$url = $_GET["url"];
	$header = strtolower($header);
	$locationUrl = explode("location: ", $header);	

	echo $header;

	if (isset($locationUrl[1])) {
		$redirectUrl = $locationUrl[1];

		if (strpos($redirectUrl, "http") !== 0) {
			$redirectUrl = $url . "/" . $redirectUrl;		
		}

		echo "[*] Looks like we're being redirected to " . $redirectUrl . "\r";
		getContentByUrl(trim($redirectUrl));
	}
 	
    return strlen($header);
}

?>