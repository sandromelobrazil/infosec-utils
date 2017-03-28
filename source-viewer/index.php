<?php
	$url = $_GET["url"];

	$curlHandle = curl_init();
	curl_setopt($curlHandle, CURLOPT_URL, $url);
	curl_setopt($curlHandle, CURLOPT_SSL_VERIFYPEER, false);
	curl_setopt($curlHandle, CURLOPT_RETURNTRANSFER, 1);
	curl_setopt($curlHandle, CURLOPT_FOLLOWLOCATION, true);
	$response = curl_exec($curlHandle);
	curl_close($curlHandle);

	echo $response;
?>
