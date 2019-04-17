<?php
$config = parse_ini_file('config.ini', true);

// Lets encrypt chain
define('LE_CHAIN', "-----BEGIN CERTIFICATE-----
MIIEkjCCA3qgAwIBAgIQCgFBQgAAAVOFc2oLheynCDANBgkqhkiG9w0BAQsFADA/
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT
DkRTVCBSb290IENBIFgzMB4XDTE2MDMxNzE2NDA0NloXDTIxMDMxNzE2NDA0Nlow
SjELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUxldCdzIEVuY3J5cHQxIzAhBgNVBAMT
GkxldCdzIEVuY3J5cHQgQXV0aG9yaXR5IFgzMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEAnNMM8FrlLke3cl03g7NoYzDq1zUmGSXhvb418XCSL7e4S0EF
q6meNQhY7LEqxGiHC6PjdeTm86dicbp5gWAf15Gan/PQeGdxyGkOlZHP/uaZ6WA8
SMx+yk13EiSdRxta67nsHjcAHJyse6cF6s5K671B5TaYucv9bTyWaN8jKkKQDIZ0
Z8h/pZq4UmEUEz9l6YKHy9v6Dlb2honzhT+Xhq+w3Brvaw2VFn3EK6BlspkENnWA
a6xK8xuQSXgvopZPKiAlKQTGdMDQMc2PMTiVFrqoM7hD8bEfwzB/onkxEz0tNvjj
/PIzark5McWvxI0NHWQWM6r6hCm21AvA2H3DkwIDAQABo4IBfTCCAXkwEgYDVR0T
AQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwfwYIKwYBBQUHAQEEczBxMDIG
CCsGAQUFBzABhiZodHRwOi8vaXNyZy50cnVzdGlkLm9jc3AuaWRlbnRydXN0LmNv
bTA7BggrBgEFBQcwAoYvaHR0cDovL2FwcHMuaWRlbnRydXN0LmNvbS9yb290cy9k
c3Ryb290Y2F4My5wN2MwHwYDVR0jBBgwFoAUxKexpHsscfrb4UuQdf/EFWCFiRAw
VAYDVR0gBE0wSzAIBgZngQwBAgEwPwYLKwYBBAGC3xMBAQEwMDAuBggrBgEFBQcC
ARYiaHR0cDovL2Nwcy5yb290LXgxLmxldHNlbmNyeXB0Lm9yZzA8BgNVHR8ENTAz
MDGgL6AthitodHRwOi8vY3JsLmlkZW50cnVzdC5jb20vRFNUUk9PVENBWDNDUkwu
Y3JsMB0GA1UdDgQWBBSoSmpjBH3duubRObemRWXv86jsoTANBgkqhkiG9w0BAQsF
AAOCAQEA3TPXEfNjWDjdGBX7CVW+dla5cEilaUcne8IkCJLxWh9KEik3JHRRHGJo
uM2VcGfl96S8TihRzZvoroed6ti6WqEBmtzw3Wodatg+VyOeph4EYpr/1wXKtx8/
wApIvJSwtmVi4MFU5aMqrSDE6ea73Mj2tcMyo5jMd6jmeWUHK8so/joWUoHOUgwu
X4Po1QYz+3dszkDqMp4fklxBwXRsW10KXzPMTZ+sOPAveyxindmjkW8lGy+QsRlG
PfZ+G6Z6h7mjem0Y+iWlkYcV4PIWL1iwBi8saCbGS5jN2p8M+X+Q7UNKEkROb3N6
KOqkqm57TH2H3eDJAkSnh6/DNFu0Qg==
-----END CERTIFICATE-----\r\n");

// get soap data
$soapRequest = new SoapClient('https://kasapi.kasserver.com/soap/wsdl/KasApi.wsdl');

// walk through domains
foreach($config as $domain => $dconfig)
{
	// skip default
	if ($domain == 'default')
		continue;
	
	if (empty($dconfig['path']))
		$dconfig['path'] = $config['default']['path'];
	
	$dconfig['path'] = str_replace('%domain%', $domain, $dconfig['path']);
	
	$params = [
		'KasUser' => (empty($dconfig['user']) ? $config['default']['user'] : $dconfig['user']),
		'KasAuthType' => 'sha1',
		'KasAuthData' => (empty($dconfig['pass']) ? $config['default']['pass'] : $dconfig['pass'])
	];
	
	// is a subdomain
	if (substr_count($domain, '.') > 1)
	{
		$params['KasRequestType'] = 'get_subdomains';
		$params['KasRequestParams'] = ['subdomain_name' => $domain];
	}
	else
	{
		$params['KasRequestType'] = 'get_domains';
		$params['KasRequestParams'] = ['domain_name' => $domain];
	}
	$req = $soapRequest->KasApi(json_encode($params));
	
	if (!empty($req['Response']['ReturnInfo'][0]))
	{
		$result = $req['Response']['ReturnInfo'][0];
		
		// create dir
		if (!is_dir($dconfig['path']))
			mkdir($dconfig['path']);
		

		// write certs
		file_put_contents($dconfig['path'] . 'chain.pem', (empty($result['ssl_certificate_sni_bundle']) ? LE_CHAIN : $result['ssl_certificate_sni_bundle']));
		file_put_contents($dconfig['path'] . 'privkey.pem', $result['ssl_certificate_sni_key']);
		file_put_contents($dconfig['path'] . 'cert.pem', $result['ssl_certificate_sni_crt']);
		file_put_contents($dconfig['path'] . 'fullchain.pem', $result['ssl_certificate_sni_crt'] . "\r\n" . file_get_contents($dconfig['path'] . 'chain.pem') . "\r\n");
	}
	sleep(2);
}