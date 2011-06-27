<?php
/*

OpenSSL based, in-browser certificate generation.
(based on http://foaf.me/simpleCreateClientCertificate.php)

Changes: 
- allows adding multiple SANs in the certificate
- allows adding emails in the certificate

Author: Andrei Sambra - andrei@fcns.eu / 2011-06-27
  
Copyright (C) 2011 by Andrei Sambra - FCNS

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

*/

if ($_GET['doit'] == 1) {

	function create_identity_x509($countryName,  $stateOrProvinceName, $localityName, $organizationName, $organizationalUnitName, $commonName, $emailAddress, $foafLocation, $pubkey) {
		// Remove any whitespace in teh supplied SPKAC
		$keyreq = "SPKAC=".str_replace(str_split(" \t\n\r\0\x0B"), '', $pubkey);

		$SAN="";
		
		// Create the DN for the openssl call
		if ($countryName)
			$keyreq .= "\ncountryName=".$countryName;
	
		if ($stateOrProvinceName)
			$keyreq .= "\nstateOrProvinceName=".$stateOrProvinceName;

		if ($localityName)
			$keyreq .= "\nlocalityName=".$localityName;

		if ($organizationName)
			$keyreq .= "\norganizationName=".$organizationName;

		if ($organizationalUnitName)
			$keyreq .= "\n0.OU=".$organizationalUnitName;

		if ($commonName)
			$keyreq .= "\nCN=".$commonName;
		if ($emailAddress) {
			$keyreq .= "\nemailAddress=".$emailAddress;
            $SAN="email:" . $emailAddress . ",";
        }
        
		// Setup the contents of the subjectAltName
		if ($foafLocation) {
            foreach($foafLocation as $key => $val) {
                if (strlen($val) > 0) {
                    $SAN .= "URI:$val";
                    if (strlen($foafLocation[$key+1]) > 0)
                        $SAN .= ",";
                }
            }
        }

		// Export the subjectAltName to be picked up by the openssl.cnf file
		if ($SAN)
		{
			putenv("SAN=$SAN");
		}
	
		// Create temporary files to hold the input and output to the openssl call.
		$tmpSPKACfname = "/tmp/SPK" . md5(time().rand());
		$tmpCERTfname  = "/tmp/CRT" . md5(time().rand());

		// Write the SPKAC and DN into the temporary file
		$handle = fopen($tmpSPKACfname, "w");
		fwrite($handle, $keyreq);
		fclose($handle);

		// TODO - This should be more easily configured
		$command = "openssl ca -config ~/ssl/webidCA/openssl.cnf -verbose -batch -notext -spkac $tmpSPKACfname -out $tmpCERTfname -passin pass:'12345' 2>&1";

		// Run the command;
		$output = shell_exec($command);
		//echo $output;

		// TODO - Check for failures on the command
		if (preg_match("/Data Base Updated/", $output)==0)
		{
			echo "Failed to create X.509 Certificate<br><br>";
			// Debug:
			/*
			echo "<pre>";
			echo $output;
			echo "</pre>";
	    */
	    
			return;
		}
		// Delete the temporary SPKAC file
		unlink($tmpSPKACfname);

		return $tmpCERTfname;
	}

	// Send the p12 encoded SSL certificate
	// Notice: it is IMPERATIVE that no html data gets transmitted to the user before the header is sent!
	function download_identity_x509($certLocation) {
		$length = filesize($certLocation);	
		header('Last-Modified: ' . date('r+b'));
		header('Accept-Ranges: bytes');
		header('Content-Length: ' . $length);
		header('Content-Type: application/x-x509-user-cert');
		readfile($certLocation);

		// Delete the temporary CRT file
		unlink($certLocation);

		exit;
	}

	//-----------------------------------------------------------------------------------------------------------------------------------
	//
	// Main
	//
	//-----------------------------------------------------------------------------------------------------------------------------------

	// Check if the foaf location is specified in the script call
	$foafLocation = $_GET['foaf'];
	if (!$foafLocation) {
		if (array_key_exists('foaf', $_GET))
			$query = $_SERVER[QUERY_STRING];
		else
			$query = ($_SERVER[QUERY_STRING]?$_SERVER[QUERY_STRING]."&":"") . "foaf=";

		echo "Please specify the location of your foaf file.";

		exit();
	}

	// Check if the commonName is specified in the script call
	$commonName = $_GET['commonName'];
	if (!$commonName) {
		if (array_key_exists('commonName', $_GET))
			$query = $_SERVER[QUERY_STRING];
		else
			$query = ($_SERVER[QUERY_STRING]?$_SERVER[QUERY_STRING]."&":"") . "commonName=";
	
		echo "Please specify the Common Name to be added to your certficate.";

		exit();
	}
	if (strlen($_GET['countryName']) < 1)
		$_GET['countryName'] = 'FR';

	// Check that script is called using the HTTPS protocol
	if ($_SERVER['HTTPS'] == NULL) {
		echo "Please use the following secure uri to download the Identity P12 certificate. ";
		echo "<a href='https://" . $_SERVER["SERVER_NAME"] . $_SERVER["REQUEST_URI"] . "?" . $_SERVER[QUERY_STRING] . "'>https://" . $_SERVER["SERVER_NAME"] . $_SERVER["REQUEST_URI"] . "?" . $_SERVER[QUERY_STRING] . "</a><br>";

		exit();
	}

	// Get the rest of the script parameters
	$countryName            = $_GET['countryName'];
	$stateOrProvinceName    = $_GET['stateOrProvinceName'];
	$localityName           = $_GET['localityName'];
	$organizationName       = $_GET['organizationName'];
	$organizationalUnitName = $_GET['organizationalUnitName'];
	$emailAddress           = $_GET['emailAddress'];
	$pubkey                 = $_GET['pubkey'];
	
	// Create a x509 SSL certificate
	if ($x509 = create_identity_x509($log, $countryName, $stateOrProvinceName, $localityName, $organizationName, $organizationalUnitName, $commonName, $emailAddress, $foafLocation, $pubkey)) {
		// Send the X.509 SSL certificate to the script caller (user) as a file transfer
		download_identity_x509($log, $x509, $foafLocation);
	}
} else {
	echo "<div class=\"container\">\n";
	echo "<font style=\"font-size: 2em; text-shadow: 0 1px 1px #cccccc;\">Generate a Simple WebID KEYGEN-based Client Certificate</font>\n";
	echo "<div class=\"clear\"></div>\n";
	echo "</div>\n";
	
	echo "<div class=\"container\">\n";
	echo "<form name=\"input\" action=\"https://webid.fcns.eu/certgen.php\" method=\"get\">\n";
	echo "<input type=\"hidden\" name=\"doit\" value=\"1\">\n";
	echo "<table>\n";
	echo "	<tr><td colspan=\"2\"><font style=\"font-size: 1.2em;\">If you already have a FOAF card, this form allows you to create a certificate for it.</font><br/><br/></td></tr>\n";
	echo "	<tr><td><h2>FOAF URI 1</h2></td><td><input type=\"text\" name=\"foaf[]\" size=\"40\" style=\"border-color: red;\"></td></tr>\n";
	echo "	<tr><td><h2>FOAF URI 2</h2></td><td><input type=\"text\" name=\"foaf[]\" size=\"40\"></td></tr>\n";
	echo "	<tr><td><h2>FOAF URI 3</h2></td><td><input type=\"text\" name=\"foaf[]\" size=\"40\"></td></tr>\n";
	echo "	<tr><td><h2>commonName</h2></td><td><input type=\"text\" name=\"commonName\" style=\"border-color: red;\"></font></td></tr>\n";
	echo "	<tr><td><h2>emailAddress</h2></td><td><input type=\"text\" name=\"emailAddress\"></td></tr>\n";
	echo "	<tr><td><h2>organizationName</h2></td><td><input type=\"text\" name=\"organizationName\"></td></tr>\n";
	echo "	<tr><td><h2>organizationalUnitName</h2></td><td><input type=\"text\" name=\"organizationalUnitName\"></td></tr>\n";
	echo "	<tr><td><h2>localityName</h2></td><td><input type=\"text\" name=\"localityName\"></td><td></td></tr>\n";
	echo "	<tr><td><h2>stateOrProvinceName</h2></td><td><input type=\"text\" name=\"stateOrProvinceName\"></td></tr>\n";
	echo "	<tr><td><h2>countryName</h2></td><td><input type=\"text\" name=\"countryName\"></td></tr>\n";
	echo "	<tr><td><h2>KEYGEN Key Length</h2></td><td><keygen name=\"pubkey\" challenge=\"randomchars\"></td></tr>\n";
	echo "	<tr><td colspan=\"3\">&nbsp;</td></tr>\n";
	echo "	<tr><td></td><td><input type=\"submit\" value=\"Submit\"></td></tr>\n";
	echo "</table>\n";
	echo "</form>\n";
	echo "<div class=\"clear\"></div>\n";
	echo "</div>\n";

}
?>
