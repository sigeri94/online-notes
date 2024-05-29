<?php

function hex2str($hex) {
        $str = "";
        $i = 0;
	while ($i < strlen($hex)) {
		$tmp = hexdec(substr($hex,$i,2));
		if ($tmp < 32) $tmp = 46;                       //protect against control characters
		if ($tmp > 126) $tmp = 46;
		$tmp = chr($tmp);
		if ($tmp == "<") $tmp = "&lt";          //protect against HTML payloads
		if ($tmp == ">") $tmp = "&gt";
		$str .= $tmp;
		$i += 2;
	}
return $str;
}
unlink('/var/www/html/local/detail.html');
$host="IDS-JKT";
$client="Food-Group";
$batas = date("Y-m-d",strtotime("today"));
$MSG="";
$BS="<html><head><style>\n
table {
    font-family: verdana,arial,sans-serif;
    font-size: 12px;
    color: #333333;
    border-width: 1px;
    border-color: #666666;
    border-collapse: collapse;
}

th {
    border-width: 1px;
    padding: 8px;
    border-style: solid;
    border-color: #666666;
    background-color: #dedede;
}

td {
    border-width: 1px;
    padding: 8px;
    border-style: solid;
    border-color: #666666;
    background-color: #ffffff;
}
</style>
</head><body>\n";
        $BS.=$batas."<br/><strong>$host</strong> has detected suspicious packet on <strong>$client</strong> Network.<br/>\n";
        $BS.="This event need further investigation it is highly recommended for blocking the source IP at firewall level.<br/>\n";
        $BS.="<strong>$host</strong> will always monitor any other connection from the source IP and will report to <strong>$client</strong> for further action.\n";
        $MSG.=$BS;

$link = mysqli_connect("localhost","root","","snort");
$sig=$_GET["sig_sid"];

$sql3="select sid,ip_proto,cid,timestamp,inet_ntoa(ip_src),inet_ntoa(ip_dst),layer4_sport,layer4_dport,sig_name,sig_priority from acid_event WHERE sig_name = ( select sig_name from signature where sig_sid = '$sig' ) ";

$q3 =  mysqli_query($link,$sql3);

while ($row3 = mysqli_fetch_array($q3) ) {
	$timestamp=$row3['timestamp'];
	$ip_sr=$row3['inet_ntoa(ip_src)'];
	$fullhost = @gethostbyaddr($ip_sr);
	$ip_src=$fullhost."(".$ip_sr.")"; 
	$layer4_sport=$row3['layer4_sport'];
	$ip_dst=$row3['inet_ntoa(ip_dst)'];
	$layer4_dport=$row3['layer4_dport'];
	$sig_name=$row3['sig_name'];

	switch($row3['ip_proto']){
		case 17:
			$ip_proto='UDP';
			break;
		case 6:
			$ip_proto='TCP';
			break;
		default:
			$ip_proto=$row3['ip_proto'];
	}
	switch($row3['sig_priority']){
		case 1:
			$clr='red';	
			$sev='HIGH';
			break;
		case 2:
			$clr='orange';
			$sev='MED';
			break;
		case 3:
			$clr='yellow';
			$sev='LOW';
			break;
		case 4:
			$clr='black';
			$sev='LOWEST';
			break;
		default:
			$clr='black';
			$sev='UNKNOWN';
	}
        $MSG.= "<br/> <br/><strong>Detail Alert </strong>:\n";
	$MSG.= "<table><th>timestamp</th><th>ip_src</th><th>src_port</th><th>ip_dst</th><th>dst_port</th><th>signature</th><th>severity</th>\n";
	$MSG.= "\t<tr>\n\t\t<td>".$timestamp."</td>\n\t\t<td>".$ip_src."</td>\n\t\t<td>".$layer4_sport."</td>\n\t\t<td>".$ip_dst."</td>\n";
	$MSG.= "\t\t<td>".$layer4_dport."</td>\n\t\t<td>".$sig_name."</td>\n\t\t<td><strong><font color=".$clr.">".$sev."</font></strong></td>\n";
	$MSG.= "\t</tr>\n</table>";
//-- table payload
    	$MSG.= "<br /><strong>Payload </strong>:<br />\n";
	$MSG.= "<table><th>payload</th><th>protocol</th>\n";
	$MSG.= "\t<tr>\n";
	$cid=$row3['cid'];
	$sid=$row3['sid'];
	$sql2 = "SELECT data_payload FROM data WHERE cid='".$cid."' and sid='".$sid."'";
	$q4=mysqli_query($link,$sql2);
	while ($row4 = mysqli_fetch_array($q4))	{
		$payload=$row4['data_payload'];
	}
        if (isset($payload)) {
                $pld = hex2str($payload);
        } else {
                $pld = "NO PAYLOAD AVAILABLE";
        }
	$MSG.= "\t\t<td>".$pld."</td>\n";        // Show ascii & hex
	$MSG.= "\t\t<td>".$ip_proto."</td>\n";  
	$MSG.= "\t</tr>\n</table>";
}
$MSG.= "<br /> <br />\n";
        $BS2="Contact Details<hr><br/>\n";
        $BS2.="<table><tr><td>Site</td><td>:</td><td>http://www.securxcess.com</td></tr>\n";
        $BS2.="<tr><td>E-mail</td><td>:</td><td>support@securxcess.com</td></tr></table><br/>\n";
        $BS2.="<br/>CONFIDENTIAL NOTICE: <br/>\n";
        $BS2.="This email is intended only for the use of the individual or entity to which it is addressed and may contain information that is confidential and may also be privileged.<br/>";
        $BS2.="Any form of unauthorized use or dissemination is strictly prohibited.<br/\n>";
        $BS2.="If you are not the intended recipient or if this email is otherwise sent to you in error,<br/>\n ";
        $BS2.="you should not disseminate, distribute or copy this email and you should delete it immediately and notify us.<br/>\n ";
        $BS2.="Thank you.\n</body></html>";
        $MSG.= $BS2;


	//============================ Write ===========================
	$fp = fopen('/var/www/html/local/detail.html', 'w');
	fwrite($fp, $MSG);
	fclose($fp);
//	echo $MSG
?>
