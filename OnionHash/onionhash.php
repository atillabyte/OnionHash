<?php
/** Retrieve the .onion hash from a specified RSA Private Key. **/
/** Author: Atilla 'tilly' Lonny (https://atil.la) **/
/** License: GNU LGPL v3 https://www.gnu.org/licenses/lgpl-3.0.txt **/
/** Credits: Bryan Ruiz (Encode in Base32 based on RFC 4648.) **/

// oldcoderdrbhuuxh.onion
$input = <<<EOF
-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDuH6AchoiZH55Gxh7eIv25nbMeNpKof9ljrvk+ycjZ08uP6zJV
dFhGe582z6/cgYC6LN8pABmOl1fVzvnH5Y+vxEWYpmbkeR9omAgcEPVSaGq1NJ3n
0sEFw1pcxkq2W9qT18Hr9N52f9b0a+Q40GTj/XZq+c3iELzv1lLHDK4HHQIEFv9Z
lwKBgBEpvl2yqbURu7pRw/Eey4tW4/4jw0ACLnMI67ZoX74DMjs8gZtIYRCRy5sB
pYSGWfi6E24w/C0KTRLpFr8jZ5r7yvVlSQxvMhwSkg0PWUu7OnVp/6FcVYq7+S/y
c1kkkVn96+s/pgT8z15u/KiX5j/mQ83bbSFXwoomvaaWj9/dAkEA/VVzxjVFs0/3
t33gX3SgdjlIG9098V+mVSa575wGliBy8aTpcKy3JwoqItSQCFNbVSk/vgryX7cL
hQUlisfMWwJBAPChMVh1oKI4y2dtLQg8ZsA8RbYoqV/cMENMpEiIL/qpPZqnpWPS
VzQzC7SnTaeDlznw39J3wqhwUDT/HCdTs+cCQFEa6tkwPT+MdzXL3xSBPa4649SV
9Kbu2x9arDEmGxczCu3sdYx8OLj5RKBwMJK/HF7Fa7ew1nRhghkZH+lK2KcCQQCV
RYyCP3UMPdg7fsjDHliwZ0Fy5K/KHVYRi71s6Byp5drL8zw23B20thLqeZQMo9Kk
bX+W2tzlbl7uN3ebLddRAkEAyXLW0MTkU46+KZmgP1dK6Rw4J+ZGmTqpec317SjW
cjD45yIxgEbHUR1SXrsA89687/TzXkQXAdY7Ug6cF8tWPg==
-----END RSA PRIVATE KEY-----
EOF;

$privateKey = openssl_pkey_get_private(array($input, ""));

// We check if the privateKey is valid.
if (!$privateKey) {
    echo "The specified privateKey is invalid.";
	die();
}

// We obtain the publicKey from the valid privateKey.
$publicKey = openssl_pkey_get_details($privateKey);

// Convert PEM to DER encoding before hashing with SHA-1.
$string_start = '-----BEGIN PUBLIC KEY-----';
$string_end = '-----END PUBLIC KEY-----';
$pem = substr($publicKey['key'], (strpos($publicKey['key'], $string_start)+strlen($string_start)), (strlen($publicKey['key']) - strpos($publicKey['key'], $string_end))*(-1));

$der = base64_decode($pem);
$der = substr($der, 22, strlen($der)); // We skip the first 22 bytes.

// We only use the first half of the hash.
$sha = substr(sha1($der), 0, 20);

$onion_hash = Base32::encode(hex2bin($sha));

echo strtolower($onion_hash);

class Base32 {
	private static $map = array(
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', //  7
        'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', // 15
        'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', // 23
        'Y', 'Z', '2', '3', '4', '5', '6', '7', // 31
        '='  // padding char
    );
   
   private static $flippedMap = array(
        'A'=>'0', 'B'=>'1', 'C'=>'2', 'D'=>'3', 'E'=>'4', 'F'=>'5', 'G'=>'6', 'H'=>'7',
        'I'=>'8', 'J'=>'9', 'K'=>'10', 'L'=>'11', 'M'=>'12', 'N'=>'13', 'O'=>'14', 'P'=>'15',
        'Q'=>'16', 'R'=>'17', 'S'=>'18', 'T'=>'19', 'U'=>'20', 'V'=>'21', 'W'=>'22', 'X'=>'23',
        'Y'=>'24', 'Z'=>'25', '2'=>'26', '3'=>'27', '4'=>'28', '5'=>'29', '6'=>'30', '7'=>'31'
    );
   
    public static function encode($input, $padding = true) {
        if(empty($input)) return "";
        $input = str_split($input);
        $binaryString = "";
        for($i = 0; $i < count($input); $i++) {
            $binaryString .= str_pad(base_convert(ord($input[$i]), 10, 2), 8, '0', STR_PAD_LEFT);
        }
        $fiveBitBinaryArray = str_split($binaryString, 5);
        $base32 = "";
        $i=0;
        while($i < count($fiveBitBinaryArray)) {   
            $base32 .= self::$map[base_convert(str_pad($fiveBitBinaryArray[$i], 5,'0'), 2, 10)];
            $i++;
        }
        if($padding && ($x = strlen($binaryString) % 40) != 0) {
            if($x == 8) $base32 .= str_repeat(self::$map[32], 6);
            else if($x == 16) $base32 .= str_repeat(self::$map[32], 4);
            else if($x == 24) $base32 .= str_repeat(self::$map[32], 3);
            else if($x == 32) $base32 .= self::$map[32];
        }
        return $base32;
    }
}