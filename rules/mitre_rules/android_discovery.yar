/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

rule location_tracking : android_discovery
{
	meta:
		description = "Adversaries may track a device’s physical location through use of standard operating system APIs via malicious or exploited applications on the compromised device"
        reference = "https://attack.mitre.org/techniques/T1430/"

	strings:
        $string_a = "ACCESS_COARSE_LOCATION"
        $string_b = "ACCESS_FINE_LOCATION"
		$string_c = "ACCESS_BACKGROUND_LOCATION"

	condition:
		any of them
}

rule process_discovery : android_discovery 
{
    meta:
        description = "Adversaries may attempt to get information about running processes on a device. Information obtained could be used to gain an understanding of common software/applications running on devices within a network"
        source = "https://attack.mitre.org/techniques/T1424/"
    strings:
        $string_a = "ps"
        $string_b = "/proc"

    condition:
        any of them
}

rule software_discovery : android_discovery
{
    meta:
        description = "Adversaries may attempt to get a listing of applications that are installed on a device"
        reference = "https://attack.mitre.org/techniques/T1418/"

    strings: 
        $string_a = "android.permission.QUERY_ALL_PACKAGES"
        
    condition:
        any of them
}

rule system_information_discovery : android_discovery
{
    meta: 
        description = "Adversaries may attempt to get detailed information about a device’s operating system and hardware, including versions, patches, and architecture"
        reference = "https://attack.mitre.org/techniques/T1426/"

    strings:
        $string_a = "android.os.Build"

    condition:
        any of them
}

rule system_network_configuration_discovery : android_discovery
{
    meta:
        description = "Adversaries may look for details about the network configuration and settings, such as IP and/or MAC addresses, of operating systems they access or through information discovery of remote systems"
        reference = "https://attack.mitre.org/techniques/T1422/"

    strings:
        $string_a = "READ_PRIVILEGED_PHONE_STATE"

    condition:
        any of them
}

rule system_network_connections_discovery : android_discovery
{
    meta: 
        description = "Adversaries may attempt to get a listing of network connections to or from the compromised device they are currently accessing or from remote systems by querying for information over the network"
        reference = "https://attack.mitre.org/techniques/T1421/"

    strings:
        $string_a = "WifiInfo"
        $string_b = "BluetoothAdapter"
        $string_c = "TelephonyManager.getNeighboringCellInfo"
        $string_d = "TelephonyManager.getAllCellInfo"

    condition:
        any of them
}
