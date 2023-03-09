/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

rule sms_control : android_impact
{
	meta:
		description = "Adversaries may delete, alter, or send SMS messages without user authorization"
        reference = "https://attack.mitre.org/techniques/T1582/"

	strings:
        $string_a = "RECEIVE_SMS"
        $string_b = "SEND_SMS"
		$string_c = "SMS_DELIVER"

	condition:
		any of them
}

rule transmitted_data_manipulation : android_impact
{
    meta:
        description = "Adversaries may alter data en route to storage or other systems in order to manipulate external outcomes or hide activity"
        reference = "https://attack.mitre.org/techniques/T1641/001/"

    strings:
        $string_a = "ClipboardManager.OnPrimaryClipChangedListener"

    condition:
        any of them
}


