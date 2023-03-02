/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

rule sms_control_a : android_impact
{
	meta:
		description = "adversaries may delete, alter, or send sms messages without user authorization"
        reference = "https://attack.mitre.org/techniques/t1582/"

	strings:
        $string_a = "RECEIVE_SMS"

	condition:
		any of them
}

rule sms_control_b : android_impact
{
	meta:
		description = "adversaries may delete, alter, or send sms messages without user authorization"
        reference = "https://attack.mitre.org/techniques/t1582/"

	strings:
        $string_b = "SEND_SMS"

	condition:
		any of them
}


rule sms_control_c : android_impact
{
	meta:
		description = "adversaries may delete, alter, or send sms messages without user authorization"
        reference = "https://attack.mitre.org/techniques/t1582/"

	strings:
		$string_c = "SMS_DELIVER"

	condition:
		any of them
}

rule sms_control_d : android_impact
{
	meta:
		description = "adversaries may delete, alter, or send sms messages without user authorization"
        reference = "https://attack.mitre.org/techniques/t1582/"

	strings:
        $string_a = "sendTextMessage"

	condition:
		any of them
}
