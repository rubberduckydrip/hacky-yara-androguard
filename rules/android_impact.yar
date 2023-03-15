/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

rule sms_control__android_impact
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

rule call_control__android_collection
{
    meta:
        description = "Adversaries may make, forward, or block phone calls without user authorization. "
        reference = "https://attack.mitre.org/techniques/T1616/"

    strings:
        $string_a = "ANSWER_PHONE_CALLS"
        $string_b = "CALL_PHONE"
        $string_c = "PROCESS_OUTGOING_CALLS"
        $string_d = "MANAGE_OWN_CALLS"
        $string_e = "ConnectionService"
        $string_f = "BIND_TELECOM_CONNECTION_SERVICE"
        $string_g = "WRITE_CALL_LOG"

    condition: 
        any of them
}

rule transmitted_data_manipulation__android_impact
{
    meta:
        description = "Adversaries may alter data en route to storage or other systems in order to manipulate external outcomes or hide activity"
        reference = "https://attack.mitre.org/techniques/T1641/001/"

    strings:
        $string_a = "ClipboardManager.OnPrimaryClipChangedListener"

    condition:
        any of them
}


