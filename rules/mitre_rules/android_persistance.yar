/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

rule event_triggered_execution_broadcast_receivers : android_persistance
{
	meta:
		description = "Adversaries may establish persistence using system mechanisms that trigger execution based on specific events"
        reference = "https://attack.mitre.org/techniques/T1624/001/"

	strings:
        $string_a = "BOOT_COMPLETED"
		$string_c = "USER_PRESENT"
        $string_d = "SCREEN_ON"

	condition:
		any of them
}

rule foreground_persistance : android_persistance
{
    meta:
        description = "Adversaries may abuse Android's startForeground() API method to maintain continuous sensor access"
        reference = "https://attack.mitre.org/techniques/T1624/001/"

    strings:
        $string_a = "startForeground"

    condition:
        any of them
}

