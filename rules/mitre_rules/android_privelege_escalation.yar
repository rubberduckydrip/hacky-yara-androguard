/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

rule device_administrator_permissions : privelege_escalation
{
	meta:
		description = "Adversaries may abuse Android’s device administration API to obtain a higher degree of control over the device"
        reference = "https://attack.mitre.org/techniques/T1626/001/"

	strings:
        $string_a = "BIND_DEVICE_ADMIN"

	condition:
		any of them
}

