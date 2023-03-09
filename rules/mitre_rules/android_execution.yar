/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

rule command_and_scripting_interpreter : android_execution
{
	meta:
		description = "Detects execution of shell commands"
        reference = "https://attack.mitre.org/techniques/T1623/"

	strings:
		$string_a = "Runtime.getRuntime().exec"

	condition:
		any of them
		
}

rule scheduled_task : android_execution
{
	meta:
		description = "Detection of possible abuse of task scheduling functionality to facilitate initial or recurring execution of malicious code"
        reference = "https://attack.mitre.org/techniques/T1603/"

	strings:
        $string_a = "WorkManager"
        $string_b = "Worker"
		$string_c = "OneTimeWorkRequest"
        $string_d = "OneTimeWorkRequest"
        $string_e = "WorkRequest"
        $string_f = "PeriodicWorkRequest"
        $string_g = "JobScheduler"
        $string_h = "GcmNetworkManager"
        $string_i = "AlarmManager"

	condition:
		any of them
}
