/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

rule dynamic_code_loading_a : defense evasion
{
	meta:
		description = "Adversaries may download and execute dynamic code not included in the original application package after installation"
        reference = "https://attack.mitre.org/techniques/T1407/"

	strings:
        $string_a = "DexClassLoader"
        $string_b = "System.load"
        $string_c = "JavaScriptInterface"

	condition:
		any of them
}


rule dynamic_code_loading_b : defense evasion
{
	meta:
		description = "Adversaries may download and execute dynamic code not included in the original application package after installation"
        reference = "https://attack.mitre.org/techniques/T1407/"

	strings:
        $string_b = "System.load"

	condition:
		any of them
}


rule dynamic_code_loading_c : defense evasion
{
	meta:
		description = "Adversaries may download and execute dynamic code not included in the original application package after installation"
        reference = "https://attack.mitre.org/techniques/T1407/"

	strings:
        $string_c = "JavaScriptInterface"

	condition:
		any of them
}

rule suppress_application : defense_evasion 
{
    meta:
        description = "A malicious application could suppress its icon from being displayed to the user in the application launcher"
        reference = "https://attack.mitre.org/techniques/T1628/001/"
        reference_code = "https://stackoverflow.com/questions/19114439/android-hide-unhide-app-icon-programmatically"

    strings:
        $string_a = "android.intent.category.LEANBACK_LAUNCHER"
        $string_b = "COMPONENT_ENABLED_STATE_DISABLED"

    condition: 
        any of them
}


/*
rule file_deletion : defense_evasion 
{
    meta: 
        description = "Adversaries may wipe a device or delete individual files in order to manipulate external outcomes or hide activity"
        reference = "https://attack.mitre.org/techniques/T1630/002/"
        reference_code = "https://stackoverflow.com/questions/24659704/how-do-i-delete-files-programmatically-on-android"

    strings:
        $string_a = ".delete()"

    condition:
        all of them
}
*/

