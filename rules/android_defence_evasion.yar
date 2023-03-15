/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

rule dynamic_code_loading__defense_evasion
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

rule execution_guardrails__defense_evasion
{
    meta:
        description = "Adversaries may use execution guardrails to constrain execution or actions based on adversary supplied and environment specific conditions that are expected to be present on the target"
        reference = "https://attack.mitre.org/techniques/T1627/"

    strings:
        $strings_a = "SystemProperties"
        $strings_b = "Build.MODEL"
        $strings_c = "Build.HARDWARE"
        $strings_d = "Build.PRODUCT"

    condition:
        any of them
}

rule geofencing__defense_evasion
{
    meta:
        description = "Adversaries may use a device’s geographical location to limit certain malicious behaviors"
        reference = "https://attack.mitre.org/techniques/T1627/001/"

    strings:
        $string_a = "ACCESS_FINE_LOCATION"
        $string_b = "ACCESS_BACKGROUND_LOCATION"

    condition:
        any of them
}

rule suppress_application__defense_evasion 
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

rule user_evasion__defense_evasion
{
    meta: 
        description = "By utilizing the various motion sensors on a device, such as accelerometer or gyroscope, an application could detect that the device is being interacted with"
        reference = "https://attack.mitre.org/techniques/T1628/002/"
        
    strings:
        $string_a = "SensorManager"
      
    condition:
        all of them
}

rule device_lockout__defense_evasion
{
    meta:
        description = "An adversary may seek to inhibit user interaction by locking the legitimate user out of the device"
        reference = "https://attack.mitre.org/techniques/T1629/002/"

    strings:
        $string_a = "DevicePolicyManager.lockNow"

    condition:
        all of them
}

rule uninstall_malicious_applicartion__defense_evasion
{
    meta:
        description = "Adversaries may include functionality in malware that uninstalls the malicious application from the device"
        reference = "https://attack.mitre.org/techniques/T1630/001/"
        referense_code = "https://stackoverflow.com/questions/6813322/install-uninstall-apks-programmatically-packagemanager-vs-intents"

    strings:
        $string_a = "REQUEST_DELETE_PACKAGES"

    condition:
        all of them
}

rule file_deletion__defense_evasion 
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


