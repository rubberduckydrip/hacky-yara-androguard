/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

rule command_and_scripting_interpreter : credential_access
{
	meta:
		description = "Adversaries may collect data within notifications sent by the operating system or other applications"
        reference = "https://attack.mitre.org/techniques/T1517/"

	strings:
		$string_a = "BIND_NOTIFICATION_LISTENER_SERVICE"

	condition:
		any of them
}		

rule clipboard_data : credential_access
{
    meta:
        description = "Adversaries may abuse clipboard manager APIs to obtain sensitive information copied to the device clipboard"
        reference = "https://attack.mitre.org/techniques/T1414/"

    strings:
        $string_a = "ClipboardManager.OnPrimaryClipChangedListener"

    condition:
        any of them
}

rule keylogging : credential_access
{
    meta:
        description = "Adversaries may log user keystrokes to intercept credentials or other information from the user as the user types them"
        reference = "https://attack.mitre.org/techniques/T1417/001/"

    strings:
        $string_a = "onAccessibilityEvent"
        $string_b = "AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED"

    condition:
        any of them
}

rule gui_input_capture : credential_access 
{
    meta:
        description = "Adversaries may mimic common operating system GUI components to prompt users for sensitive information with a seemingly legitimate prompt"
        reference = "https://attack.mitre.org/techniques/T1417/002/"

    strings:
        $string_a = "android.permission.SYSTEM_ALERT_WINDOW"

    condition:
        any of them
}
