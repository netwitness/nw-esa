/*
Version: 3
*/

module ${module_id};

<#if module_debug>@Audit('stream')</#if>
@Name('${module_id}_Alert')
@RSAAlert(oneInSeconds=${module_suppress?c}, identifiers={"user_src"})

SELECT * FROM pattern @SuppressOverlappingMatches [

	EVERY a = Event (reference_id IN ('624', '4720') AND device_class = 'Windows Hosts' AND medium = 32 AND user_src IS NOT NULL AND event_source.toLowerCase() IN ('security','microsoft-windows-security-auditing'))
	-> (b = Event(user_dst = a.user_src AND reference_id = '5140' AND device_class = 'Windows Hosts' AND medium = 32 AND event_source.toLowerCase() = 'microsoft-windows-security-auditing')
		-> c = Event(user_src = a.user_src AND reference_id IN ('630', '4726') AND device_class = 'Windows Hosts' AND medium = 32 AND event_source.toLowerCase() IN ('security','microsoft-windows-security-auditing'))
		) where timer:within(${time_window?c} seconds) 
];

