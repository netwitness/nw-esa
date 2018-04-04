/*
Version: 3
*/

module ${module_id};

<#if module_debug>@Audit('stream')</#if>
@Name('${module_id}_Alert')
@RSAAlert(oneInSeconds=${module_suppress?c}, identifiers={"user_src"})

		 
SELECT * FROM pattern @SuppressOverlappingMatches [

		   EVERY a=Event (reference_id IN ('624', '4720') AND device_class = 'Windows Hosts' AND medium = 32 AND event_source.toLowerCase() IN ('security','microsoft-windows-security-auditing') AND user_src IS NOT NULL)
			-> ( b=Event(user_src = a.user_src AND reference_id IN ('632', '4728', '636', '4732', '655', '4751', '660', '4756', '4761') AND device_class = 'Windows Hosts' AND medium = 32 AND event_source.toLowerCase() IN ('security','microsoft-windows-security-auditing'))
				->   c=Event(user_dst = b.user_src AND reference_id = '5142' AND device_class = 'Windows Hosts' AND medium = 32 AND event_source.toLowerCase() = 'microsoft-windows-security-auditing')
				) where timer:within(${time_window?c} seconds)
];
