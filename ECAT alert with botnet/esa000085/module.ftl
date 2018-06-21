/*
Version: 3
*/

module ${module_id};

<#if module_debug>@Audit('stream')</#if>

@Name('${module_id}_Alert')

@RSAAlert(oneInSeconds=${module_suppress?c}, identifiers={"ip_src"})

	
SELECT * FROM 

	Event(
		ip_src IS NOT NULL
		AND 
		(	
			(medium = 32 AND device_type='rsaecat')
			OR 
			(medium = 32 AND device_class IN ('IPS', 'IDS') AND (policy_name.toLowerCase() LIKE '%bot%' OR msg_id.toLowerCase() LIKE '%bot%'))
			OR 
			threat_category='botnet'
		)
	).win:time(${time_window?c} seconds)

	match_recognize (

		partition by ip_src

		measures A as a, B as b

		pattern (A+ B)

		define

		A as A.device_type = 'rsaecat',

		B as B.policy_name.toLowerCase() LIKE '%bot%' OR B.msg_id.toLowerCase() LIKE '%bot%' OR B.threat_category='botnet'

	);
	