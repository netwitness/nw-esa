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
		(medium = 32 AND device_class IN ('IPS', 'IDS') AND (policy_name.toLowerCase() LIKE '%beacon%' OR msg_id.toLowerCase() LIKE '%beacon%'))
		OR
		alert_id IN ('zusy botnet', 'tdss rootkit variant beaconing', 'tsone dorkbot beaconing', 'nw02635','nw02590')
	)
	).win:time(${time_window?c} seconds)

	match_recognize (

		partition by ip_src

		measures A as a, B as b

		pattern (A+ B)

		define

		A as A.device_type = 'rsaecat',

		B as B.device_type != 'rsaecat'

	);