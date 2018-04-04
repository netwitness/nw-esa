/*
Version: 3
*/

module ${module_id};

<#if module_debug>@Audit('stream')</#if>
@Name('${module_id}_Alert')
@RSAAlert(oneInSeconds=${module_suppress?c}, identifiers={"user_dst"})

SELECT * FROM 
	Event(
		( 
		  (ec_subject='User' AND ec_activity='Lockout') 
		   OR 
		  (device_class = 'Windows Hosts' AND reference_id IN ('4740', '644'))
		)
		AND
		medium = 32
		AND
		user_dst IS NOT NULL	
	   ).win:time_length_batch(${time_window?c} sec, ${event_count?c}) HAVING COUNT(*) = ${event_count?c};