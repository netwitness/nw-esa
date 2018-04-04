/*
Version: 3
*/
module ${module_id};

<#if module_debug>@Audit('stream')</#if>

@Name('${module_id}_Alert')
@RSAAlert(oneInSeconds=${module_suppress?c}, identifiers={"user_dst"})

SELECT * FROM
	Event(
		device_class = 'Windows Hosts' 
		AND 
		reference_id IN ('577','578','4673','4674') 
		AND
		user_dst IS NOT NULL
	).std:groupwin(user_dst)
		.win:time_length_batch(${time_window?c} seconds, ${count?c})
		group by user_dst
		having count(*) = ${count?c};

		
@Name('${module_id}_Alert')
@Description('${module_desc}')
@RSAAlert(oneInSeconds=${module_suppress?c}, identifiers={"user_dst"})

SELECT * FROM
	Event(
		device_class = 'Unix'
		AND
		ec_subject = 'Permission' 
		AND 
		ec_activity = 'Modify' 
		AND
		ec_theme = 'AccessControl'
		AND 
		ec_outcome = 'Failure'
		AND
		event_desc like 'failed su%' 
		AND
		user_dst IS NOT NULL
	).std:groupwin(user_dst)
		.win:time_length_batch(${time_window?c} seconds, ${count?c})
		group by user_dst
		having count(*) = ${count?c};