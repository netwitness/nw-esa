/*
Version: 3
*/
module ${module_id};

<#if module_debug>@Audit('stream')</#if>

@Name('${module_id}_Alert')

@RSAAlert(oneInSeconds=${module_suppress?c})

SELECT * FROM  
	Event(
		medium = 32
		AND
		device_class ='Windows Hosts'
		AND
		reference_id IN ('566','5136','5137','5138','5139','5141') 
		AND
		(
			(
				accesses.toLowerCase() LIKE '%create%'
				OR 
				accesses.toLowerCase() LIKE '%write%'
				OR 
				accesses.toLowerCase() LIKE '%delete%'
				OR
				event_desc.toLowerCase() LIKE '%modified%'
				OR 
				event_desc.toLowerCase() LIKE '%create%'
				OR 
				event_desc.toLowerCase() LIKE '%delete%'
				OR 
				event_desc.toLowerCase() LIKE '%move%'
			)
		)
	);