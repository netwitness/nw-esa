/*
Version: 1
*/
module ${module_id};

<#if module_debug>@Audit('stream')</#if>
@Name('${module_id}_Alert')

@RSAAlert(oneInSeconds=${module_suppress?c}, identifiers={"ip_src"})
SELECT * FROM PATTERN 
	@SuppressOverlappingMatches 
	[ 
	every
	/* Statement: HTTP_lua parser identifies integer host */
	e1=Event(medium = 1 AND 'http host header is an integer' = ANY(analysis_service))
	->
	/* Statement: RIG Exploit Kit app rule */
	e2=Event('rig exploit kit' = ANY(ioc) AND ip_src = e1.ip_src)
	where timer:within(${time_window?c} seconds)
	];