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
		(medium = 1 AND service = 22)
	)
	).win:time(${time_window?c} seconds)	  

match_recognize (

	partition by ip_src

	measures A as a, B as b

	pattern (A+ B)

	define

	A as A.service = 22,

	B as B.device_type = 'rsaecat'

	);

