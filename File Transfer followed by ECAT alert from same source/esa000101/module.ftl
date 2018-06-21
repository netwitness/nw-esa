/*
Version: 3
*/

module ${module_id};

<#if module_debug>@Audit('stream')</#if>

@Name('${module_id}_Alert')

@RSAAlert(oneInSeconds=${module_suppress?c}, identifiers={"ip_src"})


SELECT * FROM 

	Event ( 
		ip_src IS NOT NULL 
		AND 
		(
			(medium = 32 AND device_type='rsaecat')
			OR 
			(medium =1 AND size > 5242880 AND streams = 2 AND ip_dst NOT REGEXP '(10\.[0-9]{1,3}|172\.(3[01]|2[0-9]|1[6-9])|192\.168)\.[0-9]{1,3}\.[0-9]{1,3}')
		)
	).win:time(${time_window?c} seconds)	  

	match_recognize (

		partition by ip_src

		measures A as a, B as b

		pattern (A+ B)

		define

		A as A.medium = 1,

		B as B.device_type = 'rsaecat'

		);

