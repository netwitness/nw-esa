/*
Version: 3
*/

module ${module_id};


<#if module_debug>@Audit('stream')</#if>

@Name('${module_id}_Alert')

@RSAAlert(oneInSeconds=${module_suppress?c}, identifiers={"user_dst, device_ip"})



SELECT * FROM 

Event( 
	medium = 32
	AND 
	user_dst IS NOT NULL
	AND
	device_ip IS NOT NULL
	AND 
	ec_activity IN ('Logon', 'Logoff')
).win:time(${time_window?c} seconds)	  

match_recognize (

	partition by user_dst,device_ip

	measures A as a

	pattern (A A+)

	define

	A as A.ec_activity ='Logon' and A.ec_outcome='Success'

	);

