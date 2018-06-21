/*
Version: 3
*/
module ${module_id};

<#if module_debug>@Audit('stream')</#if>

@Name('${module_id}_Alert')

@RSAAlert(oneInSeconds=${module_suppress?c}, identifiers={"ip_src"})

select * from Event(
		ip_src IS NOT NULL
		AND 
		device_type IS NOT NULL
		AND
		medium = 32 
		AND 
		(
			device_class in ('IDS','IPS', 'Intrusion') 
			OR
			device_type='rsaecat'
		)
	).win:time(${time_window?c} seconds) 
	  match_recognize (
		partition by ip_src
		measures A as a, B as b
		pattern ((A+ B)|(B+ A))
		define 
	  A as A.device_type != 'rsaecat' ,
	  B as B.device_type = 'rsaecat'
	  );