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
			(medium = 1 AND service IN (22,443) AND NOT (tcp_dstport IN (<@buildArray variablelist=tcp_dstport_list/>)))
		)
	).win:time(${time_window?c} seconds)	  

	match_recognize (

		partition by ip_src

		measures A as a, B as b

		pattern (A+ B)

		define

		A as A.device_type = 'rsaecat',

		B as B.service in (443,22)

		);

<#macro buildArray variablelist>
	<@compress single_line=true>
	<#list variablelist as v>
		<@buildScalar value=v/>
		<#if v_has_next>,</#if>	
	</#list>
	</@compress>
</#macro>

<#macro buildScalar value>
	<#if value.type?starts_with("string")>
		'${value.value}'
	<#elseif value.type?starts_with("short") || value.type?starts_with("int") || value.type?starts_with("long") || value.type?starts_with("float")>
		${value.value?c}	
	</#if>
</#macro>