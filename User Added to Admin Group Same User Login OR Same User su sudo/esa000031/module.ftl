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
		device_class = 'Unix'
		AND
		user_dst IS NOT NULL
		AND
		(
			(
			ec_subject='Group' and ec_activity='Modify' and ec_outcome='Success' 
			AND 
			`group` IN (<@buildArray variablelist=group_equals/>)
			)
			OR 
			event_desc in ('successful su','successful sudo')
			OR 
			ec_subject='User' and ec_activity='Logon' and ec_outcome='Success' 
		)	
	).win:time(${time_window?c} seconds)

	match_recognize (

	partition by user_dst

	measures F as f, S as s

	pattern (F S)

	define

	F as F.ec_subject='Group' and F.ec_activity='Modify' and F.ec_outcome='Success',

	S as S.event_desc = 'successful su' or S.event_desc = 'successful sudo' or S.ec_activity='Logon');


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