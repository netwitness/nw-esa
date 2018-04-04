/*
Version: 2
*/
module ${module_id};

<#if module_debug>@Audit('stream')</#if>
@Name('${module_id}_Alert')
@Description('${module_desc}')
@RSAAlert(oneInSeconds=${module_suppress?c})
SELECT * FROM 
	Event(
		ec_subject = 'Password' 
		AND
		ec_activity = 'Modify' 
		AND(
			<#if username_contains?size &gt; 0>
				<@buildUsernameContains usernameContains=username_contains/>  
				<#if username_equals?size &gt; 0>		
					OR 
				</#if>
			</#if>
			<#if username_equals?size &gt; 0>
				user_dst IN (<@buildUsernameEquals usernameEquals=username_equals/>)
			</#if>
			)
		);

<#macro buildUsernameContains usernameContains>
	<@compress single_line=true>
		<#list usernameContains as v>
			user_dst LIKE '%${v.value}%'
			<#if v_has_next> OR </#if>	
		</#list>
	</@compress>
</#macro>

<#macro buildUsernameEquals usernameEquals>
	<@compress single_line=true>
		<#list usernameEquals as u>
			'${u.value}'
			<#if u_has_next>,</#if>	
		</#list>
	</@compress>
</#macro>		