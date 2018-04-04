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
		device_class = 'Windows Hosts' 
		AND
		(
			(
				ec_subject = 'Permission' 
				AND 
				ec_activity = 'Modify' 
				AND
				ec_theme = 'AccessControl'
				AND 
				ec_outcome = 'Success'
			)   
			OR 
			(
				ec_subject = 'Group' 
				AND
				ec_activity = 'Modify' 
				AND 
				ec_theme = 'UserGroup' 
				AND 
				ec_outcome = 'Success'
			)
		)
		AND
		(
			reference_id IN ('4704', '4717', '4787', '4785', '4761', '4732', '4728', '4756', '4751', '608', '621', '660', '636', '632', '689', '655') 
			AND 
			( 
				<#if username_contains?size &gt; 0>
				<@buildMetaContains metaContains=username_contains metakey="user_dst"/> 
				<#if group_equals?size &gt; 0>		
				OR 
				</#if>
				</#if>
				<#if group_equals?size &gt; 0>
					`group` IN (<@buildArray variablelist=group_equals/>)
				</#if>
			)
		)
	);

<#macro buildMetaContains metaContains metakey>
	<@compress single_line=true>
		<#list metaContains as v>
			${metakey} LIKE '%${v.value}%'
			<#if v_has_next> OR </#if>	
		</#list>
	</@compress>
</#macro>

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
	<#else>
		${value.value?c}	
	</#if>
</#macro>	