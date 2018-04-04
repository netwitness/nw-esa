/*
Version: 3
*/
module ${module_id};

<#if module_debug>@Audit('stream')</#if>
@Name('${module_id}_Alert')
@RSAAlert(oneInSeconds=${module_suppress?c}, identifiers={"user_dst"})

SELECT * FROM 
	Event(
	      ec_outcome in ('Success', 'Failure') 
		  AND ec_activity='Logon'
		  AND medium = 32
		  AND user_dst IS NOT NULL
		  ).win:time(${time_window?c} sec)
	match_recognize (
		  partition by user_dst
          measures F as f_array, S as s
          pattern (
	<#if failed_count &gt;= 10>
			<@repeat count=10 ; c, last> F<#if last>+ </#if> </@repeat> S
		<#else>
			<@repeat count=failed_count ; c, last> F<#if last>+ </#if> </@repeat> S
	</#if>
	  
		  )
          define
          F as F.ec_outcome= 'Failure',
          S as S.ec_outcome= 'Success');
	
	
	<#macro repeat count>
	  <#list 1..count as x>
	    <#nested x, x==count>
	  </#list>
	</#macro>
	