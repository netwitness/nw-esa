/*
Version: 3
*/
module ${module_id};

<#if module_debug>@Audit('stream')</#if>
@Name('${module_id}_Alert')
@RSAAlert(oneInSeconds=${module_suppress?c}, identifiers={"user_dst"})

Select * from Event(
	(
	ec_activity='Logon' and ec_outcome='Failure' and user_dst IS NOT NULL)   
	OR (ec_activity='Logon' and ec_outcome='Success' and user_dst IS NOT NULL)   
	OR (ec_subject='Password' and ec_activity='Modify' and user_dst IS NOT NULL)   
	).win:time(${time_window?c} seconds)
	match_recognize (   
	partition by user_dst   
	measures F as f_array, S as s, M as m   
	pattern (F F F F F S M)  
	define   
	F as F.ec_outcome = 'Failure',   
	S as S.ec_outcome = 'Success',   
	M as M.ec_activity = 'Modify');
