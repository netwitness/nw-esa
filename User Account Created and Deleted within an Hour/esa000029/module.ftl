/*
Version: 3
*/

module ${module_id};

<#if module_debug>@Audit('stream')</#if>

@Name('${module_id}_Alert')

@RSAAlert(oneInSeconds=${module_suppress?c}, identifiers={"user_src"})


SELECT * FROM

			Event(
					medium = 32
					AND
					ec_subject='User'
					AND
					ec_outcome='Success'
					AND
					user_dst is NOT NULL
					AND
					(
						ec_activity='Create'
						OR  
						ec_activity='Delete' 
					)	
				).win:time(${time_window?c} seconds)

match_recognize (

partition by user_src

measures C as c, D as d

pattern (C+ D)

define

C as C.ec_activity='Create' ,

D as D.ec_activity='Delete');

