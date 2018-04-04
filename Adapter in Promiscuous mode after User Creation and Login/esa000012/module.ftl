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
				(
					(ec_subject='User' AND ec_activity='Create' AND ec_theme='UserGroup' AND ec_outcome='Success' AND user_dst is not null) 

					OR

					(ec_activity='Logon' AND ec_outcome='Success' AND user_dst is not null)	

					OR

					(event_desc LIKE '%entered promiscuous mode%')
				)
			).win:time(${time_window?c} seconds)

		match_recognize (

		measures C as c, L as l, P as p

		pattern (C L P)

		define

		C as C.ec_activity='Create',

		L as L.ec_activity='Logon' AND C.user_dst = L.user_dst,

		P as P.event_desc LIKE '%entered promiscuous mode%');

