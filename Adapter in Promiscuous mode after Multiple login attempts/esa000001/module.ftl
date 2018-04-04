/*
Version: 3
*/

module ${module_id};

<#if module_debug>@Audit('stream')</#if>

@Name('${module_id}_Alert')

@RSAAlert(oneInSeconds=${module_suppress?c}, identifiers={"device_ip"})


SELECT * FROM  

	Event(
		 medium = 32 
		 AND
		 device_ip IS NOT NULL
		 AND
		 (
			 (ec_subject='Permission' AND ec_activity='Modify' AND ec_theme='AccessControl' AND ec_outcome='Failure' AND (event_desc LIKE '%failed su%') AND user_dst IS NOT NULL)

			  OR

			  (ec_subject='Permission' AND ec_activity='Modify' AND ec_theme='AccessControl' AND ec_outcome='Success' AND (event_desc LIKE '%successful su%') AND user_dst IS NOT NULL)

			  OR

			  (event_desc LIKE '%entered promiscuous mode%')
		  )
		  ).win:time(${time_window?c} seconds)

	   match_recognize (

	   partition by device_ip

	   measures F1 as f1, F2 as f2, F3 as f3, F4 as f4, F5 as f5, S1 as s1, S2 as s2, P as p

	   pattern (

		  F1 P* F2 P* F3 P* F4 P* F5+ P* S1 S2* F5* P

		  )

          define

		  F1 as F1.ec_outcome= 'Failure',

		  F2 as F2.ec_outcome= 'Failure' AND F2.user_dst = F1.user_dst,

		  F3 as F3.ec_outcome= 'Failure' AND F3.user_dst = F1.user_dst,

		  F4 as F4.ec_outcome= 'Failure' AND F4.user_dst = F1.user_dst,

		  F5 as F5.ec_outcome= 'Failure' AND F5.user_dst = F1.user_dst,

		  S1 as S1.ec_outcome= 'Success' AND S1.user_dst = F1.user_dst,

		  S2 as S2.ec_outcome= 'Success' AND S2.user_dst = F1.user_dst,

		  P as P.event_desc LIKE '%entered promiscuous mode%'

		  );

