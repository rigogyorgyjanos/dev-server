#ifndef __INC_METIN_II_GAME_MAINTENANCE_SYSTEM_H__
#define __INC_METIN_II_GAME_MAINTENANCE_SYSTEM_H__
#pragma once
class MaintenanceManager : public singleton<MaintenanceManager>
{
	public:
		MaintenanceManager();
		~MaintenanceManager();

	void	Send_UpdateBinary(LPCHARACTER ch);
	void	Send_CheckTable(LPCHARACTER ch);
	void	Send_Text(LPCHARACTER ch, const char* reason);
	void	Send_DisableSecurity(LPCHARACTER ch);
	void	Send_ActiveMaintenance(LPCHARACTER ch, long int time_maintenance, long int duration_maintenance);

	// Login gate for normal players (accounts of GMs always get through) - state lives in player.login_gate
	bool	IsPlayerLoginOpen();
	bool	SetPlayerLoginOpen(bool bOpen);
	bool	IsAccountAllowed(const char* c_pszLogin);
	void	Send_PlayerLogin(LPCHARACTER ch, const char* c_pszArg);
};
#endif
