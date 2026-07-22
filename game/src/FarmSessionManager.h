#ifndef __INC_METIN_II_GAME_FARM_SESSION_MANAGER_H__
#define __INC_METIN_II_GAME_FARM_SESSION_MANAGER_H__

#ifdef __FARM_SESSION_SYSTEM__

#include <map>
#include <stdint.h>

class CHARACTER;

enum EFarmSessionMobCategory
{
	FARM_SESSION_MOB_NORMAL	= 0,
	FARM_SESSION_MOB_BOSS		= 1,
	FARM_SESSION_MOB_STONE		= 2,
};

struct SFarmSessionData
{
	bool	isActive;
	DWORD	dwStartTime;
	DWORD	dwKillCountTotal;
	DWORD	dwStoneKillTotal;
	DWORD	dwBossKillTotal;
	DWORD	dwNormalKillTotal;
	std::map<DWORD, DWORD>	killsByType;	// mob race vnum -> count
	DWORD	dwItemCountTotal;
	std::map<DWORD, DWORD>	itemsByType;	// item vnum -> count
	int64_t	lYangGained;
	int64_t	lYangSpent;

	SFarmSessionData()
		: isActive(false)
		, dwStartTime(0)
		, dwKillCountTotal(0)
		, dwStoneKillTotal(0)
		, dwBossKillTotal(0)
		, dwNormalKillTotal(0)
		, dwItemCountTotal(0)
		, lYangGained(0)
		, lYangSpent(0)
	{
	}
};

// Tracks per-player farm sessions independently of the transient CHARACTER object,
// so a session survives a simple disconnect/relogin (only a full game process
// restart loses active, un-stopped sessions - accepted v1 limitation).
class CFarmSessionManager : public singleton<CFarmSessionManager>
{
	public:
		CFarmSessionManager();
		virtual ~CFarmSessionManager();

		void	StartSession(LPCHARACTER ch);
		void	StopSession(LPCHARACTER ch);

		void	OnKill(LPCHARACTER pkAttacker, DWORD dwRaceNum, BYTE bCategory);
		void	OnItemReceived(LPCHARACTER ch, DWORD dwItemVnum, DWORD dwCount);
		void	OnGoldChange(LPCHARACTER ch, int amount);

		void	OnDisconnect(DWORD dwPID);
		void	OnEnterGame(LPCHARACTER ch);

		// P2P handoff - this server shards maps across multiple game processes
		// per channel, so a cross-process portal is a real (if client-invisible)
		// reconnect to a different process with its own CFarmSessionManager
		// instance. Every CHARACTER::WarpSet() call - even ones that land back
		// on THIS same process - goes through the same "tell client to
		// reconnect" flow, so TransferOut must be told the resolved
		// destination address/port and only actually hand the session off
		// (broadcast + drop the local copy) when that destination is a
		// DIFFERENT process; otherwise the character is coming right back to
		// this process's own OnEnterGame and the existing entry must be left
		// alone. TransferIn* apply an incoming transfer on the destination,
		// either directly (character already logged in there) or staged
		// until OnEnterGame claims it (character hasn't reconnected yet).
		void	TransferOut(LPCHARACTER ch, long lDestAddr, WORD wDestPort);
		void	TransferInState(DWORD dwPID, bool isActive, DWORD dwElapsedSec, DWORD dwKillCountTotal, DWORD dwStoneKillTotal, DWORD dwBossKillTotal, DWORD dwNormalKillTotal, DWORD dwItemCountTotal, int64_t lYangGained, int64_t lYangSpent);
		void	TransferInKillEntry(DWORD dwPID, DWORD dwMobVnum, DWORD dwCount);
		void	TransferInItemEntry(DWORD dwPID, DWORD dwItemVnum, DWORD dwCount);

	private:
		SFarmSessionData *	__FindActive(DWORD dwPID);
		void	__SendState(LPCHARACTER ch, const SFarmSessionData & data);
		void	__SendKillEntry(LPCHARACTER ch, DWORD dwMobVnum, DWORD dwCount);
		void	__SendItemEntry(LPCHARACTER ch, DWORD dwItemVnum, DWORD dwCount);
		void	__SendAllEntries(LPCHARACTER ch, const SFarmSessionData & data);

		std::map<DWORD, SFarmSessionData>	m_map_kSession;
		std::map<DWORD, SFarmSessionData>	m_map_kStaged;	// P2P-received, character not yet logged into this process
};

#endif
#endif
