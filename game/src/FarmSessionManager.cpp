#include "stdafx.h"

#ifdef __FARM_SESSION_SYSTEM__

#include "FarmSessionManager.h"
#include "char.h"
#include "char_manager.h"
#include "config.h"
#include "desc.h"
#include "packet.h"
#include "p2p.h"

CFarmSessionManager::CFarmSessionManager()
{
}

CFarmSessionManager::~CFarmSessionManager()
{
}

SFarmSessionData * CFarmSessionManager::__FindActive(DWORD dwPID)
{
	std::map<DWORD, SFarmSessionData>::iterator it = m_map_kSession.find(dwPID);

	if (it == m_map_kSession.end())
		return NULL;

	if (!it->second.isActive)
		return NULL;

	return &it->second;
}

void CFarmSessionManager::__SendState(LPCHARACTER ch, const SFarmSessionData & data)
{
	if (!ch || !ch->GetDesc())
		return;

	TPacketGCFarmSessionState pack;
	pack.header			= HEADER_GC_FARM_SESSION_STATE;
	pack.isActive			= data.isActive ? 1 : 0;
	pack.dwElapsedSec		= (get_dword_time() - data.dwStartTime) / 1000;
	pack.dwKillCountTotal		= data.dwKillCountTotal;
	pack.dwStoneKillTotal		= data.dwStoneKillTotal;
	pack.dwBossKillTotal		= data.dwBossKillTotal;
	pack.dwNormalKillTotal		= data.dwNormalKillTotal;
	pack.dwItemCountTotal		= data.dwItemCountTotal;
	pack.lYangGained		= data.lYangGained;
	pack.lYangSpent			= data.lYangSpent;

	ch->GetDesc()->Packet(&pack, sizeof(pack));
}

void CFarmSessionManager::__SendKillEntry(LPCHARACTER ch, DWORD dwMobVnum, DWORD dwCount)
{
	if (!ch || !ch->GetDesc())
		return;

	TPacketGCFarmSessionKillEntry pack;
	pack.header		= HEADER_GC_FARM_SESSION_KILL_ENTRY;
	pack.dwMobVnum		= dwMobVnum;
	pack.dwCount		= dwCount;

	ch->GetDesc()->Packet(&pack, sizeof(pack));
}

void CFarmSessionManager::__SendItemEntry(LPCHARACTER ch, DWORD dwItemVnum, DWORD dwCount)
{
	if (!ch || !ch->GetDesc())
		return;

	TPacketGCFarmSessionItemEntry pack;
	pack.header		= HEADER_GC_FARM_SESSION_ITEM_ENTRY;
	pack.dwItemVnum		= dwItemVnum;
	pack.dwCount		= dwCount;

	ch->GetDesc()->Packet(&pack, sizeof(pack));
}

void CFarmSessionManager::__SendAllEntries(LPCHARACTER ch, const SFarmSessionData & data)
{
	if (!ch || !ch->GetDesc())
		return;

	for (std::map<DWORD, DWORD>::const_iterator kill_it = data.killsByType.begin(); kill_it != data.killsByType.end(); ++kill_it)
		__SendKillEntry(ch, kill_it->first, kill_it->second);

	for (std::map<DWORD, DWORD>::const_iterator item_it = data.itemsByType.begin(); item_it != data.itemsByType.end(); ++item_it)
		__SendItemEntry(ch, item_it->first, item_it->second);
}

void CFarmSessionManager::StartSession(LPCHARACTER ch)
{
	if (!ch || !ch->IsPC())
		return;

	DWORD dwPID = ch->GetPlayerID();

	// Ignore a duplicate/desynced Start while a session is already running -
	// resetting here would silently wipe the player's accumulated progress.
	if (__FindActive(dwPID))
		return;

	SFarmSessionData & data = m_map_kSession[dwPID];
	data = SFarmSessionData();
	data.isActive = true;
	data.dwStartTime = get_dword_time();

	__SendState(ch, data);
}

void CFarmSessionManager::StopSession(LPCHARACTER ch)
{
	if (!ch || !ch->IsPC())
		return;

	DWORD dwPID = ch->GetPlayerID();

	std::map<DWORD, SFarmSessionData>::iterator it = m_map_kSession.find(dwPID);

	if (it == m_map_kSession.end() || !it->second.isActive)
		return;

	SFarmSessionData data = it->second;
	data.isActive = false;

	m_map_kSession.erase(it);

	if (!ch->GetDesc())
		return;

	__SendState(ch, data);
	__SendAllEntries(ch, data);

	TPacketGCFarmSessionReportEnd endPack;
	endPack.header = HEADER_GC_FARM_SESSION_REPORT_END;
	ch->GetDesc()->Packet(&endPack, sizeof(endPack));
}

void CFarmSessionManager::OnKill(LPCHARACTER pkAttacker, DWORD dwRaceNum, BYTE bCategory)
{
	SFarmSessionData * pData = pkAttacker ? __FindActive(pkAttacker->GetPlayerID()) : NULL;

	if (!pData)
		return;

	++pData->dwKillCountTotal;

	switch (bCategory)
	{
		case FARM_SESSION_MOB_STONE:	++pData->dwStoneKillTotal;	break;
		case FARM_SESSION_MOB_BOSS:	++pData->dwBossKillTotal;	break;
		default:			++pData->dwNormalKillTotal;	break;
	}

	DWORD dwNewKillCount = ++pData->killsByType[dwRaceNum];

	__SendState(pkAttacker, *pData);
	__SendKillEntry(pkAttacker, dwRaceNum, dwNewKillCount);
}

void CFarmSessionManager::OnItemReceived(LPCHARACTER ch, DWORD dwItemVnum, DWORD dwCount)
{
	SFarmSessionData * pData = ch ? __FindActive(ch->GetPlayerID()) : NULL;

	if (!pData)
		return;

	pData->dwItemCountTotal += dwCount;
	DWORD dwNewItemCount = (pData->itemsByType[dwItemVnum] += dwCount);

	__SendState(ch, *pData);
	__SendItemEntry(ch, dwItemVnum, dwNewItemCount);
}

void CFarmSessionManager::OnGoldChange(LPCHARACTER ch, int amount)
{
	if (0 == amount)
		return;

	SFarmSessionData * pData = ch ? __FindActive(ch->GetPlayerID()) : NULL;

	if (!pData)
		return;

	if (amount > 0)
		pData->lYangGained += amount;
	else
		pData->lYangSpent += -(int64_t)amount;

	__SendState(ch, *pData);
}

void CFarmSessionManager::OnDisconnect(DWORD dwPID)
{
	// No-op: the session simply stops receiving events while the player is
	// offline (nothing can fire OnKill/OnItemReceived/OnGoldChange for a
	// disconnected player), which is already the "pause" behavior. The entry
	// is deliberately NOT removed from m_map_kSession here.
	(void)dwPID;
}

void CFarmSessionManager::OnEnterGame(LPCHARACTER ch)
{
	if (!ch || !ch->IsPC())
		return;

	DWORD dwPID = ch->GetPlayerID();

	// A session P2P-transferred in from a different game process (cross-process
	// portal handoff) may have arrived before this player finished reconnecting -
	// claim it into the live map now that the character actually exists here.
	std::map<DWORD, SFarmSessionData>::iterator staged_it = m_map_kStaged.find(dwPID);
	if (staged_it != m_map_kStaged.end())
	{
		m_map_kSession[dwPID] = staged_it->second;
		m_map_kStaged.erase(staged_it);
	}

	SFarmSessionData * pData = __FindActive(dwPID);

	if (!pData)
		return;

	// Client's breakdown dicts are always empty right after a fresh login (the
	// FarmSessionWindow object is recreated from scratch) - resend everything
	// accumulated so far, not just the aggregate totals, so a resumed session's
	// list view isn't missing entries from before the disconnect.
	__SendState(ch, *pData);
	__SendAllEntries(ch, *pData);
}

void CFarmSessionManager::TransferOut(LPCHARACTER ch, long lDestAddr, WORD wDestPort)
{
	if (!ch || !ch->IsPC())
		return;

	// CHARACTER::WarpSet() sends a "reconnect to (addr,port)" instruction to
	// the client for EVERY warp, even ones that land back on this very same
	// process (this codebase doesn't special-case local moves at that layer).
	// Only actually hand the session off when the destination is genuinely a
	// different process - otherwise leave it alone, since the character is
	// just coming straight back to this process's own OnEnterGame.
	if (lDestAddr == (long)inet_addr(g_szPublicIP) && wDestPort == mother_port)
		return;

	DWORD dwPID = ch->GetPlayerID();

	std::map<DWORD, SFarmSessionData>::iterator it = m_map_kSession.find(dwPID);

	if (it == m_map_kSession.end() || !it->second.isActive)
		return;

	const SFarmSessionData & data = it->second;

	TPacketGGFarmSessionState pack;
	pack.header			= HEADER_GG_FARM_SESSION_STATE;
	pack.dwPID			= dwPID;
	pack.isActive			= 1;
	pack.dwElapsedSec		= (get_dword_time() - data.dwStartTime) / 1000;
	pack.dwKillCountTotal		= data.dwKillCountTotal;
	pack.dwStoneKillTotal		= data.dwStoneKillTotal;
	pack.dwBossKillTotal		= data.dwBossKillTotal;
	pack.dwNormalKillTotal		= data.dwNormalKillTotal;
	pack.dwItemCountTotal		= data.dwItemCountTotal;
	pack.lYangGained		= data.lYangGained;
	pack.lYangSpent			= data.lYangSpent;

	P2P_MANAGER::instance().Send(&pack, sizeof(pack));

	for (std::map<DWORD, DWORD>::const_iterator kill_it = data.killsByType.begin(); kill_it != data.killsByType.end(); ++kill_it)
	{
		TPacketGGFarmSessionKillEntry entryPack;
		entryPack.header	= HEADER_GG_FARM_SESSION_KILL_ENTRY;
		entryPack.dwPID		= dwPID;
		entryPack.dwMobVnum	= kill_it->first;
		entryPack.dwCount	= kill_it->second;
		P2P_MANAGER::instance().Send(&entryPack, sizeof(entryPack));
	}

	for (std::map<DWORD, DWORD>::const_iterator item_it = data.itemsByType.begin(); item_it != data.itemsByType.end(); ++item_it)
	{
		TPacketGGFarmSessionItemEntry entryPack;
		entryPack.header	= HEADER_GG_FARM_SESSION_ITEM_ENTRY;
		entryPack.dwPID		= dwPID;
		entryPack.dwItemVnum	= item_it->first;
		entryPack.dwCount	= item_it->second;
		P2P_MANAGER::instance().Send(&entryPack, sizeof(entryPack));
	}

	// The session now belongs to whichever process the player is warping to -
	// drop the local copy so a later return trip to this process doesn't find
	// a stale entry that missed everything tracked while they were away.
	m_map_kSession.erase(it);
}

void CFarmSessionManager::TransferInState(DWORD dwPID, bool isActive, DWORD dwElapsedSec, DWORD dwKillCountTotal, DWORD dwStoneKillTotal, DWORD dwBossKillTotal, DWORD dwNormalKillTotal, DWORD dwItemCountTotal, int64_t lYangGained, int64_t lYangSpent)
{
	SFarmSessionData data;
	data.isActive			= isActive;
	// Each process's get_dword_time() is its own clock - reconstruct a start
	// time relative to THIS process's clock from the elapsed seconds the
	// origin process measured, rather than trusting a raw timestamp across
	// processes.
	data.dwStartTime		= get_dword_time() - dwElapsedSec * 1000;
	data.dwKillCountTotal		= dwKillCountTotal;
	data.dwStoneKillTotal		= dwStoneKillTotal;
	data.dwBossKillTotal		= dwBossKillTotal;
	data.dwNormalKillTotal		= dwNormalKillTotal;
	data.dwItemCountTotal		= dwItemCountTotal;
	data.lYangGained		= lYangGained;
	data.lYangSpent			= lYangSpent;

	LPCHARACTER ch = CHARACTER_MANAGER::instance().FindByPID(dwPID);

	if (ch && ch->GetDesc())
		m_map_kSession[dwPID] = data;
	else
		m_map_kStaged[dwPID] = data;
}

void CFarmSessionManager::TransferInKillEntry(DWORD dwPID, DWORD dwMobVnum, DWORD dwCount)
{
	std::map<DWORD, SFarmSessionData>::iterator it = m_map_kSession.find(dwPID);
	if (it != m_map_kSession.end())
	{
		it->second.killsByType[dwMobVnum] = dwCount;
		return;
	}

	it = m_map_kStaged.find(dwPID);
	if (it != m_map_kStaged.end())
		it->second.killsByType[dwMobVnum] = dwCount;
}

void CFarmSessionManager::TransferInItemEntry(DWORD dwPID, DWORD dwItemVnum, DWORD dwCount)
{
	std::map<DWORD, SFarmSessionData>::iterator it = m_map_kSession.find(dwPID);
	if (it != m_map_kSession.end())
	{
		it->second.itemsByType[dwItemVnum] = dwCount;
		return;
	}

	it = m_map_kStaged.find(dwPID);
	if (it != m_map_kStaged.end())
		it->second.itemsByType[dwItemVnum] = dwCount;
}

#endif
