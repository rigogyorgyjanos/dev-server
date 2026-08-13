#include "stdafx.h"
#ifdef ENABLE_OFFLINESHOP_SYSTEM
#include "../../libgame/include/grid.h"
#include "constants.h"
#include "utils.h"
#include "config.h"
#include "offline_shop.h"
#include "desc.h"
#include "desc_manager.h"
#include "char.h"
#include "char_manager.h"
#include "item.h"
#include "item_manager.h"
#include "buffer_manager.h"
#include "packet.h"
#include "db.h"
#include "questmanager.h"
#include "mob_manager.h"
#include "locale_service.h"
#include "desc_client.h"
#include "group_text_parse_tree.h"
#include <cctype>
#include "offlineshop_manager.h"
#include "p2p.h"
#include "entity.h"
#include "sectree_manager.h"
#include "target.h"

#include "desc.h"
#include "desc_manager.h"
#include "desc_client.h"
#include "../../common/PulseManager.h"

// Minimal guard against breaking out of the surrounding single-quoted SQL literal
// (sign/title strings get interpolated directly into UPDATE/INSERT statements on the DB side).
static bool getInjectText(const char* str)
{
	if (!str)
		return false;
	return strchr(str, '\'') != NULL || strchr(str, '"') != NULL || strchr(str, '\\') != NULL || strchr(str, ';') != NULL;
}

COfflineShopManager::COfflineShopManager(){}
COfflineShopManager::~COfflineShopManager()
{
	if (m_pShopTimeEvent)
		event_cancel(&m_pShopTimeEvent);
	m_pShopTimeEvent = NULL;

#ifdef ENABLE_SHOP_SEARCH_SYSTEM
	for (auto it = m_itemMap.begin(); it != m_itemMap.end(); it++)
		M2_DELETE(it->second);
	m_itemMap.clear();
#endif

	for (auto it = m_Map_pkOfflineShopByNPC.begin(); it != m_Map_pkOfflineShopByNPC.end(); it++)
		M2_DELETE(it->second);
	m_Map_pkOfflineShopByNPC.clear();
}


EVENTINFO(TShopTimeEventInfo)
{
	DWORD	data;
	TShopTimeEventInfo(): data(0){}
};

EVENTFUNC(shop_time_event)
{
	if (!event)
		return 0;
	COfflineShopManager& shopMngr = COfflineShopManager::Instance();
	for (DWORD j = 0; j < shopMngr.m_Map_pkShopTimes.size(); ++j)
	{
		LPOFFLINESHOP pkOfflineShop = shopMngr.FindOfflineShopPID(shopMngr.m_Map_pkShopTimes[j]);
		if (pkOfflineShop && pkOfflineShop->IsClosed())
		{
			shopMngr.CloseOfflineShopForTime(pkOfflineShop);
			continue;
		}
	}
	return PASSES_PER_SEC(5);
}

/*void COfflineShopManager::CompareOffShopEventTime()
{
	
	if (!m_pShopTimeEvent)
		return;
	const int eventNextRun = event_time(m_pShopTimeEvent);
	long lowerTime = eventNextRun;
	for (DWORD j = 0; j < m_Map_pkShopTimes.size(); ++j)
	{
		LPOFFLINESHOP pkOfflineShop = FindOfflineShopPID(m_Map_pkShopTimes[j]);
		if (!pkOfflineShop)
			continue;
		const int shopTime = (pkOfflineShop->m_data.time - time(0));
		if (shopTime < lowerTime)
			lowerTime = shopTime;
	}
	if (lowerTime < 0)
		lowerTime = 0;
	event_reset_time(m_pShopTimeEvent, PASSES_PER_SEC(lowerTime));
	
}*/

BYTE COfflineShopManager::GetItemPos(DWORD ownerID, DWORD itemID)
{
	LPOFFLINESHOP pkOfflineShop = FindOfflineShopPID(ownerID);
	if (pkOfflineShop)
	{
		for (BYTE j = 0; j < OFFLINE_SHOP_HOST_ITEM_MAX_NUM; ++j)
			if (pkOfflineShop->m_data.items[j].id == itemID)
				return j;
	}
	return OFFLINE_SHOP_HOST_ITEM_MAX_NUM;
}

LPOFFLINESHOP COfflineShopManager::FindOfflineShopPID(DWORD pid)
{
	const auto it = m_Map_pkOfflineShopByNPC.find(pid);
	return it != m_Map_pkOfflineShopByNPC.end() ? it->second : NULL;
}

void COfflineShopManager::CreateOfflineShop(TOfflineShop* offlineshop)
{
	if (!offlineshop)
		return;

	if (FindOfflineShopPID(offlineshop->owner_id) != NULL) {
		sys_err("COfflineShopManager::CreateOfflineShop: duplicate create offlineshop! owner_id=%d", offlineshop->owner_id);
		return;
	}

	LPOFFLINESHOP pkOfflineShop = M2_NEW COfflineShop;
	thecore_memcpy(&pkOfflineShop->m_data, offlineshop, sizeof(TOfflineShop));

	// This runs on EVERY game core (the DB fans out CREATE_OFFLINESHOP to all
	// connected cores unconditionally, see SendOfflineShopOnSetup/ForwardPacket
	// on the db side) - the channel check below only decides whether THIS core
	// also spawns the live, visible NPC mob. The search index insert further down
	// is intentionally NOT gated by channel, so shop search is global by
	// construction: every core ends up with every shop's items in m_itemMap.
	LPCHARACTER npc = (g_bChannel == offlineshop->channel && !pkOfflineShop->IsClosed()) ? CHARACTER_MANAGER::instance().SpawnMob(offlineshop->type, offlineshop->mapindex, offlineshop->x, offlineshop->y, offlineshop->z, false, -1, false) : NULL;
#ifdef ENABLE_SHOP_SEARCH_SYSTEM
	if (!pkOfflineShop->IsClosed())
		for (DWORD i = 0; i < OFFLINE_SHOP_HOST_ITEM_MAX_NUM; ++i)
			InsertItem(&pkOfflineShop->m_data.items[i]);
#endif

	if (npc)
	{
		pkOfflineShop->SetOfflineShopNPC(npc);

		m_Map_pkShopTimes.push_back(offlineshop->owner_id);

		if (!m_pShopTimeEvent)
		{
			TShopTimeEventInfo* info = AllocEventInfo<TShopTimeEventInfo>();
			m_pShopTimeEvent = event_create(shop_time_event, info, PASSES_PER_SEC(5));
		}

		npc->SetOfflineShop(pkOfflineShop);
		npc->SetName(offlineshop->owner_name);
		npc->Show(offlineshop->mapindex, offlineshop->x, offlineshop->y, offlineshop->z, true);
		npc->ViewReencode();
	}

	m_Map_pkOfflineShopByNPC.emplace(offlineshop->owner_id, pkOfflineShop);
	m_Map_pkOfflineShopByName.emplace(offlineshop->owner_name, pkOfflineShop);

	LPCHARACTER ownerCh = CHARACTER_MANAGER::Instance().FindByPID(offlineshop->owner_id);
	HasOfflineShop(ownerCh);

	// If the owner is online right now, open their owner-view panel immediately
	// instead of waiting for them to click their own NPC.
	if (ownerCh && npc)
		pkOfflineShop->AddGuest(ownerCh, npc);

	sys_log(0, "shop insert: owner_id %d owner_name %s sign %s x %ld y %ld mapIndex %d channel %d item_count %d", offlineshop->owner_id, offlineshop->owner_name, offlineshop->sign, offlineshop->x, offlineshop->y, offlineshop->mapindex, offlineshop->channel, pkOfflineShop->GetItemCount());
}

void COfflineShopManager::OpenOfflineShop(LPCHARACTER ch)
{
	if (!ch)
		return;
	if (ch->CanOpenShopPanel())
		return;

	/*auto it = std::find(m_Map_pkOfflineShopCache.begin(), m_Map_pkOfflineShopCache.end(), ch->GetPlayerID());
	if (it != m_Map_pkOfflineShopCache.end())
	{
		ch->ChatPacket(CHAT_TYPE_COMMAND, "OpenBackAllItem");
		return;
	}*/

	if (!HasOfflineShop(ch))
	{
		ch->SetOfflineShopPanel(true);
		char cmd[256];
		snprintf(cmd, sizeof(cmd), "OfflineShopSetFlag %lld", ch->GetOfflineShopFlag());
		ch->ChatPacket(CHAT_TYPE_COMMAND,cmd);
		return;
	}

	LPOFFLINESHOP pkOfflineShop = FindOfflineShopPID(ch->GetPlayerID());
	if (!pkOfflineShop)
		return;
	// GetOfflineShopNPC() is NULL whenever this core isn't the one hosting the
	// shop's live NPC - AddGuest() tolerates that by design, so the owner can
	// manage their shop from any channel/core, not just the one it physically
	// stands on.
	pkOfflineShop->AddGuest(ch, pkOfflineShop->GetOfflineShopNPC());
	sys_log(0, "COfflineShopManager::OpenOfflineShop owner open offlineshop panel: %s:%d", ch->GetName(), ch->GetPlayerID());
}

void COfflineShopManager::DestroyOfflineShopReal(DWORD ch)
{
	auto it = m_Map_pkOfflineShopByNPC.find(ch);
	if (it == m_Map_pkOfflineShopByNPC.end())
		return;

	LPOFFLINESHOP pkOfflineShop = it->second;
	if (!pkOfflineShop)
		return;

	auto it2 = std::find(m_Map_pkOfflineShopCache.begin(), m_Map_pkOfflineShopCache.end(), ch);
	if (it2 != m_Map_pkOfflineShopCache.end())
		m_Map_pkOfflineShopCache.erase(it2);

	if (m_Map_pkOfflineShopByName.find(pkOfflineShop->m_data.owner_name) != m_Map_pkOfflineShopByName.end())
		m_Map_pkOfflineShopByName.erase(pkOfflineShop->m_data.owner_name);

	// Tell everyone currently showing this NPC's floating sign to drop it before the NPC
	// itself is destroyed below - mirrors CHARACTER::CloseMyShop()'s empty-sign packet.
	LPCHARACTER npc = pkOfflineShop->GetOfflineShopNPC();
	if (npc)
	{
		TPacketGCShopSign p;
		p.bHeader = HEADER_GC_SHOP_SIGN;
		p.dwVID = npc->GetVID();
		p.szSign[0] = '\0';
		npc->PacketAround(&p, sizeof(TPacketGCShopSign));
	}

	pkOfflineShop->Destroy();
	M2_DELETE(pkOfflineShop);
	m_Map_pkOfflineShopByNPC.erase(ch);

	HasOfflineShop(CHARACTER_MANAGER::Instance().FindByPID(ch));
}

void COfflineShopManager::DestroyOfflineShop(LPCHARACTER ch)
{
	if (!ch)
		return;
	if (ch->CanDestroyShop())
		return;
	LPOFFLINESHOP pkOfflineShop = FindOfflineShopPID(ch->GetPlayerID());
	if (!pkOfflineShop)
	{
		ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("OFFLINE_SHOP_CANT_FIND"));
		return;
	}
	else if (pkOfflineShop->GetItemCount() > 0)
	{
		ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("OFFLINE_SHOP_CANT_CLOSE_SHOP"));
		return;
	}

	shop_owner n;
	n.subheader = DESTROY_OFFLINESHOP;
	n.owner_id = ch->GetPlayerID();
	db_clientdesc->DBPacket(HEADER_GD_OFFLINESHOP, 0, &n, sizeof(shop_owner));
}

void COfflineShopManager::AddItemReal(OFFLINE_SHOP_ITEM* item)
{
	if (!item) {
		sys_err("COfflineShopManager::AddItemReal item data is null!!!!!!!!!");
		return;
	}

	LPOFFLINESHOP pkOfflineShop = FindOfflineShopPID(item->owner_id);
	if (!pkOfflineShop)
		return;

	thecore_memcpy(&pkOfflineShop->m_data.items[item->pos], item, sizeof(OFFLINE_SHOP_ITEM));
#ifdef ENABLE_SHOP_SEARCH_SYSTEM
	InsertItem(&pkOfflineShop->m_data.items[item->pos]);
#endif
	pkOfflineShop->BroadcastUpdateItem(item->pos);
}

void COfflineShopManager::AddItem(LPCHARACTER ch, BYTE bDisplayPos, TItemPos bPos, long long iPrice)
{
	if (!ch || bDisplayPos >= OFFLINE_SHOP_HOST_ITEM_MAX_NUM)
		return;

	if (bDisplayPos >= 40)
	{
		BYTE cell = bDisplayPos - 40;
		if (!IS_SET(ch->GetOfflineShopFlag(), 1ULL<<cell))
			return;
	}

	LPITEM pkItem = ch->GetItem(bPos);
	if (!pkItem)
		return;

	if (ch->IsDead())
	{
		ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("OFFLINE_SHOP_CANT_ADD_ITEM %s"),pkItem->GetName());
		return;
	}

	if (!ch->CheckPremiumStateMap())
	{
		ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("You need to be in the same map or to have the Extended Market activated in order to add the item."));
		return;
	}

	else if (pkItem->isLocked())
	{
		ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("OFFLINE_SHOP_CANT_ADD_ITEM %s"),pkItem->GetName());
		return;
	}
	else if (pkItem->IsEquipped())
	{
		ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("OFFLINE_SHOP_CANT_ADD_ITEM %s"),pkItem->GetName());
		return;
	}
	else if (pkItem->IsExchanging())
	{
		ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("OFFLINE_SHOP_CANT_ADD_ITEM %s"),pkItem->GetName());
		return;
	}
	else if (ch->PreventTradeWindow(WND_MYSHOP | WND_SHOPOWNER, true))
	{
		ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("You need to close other windows."));
		return;
	}

	if ((pkItem->GetVnum() >= 51010 && pkItem->GetVnum() <= 51030) && pkItem->GetSocket(0) == 1)
	{
		ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("Deactivate the Energy Crystal first."));
		return;
	}

	const TItemTable * itemTable = pkItem->GetProto();
	if (itemTable && IS_SET(itemTable->dwAntiFlags, ITEM_ANTIFLAG_GIVE | ITEM_ANTIFLAG_MYSHOP) || pkItem->GetSocket(4) == 99)
		return;
	
	LPOFFLINESHOP pkOfflineShop = FindOfflineShopPID(ch->GetPlayerID());
	if (!pkOfflineShop)
	{
		ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("OFFLINE_SHOP_CANT_FIND"));
		return;
	}

	if (pkOfflineShop->IsClosed())
	{
		ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("OFFLINE_SHOP_CANT_ADD_ITEM %s"), pkItem->GetName());
		return;
	}

	// bSize-aware occupancy check: some weapon/armor icons visually span multiple
	// grid rows below their own position (item_proto bSize - same mechanism the
	// main inventory/warehouse/PC-shop grids already use via CGrid). Without this,
	// bDisplayPos was accepted unconditionally, so a big item could be dropped onto
	// a cell already covered by a neighboring item's footprint (or onto an already-
	// occupied cell at all), producing overlapping icons in the client grid.
	{
		CGrid shopGrid(10, 8);
		const auto& itemSlots = pkOfflineShop->m_data.items;
		const auto& playerFlag = ch->GetOfflineShopFlag();
		for (BYTE j = 0; j < OFFLINE_SHOP_HOST_ITEM_MAX_NUM; ++j)
		{
			if (itemSlots[j].vnum != 0)
			{
				TItemTable* tableItem = ITEM_MANAGER::instance().GetTable(itemSlots[j].vnum);
				if (tableItem)
					shopGrid.Put(j, 1, tableItem->bSize);
				continue;
			}
			if (j >= 40)
			{
				const BYTE cell = j - 40;
				if (!IS_SET(playerFlag, 1ULL << cell))
					shopGrid.Put(j, 1, 1);
			}
		}

		if (!shopGrid.IsEmpty(bDisplayPos, 1, pkItem->GetSize()))
		{
			ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("This item doesn't fit there."));
			return;
		}
	}

	OFFLINE_SHOP_ITEM item;
	item.vnum = pkItem->GetVnum();
	item.id = pkItem->GetID();
	item.owner_id = ch->GetPlayerID();
	item.pos = bDisplayPos;
	item.count = pkItem->GetCount();
	item.price = iPrice;
	item.status = 0;
	thecore_memcpy(item.alSockets, pkItem->GetSockets(), sizeof(item.alSockets));
	thecore_memcpy(item.aAttr, pkItem->GetAttributes(), sizeof(item.aAttr));

	strlcpy(item.szOwnerName, ch->GetName(), sizeof(item.szOwnerName));
	pkItem->RemoveFromCharacter();
	ITEM_MANAGER::instance().SaveSingleItem(pkItem);

	shop_item n;
	n.subheader = ADD_ITEM;
	thecore_memcpy(&n.item, &item, sizeof(n.item));
	db_clientdesc->DBPacket(HEADER_GD_OFFLINESHOP, 0, &n, sizeof(shop_item));
}

void COfflineShopManager::RemoveItemReal(OFFLINE_SHOP_ITEM* item)
{
	if (!item)
		return;

	LPOFFLINESHOP pkOfflineShop = FindOfflineShopPID(item->owner_id);
	if (!pkOfflineShop)
		return;

#ifdef ENABLE_SHOP_SEARCH_SYSTEM
	ClearItem(pkOfflineShop->m_data.items[item->pos].id);
#endif

	memset(&pkOfflineShop->m_data.items[item->pos], 0, sizeof(OFFLINE_SHOP_ITEM));
	pkOfflineShop->BroadcastUpdateItem(item->pos, true);
	
	if (IsRealTimeItem(item))
		return;

	if (item->status == 0)
	{
		LPCHARACTER ch = CHARACTER_MANAGER::Instance().FindByPID(item->owner_id);
		if (ch != NULL)
		{
			LPITEM pItem = ch->AutoGiveItem(item->vnum, item->count,0,true);
			if (pItem)
			{
				pItem->SetAttributes(item->aAttr);
				pItem->SetSockets(item->alSockets);

				pItem->UpdatePacket();
			}
		}
	}
}
void COfflineShopManager::ChangePriceReal(DWORD ownerID, BYTE bPos, long long itemPrice)
{
	LPOFFLINESHOP pkOfflineShop = FindOfflineShopPID(ownerID);
	if (!pkOfflineShop)
		return;

	pkOfflineShop->m_data.items[bPos].price = itemPrice;

#ifdef ENABLE_SHOP_SEARCH_SYSTEM
	ClearItem(pkOfflineShop->m_data.items[bPos].id);
	InsertItem(&pkOfflineShop->m_data.items[bPos]);
#endif
	pkOfflineShop->BroadcastUpdateItem(bPos);
}
void COfflineShopManager::ChangePrice(LPCHARACTER ch, BYTE bPos, DWORD itemID, long long itemPrice, BYTE bAllItem)
{
	if (!ch || bPos >= OFFLINE_SHOP_HOST_ITEM_MAX_NUM || itemPrice <= 0)
		return;

	if (ch->CanChangePriceShop())
		return;

	LPOFFLINESHOP pkOfflineShop = FindOfflineShopPID(ch->GetPlayerID());
	if (!pkOfflineShop)
	{
		ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("OFFLINE_SHOP_CANT_FIND"));
		return;
	}

	if (pkOfflineShop->IsClosed())
	{
		ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("Reactivate your shop first."));
		return;
	}

	if (pkOfflineShop->m_data.items[bPos].vnum == 0 || pkOfflineShop->m_data.items[bPos].id != itemID)
	{
		bPos = GetItemPos(ch->GetPlayerID(), itemID);
		if (bPos >= OFFLINE_SHOP_HOST_ITEM_MAX_NUM)
			return;
		if (pkOfflineShop->m_data.items[bPos].vnum == 0)
			return;
	}

	change_price n;
	n.subheader = CHANGE_PRICE;
	n.ownerID = ch->GetPlayerID();
	n.bPos = bPos;
	n.itemPrice = itemPrice;
	db_clientdesc->DBPacket(HEADER_GD_OFFLINESHOP, 0, &n, sizeof(change_price));

	if (bAllItem)
	{
		const DWORD itemIdx = pkOfflineShop->m_data.items[bPos].vnum;
		const long long unitPrice = itemPrice / pkOfflineShop->m_data.items[bPos].count;
		for (BYTE j = 0; j < OFFLINE_SHOP_HOST_ITEM_MAX_NUM; ++j)
		{
			if (pkOfflineShop->m_data.items[j].vnum == itemIdx && pkOfflineShop->m_data.items[j].id != itemID)
			{
				n.bPos = j;
				n.itemPrice = unitPrice * pkOfflineShop->m_data.items[j].count;
				db_clientdesc->DBPacket(HEADER_GD_OFFLINESHOP, 0, &n, sizeof(change_price));
			}
		}
	}
}

void COfflineShopManager::RemoveItem(LPCHARACTER ch, BYTE bPos, DWORD itemID, BYTE bTakeAll)
{
	if (!ch || bPos >= OFFLINE_SHOP_HOST_ITEM_MAX_NUM)
		return;
	
	if (ch->CanRemoveItemShop())
		return;
	
	LPOFFLINESHOP pkOfflineShop = FindOfflineShopPID(ch->GetPlayerID());
	if (!pkOfflineShop)
	{
		ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("OFFLINE_SHOP_CANT_FIND"));
		return;
	}
	
	DWORD itemVnum = pkOfflineShop->m_data.items[bPos].vnum;
	if (itemVnum == 0 || pkOfflineShop->m_data.items[bPos].id != itemID)
	{
		bPos = GetItemPos(ch->GetPlayerID(), itemID);
		if (bPos >= OFFLINE_SHOP_HOST_ITEM_MAX_NUM)
			return;
		itemVnum = pkOfflineShop->m_data.items[bPos].vnum;
		if (itemVnum == 0)
			return;
	}

	LPITEM item = ITEM_MANAGER::Instance().CreateItem(itemVnum);
	if (!item)
		return;
	const int iEmptyCell = ch->GetEmptyInventory(item->GetSize());
	M2_DESTROY_ITEM(item);
	if(iEmptyCell == -1)
	{
		ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("You don't has enought space in inventory."));
		return;
	}
	
	shop_item n;
	n.subheader = REMOVE_ITEM;
	thecore_memcpy(&n.item, &pkOfflineShop->m_data.items[bPos], sizeof(n.item));
	db_clientdesc->DBPacket(HEADER_GD_OFFLINESHOP, 0, &n, sizeof(shop_item));
	
	if (bTakeAll)
	{
		for (BYTE j = 0; j < OFFLINE_SHOP_HOST_ITEM_MAX_NUM; ++j)
		{
			if (pkOfflineShop->m_data.items[j].vnum == itemVnum && bPos != j)
			{
				thecore_memcpy(&n.item, &pkOfflineShop->m_data.items[j], sizeof(n.item));
				db_clientdesc->DBPacket(HEADER_GD_OFFLINESHOP, 0, &n, sizeof(shop_item));
			}
		}
	}
}

void COfflineShopManager::StopShopping(LPCHARACTER ch)
{
	if(!ch)
		return;

	// These two are independent, not mutually exclusive: a stale OfflineShopPanel flag
	// (left over from a cancelled/completed creation flow) must never block clearing an
	// active GetOfflineShop() guest/owner link, or the character gets stuck permanently
	// "inside" their shop and every future AddGuest() call is silently rejected.
	if (ch->GetOfflineShopPanel())
		ch->SetOfflineShopPanel(false);

	LPOFFLINESHOP pkOfflineShop = ch->GetOfflineShop();
	if (pkOfflineShop)
		pkOfflineShop->RemoveGuest(ch);
}

void SendReturnPacket(LPCHARACTER ch, BYTE ret)
{
	if (ch)
	{
		TPacketGCShop pack;
		pack.header = HEADER_GC_OFFLINE_SHOP;
		pack.subheader = ret;
		pack.size = sizeof(TPacketGCShop);
		ch->GetDesc()->Packet(&pack, sizeof(pack));
	}
}

void COfflineShopManager::BuyItemReal(TOfflineShopBuy* item)
{
	LPOFFLINESHOP pkOfflineShop = FindOfflineShopPID(item->item.owner_id);
	if (!pkOfflineShop)
		return;

	for (DWORD j = 0; j < OFFLINE_SHOP_HOST_ITEM_MAX_NUM; ++j)
	{
		if (pkOfflineShop->m_data.items[j].vnum != 0)
		{
			if(item->item.pos != j && item->item.id == pkOfflineShop->m_data.items[j].id)
				memset(&pkOfflineShop->m_data.items[j], 0, sizeof(pkOfflineShop->m_data.items[j]));
		}
	}

	// Always fully clear the sold slot - see the matching fix/comment in
	// CClientManager::BuyItem (db-src) for why the old AFTER_BUY_REMOVE_DIRECTLY
	// toggle never actually cleared anything (that macro is never #define'd, so
	// this always ran the #else branch, which - before that DB fix - restored the
	// just-sold item right back into the slot verbatim).
	memset(&pkOfflineShop->m_data.items[item->item.pos], 0, sizeof(pkOfflineShop->m_data.items[item->item.pos]));

	const long long calculateFeePrice = (100 - SHOP_FEE) * (item->item.price / 100);

	pkOfflineShop->m_data.price += calculateFeePrice;

	// BuyItemReal runs on every game core (BUY_ITEM's DB reply is fanned out to all
	// connected cores unconditionally, same as CREATE_OFFLINESHOP), so updating the
	// average here - keyed off the actual realized sale price, not the asking price
	// - keeps every core's market-average figure identical for free, with no extra
	// network code.
	SetAveragePrice(item->item.vnum, item->item.price / (item->item.count ? item->item.count : 1));

	LPCHARACTER owner_ch = CHARACTER_MANAGER::Instance().FindByPID(item->item.owner_id);
	if (owner_ch)
	{
		owner_ch->SetOfflineShopRefresh(false);
		owner_ch->ChatPacket(CHAT_TYPE_COMMAND, "AddSellNotification %u %d %lld", item->item.vnum, item->item.count, item->item.price);
	}

	if (item->log_index >= 0 && item->log_index < OFFLINE_SHOP_HOST_ITEM_MAX_NUM)
		thecore_memcpy(&pkOfflineShop->m_data.log[item->log_index], &item->log, sizeof(pkOfflineShop->m_data.log[item->log_index]));

	pkOfflineShop->BroadcastUpdateItem(item->item.pos,false, item->log_index);
#ifdef ENABLE_SHOP_SEARCH_SYSTEM
	ClearItem(item->item.id);
#endif

	LPCHARACTER ch = CHARACTER_MANAGER::Instance().FindByPID(item->customer_id);
	if (ch != NULL)
	{
		if (ch->GetGold() < item->item.price)
			return;
		ch->PointChange(POINT_GOLD, -item->item.price);
		LPITEM pItem = ch->AutoGiveItem(item->item.vnum, item->item.count, 0, true);
		if (pItem != NULL)
		{
			pItem->SetAttributes(item->item.aAttr);
			pItem->SetSockets(item->item.alSockets);

			pItem->UpdatePacket();
			SendReturnPacket(ch, SHOP_SUBHEADER_GC_OK);
		}
	}
}

void COfflineShopManager::Buy(LPCHARACTER ch, DWORD vid, BYTE pos, DWORD itemID)
{
	if(!ch)
		return;

	LPOFFLINESHOP pkOfflineShop = FindOfflineShopPID(vid);
	if (!pkOfflineShop)
	{
		ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("OFFLINE_SHOP_CANT_FIND"));
		return;
	}
	else if (pkOfflineShop->IsClosed())
	{
		ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("You can't do that!"));
		return;
	}
	else if (pkOfflineShop->m_data.slotflag & SHOP_LOCKED_FLAG)
	{
		ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("This shop is currently locked."));
		return;
	}

	else if (ch->PreventTradeWindow(WND_MYSHOP | WND_SHOPOWNER, true))
	{
		ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("You need to close other windows."));
		return;
	}

	OFFLINE_SHOP_ITEM& item = pkOfflineShop->m_data.items[pos];

	if (item.vnum == 0 || item.id != itemID)
	{
		pos = GetItemPos(vid, itemID);
		if (pos >= OFFLINE_SHOP_HOST_ITEM_MAX_NUM)
			return;
		item = pkOfflineShop->m_data.items[pos];
		if (item.vnum == 0)
			return;
	}

	if (item.owner_id == ch->GetPlayerID())
		return;
	else if (item.status != 0){
		SendReturnPacket(ch, SHOP_SUBHEADER_GC_SOLD_OUT);
		return;
	}
	else if (ch->GetGold() < item.price) {
		SendReturnPacket(ch, SHOP_SUBHEADER_GC_NOT_ENOUGH_MONEY);
		return;
	}

	LPITEM checkItem = ITEM_MANAGER::Instance().CreateItem(item.vnum);
	const int iEmptyCell = ch->GetEmptyInventory(checkItem->GetSize());
	M2_DESTROY_ITEM(checkItem);
	if(iEmptyCell == -1)
	{
		ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("You don't has enought space in inventory."));
		return;
	}

	shop_buy n;
	n.subheader = BUY_ITEM;
	memset(&n.buyItem, 0, sizeof(TOfflineShopBuy));
	thecore_memcpy(&n.buyItem.item, &item, sizeof(OFFLINE_SHOP_ITEM));
	n.buyItem.customer_id = ch->GetPlayerID();
	strlcpy(n.buyItem.customer_name, ch->GetName(), sizeof(n.buyItem.customer_name));
	db_clientdesc->DBPacket(HEADER_GD_OFFLINESHOP, 0, &n, sizeof(shop_buy));
}

bool COfflineShopManager::HasOfflineShop(LPCHARACTER ch)
{
	if (!ch)
		return false;
	const BYTE ptr = FindOfflineShopPID(ch->GetPlayerID()) ? 1 : 0;
	TPacketGCShop p;
	p.header = HEADER_GC_OFFLINE_SHOP;
	p.subheader = SHOP_SUBHEADER_GC_CHECK_RESULT;
	p.size = sizeof(p)+sizeof(BYTE);
	ch->GetDesc()->BufferedPacket(&p, sizeof(p));
	ch->GetDesc()->Packet(&ptr, sizeof(BYTE));
	return ptr;
}


void COfflineShopManager::ChangeTitleReal(TOfflineShopChangeTitle* p)
{
	if (!p)
		return;

	LPOFFLINESHOP pkOfflineShop = FindOfflineShopPID(p->owner_id);
	if (!pkOfflineShop)
		return;

	strlcpy(pkOfflineShop->m_data.sign, p->sign, sizeof(pkOfflineShop->m_data.sign));

	LPCHARACTER shop = pkOfflineShop->GetOfflineShopNPC();
	if (shop)
	{
		TPacketGCShopSign p;
		p.bHeader = HEADER_GC_SHOP_SIGN;
		p.dwVID = shop->GetVID();
		// m_data.sign is stored as "<titleType digit><actual sign text>" - skip the digit.
		const char* sign = pkOfflineShop->m_data.sign;
		strlcpy(p.szSign, sign[0] != '\0' ? sign + 1 : sign, sizeof(p.szSign));
		shop->PacketAround(&p, sizeof(TPacketGCShopSign));
	}

	TPacketGCShop pack;
	TEMP_BUFFER buf;
	pack.header = HEADER_GC_OFFLINE_SHOP;
	pack.subheader = SHOP_SUBHEADER_GC_CHANGE_TITLE;
	pack.size = sizeof(pack) + sizeof(pkOfflineShop->m_data.sign);
	buf.write(&pack, sizeof(pack));
	buf.write(&pkOfflineShop->m_data.sign, sizeof(pkOfflineShop->m_data.sign));
	pkOfflineShop->Broadcast(buf.read_peek(), buf.size());
}

void COfflineShopManager::ChangeTitle(LPCHARACTER ch, const char* title)
{
	if (!ch || getInjectText(title))
		return;	
	if (ch->CanChangeTitle())
		return;

	LPOFFLINESHOP pkOfflineShop = FindOfflineShopPID(ch->GetPlayerID());
	if (!pkOfflineShop)
	{
		ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("OFFLINE_SHOP_CANT_FIND"));
		return;
	}

	if (pkOfflineShop->IsClosed())
	{
		ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("You can't do that!"));
		return;
	}

	char sign[SHOP_SIGN_MAX_LEN + 1];
	snprintf(sign, sizeof(sign), "%c%s", pkOfflineShop->m_data.sign[0], title);

	shop_title n;
	n.subheader = CHANGE_TITLE;
	n.title.owner_id = ch->GetPlayerID();
	strlcpy(n.title.sign, sign, sizeof(n.title.sign));
	db_clientdesc->DBPacket(HEADER_GD_OFFLINESHOP, 0, &n, sizeof(shop_title));
}

void COfflineShopManager::WithdrawMoneyReal(DWORD ch)
{
	LPOFFLINESHOP pkOfflineShop = FindOfflineShopPID(ch);
	if (!pkOfflineShop)
		return;
	
	LPCHARACTER rch = CHARACTER_MANAGER::Instance().FindByPID(ch);
	if (rch != NULL && rch->GetOfflineShop())
	{
		rch->PointChange(POINT_GOLD, pkOfflineShop->m_data.price);
		long long price = 0;
		TPacketGCShop pack;
		TEMP_BUFFER buf;
		pack.header = HEADER_GC_OFFLINE_SHOP;
		pack.subheader = SHOP_SUBHEADER_GC_REFRESH_MONEY;
		pack.size = sizeof(pack) + sizeof(long long);
		buf.write(&pack, sizeof(pack));
		buf.write(&price, sizeof(long long));
		rch->GetDesc()->Packet(buf.read_peek(), buf.size());
	}
	pkOfflineShop->m_data.price = 0;
}

void COfflineShopManager::WithdrawMoney(LPCHARACTER ch)
{
	if (!ch)
		return;
	if (ch->CanWithdrawMoney())
		return;
	LPOFFLINESHOP pkOfflineShop = FindOfflineShopPID(ch->GetPlayerID());
	if (!pkOfflineShop)
	{
		ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("OFFLINE_SHOP_CANT_FIND"));
		return;
	}
	if (pkOfflineShop->m_data.price == 0)
		return;
	const long long nTotalMoney = static_cast<long long>(ch->GetGold()) + static_cast<long long>(pkOfflineShop->m_data.price);
	if (GOLD_MAX <= nTotalMoney)
	{
		ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("OFFLINE_SHOP_CANT_GET_MONEY"));
		return;
	}

	shop_owner n;
	n.subheader = WITHDRAW_MONEY;
	n.owner_id = ch->GetPlayerID();
	db_clientdesc->DBPacket(HEADER_GD_OFFLINESHOP, 0, &n, sizeof(shop_owner));
}

void COfflineShopManager::ShopLogRemove(LPCHARACTER ch)
{
	if (!ch)
		return;
	if (ch->CanRemoveLogShop())
		return;

	LPOFFLINESHOP pkOfflineShop = FindOfflineShopPID(ch->GetPlayerID());
	if (!pkOfflineShop)
	{
		ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("OFFLINE_SHOP_CANT_FIND"));
		return;
	}
	if (pkOfflineShop->m_data.log[0].itemVnum == 0)
		return;
	shop_owner n;
	n.subheader = CLEAR_LOG;
	n.owner_id = ch->GetPlayerID();
	db_clientdesc->DBPacket(HEADER_GD_OFFLINESHOP, 0, &n, sizeof(shop_owner));
}

void COfflineShopManager::ShopLogRemoveReal(DWORD ch)
{
	LPOFFLINESHOP pkOfflineShop = FindOfflineShopPID(ch);
	if (!pkOfflineShop)
		return;
	memset(&pkOfflineShop->m_data.log, 0, sizeof(pkOfflineShop->m_data.log));
	LPCHARACTER rch = CHARACTER_MANAGER::Instance().FindByPID(ch);
	if (rch != NULL && rch->GetOfflineShop())
		rch->ChatPacket(CHAT_TYPE_COMMAND, "ClearOfflineShopLog");
}

void COfflineShopManager::ChangeDecoration(LPCHARACTER ch, TShopDecoration* data)
{
	if (!ch || !data)
		return;
	if (ch->CanChangeDecoration())
		return;
	if (getInjectText(data->sign))
		return;

	LPOFFLINESHOP pkOfflineShop = FindOfflineShopPID(ch->GetPlayerID());
	if (!pkOfflineShop)
	{
		ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("OFFLINE_SHOP_CANT_FIND"));
		return;
	}

	if (pkOfflineShop->IsClosed())
	{
		ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("You can't do that!"));
		return;
	}

	if (data->vnum > 15 || data->type > 6)
		return;
	else if (data->vnum+30000 == pkOfflineShop->m_data.type && strstr(pkOfflineShop->m_data.sign, data->sign))
		return;
	data->owner_id = ch->GetPlayerID();
	shop_decoration n;
	n.subheader = CHANGE_DECORATION;
	thecore_memcpy(&n.decoration, data, sizeof(n.decoration));
	db_clientdesc->DBPacket(HEADER_GD_OFFLINESHOP, 0, &n, sizeof(shop_decoration));

}

void COfflineShopManager::ChangeDecorationReal(TShopDecoration* ch)
{
	LPOFFLINESHOP pkOfflineShop = FindOfflineShopPID(ch->owner_id);
	if (!pkOfflineShop)
		return;
	else if (pkOfflineShop->m_data.type == 30000 + ch->vnum && strstr(pkOfflineShop->m_data.sign, ch->sign))
		return;

	pkOfflineShop->m_data.type = 30000 + ch->vnum;
	strlcpy(pkOfflineShop->m_data.sign, ch->sign, sizeof(pkOfflineShop->m_data.sign));
	LPCHARACTER shop = pkOfflineShop->GetOfflineShopNPC();
	if (shop)
	{
		if (shop->GetRaceNum() == pkOfflineShop->m_data.type)
			shop->ViewReencode();
		else
		{
			M2_DESTROY_CHARACTER(shop);
			pkOfflineShop->SetOfflineShopNPC(NULL);
			shop = CHARACTER_MANAGER::instance().SpawnMob(pkOfflineShop->m_data.type, pkOfflineShop->m_data.mapindex, pkOfflineShop->m_data.x, pkOfflineShop->m_data.y, pkOfflineShop->m_data.z, false, -1, false);
			if (shop)
			{
				pkOfflineShop->SetOfflineShopNPC(shop);
				shop->SetOfflineShop(pkOfflineShop);
				shop->SetName(pkOfflineShop->m_data.owner_name);
				shop->Show(pkOfflineShop->m_data.mapindex, pkOfflineShop->m_data.x, pkOfflineShop->m_data.y, pkOfflineShop->m_data.z, true);
				shop->ViewReencode();
			}
		}

		// Decoration change also changes the sign text (above) - the respawn/ViewReencode
		// path only refreshes the model for people already watching, it doesn't touch the
		// floating sign board, so re-broadcast it explicitly (same as ChangeTitleReal()).
		if (shop)
		{
			TPacketGCShopSign p;
			p.bHeader = HEADER_GC_SHOP_SIGN;
			p.dwVID = shop->GetVID();
			const char* sign = pkOfflineShop->m_data.sign;
			strlcpy(p.szSign, sign[0] != '\0' ? sign + 1 : sign, sizeof(p.szSign));
			shop->PacketAround(&p, sizeof(TPacketGCShopSign));
		}
	}
	pkOfflineShop->BroadcastUpdateItem(0);
}


struct FuncSearchNearShops
{
	long m_lNewX;
	long m_lNewY;
	bool m_bResult;
	LPCHARACTER m_ch;
	FuncSearchNearShops(LPCHARACTER ch, long lNewX, long lNewY) { m_ch = ch; m_bResult = false; m_lNewX = lNewX; m_lNewY = lNewY; }
	void operator() (LPENTITY ent)
	{
		if (ent->IsType(ENTITY_CHARACTER))
		{
			LPCHARACTER ch = (LPCHARACTER)ent;
			if (ch && ch->IsOfflineShopNPC())
			{
				if (DISTANCE_APPROX(ch->GetX() - m_lNewX, ch->GetY() - m_lNewY) < 300)
					m_bResult = true;
			}
		}
	}
};


bool HasNearOfflineShop(LPCHARACTER ch, long newX, long newY)
{
	LPSECTREE pSec = ch->GetSectree();
	if (!pSec)
		return true;
	FuncSearchNearShops f(ch, newX, newY);
	pSec->ForEachAround(f);
	if (f.m_bResult == true)
		return true;
	return false;
}

void COfflineShopManager::OpenMyOfflineShop(LPCHARACTER ch, const char* c_pszSign, TOfflineShopItemTable* pTable, BYTE bItemCount, DWORD shopVnum, BYTE titleType)
{
	
	if (bItemCount == 0)
		return;

	if (ch->CanCreateShop())
		return;

	if (shopVnum >= 30001 || titleType >= 1)
	{
		if (!ch->FindAffect(AFFECT_DECORATION))
		{
			shopVnum = 30000;
			titleType = 0;
		}
	}

	char szSign[SHOP_SIGN_MAX_LEN + 1];
	snprintf(szSign, sizeof(szSign), "%d%s", titleType, c_pszSign);
	if (strlen(c_pszSign) == 0 || strstr(szSign, "%") || strstr(szSign, "'") || getInjectText(szSign))
		return;
	else if (HasNearOfflineShop(ch, ch->GetX(), ch->GetY()))
	{
		ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("OFFLINE_SHOP_CANT_CREATE_PLACE"));
		return;
	}
	
	std::set<TItemPos> cont;
	for (BYTE i = 0; i < bItemCount; ++i)
	{
		if (cont.find((pTable+i)->pos) != cont.end())
		{
			sys_err("MY_OFFLINE_SHOP: duplicate shop item detected! (name: %s)", ch->GetName());
			return;
		}
		LPITEM pkItem = ch->GetItem((pTable + i)->pos);

		if ((pTable + i)->display_pos >= 40)
		{
			BYTE cell = (pTable + i)->display_pos - 40;
			if (!IS_SET(ch->GetOfflineShopFlag(), 1ULL<<cell))
				return;
		}

		if (pkItem != NULL)
		{
			const TItemTable* item_table = pkItem->GetProto();
			if (!item_table)
				return;
			else if (item_table && (IS_SET(item_table->dwAntiFlags, ITEM_ANTIFLAG_GIVE | ITEM_ANTIFLAG_MYSHOP)) || pkItem->GetSocket(4) == 99)
			{
				//ch->ChatPacket(CHAT_TYPE_INFO, "You can't add this item %s!", pkItem->GetName());
				return;
			}
			else if (pkItem->IsEquipped() == true)
			{
				ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("You can't add your wearing item!"));
				return;
			}
			else if (true == pkItem->isLocked())
			{
				ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("You can't add lock item!"));
				return;
			}
			else if ((pkItem->GetVnum() >= 51010 && pkItem->GetVnum() <= 51030) && pkItem->GetSocket(0) == 1)
			{
				ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("Deactivate the Energy Crystal first."));
				return;
			}
			else if (true == pkItem->IsExchanging())
			{
				ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("You can't add exchanging item!"));
				return;
			}
			else if (ch->PreventTradeWindow(WND_ALL, false))
			{
				ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("You need to close other windows."));
				return;
			}
		}
	}

	// PointChange(POINT_GOLD, ...) never clamps at 0, so without this check a player
	// with less than the creation fee would go negative instead of creation failing.
	if (ch->GetGold() < 2000000)
	{
		ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("Not enough gold."));
		return;
	}

	// We're past every validation check and committed to creating the shop - clear the
	// "still in the pre-creation panel flow" flag now. Leaving it set here was a real bug:
	// it's only ever cleared inside StopShopping(), and the FIRST StopShopping() call after
	// a successful creation would wrongly take the "still in panel" branch and never reach
	// RemoveGuest()/SetOfflineShop(NULL) - permanently stranding the owner "inside" their own
	// shop server-side, so every later AddGuest() (i.e. every future F7 reopen) silently no-ops.
	ch->SetOfflineShopPanel(false);

	ch->PointChange(POINT_GOLD, -2000000);
	TOfflineShop m_data;
	m_data.owner_id = ch->GetPlayerID();
	strlcpy(m_data.owner_name, ch->GetName(), sizeof(m_data.owner_name));
	strlcpy(m_data.sign, szSign, sizeof(m_data.sign));
	m_data.x = ch->GetX();
	m_data.y = ch->GetY();
	m_data.z = ch->GetZ();
	m_data.mapindex = ch->GetMapIndex();
	m_data.type = shopVnum;
	m_data.channel = g_bChannel;
	m_data.slotflag = ch->GetOfflineShopFlag();
	if (ch->FindAffect(AFFECT_DECORATION))
		m_data.time = time(0) + SHOP_TIME_CREATE_PREMIUM;
	else 
		m_data.time = time(0) + SHOP_TIME_CREATE;

	memset(&m_data.items, 0, sizeof(OFFLINE_SHOP_ITEM) * OFFLINE_SHOP_HOST_ITEM_MAX_NUM);
	for (int i = 0; i < bItemCount; ++i)
	{
		LPITEM pkItem = ch->GetItem(pTable->pos);
		if (!pkItem)
			continue;
		if (!pkItem->GetVnum())
			continue;

		TItemTable* item_table = ITEM_MANAGER::instance().GetTable(pkItem->GetVnum());
		if (!item_table)
		{
			sys_err("OfflineShop: no item table by item vnum #%d", pkItem->GetVnum());
			continue;
		}

		OFFLINE_SHOP_ITEM& item = m_data.items[pTable->display_pos];
		item.vnum = pkItem->GetVnum();
		item.id = pkItem->GetID();
		item.owner_id = ch->GetPlayerID();
		item.pos = pTable->display_pos;
		item.count = pkItem->GetCount();
		item.price = pTable->price;
		item.status = 0;
		thecore_memcpy(item.alSockets, pkItem->GetSockets(), sizeof(item.alSockets));
		thecore_memcpy(item.aAttr, pkItem->GetAttributes(), sizeof(item.aAttr));
#ifdef ENABLE_CHANGELOOK_SYSTEM
		item.transmutation = pkItem->GetTransmutation();
#endif
#ifdef ENABLE_NEW_NAME_ITEM
		strlcpy(item.name, pkItem->GetNewName(),sizeof(item.name));
#endif
#ifdef ENABLE_PERMA_ITEM
		item.perma = pkItem->GetPerma();
#endif

		strlcpy(item.szOwnerName, ch->GetName(), sizeof(item.szOwnerName));
		strlcpy(item.szBuyerName, "NONAME", sizeof(item.szBuyerName));
		pkItem->RemoveFromCharacter();
		ITEM_MANAGER::instance().SaveSingleItem(pkItem);
		++pTable;
	}

	shop_create n;
	n.subheader = CREATE_OFFLINESHOP;
	thecore_memcpy(&n.offlineshop, &m_data, sizeof(n.offlineshop));
	db_clientdesc->DBPacket(HEADER_GD_OFFLINESHOP, 0, &n, sizeof(shop_create));
}

void COfflineShopManager::OpenSlotReal(TOfflineShopOpenSlot* ch)
{
	if (!ch)
		return;
	LPOFFLINESHOP pkOfflineShop = FindOfflineShopPID(ch->owner_id);
	if (!pkOfflineShop)
		return;
	pkOfflineShop->m_data.slotflag = ch->flag;
	pkOfflineShop->BroadcastUpdateItem(0);
}

void COfflineShopManager::OpenSlot(LPCHARACTER ch, BYTE bPos)
{
	if (!ch)
		return;
	unsigned long long myFlag = ch->GetOfflineShopFlag();
	unsigned long long flag = 1ULL << bPos;
	LPOFFLINESHOP pkOfflineShop = FindOfflineShopPID(ch->GetPlayerID());
	if (IS_SET(myFlag, flag))
		return;
	else if (ch->CountSpecifyItem(72319) < 2)
	{
		ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("OFFLINE_SHOP_CANT_SLOT_OPEN"));
		return;
	}

	if (pkOfflineShop)
	{
		SET_BIT(myFlag, flag);
		ch->SetOfflineShopFlag(myFlag);
		// if (myFlag == 1099511627775)
			// CHARACTER_MANAGER::Instance().SetRewardData(REWARD_OFFLINE_SLOT,ch->GetName(), true);		
		ch->RemoveSpecifyItem(72319, 2);

		shop_slot n;
		n.subheader = CHANGE_OPEN_SLOT;
		n.ch.owner_id = ch->GetPlayerID();
		n.ch.flag = myFlag;
		db_clientdesc->DBPacket(HEADER_GD_OFFLINESHOP, 0, &n, sizeof(shop_slot));
	}
	else if (ch->GetOfflineShopPanel())
	{
		ch->RemoveSpecifyItem(72319, 2);
		SET_BIT(myFlag, flag);
		ch->SetOfflineShopFlag(myFlag);
		// if (myFlag == 1099511627775)
			// CHARACTER_MANAGER::Instance().SetRewardData(REWARD_OFFLINE_SLOT,ch->GetName(), true);		

		char cmd[256];
		snprintf(cmd, sizeof(cmd), "OfflineShopSetFlag %lld", myFlag);
		ch->ChatPacket(CHAT_TYPE_COMMAND, cmd);
	}
	ch->Save();

}

// Same slot-unlock mechanism as OpenSlot(), but paid with gold instead of consuming
// item 72319 - an alternative funding path for players who'd rather spend yang.
void COfflineShopManager::ExpandSlot(LPCHARACTER ch, BYTE bPos)
{
	if (!ch)
		return;
	unsigned long long myFlag = ch->GetOfflineShopFlag();
	unsigned long long flag = 1ULL << bPos;
	LPOFFLINESHOP pkOfflineShop = FindOfflineShopPID(ch->GetPlayerID());
	if (IS_SET(myFlag, flag))
		return;
	else if (ch->GetGold() < SHOP_EXPAND_SLOT_PRICE)
	{
		ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("Not enough gold."));
		return;
	}

	if (pkOfflineShop)
	{
		SET_BIT(myFlag, flag);
		ch->SetOfflineShopFlag(myFlag);
		ch->PointChange(POINT_GOLD, -SHOP_EXPAND_SLOT_PRICE);

		shop_slot n;
		n.subheader = CHANGE_OPEN_SLOT;
		n.ch.owner_id = ch->GetPlayerID();
		n.ch.flag = myFlag;
		db_clientdesc->DBPacket(HEADER_GD_OFFLINESHOP, 0, &n, sizeof(shop_slot));
	}
	else if (ch->GetOfflineShopPanel())
	{
		ch->PointChange(POINT_GOLD, -SHOP_EXPAND_SLOT_PRICE);
		SET_BIT(myFlag, flag);
		ch->SetOfflineShopFlag(myFlag);

		char cmd[256];
		snprintf(cmd, sizeof(cmd), "OfflineShopSetFlag %lld", myFlag);
		ch->ChatPacket(CHAT_TYPE_COMMAND, cmd);
	}
	ch->Save();
}

// Toggles bit 63 of the owner's (persisted, DB-fanned-out) slot flag - see
// SHOP_LOCKED_FLAG in length.h. Reuses the exact same CHANGE_OPEN_SLOT DB round trip
// OpenSlot()/ExpandSlot() already use, since it's just another bit of the same field.
void COfflineShopManager::ToggleLock(LPCHARACTER ch)
{
	if (!ch)
		return;
	LPOFFLINESHOP pkOfflineShop = FindOfflineShopPID(ch->GetPlayerID());
	if (!pkOfflineShop)
		return;

	unsigned long long myFlag = ch->GetOfflineShopFlag();
	myFlag ^= SHOP_LOCKED_FLAG;
	ch->SetOfflineShopFlag(myFlag);
	ch->Save();

	shop_slot n;
	n.subheader = CHANGE_OPEN_SLOT;
	n.ch.owner_id = ch->GetPlayerID();
	n.ch.flag = myFlag;
	db_clientdesc->DBPacket(HEADER_GD_OFFLINESHOP, 0, &n, sizeof(shop_slot));
}

void COfflineShopManager::CloseOfflineShopForTimeReal(DWORD offlineshop)
{
	LPOFFLINESHOP pkOfflineShop = FindOfflineShopPID(offlineshop);
	if (!pkOfflineShop)
		return;

	bool status = false;
	for (DWORD i = 0; i < OFFLINE_SHOP_HOST_ITEM_MAX_NUM; ++i)
	{
		if (pkOfflineShop->m_data.items[i].vnum != 0 && pkOfflineShop->m_data.items[i].status == 0) {
			ClearItem(pkOfflineShop->m_data.items[i].id);
			if (!status)
				status = true;
		}
	}

	if (status)
	{
		m_Map_pkOfflineShopCache.push_back(offlineshop);
		pkOfflineShop->DestroyEx();
		auto timesVector = std::find(m_Map_pkShopTimes.begin(), m_Map_pkShopTimes.end(), offlineshop);
		if (timesVector != m_Map_pkShopTimes.end())
			m_Map_pkShopTimes.erase(timesVector);
	}
	else
	{
		if (m_Map_pkOfflineShopByName.find(pkOfflineShop->m_data.owner_name) != m_Map_pkOfflineShopByName.end())
			m_Map_pkOfflineShopByName.erase(pkOfflineShop->m_data.owner_name);
		pkOfflineShop->Destroy();
		m_Map_pkOfflineShopByNPC.erase(offlineshop);
		HasOfflineShop(CHARACTER_MANAGER::Instance().FindByPID(offlineshop));
		M2_DELETE(pkOfflineShop);
	}
}

void COfflineShopManager::CloseOfflineShopForTime(LPOFFLINESHOP offlineshop)
{
	if (!offlineshop)
		return;

	shop_owner n;
	n.subheader = TIME_DONE;
	n.owner_id = offlineshop->m_data.owner_id;
	db_clientdesc->DBPacket(HEADER_GD_OFFLINESHOP, 0, &n, sizeof(shop_owner));
}


void COfflineShopManager::GetBackItem(LPCHARACTER ch)
{
	if (!ch)
		return;
	if (ch->CanGetBackItems())
		return;

	auto it = std::find(m_Map_pkOfflineShopCache.begin(), m_Map_pkOfflineShopCache.end(), ch->GetPlayerID());
	if (it== m_Map_pkOfflineShopCache.end())
		return;

	shop_owner n;
	n.subheader = GET_BACK_ITEM;
	n.owner_id = ch->GetPlayerID();
	db_clientdesc->DBPacket(HEADER_GD_OFFLINESHOP, 0, &n, sizeof(shop_owner));
}


void COfflineShopManager::GetBackItemReal(TOfflineShopBackItem* ch)
{
	if (!ch)
		return;
	LPCHARACTER t = CHARACTER_MANAGER::Instance().FindByPID(ch->owner_id);
	if (t)
	{
		for (DWORD i = 0; i < OFFLINE_SHOP_HOST_ITEM_MAX_NUM; ++i)
		{
			if (ch->items[i].vnum == 0 || ch->items[i].status == 1)
				continue;
			LPITEM pItem = t->AutoGiveItem(ch->items[i].vnum, ch->items[i].count,0,true);
			if (pItem != NULL)
			{
				pItem->SetAttributes(ch->items[i].aAttr);
				pItem->SetSockets(ch->items[i].alSockets);
#ifdef ENABLE_CHANGELOOK_SYSTEM
				pItem->SetTransmutation(ch->items[i].transmutation);
#endif
#ifdef ENABLE_PERMA_ITEM
				pItem->SetPerma(ch->items[i].perma);
#endif
				pItem->UpdatePacket();

				sys_log(0, "GetBackItemReal: %s item vnum %d count %d price %lld", t->GetName(),pItem->GetVnum(), pItem->GetCount(), ch->items[i].price);
			}
		}
	}

	auto it = std::find(m_Map_pkOfflineShopCache.begin(), m_Map_pkOfflineShopCache.end(), ch->owner_id);
	if (it != m_Map_pkOfflineShopCache.end())
		m_Map_pkOfflineShopCache.erase(it);

	auto it2 = m_Map_pkOfflineShopByNPC.find(ch->owner_id);
	if (it2 != m_Map_pkOfflineShopByNPC.end())
	{
		LPOFFLINESHOP pkOfflineShop = it2->second;
		if (pkOfflineShop) {
			if (m_Map_pkOfflineShopByName.find(pkOfflineShop->m_data.owner_name) != m_Map_pkOfflineShopByName.end())
				m_Map_pkOfflineShopByName.erase(pkOfflineShop->m_data.owner_name);
			pkOfflineShop->Destroy();
			M2_DELETE(pkOfflineShop);
			pkOfflineShop = NULL;
			m_Map_pkOfflineShopByNPC.erase(ch->owner_id);
		}
	}
	HasOfflineShop(t);
}

void COfflineShopManager::ShopAddTime(LPCHARACTER ch)
{
	if (!ch)
		return;
	if (ch->CanAddTimeShop())
		return;
	LPOFFLINESHOP pkOfflineShop = FindOfflineShopPID(ch->GetPlayerID());
	if (!pkOfflineShop)
		return;

	const int oldtime = pkOfflineShop->m_data.time - time(0);

	if (ch->FindAffect(AFFECT_DECORATION))
	{
		if (oldtime > SHOP_MAX_TIME_PREMIUM)
			return;

		// PointChange(POINT_GOLD, ...) never clamps at 0 - it just adds the (negative)
		// amount to whatever gold the character has, so without this check a player
		// with less than the cost would go negative instead of the purchase failing.
		if (ch->GetGold() < 2000000)
		{
			ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("Not enough gold."));
			return;
		}

		ch->PointChange(POINT_GOLD, -2000000);

		shop_owner n;
		n.subheader = ADD_TIME_PREMIUM;
		n.owner_id = ch->GetPlayerID();
		db_clientdesc->DBPacket(HEADER_GD_OFFLINESHOP,0, &n, sizeof(shop_owner));
	}
	else
	{
		if (oldtime > SHOP_MAX_TIME)
			return;

		if (ch->GetGold() < 1000000)
		{
			ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("Not enough gold."));
			return;
		}

		ch->PointChange(POINT_GOLD, -1000000);

		shop_owner n;
		n.subheader = ADD_TIME;
		n.owner_id = ch->GetPlayerID();
		db_clientdesc->DBPacket(HEADER_GD_OFFLINESHOP,0, &n, sizeof(shop_owner));
	}
}

void COfflineShopManager::ShopAddTimeReal(DWORD ch)
{
	LPOFFLINESHOP pkOfflineShop = FindOfflineShopPID(ch);
	if (!pkOfflineShop)
		return;

	TOfflineShop& m_data = pkOfflineShop->m_data;

	int oldTime = m_data.time - time(0);
	if (oldTime <= 0)
		oldTime = 0;

	// This used to be a flat "reset to now + 1 day" instead of adding to whatever was
	// left, so the button always showed exactly 1 day remaining no matter how many
	// times it was clicked. Add the grant to the remaining time, capped at SHOP_MAX_TIME
	// (ShopAddTime() already enforces this cap before requesting the DB round-trip that
	// leads here, but re-clamping keeps this function correct on its own).
	int newRemaining = oldTime + SHOP_TIME_ADD_TIME;
	if (newRemaining > SHOP_MAX_TIME)
		newRemaining = SHOP_MAX_TIME;
	m_data.time = time(0) + newRemaining;

	pkOfflineShop->BroadcastUpdateItem(0);

	if (oldTime <= 0 && !pkOfflineShop->GetOfflineShopNPC() && g_bChannel == m_data.channel)
	{
		LPCHARACTER npc = CHARACTER_MANAGER::instance().SpawnMob(m_data.type, m_data.mapindex, m_data.x, m_data.y, m_data.z, false, -1, false);

		if (!npc)
			return;

		pkOfflineShop->SetOfflineShopNPC(npc);

		if (!m_pShopTimeEvent)
		{
			TShopTimeEventInfo* info = AllocEventInfo<TShopTimeEventInfo>();
			m_pShopTimeEvent = event_create(shop_time_event, info, PASSES_PER_SEC(5));
		}

		npc->SetOfflineShop(pkOfflineShop);
		npc->SetName(m_data.owner_name);
		npc->Show(m_data.mapindex, m_data.x, m_data.y, m_data.z, true);
		npc->ViewReencode();

#ifdef ENABLE_SHOP_SEARCH_SYSTEM
		for (DWORD i = 0; i < OFFLINE_SHOP_HOST_ITEM_MAX_NUM; ++i)
			InsertItem(&m_data.items[i]);
#endif

		m_Map_pkShopTimes.push_back(m_data.owner_id);
	}
}

void COfflineShopManager::ShopAddTimeRealPremium(DWORD ch)
{
	LPOFFLINESHOP pkOfflineShop = FindOfflineShopPID(ch);
	if (!pkOfflineShop)
		return;

	TOfflineShop& m_data = pkOfflineShop->m_data;

	int oldTime = m_data.time - time(0);
	if (oldTime <= 0)
		oldTime = 0;

	m_data.time = time(0) + SHOP_TIME_ADD_TIME_PREMIUM;

	pkOfflineShop->BroadcastUpdateItem(0);

	if (oldTime <= 0 && !pkOfflineShop->GetOfflineShopNPC() && g_bChannel == m_data.channel)
	{
		LPCHARACTER npc = CHARACTER_MANAGER::instance().SpawnMob(m_data.type, m_data.mapindex, m_data.x, m_data.y, m_data.z, false, -1, false);

		if (!npc)
			return;

		pkOfflineShop->SetOfflineShopNPC(npc);

		if (!m_pShopTimeEvent)
		{
			TShopTimeEventInfo* info = AllocEventInfo<TShopTimeEventInfo>();
			m_pShopTimeEvent = event_create(shop_time_event, info, PASSES_PER_SEC(5));
		}

		npc->SetOfflineShop(pkOfflineShop);
		npc->SetName(m_data.owner_name);
		npc->Show(m_data.mapindex, m_data.x, m_data.y, m_data.z, true);
		npc->ViewReencode();
#ifdef ENABLE_SHOP_SEARCH_SYSTEM
		for (DWORD i = 0; i < OFFLINE_SHOP_HOST_ITEM_MAX_NUM; ++i)
			InsertItem(&m_data.items[i]);
#endif

		m_Map_pkShopTimes.push_back(m_data.owner_id);
	}
}

void COfflineShopManager::RecvPackets(const char* data)
{
	BYTE sub_header = (BYTE)*data;
	switch (sub_header)
	{
		case CREATE_OFFLINESHOP:
		{
			shop_create* p = (shop_create*)data;
			if (p)
				CreateOfflineShop(&p->offlineshop);
		}
		break;

		case DESTROY_OFFLINESHOP:
		{
			shop_owner* p = (shop_owner*)data;
			if (p)
				DestroyOfflineShopReal(p->owner_id);
		}
		break;

		case REMOVE_ITEM:
		{
			shop_item* p = (shop_item*)data;
			if (p)
				RemoveItemReal(&p->item);
		}
		break;

		case ADD_ITEM:
		{
			shop_item* p = (shop_item*)data;
			if (p)
				AddItemReal(&p->item);
		}
		break;

		case BUY_ITEM:
		{
			shop_buy* p = (shop_buy*)data;
			if (p)
				BuyItemReal(&p->buyItem);
		}
		break;

		case WITHDRAW_MONEY:
		{
			shop_owner* p = (shop_owner*)data;
			if (p)
				WithdrawMoneyReal(p->owner_id);
		}
		break;

		case CHANGE_TITLE:
		{
			shop_title* p = (shop_title*)data;
			if (p)
				ChangeTitleReal(&p->title);
		}
		break;

		case CLEAR_LOG:
		{
			shop_owner* p = (shop_owner*)data;
			if (p)
				ShopLogRemoveReal(p->owner_id);
		}
		break;

		case CHANGE_DECORATION:
		{
			shop_decoration* p = (shop_decoration*)data;
			if (p)
				ChangeDecorationReal(&p->decoration);
		}
		break;

		case CHANGE_OPEN_SLOT:
		{
			shop_slot* p = (shop_slot*)data;
			if (p)
				OpenSlotReal(&p->ch);
		}
		break;

		case TIME_DONE:
		{
			shop_owner* p = (shop_owner*)data;
			if (p)
				CloseOfflineShopForTimeReal(p->owner_id);
		}
		break;

		case GET_BACK_ITEM:
		{
			shop_back* p = (shop_back*)data;
			if (p)
				GetBackItemReal(&p->back);
		}
		break;

		case ADD_TIME:
		{
			shop_owner* p = (shop_owner*)data;
			if(p)
				ShopAddTimeReal(p->owner_id);
		}
		break;

		case ADD_TIME_PREMIUM:
		{
			shop_owner* p = (shop_owner*)data;
			if(p)
				ShopAddTimeRealPremium(p->owner_id);
		}
		break;

		case MOVE_ITEM:
		{
			move_item* p = (move_item*)data;
			if (p)
				MoveItemReal(p->ownerID, p->slotPos, p->targetPos);
		}
		break;

		case CHANGE_PRICE:
		{
			change_price* p = (change_price*)data;
			if (p)
				ChangePriceReal(p->ownerID, p->bPos, p->itemPrice);
		}
		break;

		case REMOVE_ALL_ITEM:
		{
			remove_all* p = (remove_all*)data;
			if (p)
				RemoveItemAllReal(p->ownerID);
		}
		break;

		case SEED_PRICE_STAT:
		{
			shop_price_seed* p = (shop_price_seed*)data;
			// Only seeds if this vnum has no in-memory average yet - if this core
			// already observed sales itself (or an earlier seed), that stays authoritative.
			if (p && m_pShopItemAveragePrice.find(p->vnum) == m_pShopItemAveragePrice.end())
				SetAveragePrice(p->vnum, p->avgPrice);
		}
		break;
	}
}

long long COfflineShopManager::GetAveragePrice(DWORD itemIdx)
{
	const auto it = m_pShopItemAveragePrice.find(itemIdx);
	return it != m_pShopItemAveragePrice.end() ? it->second.GetAveragePrice() : 0;
}
void COfflineShopManager::SetAveragePrice(DWORD itemIdx, long long itemPrice)
{
	const auto it = m_pShopItemAveragePrice.find(itemIdx);
	if (it != m_pShopItemAveragePrice.end())
		it->second.AddItem(itemPrice);
	else
		m_pShopItemAveragePrice.emplace(itemIdx, CItemAverage(itemPrice));
}
void COfflineShopManager::CheckAveragePrice(LPCHARACTER ch, DWORD itemIdx)
{
	if (ch)
		ch->ChatPacket(CHAT_TYPE_COMMAND, "AppendAverageItem %u %lld", itemIdx, GetAveragePrice(itemIdx));
}
void COfflineShopManager::AddItemShortcut(LPCHARACTER ch, TItemPos pos, long long itemPrice)
{
	LPITEM pkItem = ch->GetItem(pos);
	if (!pkItem)
		return;

	LPOFFLINESHOP pkOfflineShop = FindOfflineShopPID(ch->GetPlayerID());
	if (!pkOfflineShop)
	{
		ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("OFFLINE_SHOP_CANT_FIND"));
		return;
	}

	if (pkOfflineShop->IsClosed())
	{
		ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("Reactivate your shop first."));
		return;
	}

	if (ch->IsDead())
	{
		ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("OFFLINE_SHOP_CANT_ADD_ITEM %s"),pkItem->GetName());
		return;
	}

	if (!ch->CheckPremiumStateMap())
	{
		ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("You need to be in the same map or to have the Extended Market activated in order to add the item."));
		return;
	}

	if (pkItem->isLocked())
	{
		ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("OFFLINE_SHOP_CANT_ADD_ITEM %s"),pkItem->GetName());
		return;
	}
	else if (pkItem->IsEquipped())
	{
		ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("OFFLINE_SHOP_CANT_ADD_ITEM %s"),pkItem->GetName());
		return;
	}
	else if (pkItem->IsExchanging())
	{
		ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("OFFLINE_SHOP_CANT_ADD_ITEM %s"),pkItem->GetName());
		return;
	}
	else if (ch->PreventTradeWindow(WND_MYSHOP | WND_SHOPOWNER, true))
	{
		ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("You need to close other windows."));
		return;
	}
	if ((pkItem->GetVnum() >= 51010 && pkItem->GetVnum() <= 51030) && pkItem->GetSocket(0) == 1)
	{
		ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("Deactivate the Energy Crystal first."));
		return;
	}

	const TItemTable* itemTable = pkItem->GetProto();
	if (itemTable && IS_SET(itemTable->dwAntiFlags, ITEM_ANTIFLAG_GIVE | ITEM_ANTIFLAG_MYSHOP) || pkItem->GetSocket(4) == 99)
		return;

	const auto& itemSlots = pkOfflineShop->m_data.items;
	const auto& playerFlag = ch->GetOfflineShopFlag();
	// Real display grid is 10 wide x 8 tall (uiscript/offlineshop/offlineshopwindow.py:
	// x_count 10, y_count 8) - NOT 5x16. CGrid computes "row below" as pos + width, so
	// the wrong width here silently reserved/checked the wrong cells entirely.
	CGrid shopGrid(10, 8);
	for (BYTE j = 0; j < OFFLINE_SHOP_HOST_ITEM_MAX_NUM; ++j)
	{
		if (itemSlots[j].vnum != 0)
		{
			TItemTable* tableItem = ITEM_MANAGER::instance().GetTable(itemSlots[j].vnum);
			if (!tableItem)
				return;
			shopGrid.Put(j, 1, tableItem->bSize);
			continue;
		}
		if (j >= 40)
		{
			const BYTE cell = j-40;
			if (!IS_SET(playerFlag, 1ULL << cell))
				shopGrid.Put(j, 1, 1);
		}
	}

	const int emptyPos = shopGrid.FindBlank(1, pkItem->GetSize());
	if (emptyPos == -1)
	{
		ch->ChatPacket(1, "can't find any empty slot!");
		return;
	}

	OFFLINE_SHOP_ITEM item;
	item.vnum = pkItem->GetVnum();
	item.id = pkItem->GetID();
	item.owner_id = ch->GetPlayerID();
	item.pos = emptyPos;
	item.count = pkItem->GetCount();
	item.price = itemPrice;
	item.status = 0;
	thecore_memcpy(item.alSockets, pkItem->GetSockets(), sizeof(item.alSockets));
	thecore_memcpy(item.aAttr, pkItem->GetAttributes(), sizeof(item.aAttr));
#ifdef ENABLE_CHANGELOOK_SYSTEM
	item.transmutation = pkItem->GetTransmutation();
#endif
#ifdef ENABLE_NEW_NAME_ITEM
	strlcpy(item.name, pkItem->GetNewName(), sizeof(item.name));
#endif
#ifdef ENABLE_PERMA_ITEM
	item.perma = pkItem->GetPerma();
#endif

	strlcpy(item.szOwnerName, ch->GetName(), sizeof(item.szOwnerName));
	pkItem->RemoveFromCharacter();
	ITEM_MANAGER::instance().SaveSingleItem(pkItem);

	shop_item n;
	n.subheader = ADD_ITEM;
	thecore_memcpy(&n.item, &item, sizeof(n.item));
	db_clientdesc->DBPacket(HEADER_GD_OFFLINESHOP, 0, &n, sizeof(shop_item));
}
void COfflineShopManager::OpenOfflineShopWithVID(LPCHARACTER ch, DWORD ownerID)
{
	if (!ch)
		return;
	if (ch->CanOpenOfflineShop())
		return;
	LPOFFLINESHOP pkOfflineShop = FindOfflineShopPID(ownerID);
	if (!pkOfflineShop)
		return;
	pkOfflineShop->AddGuest(ch, pkOfflineShop->GetOfflineShopNPC());
}
void COfflineShopManager::Teleport(LPCHARACTER ch, const char* szOwnerName)
{
	if (!ch || ch->CanTeleportOfflineShop())
		return;

#ifdef ENABLE_ANTI_CMD_FLOOD
	if (!PulseManager::Instance().IncreaseClock(ch->GetPlayerID(), ePulse::SharedRequest, std::chrono::milliseconds(5000)))
		return ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("퀘스트를 로드하는 중입니다. 잠시만 기다려 주십시오."));
#endif	

	auto it = m_Map_pkOfflineShopByName.find(szOwnerName);
	if (it == m_Map_pkOfflineShopByName.end())
		return;
		
	LPOFFLINESHOP pkOfflineShop = it->second;
	if (pkOfflineShop->IsClosed())
		return;

	if (pkOfflineShop->m_data.channel == g_bChannel && ch->GetMapIndex() == pkOfflineShop->m_data.mapindex)
		ch->Show(ch->GetMapIndex(), pkOfflineShop->m_data.x, pkOfflineShop->m_data.y);
	else
		ch->WarpSet(pkOfflineShop->m_data.x, pkOfflineShop->m_data.y, pkOfflineShop->m_data.mapindex, pkOfflineShop->m_data.channel);
}

void COfflineShopManager::MoveItem(LPCHARACTER ch, WORD slotPos, WORD targetPos)
{
	if (!ch || ch->CanMoveItemOfflineShop())
		return;
	LPOFFLINESHOP pkOfflineShop = FindOfflineShopPID(ch->GetPlayerID());
	if (!pkOfflineShop)
		return;
	else if (slotPos > OFFLINE_SHOP_HOST_ITEM_MAX_NUM || targetPos > OFFLINE_SHOP_HOST_ITEM_MAX_NUM)
		return;
	else if (pkOfflineShop->m_data.items[slotPos].vnum == 0 || pkOfflineShop->m_data.items[targetPos].vnum != 0)
		return;

	// bSize-aware occupancy check - see AddItem() for why. Exclude slotPos itself
	// (the item being moved away from) so it doesn't block its own move; this also
	// rejects a locked (not-yet-unlocked) targetPos, which the checks above never did.
	{
		CGrid shopGrid(10, 8);
		const auto& itemSlots = pkOfflineShop->m_data.items;
		const auto& playerFlag = ch->GetOfflineShopFlag();
		for (BYTE j = 0; j < OFFLINE_SHOP_HOST_ITEM_MAX_NUM; ++j)
		{
			if (j == slotPos)
				continue;
			if (itemSlots[j].vnum != 0)
			{
				TItemTable* tableItem = ITEM_MANAGER::instance().GetTable(itemSlots[j].vnum);
				if (tableItem)
					shopGrid.Put(j, 1, tableItem->bSize);
				continue;
			}
			if (j >= 40)
			{
				const BYTE cell = j - 40;
				if (!IS_SET(playerFlag, 1ULL << cell))
					shopGrid.Put(j, 1, 1);
			}
		}

		TItemTable* movingTable = ITEM_MANAGER::instance().GetTable(itemSlots[slotPos].vnum);
		BYTE movingSize = movingTable ? movingTable->bSize : 1;
		if (!shopGrid.IsEmpty(targetPos, 1, movingSize))
			return;
	}

	move_item n;
	n.subheader = MOVE_ITEM;
	n.ownerID = ch->GetPlayerID();
	n.slotPos = slotPos;
	n.targetPos = targetPos;
	db_clientdesc->DBPacket(HEADER_GD_OFFLINESHOP, 0, &n, sizeof(move_item));
}
void COfflineShopManager::MoveItemReal(DWORD ownerID, WORD slotPos, WORD targetPos)
{
	LPOFFLINESHOP pkOfflineShop = FindOfflineShopPID(ownerID);
	if (!pkOfflineShop)
		return;
	thecore_memcpy(&pkOfflineShop->m_data.items[targetPos], &pkOfflineShop->m_data.items[slotPos], sizeof(pkOfflineShop->m_data.items[targetPos]));
	memset(&pkOfflineShop->m_data.items[slotPos], 0, sizeof(pkOfflineShop->m_data.items[slotPos]));
	pkOfflineShop->m_data.items[targetPos].pos = targetPos;
	pkOfflineShop->BroadcastUpdateItem(slotPos, true);
	pkOfflineShop->BroadcastUpdateItem(targetPos);
}

void COfflineShopManager::RemoveItemAllReal(DWORD ownerID)
{
	LPOFFLINESHOP pkOfflineShop = FindOfflineShopPID(ownerID);
	if (!pkOfflineShop)
		return;
	LPCHARACTER ch = CHARACTER_MANAGER::Instance().FindByPID(ownerID);
	for (DWORD j = 0; j < OFFLINE_SHOP_HOST_ITEM_MAX_NUM; ++j)
	{
		const auto& item = pkOfflineShop->m_data.items[j];
		if (item.vnum == 0 || item.status != 0)
			continue;

		if (ch)
		{
			LPITEM pItem = ch->AutoGiveItem(item.vnum, item.count, 0, true);
			if (pItem)
			{
				pItem->SetAttributes(item.aAttr);
				pItem->SetSockets(item.alSockets);
				pItem->UpdatePacket();
			}
		}
		pkOfflineShop->BroadcastUpdateItem(j, true);
#ifdef ENABLE_SHOP_SEARCH_SYSTEM
		ClearItem(item.id);
#endif
	}
	memset(&pkOfflineShop->m_data.items, 0, sizeof(pkOfflineShop->m_data.items));
	
}
void COfflineShopManager::RemoveItemAll(LPCHARACTER ch)
{
	if (!ch || ch->CanTakeOutAllItemsOfflineShop())
		return;
	LPOFFLINESHOP pkOfflineShop = FindOfflineShopPID(ch->GetPlayerID());
	if (!pkOfflineShop)
		return;
	bool notHasItem = false;
	const auto& itemList = pkOfflineShop->m_data.items;
	for (DWORD j = 0; j < OFFLINE_SHOP_HOST_ITEM_MAX_NUM; ++j)
	{
		if (itemList[j].vnum == 0 || itemList[j].status != 0)
			continue;
		TItemTable* itemTable = ITEM_MANAGER::instance().GetTable(itemList[j].vnum);
		if (!itemTable)
			continue;
		notHasItem = true;
		break;		
	}
	if (!notHasItem)
		return;
	remove_all n;
	n.subheader = REMOVE_ALL_ITEM;
	n.ownerID = ch->GetPlayerID();
	db_clientdesc->DBPacket(HEADER_GD_OFFLINESHOP, 0, &n, sizeof(remove_all));
}
#endif





