#pragma once

#ifdef ENABLE_OFFLINESHOP_SYSTEM
class COfflineShop
{
	public:
		TOfflineShop		m_data;
		COfflineShop();
		virtual ~COfflineShop();

		virtual bool	AddGuest(LPCHARACTER ch, LPCHARACTER npc);
		void			RemoveGuest(LPCHARACTER ch, bool isDestroy = false);

		DWORD			GetItemCount();

		bool			IsClosed();
		void			Destroy();
		void			DestroyEx();
		void			BroadcastUpdateItem(BYTE bPos, bool bDestroy = false, int log_index = -1);

		DWORD			GetOwner(){return m_data.owner_id;}
		void			SetShopSign(const char* f){strcpy(m_data.sign,f);}
		const char*		GetShopSign() {return m_data.sign;}

		virtual void	SetOfflineShopNPC(LPCHARACTER npc) { m_pkOfflineShopNPC = npc; }
		LPCHARACTER		GetOfflineShopNPC() { return m_pkOfflineShopNPC; }

		void			Broadcast(const void * data, int bytes);

		void			SetRefreshLog(bool flag) { m_dwRefreshLog = flag; }
		bool			GetRefreshLog() { return m_dwRefreshLog; }

		// Every game core keeps its own COfflineShop mirror + its own local guest
		// list (m_map_guest), so m_dwDisplayedCount/m_dwRealWatcherCount below only
		// ever reflect watchers connected to THIS core. GetGlobalDisplayedCount/
		// GetGlobalRealWatcherCount add in what every other core last reported about
		// itself (see ApplyRemoteWatcherCount, fed by the HEADER_GG_OFFLINESHOP_WATCHER
		// P2P broadcast) so the number actually shown to clients is server-wide.
		void			BroadcastWatcherCountP2P();
		void			ApplyRemoteWatcherCount(WORD wSenderPort, DWORD dwDisplayed, DWORD dwRealWatcher);
		DWORD			GetGlobalDisplayedCount();
		DWORD			GetGlobalRealWatcherCount();

	private:
		std::map<DWORD, LPCHARACTER> m_map_guest;
		LPCHARACTER m_pkOfflineShopNPC;
		DWORD m_dwDisplayedCount;
		DWORD m_dwRealWatcherCount;
		bool  m_dwRefreshLog;
		std::map<WORD, std::pair<DWORD, DWORD>> m_map_remoteWatcherCounts;	// senderPort -> (displayed, real)
};
#endif


