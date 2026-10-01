// vim:ts=8 sw=4
#ifndef __INC_ITEM_AWARD_H
#define __INC_ITEM_AWARD_H
#include <map>
#include <set>
#include "Peer.h"

typedef struct SItemAward
{
    DWORD	dwID;
    char	szLogin[LOGIN_MAX_LEN+1];
    DWORD	dwVnum;
    DWORD	dwCount;
    DWORD	dwSocket0;
    DWORD	dwSocket1;
    DWORD	dwSocket2;
    char	szWhy[ITEM_AWARD_WHY_MAX_LEN+1];
    bool	bTaken;
    bool	bMall;
    // item_award.attrtype0-6 / attrvalue0-6 (server-live/item_award_attr_setup.sql) - lets an
    // award carry exact bonuses, e.g. a webadmin gift that didn't fit the inventory
    BYTE	abAttrType[ITEM_ATTRIBUTE_MAX_NUM];
    short	asAttrValue[ITEM_ATTRIBUTE_MAX_NUM];
} TItemAward;

class ItemAwardManager : public singleton<ItemAwardManager>
{
    public:
	ItemAwardManager();
	virtual ~ItemAwardManager();

	void				RequestLoad();
	void				Load(SQLMsg * pMsg);
	std::set<TItemAward *> *	GetByLogin(const char * c_pszLogin);

	void				Taken(DWORD dwAwardID, DWORD dwItemID);
	// gift notify
	std::map<DWORD, TItemAward *>& GetMapAward();
	std::map<std::string, std::set<TItemAward *> >& GetMapkSetAwardByLogin();
    private:
	// ID, ItemAward pair
	std::map<DWORD, TItemAward *>			m_map_award;
	// PID, ItemAward pair
	std::map<std::string, std::set<TItemAward *> >	m_map_kSetAwardByLogin;
};

#endif
