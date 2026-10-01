#include "stdafx.h"
#include <sstream>
#include <memory>

#include "desc.h"
#include "desc_manager.h"
#include "char.h"
#include "char_manager.h"
#include "item.h"
#include "item_manager.h"
#include "mob_manager.h"
#include "skill.h"
#include "buffer_manager.h"
#include "config.h"
#include "profiler.h"
#include "p2p.h"
#include "log.h"
#include "db.h"
#include "questmanager.h"
#include "login_sim.h"
#include "fishing.h"
#include "TrafficProfiler.h"
#include "priv_manager.h"
#include "castle.h"
#include "dev_log.h"
#ifdef ENABLE_MAINTENANCE_SYSTEM
	#include "maintenance.h"
#endif

#ifndef __WIN32__
	#include "limit_time.h"
#endif

extern time_t get_global_time();
extern bool g_bNoPasspod;
#ifdef ENABLE_MAINTENANCE_SYSTEM
	extern long int global_time_maintenance;
#endif

bool IsEmptyAdminPage()
{
	return g_stAdminPageIP.empty();
}

bool IsAdminPage(const char * ip)
{
	for (size_t n = 0; n < g_stAdminPageIP.size(); ++n)
	{
		if (g_stAdminPageIP[n] == ip)
			return 1; 
	}	
	return 0;
}

void ClearAdminPages()
{
	for (size_t n = 0; n < g_stAdminPageIP.size(); ++n)
		g_stAdminPageIP[n].clear();

	g_stAdminPageIP.clear();
}

// Shared by every read-only WEBADMIN command below (PLAYER_LIST, PLAYER_DETAIL): same gate
// USER_COUNT already used inline twice above - factored out here instead of a third copy.
static bool IsCallerAllowedOnAdminSocket(LPDESC d)
{
	return IsEmptyAdminPage() || IsAdminPage(inet_ntoa(d->GetAddr().sin_addr));
}

CInputProcessor::CInputProcessor() : m_pPacketInfo(NULL), m_iBufferLeft(0)
{
	if (!m_pPacketInfo)
		BindPacketInfo(&m_packetInfoCG);
}

void CInputProcessor::BindPacketInfo(CPacketInfo * pPacketInfo)
{
	m_pPacketInfo = pPacketInfo;
}

bool CInputProcessor::Process(LPDESC lpDesc, const void * c_pvOrig, int iBytes, int & r_iBytesProceed)
{
	const char * c_pData = (const char *) c_pvOrig;

	BYTE	bLastHeader = 0;
	int		iLastPacketLen = 0;
	int		iPacketLen;

	if (!m_pPacketInfo)
	{
		sys_err("No packet info has been binded to");
		return true;
	}

	for (m_iBufferLeft = iBytes; m_iBufferLeft > 0;)
	{
		BYTE bHeader = (BYTE) *(c_pData);
		const char * c_pszName;

		if (bHeader == 0) // 암호화 처리가 있으므로 0번 헤더는 스킵한다.
			iPacketLen = 1;
		else if (!m_pPacketInfo->Get(bHeader, &iPacketLen, &c_pszName))
		{
			sys_err("UNKNOWN HEADER: %d, LAST HEADER: %d(%d), REMAIN BYTES: %d, fd: %d",
					bHeader, bLastHeader, iLastPacketLen, m_iBufferLeft, lpDesc->GetSocket());
			//printdata((BYTE *) c_pvOrig, m_iBufferLeft);
			lpDesc->SetPhase(PHASE_CLOSE);
			return true;
		}

		if (m_iBufferLeft < iPacketLen)
			return true;

		if (bHeader)
		{
			if (test_server && bHeader != HEADER_CG_MOVE)
				sys_log(0, "Packet Analyze [Header %d][bufferLeft %d] ", bHeader, m_iBufferLeft);

			m_pPacketInfo->Start();

			int iExtraPacketSize = Analyze(lpDesc, bHeader, c_pData);

			if (iExtraPacketSize < 0)
				return true;

			iPacketLen += iExtraPacketSize;
			lpDesc->Log("%s %d", c_pszName, iPacketLen);
			m_pPacketInfo->End();
		}

		// TRAFFIC_PROFILER
		if (g_bTrafficProfileOn)
			TrafficProfiler::instance().Report(TrafficProfiler::IODIR_INPUT, bHeader, iPacketLen);
		// END_OF_TRAFFIC_PROFILER

		if (bHeader == HEADER_CG_PONG)
			sys_log(0, "PONG! %u %u", m_pPacketInfo->IsSequence(bHeader), *(BYTE *) (c_pData + iPacketLen - sizeof(BYTE)));

		if (m_pPacketInfo->IsSequence(bHeader))
		{
			BYTE bSeq = lpDesc->GetSequence();
			BYTE bSeqReceived = *(BYTE *) (c_pData + iPacketLen - sizeof(BYTE));

			if (bSeq != bSeqReceived)
			{
				sys_err("SEQUENCE %x mismatch 0x%x != 0x%x header %u", get_pointer(lpDesc), bSeq, bSeqReceived, bHeader);

				LPCHARACTER	ch = lpDesc->GetCharacter();

				char buf[1024];
				int	offset, len;

				offset = snprintf(buf, sizeof(buf), "SEQUENCE_LOG [%s]-------------\n", ch ? ch->GetName() : "UNKNOWN");

				if (offset < 0 || offset >= (int) sizeof(buf))
					offset = sizeof(buf) - 1;

				for (size_t i = 0; i < lpDesc->m_seq_vector.size(); ++i)
				{
					len = snprintf(buf + offset, sizeof(buf) - offset, "\t[%03d : 0x%x]\n",
							lpDesc->m_seq_vector[i].hdr,
							lpDesc->m_seq_vector[i].seq);

					if (len < 0 || len >= (int) sizeof(buf) - offset)
						offset += (sizeof(buf) - offset) - 1;
					else
						offset += len;
				}

				snprintf(buf + offset, sizeof(buf) - offset, "\t[%03d : 0x%x]\n", bHeader, bSeq);
				sys_err("%s", buf);

				lpDesc->SetPhase(PHASE_CLOSE);
				return true;
			}
			else
			{
				lpDesc->push_seq(bHeader, bSeq);
				lpDesc->SetNextSequence();
				//sys_err("SEQUENCE %x match %u next %u header %u", lpDesc, bSeq, lpDesc->GetSequence(), bHeader);
			}
		}

		c_pData	+= iPacketLen;
		m_iBufferLeft -= iPacketLen;
		r_iBytesProceed += iPacketLen;

		iLastPacketLen = iPacketLen;
		bLastHeader	= bHeader;

		if (GetType() != lpDesc->GetInputProcessor()->GetType())
			return false;
	}

	return true;
}

void CInputProcessor::Pong(LPDESC d)
{
	d->SetPong(true);

	extern bool Metin2Server_IsInvalid();

#ifdef ENABLE_LIMIT_TIME
	if (Metin2Server_IsInvalid())
	{
		extern bool g_bShutdown;
		g_bShutdown = true;
		ClearAdminPages();
	}
#endif
}

void CInputProcessor::Handshake(LPDESC d, const char * c_pData)
{
	TPacketCGHandshake * p = (TPacketCGHandshake *) c_pData;

	if (d->GetHandshake() != p->dwHandshake)
	{
		sys_err("Invalid Handshake on %d", d->GetSocket());
		d->SetPhase(PHASE_CLOSE);
	}
	else
	{
		if (d->IsPhase(PHASE_HANDSHAKE))
		{
			if (d->HandshakeProcess(p->dwTime, p->lDelta, false))
			{
#ifdef _IMPROVED_PACKET_ENCRYPTION_
				d->SendKeyAgreement();
#else
				if (g_bAuthServer)
					d->SetPhase(PHASE_AUTH);
				else
					d->SetPhase(PHASE_LOGIN);
#endif // #ifdef _IMPROVED_PACKET_ENCRYPTION_
			}
		}
		else
			d->HandshakeProcess(p->dwTime, p->lDelta, true);
	}
}

void CInputProcessor::Version(LPCHARACTER ch, const char* c_pData)
{
	if (!ch)
		return;

	TPacketCGClientVersion * p = (TPacketCGClientVersion *) c_pData;
	sys_log(0, "VERSION: %s %s %s", ch->GetName(), p->timestamp, p->filename);
	ch->GetDesc()->SetClientVersion(p->timestamp);
}

void LoginFailure(LPDESC d, const char * c_pszStatus)
{
	if (!d)
		return;

	TPacketGCLoginFailure failurePacket;

	failurePacket.header = HEADER_GC_LOGIN_FAILURE;
	strlcpy(failurePacket.szStatus, c_pszStatus, sizeof(failurePacket.szStatus));

	d->Packet(&failurePacket, sizeof(failurePacket));
}

CInputHandshake::CInputHandshake()
{
	CPacketInfoCG * pkPacketInfo = M2_NEW CPacketInfoCG;
	pkPacketInfo->SetSequence(HEADER_CG_PONG, false);

	m_pMainPacketInfo = m_pPacketInfo;
	BindPacketInfo(pkPacketInfo);
}

CInputHandshake::~CInputHandshake()
{
	if( NULL != m_pPacketInfo )
	{
		M2_DELETE(m_pPacketInfo);
		m_pPacketInfo = NULL;
	}
}


std::map<DWORD, CLoginSim *> g_sim;
std::map<DWORD, CLoginSim *> g_simByPID;
std::vector<TPlayerTable> g_vec_save;

// BLOCK_CHAT
ACMD(do_block_chat);
// END_OF_BLOCK_CHAT

// ---------------------------------------------------------------------------
// WEBADMIN: PLAYER_LIST / PLAYER_DETAIL - see the webadmin app's
// reference_game_admin_socket_protocol memory / src/lib/actions/players.ts.
// Hand-rolled JSON (no JSON lib is linked into this project) - safe here because every
// string field we emit is escaped, and the whole reply always stays on one line for the
// existing "read a single \n-terminated line" transport this admin-socket already uses.
// ---------------------------------------------------------------------------
static void JsonAppendEscaped(std::string& rDest, const char* c_szText)
{
	rDest += '"';
	for (const unsigned char* p = (const unsigned char*) c_szText; *p; ++p)
	{
		switch (*p)
		{
			case '"':	rDest += "\\\"";	break;
			case '\\':	rDest += "\\\\";	break;
			case '\n':	rDest += "\\n";		break;
			case '\r':	rDest += "\\r";		break;
			case '\t':	rDest += "\\t";		break;
			default:
				if (*p < 0x20)
				{
					char buf[8];
					snprintf(buf, sizeof(buf), "\\u%04x", *p);
					rDest += buf;
				}
				else
				{
					rDest += (char) *p;
				}
		}
	}
	rDest += '"';
}

static void JsonAppendPlayerListEntry(std::string& rDest, LPCHARACTER ch)
{
	char buf[512];
	snprintf(buf, sizeof(buf),
			"{\"name\":%%NAME%%,\"level\":%d,\"job\":%d,\"empire\":%d,\"gmLevel\":%d,"
			"\"mapIndex\":%ld,\"x\":%ld,\"y\":%ld,\"hp\":%d,\"maxHp\":%d,\"playSeconds\":%u}",
			ch->GetLevel(), (int) ch->GetJob(), (int) ch->GetEmpire(), (int) ch->GetGMLevel(),
			ch->GetMapIndex(), ch->GetX(), ch->GetY(), ch->GetHP(), ch->GetMaxHP(),
			(unsigned) ch->GetSessionSeconds());

	// snprintf can't escape the name for us (it might contain '"' in theory) - splice the
	// properly-escaped name in where the placeholder is instead of formatting it directly
	// into the buffer. Note: snprintf turns the "%%NAME%%" in the format into "%NAME%".
	std::string stEntry(buf);
	size_t placeholder = stEntry.find("%NAME%");
	std::string stName;
	JsonAppendEscaped(stName, ch->GetName());
	if (placeholder != std::string::npos)
		stEntry.replace(placeholder, 6, stName);

	rDest += stEntry;
}

static void BuildPlayerListJson(std::string& rDest)
{
	rDest = "[";
	bool bFirst = true;

	CHARACTER_MANAGER::NAME_MAP& rMap = CHARACTER_MANAGER::instance().GetPCMap();
	for (CHARACTER_MANAGER::NAME_MAP::iterator it = rMap.begin(); it != rMap.end(); ++it)
	{
		LPCHARACTER ch = it->second;
		if (!ch || !ch->GetDesc())
			continue;

		if (!bFirst)
			rDest += ",";
		bFirst = false;

		JsonAppendPlayerListEntry(rDest, ch);
	}

	rDest += "]";
}

static void JsonAppendItem(std::string& rDest, const char* c_szPosKey, int iPos, LPITEM item)
{
	// "id" is the item's unique DB id - the webadmin passes it back to TAKE_ITEM
	char buf[128];
	snprintf(buf, sizeof(buf), "{\"%s\":%d,\"id\":%u,\"vnum\":%u,\"count\":%u,\"name\":",
			c_szPosKey, iPos, item->GetID(), item->GetVnum(), (unsigned) item->GetCount());
	rDest += buf;
	JsonAppendEscaped(rDest, item->GetName());
	rDest += "}";
}

static void BuildPlayerDetailJson(std::string& rDest, LPCHARACTER ch)
{
	char buf[768];
	snprintf(buf, sizeof(buf),
			"{\"found\":true,\"name\":%%NAME%%,\"level\":%d,\"job\":%d,\"empire\":%d,\"gmLevel\":%d,"
			"\"mapIndex\":%ld,\"x\":%ld,\"y\":%ld,"
			"\"hp\":%d,\"maxHp\":%d,\"sp\":%d,\"maxSp\":%d,\"stamina\":%d,\"maxStamina\":%d,"
			"\"exp\":%u,\"gold\":%d,\"playSeconds\":%u,",
			ch->GetLevel(), (int) ch->GetJob(), (int) ch->GetEmpire(), (int) ch->GetGMLevel(),
			ch->GetMapIndex(), ch->GetX(), ch->GetY(),
			ch->GetHP(), ch->GetMaxHP(), ch->GetSP(), ch->GetMaxSP(), ch->GetStamina(), ch->GetMaxStamina(),
			(unsigned) ch->GetExp(), ch->GetGold(), (unsigned) ch->GetSessionSeconds());

	std::string stName;
	JsonAppendEscaped(stName, ch->GetName());
	std::string stHead(buf);
	// snprintf turned the "%%NAME%%" in the format into "%NAME%"
	size_t placeholder = stHead.find("%NAME%");
	if (placeholder != std::string::npos)
		stHead.replace(placeholder, 6, stName);
	rDest = stHead;

	// Equipped items (all WEAR_* slots - see common/item_length.h)
	rDest += "\"equipped\":[";
	bool bFirst = true;
	for (int slot = 0; slot < WEAR_POSITION_COUNT; ++slot)
	{
		LPITEM item = ch->GetWear(slot);
		if (!item)
			continue;

		if (!bFirst)
			rDest += ",";
		bFirst = false;
		JsonAppendItem(rDest, "slot", slot, item);
	}
	rDest += "],";

	// Every INVENTORY-window cell except the worn-equipment block (already listed above): base
	// bag, active dragon soul decks, belt and the WJ_SPLIT_INVENTORY tabs (see common/length.h)
	rDest += "\"inventory\":[";
	bFirst = true;
	for (int cell = 0; cell < INVENTORY_AND_EQUIP_SLOT_MAX; ++cell)
	{
		if (cell >= EQUIPMENT_SLOT_START && cell < EQUIPMENT_SLOT_END)
			continue;

		LPITEM item = ch->GetInventoryItem(cell);
		if (!item)
			continue;

		if (!bFirst)
			rDest += ",";
		bFirst = false;
		JsonAppendItem(rDest, "cell", cell, item);
	}
	rDest += "],";

	// Learned skills - GetSkillLevel() returns 0 for anything not learned, so a plain sweep
	// over every possible vnum is simplest (SKILL_MAX_NUM is small, this runs once per request)
	rDest += "\"skills\":[";
	bFirst = true;
	for (DWORD vnum = 1; vnum < SKILL_MAX_NUM; ++vnum)
	{
		int level = ch->GetSkillLevel(vnum);
		if (level <= 0)
			continue;

		if (!bFirst)
			rDest += ",";
		bFirst = false;

		const CSkillProto* pkSkill = CSkillManager::instance().Get(vnum);
		char skillBuf[256];
		snprintf(skillBuf, sizeof(skillBuf), "{\"vnum\":%u,\"level\":%d,\"name\":", vnum, level);
		rDest += skillBuf;
		JsonAppendEscaped(rDest, pkSkill ? pkSkill->szName : "?");
		rDest += "}";
	}
	rDest += "],";

	// Active affects/buffs - lDuration counts DOWN once a second on a live character (see
	// char_affect.cpp), so it already IS "seconds remaining", not the original total duration.
	rDest += "\"affects\":[";
	bFirst = true;
	const std::list<CAffect *>& rAffects = ch->GetAffectContainer();
	for (std::list<CAffect *>::const_iterator it = rAffects.begin(); it != rAffects.end(); ++it)
	{
		if (!bFirst)
			rDest += ",";
		bFirst = false;

		char affectBuf[128];
		snprintf(affectBuf, sizeof(affectBuf), "{\"type\":%u,\"applyOn\":%u,\"value\":%ld,\"remainingSeconds\":%ld}",
				(*it)->dwType, (unsigned) (*it)->bApplyOn, (*it)->lApplyValue, (*it)->lDuration);
		rDest += affectBuf;
	}
	rDest += "]}";
}

// ---------------------------------------------------------------------------
// Webadmin write commands (admin mode only - see the IsAdminMode() block in Analyze).
// Every one of them targets a character by name and only acts if that character is logged
// into THIS core; the webadmin sends the command to every core and uses whichever replies
// "OK ...". Replies: "OK[ <detail>]" or "ERR <CODE>" (NOT_FOUND = not online on this core).
// ---------------------------------------------------------------------------
static LPCHARACTER WebAdminFindLocalPC(const std::string& stName)
{
	LPCHARACTER ch = CHARACTER_MANAGER::instance().FindPC(stName.c_str());
	return (ch && ch->GetDesc()) ? ch : NULL;
}

static int WebAdminFindEmptyCell(LPCHARACTER ch, LPITEM item);

// System whisper from "[Szerver]" - shows up in the player's PM window as a system line
// (client game.py OnRecvWhisperSystemMessage). Same packet the PvP-duel notice uses (pvp.cpp).
static void WebAdminWhisper(LPCHARACTER ch, const char* c_szMessage)
{
	LPDESC pkDesc = ch->GetDesc();
	if (!pkDesc || !*c_szMessage)
		return;

	const int len = MIN(CHAT_MAX_LEN, (int) strlen(c_szMessage) + 1);

	TPacketGCWhisper pack;
	pack.bHeader = HEADER_GC_WHISPER;
	pack.wSize = sizeof(TPacketGCWhisper) + len;
	pack.bType = WHISPER_TYPE_SYSTEM;
	strlcpy(pack.szNameFrom, "[Szerver]", sizeof(pack.szNameFrom));

	TEMP_BUFFER buf;
	buf.write(&pack, sizeof(TPacketGCWhisper));
	buf.write(c_szMessage, len);
	pkDesc->Packet(buf.read_peek(), buf.size());
}

// Queues an item into the account's Itemshop storage (MALL) through item_award - the db core
// picks the row up within ~5s and places it the next time the storage is opened (db
// ClientManager.cpp, HEADER_GD_MALL_LOAD). Needs the attrtype/attrvalue columns from
// server-live/item_award_attr_setup.sql; returns false if the row couldn't be written.
static bool WebAdminAwardToMall(LPCHARACTER ch, DWORD dwVnum, int iCount,
		const long* alSockets, const BYTE* abAttrType, const short* asAttrValue)
{
	if (!ch->GetDesc())
		return false;

	static const long s_alNoSockets[ITEM_SOCKET_MAX_NUM] = {};
	static const BYTE s_abNoType[ITEM_ATTRIBUTE_MAX_NUM] = {};
	static const short s_asNoValue[ITEM_ATTRIBUTE_MAX_NUM] = {};
	const long* s = alSockets ? alSockets : s_alNoSockets;
	const BYTE* t = abAttrType ? abAttrType : s_abNoType;
	const short* v = asAttrValue ? asAttrValue : s_asNoValue;

	const char* c_szLogin = ch->GetDesc()->GetAccountTable().login;
	char szLogin[LOGIN_MAX_LEN * 2 + 1];
	DBManager::instance().EscapeString(szLogin, sizeof(szLogin), c_szLogin, strlen(c_szLogin));

	std::unique_ptr<SQLMsg> pMsg(DBManager::instance().DirectQuery(
			"INSERT INTO item_award (pid, login, vnum, count, given_time, why, mall, socket0, socket1, socket2, "
			"attrtype0, attrvalue0, attrtype1, attrvalue1, attrtype2, attrvalue2, attrtype3, attrvalue3, "
			"attrtype4, attrvalue4, attrtype5, attrvalue5, attrtype6, attrvalue6) "
			"VALUES(%u, '%s', %u, %d, NOW(), 'WEBADMIN', 1, %ld, %ld, %ld, "
			"%u, %d, %u, %d, %u, %d, %u, %d, %u, %d, %u, %d, %u, %d)",
			ch->GetPlayerID(), szLogin, dwVnum, iCount, s[0], s[1], s[2],
			t[0], v[0], t[1], v[1], t[2], v[2], t[3], v[3], t[4], v[4], t[5], v[5], t[6], v[6]));

	const bool bOk = pMsg->Get() && pMsg->Get()->uiAffectedRows == 1;
	if (!bOk)
		sys_err("WEBADMIN: item_award insert failed for %s (vnum %u) - item_award_attr_setup.sql not run?", ch->GetName(), dwVnum);
	return bOk;
}

static std::string WebAdminKick(const std::string& stName)
{
	LPDESC pkDesc = DESC_MANAGER::instance().FindByCharacterName(stName.c_str());
	if (!pkDesc || !pkDesc->GetCharacter())
		return "ERR NOT_FOUND";

	sys_log(0, "WEBADMIN: KICK %s", stName.c_str());
	// Same as the /dc GM command
	DESC_MANAGER::instance().DestroyDesc(pkDesc);
	return "OK";
}

static std::string WebAdminGiveItem(const std::string& stName, DWORD dwVnum, int iCount)
{
	LPCHARACTER ch = WebAdminFindLocalPC(stName);
	if (!ch)
		return "ERR NOT_FOUND";

	TItemTable* pTable = ITEM_MANAGER::instance().GetTable(dwVnum);
	if (!pTable)
		return "ERR NO_SUCH_ITEM";

	iCount = MINMAX(1, iCount, ITEM_MAX_COUNT);
	sys_log(0, "WEBADMIN: GIVE_ITEM %s vnum %u count %d", stName.c_str(), dwVnum, iCount);

	// Non-stackable items can't carry a count - hand them out one by one (capped, a typo like
	// "3000 swords" shouldn't flood the storage)
	const bool bStackable = IS_SET(pTable->dwFlags, ITEM_FLAG_STACKABLE);
	const int iPieces = bStackable ? 1 : MIN(iCount, 50);
	const int iPerPiece = bStackable ? iCount : 1;
	int iInInventory = 0, iToMall = 0;
	for (int i = 0; i < iPieces; ++i)
	{
		// AutoGiveItem would drop the item on the ground when there's no room - check first
		// (with a throwaway item of the same vnum, the tab choice depends on the item type)
		// and send it to the Itemshop storage instead
		LPITEM pkProbe = ITEM_MANAGER::instance().CreateItem(dwVnum, 1, 0, false);
		if (!pkProbe)
			return "ERR CREATE_FAILED";
		const bool bRoom = WebAdminFindEmptyCell(ch, pkProbe) != -1;
		M2_DESTROY_ITEM(pkProbe);

		if (bRoom)
		{
			if (!ch->AutoGiveItem(dwVnum, iPerPiece))
				return "ERR CREATE_FAILED";
			iInInventory += iPerPiece;
		}
		else if (WebAdminAwardToMall(ch, dwVnum, iPerPiece, NULL, NULL, NULL))
			iToMall += iPerPiece;
		else
			return (iInInventory || iToMall) ? "ERR PARTIAL" : "ERR NO_SPACE";
	}

	char szResult[64];
	snprintf(szResult, sizeof(szResult), "OK %d %d", iInInventory, iToMall);
	return szResult;
}

// Same tab selection as CHARACTER::AutoGiveItem (WJ_SPLIT_INVENTORY_SYSTEM), -1 = no room
static int WebAdminFindEmptyCell(LPCHARACTER ch, LPITEM item)
{
	if (item->IsDragonSoul())
		return ch->GetEmptyDragonSoulInventory(item);
	if (item->IsSkillBook())
		return ch->GetEmptySkillBookInventory(item->GetSize());
	if (item->IsUpgradeItem())
		return ch->GetEmptyUpgradeItemsInventory(item->GetSize());
	if (item->IsStone())
		return ch->GetEmptyStoneInventory(item->GetSize());
	if (item->IsSandik())
		return ch->GetEmptySandikInventory(item->GetSize());
	return ch->GetEmptyInventory(item->GetSize());
}

// GIVE_ITEM with an exact item layout: no random bonuses (CreateItem without bTryMagic), the 3
// sockets and all 7 attribute slots exactly as given. Socket values: 0 = no socket, 1 = empty
// socket, otherwise the vnum of the spirit stone sitting in it (see ITEM_METIN in
// char_item.cpp). Attribute slots 0-4 are the normal bonuses, 5-6 the rare ("6/7") ones; type 0
// leaves the slot empty. Unlike AutoGiveItem this never drops the item on the ground - a
// hand-made item shouldn't be up for grabs when the inventory is full.
static std::string WebAdminGiveItemEx(const std::string& stName, DWORD dwVnum, int iCount,
		const long* alSockets, const BYTE* abAttrType, const short* asAttrValue)
{
	LPCHARACTER ch = WebAdminFindLocalPC(stName);
	if (!ch)
		return "ERR NOT_FOUND";

	TItemTable* pTable = ITEM_MANAGER::instance().GetTable(dwVnum);
	if (!pTable)
		return "ERR NO_SUCH_ITEM";

	for (int i = 0; i < ITEM_ATTRIBUTE_MAX_NUM; ++i)
		if (abAttrType[i] >= MAX_APPLY_NUM)
			return "ERR BAD_ATTRIBUTE";

	// Only a non-stackable item can carry its own sockets/bonuses - give copies one by one
	iCount = MINMAX(1, iCount, 50);
	sys_log(0, "WEBADMIN: GIVE_ITEM_EX %s vnum %u x%d sockets %ld %ld %ld", stName.c_str(), dwVnum, iCount,
			alSockets[0], alSockets[1], alSockets[2]);

	int iGiven = 0, iToMall = 0;
	for (int n = 0; n < iCount; ++n)
	{
		LPITEM item = ITEM_MANAGER::instance().CreateItem(dwVnum, 1, 0, false);
		if (!item)
			return (iGiven || iToMall) ? "ERR PARTIAL" : "ERR CREATE_FAILED";

		for (int i = 0; i < ITEM_SOCKET_MAX_NUM; ++i)
			item->SetSocket(i, alSockets[i], false);

		for (int i = 0; i < ITEM_ATTRIBUTE_MAX_NUM; ++i)
			item->SetForceAttribute(i, abAttrType[i], abAttrType[i] ? asAttrValue[i] : 0);

		const int iCell = WebAdminFindEmptyCell(ch, item);
		if (iCell == -1)
		{
			// No room: this copy (and every later one) goes to the Itemshop storage with the
			// exact same sockets/bonuses via item_award
			M2_DESTROY_ITEM(item);
			if (WebAdminAwardToMall(ch, dwVnum, 1, alSockets, abAttrType, asAttrValue))
			{
				++iToMall;
				continue;
			}
			if (!iGiven && !iToMall)
				return "ERR NO_SPACE";
			break;
		}

		item->AddToCharacter(ch, TItemPos(item->IsDragonSoul() ? DRAGON_SOUL_INVENTORY : INVENTORY, iCell));
		LogManager::instance().ItemLog(ch, item, "WEBADMIN_GIVE", item->GetName());
		ch->ChatPacket(CHAT_TYPE_COMMAND, "BINARY_DropInfo_Item %u %u", dwVnum, 1u);
		++iGiven;
	}

	char szResult[32];
	snprintf(szResult, sizeof(szResult), "OK %d %d", iGiven, iToMall);
	return szResult;
}

static std::string WebAdminSetLevel(const std::string& stName, int iLevel)
{
	LPCHARACTER ch = WebAdminFindLocalPC(stName);
	if (!ch)
		return "ERR NOT_FOUND";

	iLevel = MINMAX(1, iLevel, gPlayerMaxLevel);
	sys_log(0, "WEBADMIN: SET_LEVEL %s %d -> %d", stName.c_str(), ch->GetLevel(), iLevel);
	// Same as the /advance GM command
	ch->ResetPoint(iLevel);

	char szResult[32];
	snprintf(szResult, sizeof(szResult), "OK %d", ch->GetLevel());
	return szResult;
}

static std::string WebAdminGiveExp(const std::string& stName, long lAmount)
{
	LPCHARACTER ch = WebAdminFindLocalPC(stName);
	if (!ch)
		return "ERR NOT_FOUND";

	if (lAmount <= 0)
		return "ERR BAD_AMOUNT";

	if (ch->GetLevel() >= gPlayerMaxLevel)
		return "ERR MAX_LEVEL";

	sys_log(0, "WEBADMIN: GIVE_EXP %s %ld", stName.c_str(), lAmount);
	// PointChange(POINT_EXP) levels the character up (repeatedly) exactly like killing a mob
	ch->PointChange(POINT_EXP, (int) lAmount, true);

	char szResult[48];
	snprintf(szResult, sizeof(szResult), "OK %d %u", ch->GetLevel(), (unsigned) ch->GetExp());
	return szResult;
}

static std::string WebAdminSpawnMob(const std::string& stName, DWORD dwVnum, int iCount)
{
	LPCHARACTER ch = WebAdminFindLocalPC(stName);
	if (!ch)
		return "ERR NOT_FOUND";

	const CMob* pkMob = CMobManager::instance().Get(dwVnum);
	if (!pkMob)
		return "ERR NO_SUCH_MOB";

	iCount = MINMAX(1, iCount, 20);
	sys_log(0, "WEBADMIN: SPAWN_MOB near %s vnum %u count %d", stName.c_str(), dwVnum, iCount);

	// Same spread as the /mob GM command
	int iSpawned = 0;
	for (int i = 0; i < iCount; ++i)
	{
		if (CHARACTER_MANAGER::instance().SpawnMobRange(dwVnum,
				ch->GetMapIndex(),
				ch->GetX() - number(200, 750),
				ch->GetY() - number(200, 750),
				ch->GetX() + number(200, 750),
				ch->GetY() + number(200, 750),
				true,
				pkMob->m_table.bType == CHAR_TYPE_STONE))
			++iSpawned;
	}

	char szResult[32];
	snprintf(szResult, sizeof(szResult), "OK %d", iSpawned);
	return szResult;
}

// iCount <= 0 or >= the stack size removes the whole item
static std::string WebAdminTakeItem(const std::string& stName, DWORD dwItemID, int iCount)
{
	LPCHARACTER ch = WebAdminFindLocalPC(stName);
	if (!ch)
		return "ERR NOT_FOUND";

	LPITEM item = ITEM_MANAGER::instance().Find(dwItemID);
	if (!item || item->GetOwner() != ch)
		return "ERR NO_SUCH_ITEM";

	if (item->IsExchanging() || item->isLocked())
		return "ERR ITEM_BUSY";

	sys_log(0, "WEBADMIN: TAKE_ITEM %s id %u vnum %u count %d/%u", stName.c_str(), dwItemID,
			item->GetVnum(), iCount, (unsigned) item->GetCount());

	const DWORD dwTakenVnum = item->GetVnum();
	const unsigned uTaken = (iCount > 0 && (DWORD) iCount < item->GetCount()) ? (unsigned) iCount : (unsigned) item->GetCount();

	if (iCount > 0 && (DWORD) iCount < item->GetCount())
	{
		char szHint[64];
		snprintf(szHint, sizeof(szHint), "%s %d", item->GetName(), iCount);
		LogManager::instance().ItemLog(ch, item, "WEBADMIN_TAKE", szHint);
		item->SetCount(item->GetCount() - iCount);
	}
	else
	{
		ITEM_MANAGER::instance().RemoveItem(item, "WEBADMIN_TAKE");
	}

	char szResult[48];
	snprintf(szResult, sizeof(szResult), "OK %u %u", dwTakenVnum, uTaken);
	return szResult;
}

int CInputHandshake::Analyze(LPDESC d, BYTE bHeader, const char * c_pData)
{
	if (bHeader == 10) // 엔터는 무시
		return 0;

	if (bHeader == HEADER_CG_TEXT)
	{
		++c_pData;
		const char * c_pSep;

		if (!(c_pSep = strchr(c_pData, '\n')))	// \n을 찾는다.
			return -1;

#ifdef ENABLE_PORT_SECURITY
		if (IsEmptyAdminPage() || !IsAdminPage(inet_ntoa(d->GetAddr().sin_addr))) // block if adminpage is not set or if not admin
		{
			sys_log(0, "PORT_SECURITY: BLOCK FROM(%s)", d->GetHostName());
			return -1;
		}
#endif

		if (*(c_pSep - 1) == '\r')
			--c_pSep;

		std::string stResult;
		std::string stBuf;
		stBuf.assign(c_pData, 0, c_pSep - c_pData);

		sys_log(0, "SOCKET_CMD: FROM(%s) CMD(%s)", d->GetHostName(), stBuf.c_str());

		if (!stBuf.compare("IS_SERVER_UP"))
		{
			if (g_bNoMoreClient)
				stResult = "NO";
			else
				stResult = "YES";
		}
		else if (!stBuf.compare("IS_PASSPOD_UP"))
		{
			if (g_bNoPasspod)
				stResult = "NO";
			else
				stResult = "YES";
		}
		//else if (!stBuf.compare("SHOWMETHEMONEY"))
		else if (stBuf == g_stAdminPagePassword)
		{
			if (!IsEmptyAdminPage())
			{
				if (!IsAdminPage(inet_ntoa(d->GetAddr().sin_addr)))
				{
					char szTmp[64];
					snprintf(szTmp, sizeof(szTmp), "WEBADMIN : Wrong Connector : %s", inet_ntoa(d->GetAddr().sin_addr));
					stResult += szTmp;
				}
				else
				{
					d->SetAdminMode();
					stResult = "UNKNOWN";
				}
			}
			else
			{
				d->SetAdminMode();
				stResult = "UNKNOWN";
			}
		}
		else if (!stBuf.compare("USER_COUNT"))
		{
			char szTmp[64];

			if (!IsEmptyAdminPage())
			{
				if (!IsAdminPage(inet_ntoa(d->GetAddr().sin_addr)))
				{
					snprintf(szTmp, sizeof(szTmp), "WEBADMIN : Wrong Connector : %s", inet_ntoa(d->GetAddr().sin_addr));
				}
				else
				{
					int iTotal;
					int * paiEmpireUserCount;
					int iLocal;
					DESC_MANAGER::instance().GetUserCount(iTotal, &paiEmpireUserCount, iLocal);
					snprintf(szTmp, sizeof(szTmp), "%d %d %d %d %d", iTotal, paiEmpireUserCount[1], paiEmpireUserCount[2], paiEmpireUserCount[3], iLocal);
				}
			}
			else
			{
				int iTotal;
				int * paiEmpireUserCount;
				int iLocal;
				DESC_MANAGER::instance().GetUserCount(iTotal, &paiEmpireUserCount, iLocal);
				snprintf(szTmp, sizeof(szTmp), "%d %d %d %d %d", iTotal, paiEmpireUserCount[1], paiEmpireUserCount[2], paiEmpireUserCount[3], iLocal);
			}
			stResult += szTmp;
		}
		else if (!stBuf.compare("PLAYER_LIST"))
		{
			if (!IsCallerAllowedOnAdminSocket(d))
			{
				char szTmp[64];
				snprintf(szTmp, sizeof(szTmp), "WEBADMIN : Wrong Connector : %s", inet_ntoa(d->GetAddr().sin_addr));
				stResult = szTmp;
			}
			else
			{
				BuildPlayerListJson(stResult);
			}
		}
		else if (!stBuf.compare(0, 14, "PLAYER_DETAIL "))
		{
			if (!IsCallerAllowedOnAdminSocket(d))
			{
				char szTmp[64];
				snprintf(szTmp, sizeof(szTmp), "WEBADMIN : Wrong Connector : %s", inet_ntoa(d->GetAddr().sin_addr));
				stResult = szTmp;
			}
			else
			{
				std::string stName = stBuf.substr(14, CHARACTER_NAME_MAX_LEN);
				LPCHARACTER ch = CHARACTER_MANAGER::instance().FindPC(stName.c_str());

				if (!ch || !ch->GetDesc())
					stResult = "{\"found\":false}";
				else
					BuildPlayerDetailJson(stResult, ch);
			}
		}
		else if (!stBuf.compare("CHECK_P2P_CONNECTIONS"))
		{
			std::ostringstream oss(std::ostringstream::out);
			
			oss << "P2P CONNECTION NUMBER : " << P2P_MANAGER::instance().GetDescCount() << "\n";
			std::string hostNames;
			P2P_MANAGER::Instance().GetP2PHostNames(hostNames);
			oss << hostNames;
			stResult = oss.str();
			TPacketGGCheckAwakeness packet;
			packet.bHeader = HEADER_GG_CHECK_AWAKENESS;

			P2P_MANAGER::instance().Send(&packet, sizeof(packet));
		}
		else if (!stBuf.compare("PACKET_INFO"))
		{
			m_pMainPacketInfo->Log("packet_info.txt");
			stResult = "OK";
		}
		else if (!stBuf.compare("PROFILE"))
		{
			CProfiler::instance().Log("profile.txt");
			stResult = "OK";
		}
		//gift notify delete command
		else if (!stBuf.compare(0,15,"DELETE_AWARDID "))
			{
				char szTmp[64];
				std::string msg = stBuf.substr(15,26);	// item_award의 id범위?
				
				TPacketDeleteAwardID p;
				p.dwID = (DWORD)(atoi(msg.c_str()));
				snprintf(szTmp,sizeof(szTmp),"Sent to DB cache to delete ItemAward, id: %d",p.dwID);
				//sys_log(0,"%d",p.dwID);
				// strlcpy(p.login, msg.c_str(), sizeof(p.login));
				db_clientdesc->DBPacket(HEADER_GD_DELETE_AWARDID, 0, &p, sizeof(p));
				stResult += szTmp;
			}
		else
		{
			stResult = "UNKNOWN";
			
			if (d->IsAdminMode())
			{
				// 어드민 명령들
				if (!stBuf.compare(0, 7, "NOTICE "))
				{
					// was 50 - long enough for a real announcement, still well under CHAT_MAX_LEN
					std::string msg = stBuf.substr(7, 250);
					LogManager::instance().CharLog(0, 0, 0, 1, "NOTICE", msg.c_str(), d->GetHostName());
					BroadcastNotice(msg.c_str());
					stResult = "OK";
				}
				else if (!stBuf.compare("CLOSE_PASSPOD"))
				{
					g_bNoPasspod = true;
					stResult += "CLOSE_PASSPOD";
				}
				else if (!stBuf.compare("OPEN_PASSPOD"))
				{
					g_bNoPasspod = false;
					stResult += "OPEN_PASSPOD";
				}
				else if (!stBuf.compare("SHUTDOWN"))
				{
					LogManager::instance().CharLog(0, 0, 0, 2, "SHUTDOWN", "", d->GetHostName());
					TPacketGGShutdown p;
					p.bHeader = HEADER_GG_SHUTDOWN;
					P2P_MANAGER::instance().Send(&p, sizeof(TPacketGGShutdown));
					sys_err("Accept shutdown command from %s.", d->GetHostName());
#ifdef ENABLE_MAINTENANCE_SYSTEM
					Shutdown(global_time_maintenance);
#else
					Shutdown(10);
#endif
				}
				else if (!stBuf.compare("SHUTDOWN_ONLY"))
				{
					LogManager::instance().CharLog(0, 0, 0, 2, "SHUTDOWN", "", d->GetHostName());
					sys_err("Accept shutdown only command from %s.", d->GetHostName());
#ifdef ENABLE_MAINTENANCE_SYSTEM
					Shutdown(global_time_maintenance);
#else
					Shutdown(10);
#endif
				}
				else if (!stBuf.compare(0, 3, "DC "))
				{
					std::string msg = stBuf.substr(3, LOGIN_MAX_LEN);

dev_log(LOG_DEB0, "DC : '%s'", msg.c_str());

					TPacketGGDisconnect pgg;

					pgg.bHeader = HEADER_GG_DISCONNECT;
					strlcpy(pgg.szLogin, msg.c_str(), sizeof(pgg.szLogin));

					P2P_MANAGER::instance().Send(&pgg, sizeof(TPacketGGDisconnect));

					// delete login key
					{
						TPacketDC p;
						strlcpy(p.login, msg.c_str(), sizeof(p.login));
						db_clientdesc->DBPacket(HEADER_GD_DC, 0, &p, sizeof(p));
					}
				}
				else if (!stBuf.compare(0, 10, "RELOAD_CRC"))
				{
					LoadValidCRCList();

					BYTE bHeader = HEADER_GG_RELOAD_CRC_LIST;
					P2P_MANAGER::instance().Send(&bHeader, sizeof(BYTE));
					stResult = "OK";
				}
				else if (!stBuf.compare(0, 20, "CHECK_CLIENT_VERSION"))
				{
					CheckClientVersion();

					BYTE bHeader = HEADER_GG_CHECK_CLIENT_VERSION;
					P2P_MANAGER::instance().Send(&bHeader, sizeof(BYTE));
					stResult = "OK";
				}
				else if (!stBuf.compare(0, 6, "RELOAD"))
				{
					if (stBuf.size() == 6)
					{
						LoadStateUserCount();
						db_clientdesc->DBPacket(HEADER_GD_RELOAD_PROTO, 0, NULL, 0);
						DBManager::instance().LoadDBString();
					}
					else
					{
						char c = stBuf[7];

						switch (LOWER(c))
						{
							case 'u':
								LoadStateUserCount();
								break;

							case 'p':
								db_clientdesc->DBPacket(HEADER_GD_RELOAD_PROTO, 0, NULL, 0);
								break;

							case 's':
								DBManager::instance().LoadDBString();
								break;

							case 'q':
								quest::CQuestManager::instance().Reload();
								break;

							case 'f':
								fishing::Initialize();
								break;

							case 'a':
								db_clientdesc->DBPacket(HEADER_GD_RELOAD_ADMIN, 0, NULL, 0);
								sys_log(0, "Reloading admin infomation.");
								break;
						}
					}
				}
				else if (!stBuf.compare(0, 6, "EVENT "))
				{
					std::istringstream is(stBuf);
					std::string strEvent, strFlagName;
					long lValue;
					is >> strEvent >> strFlagName >> lValue;

					if (!is.fail())
					{
						sys_log(0, "EXTERNAL EVENT FLAG name %s value %d", strFlagName.c_str(), lValue);
						quest::CQuestManager::instance().RequestSetEventFlag(strFlagName, lValue);
						stResult = "EVENT FLAG CHANGE ";
						stResult += strFlagName;
					}
					else
					{
						stResult = "EVENT FLAG FAIL";
					}
				}
				// BLOCK_CHAT
				else if (!stBuf.compare(0, 11, "BLOCK_CHAT "))
				{
					std::istringstream is(stBuf);
					std::string strBlockChat, strCharName;
					long lDuration;
					is >> strBlockChat >> strCharName >> lDuration;

					if (!is.fail())
					{
						sys_log(0, "EXTERNAL BLOCK_CHAT name %s duration %d", strCharName.c_str(), lDuration);

						do_block_chat(NULL, const_cast<char*>(stBuf.c_str() + 11), 0, 0);

						stResult = "BLOCK_CHAT ";
						stResult += strCharName;
					}
					else
					{
						stResult = "BLOCK_CHAT FAIL";
					}
				}
				// END_OF_BLOCK_CHAT
				else if (!stBuf.compare(0, 12, "PRIV_EMPIRE "))
				{
					int	empire, type, value, duration;
					std::istringstream is(stBuf);
					std::string strPrivEmpire;
					is >> strPrivEmpire >> empire >> type >> value >> duration;

					// 최대치 10배
					value = MINMAX(0, value, 1000);
					stResult = "PRIV_EMPIRE FAIL";

					if (!is.fail())
					{
						// check parameter
						if (empire < 0 || 3 < empire);
						else if (type < 1 || 4 < type);
						else if (value < 0);
						else if (duration < 0);
						else
						{
							stResult = "PRIV_EMPIRE SUCCEED";

							// 시간 단위로 변경
							duration = duration * (60 * 60);

							sys_log(0, "_give_empire_privileage(empire=%d, type=%d, value=%d, duration=%d) by web", 
									empire, type, value, duration);
							CPrivManager::instance().RequestGiveEmpirePriv(empire, type, value, duration);
						}
					}
				}
				// Webadmin write commands - helpers above Analyze()
				else if (!stBuf.compare(0, 5, "KICK "))
				{
					std::istringstream is(stBuf.substr(5));
					std::string strName;
					is >> strName;
					stResult = is.fail() ? "ERR SYNTAX" : WebAdminKick(strName);
				}
				else if (!stBuf.compare(0, 10, "GIVE_ITEM "))
				{
					std::istringstream is(stBuf.substr(10));
					std::string strName;
					DWORD dwVnum = 0;
					int iCount = 0;
					is >> strName >> dwVnum >> iCount;
					stResult = is.fail() ? "ERR SYNTAX" : WebAdminGiveItem(strName, dwVnum, iCount);
				}
				else if (!stBuf.compare(0, 7, "NOTIFY "))
				{
					const std::string stRest = stBuf.substr(7);
					const size_t sep = stRest.find(' ');
					LPCHARACTER ch = sep == std::string::npos ? NULL : WebAdminFindLocalPC(stRest.substr(0, sep));
					if (sep == std::string::npos)
						stResult = "ERR SYNTAX";
					else if (!ch)
						stResult = "ERR NOT_FOUND";
					else
					{
						std::string stText = stRest.substr(sep + 1);
						size_t start = 0;
						while (start <= stText.size())
						{
							size_t end = stText.find("||", start);
							if (end == std::string::npos)
								end = stText.size();
							const std::string stLine = stText.substr(start, MIN(end - start, (size_t) 250));
							WebAdminWhisper(ch, stLine.c_str());
							start = end + 2;
						}
						stResult = "OK";
					}
				}
				else if (!stBuf.compare(0, 13, "GIVE_ITEM_EX "))
				{
					// GIVE_ITEM_EX <name> <vnum> <count> <socket0..2> <attrType0> <attrValue0> ... <attrType6> <attrValue6>
					std::istringstream is(stBuf.substr(13));
					std::string strName;
					DWORD dwVnum = 0;
					int iCount = 0;
					long alSockets[ITEM_SOCKET_MAX_NUM] = {};
					BYTE abAttrType[ITEM_ATTRIBUTE_MAX_NUM] = {};
					short asAttrValue[ITEM_ATTRIBUTE_MAX_NUM] = {};
					is >> strName >> dwVnum >> iCount;
					for (int i = 0; i < ITEM_SOCKET_MAX_NUM; ++i)
						is >> alSockets[i];
					for (int i = 0; i < ITEM_ATTRIBUTE_MAX_NUM; ++i)
					{
						// read the type as an int - ">> BYTE" would read a single character
						int iType = 0;
						is >> iType >> asAttrValue[i];
						abAttrType[i] = (BYTE) MINMAX(0, iType, 255);
					}
					stResult = is.fail() ? "ERR SYNTAX"
						: WebAdminGiveItemEx(strName, dwVnum, iCount, alSockets, abAttrType, asAttrValue);
				}
				else if (!stBuf.compare(0, 10, "SET_LEVEL "))
				{
					std::istringstream is(stBuf.substr(10));
					std::string strName;
					int iLevel = 0;
					is >> strName >> iLevel;
					stResult = is.fail() ? "ERR SYNTAX" : WebAdminSetLevel(strName, iLevel);
				}
				else if (!stBuf.compare(0, 9, "GIVE_EXP "))
				{
					std::istringstream is(stBuf.substr(9));
					std::string strName;
					long lAmount = 0;
					is >> strName >> lAmount;
					stResult = is.fail() ? "ERR SYNTAX" : WebAdminGiveExp(strName, lAmount);
				}
				else if (!stBuf.compare(0, 10, "SPAWN_MOB "))
				{
					std::istringstream is(stBuf.substr(10));
					std::string strName;
					DWORD dwVnum = 0;
					int iCount = 0;
					is >> strName >> dwVnum >> iCount;
					stResult = is.fail() ? "ERR SYNTAX" : WebAdminSpawnMob(strName, dwVnum, iCount);
				}
				else if (!stBuf.compare(0, 10, "TAKE_ITEM "))
				{
					std::istringstream is(stBuf.substr(10));
					std::string strName;
					DWORD dwItemID = 0;
					int iCount = 0;
					is >> strName >> dwItemID >> iCount;
					stResult = is.fail() ? "ERR SYNTAX" : WebAdminTakeItem(strName, dwItemID, iCount);
				}
#ifdef ENABLE_EVENT_MANAGER
				else if (stBuf == "EVENT_RELOAD")
				{
					// Same as the GM's "/event_manager update": the db core re-reads
					// player.event_table and pushes it to every core and online player,
					// so one core is enough - the webadmin stops at the first "OK".
					const BYTE subHeader = EVENT_MANAGER_UPDATE;
					db_clientdesc->DBPacket(HEADER_GD_EVENT_MANAGER, 0, &subHeader, sizeof(BYTE));
					stResult = "OK";
				}
#endif
			}
		}

		sys_log(1, "TEXT %s RESULT %s", stBuf.c_str(), stResult.c_str());
		stResult += "\n";
		d->Packet(stResult.c_str(), stResult.length());
		return (c_pSep - c_pData) + 1;
	}
	else if (bHeader == HEADER_CG_MARK_LOGIN)
	{
		if (!guild_mark_server)
		{
			// 끊어버려! - 마크 서버가 아닌데 마크를 요청하려고?
			sys_err("Guild Mark login requested but i'm not a mark server!");
			d->SetPhase(PHASE_CLOSE);
			return 0;
		}

		// 무조건 인증 --;
		sys_log(0, "MARK_SERVER: Login");
		d->SetPhase(PHASE_LOGIN);
		return 0;
	}
	else if (bHeader == HEADER_CG_STATE_CHECKER)
	{
		if (d->isChannelStatusRequested()) {
			return 0;
		}
		d->SetChannelStatusRequested(true);
		db_clientdesc->DBPacket(HEADER_GD_REQUEST_CHANNELSTATUS, d->GetHandle(), NULL, 0);
	}
	else if (bHeader == HEADER_CG_PONG)
		Pong(d);
	else if (bHeader == HEADER_CG_HANDSHAKE)
		Handshake(d, c_pData);
#ifdef _IMPROVED_PACKET_ENCRYPTION_
	else if (bHeader == HEADER_CG_KEY_AGREEMENT)
	{
		// Send out the key agreement completion packet first
		// to help client to enter encryption mode
		d->SendKeyAgreementCompleted();
		// Flush socket output before going encrypted
		d->ProcessOutput();

		TPacketKeyAgreement* p = (TPacketKeyAgreement*)c_pData;
		if (!d->IsCipherPrepared())
		{
			sys_err ("Cipher isn't prepared. %s maybe a Hacker.", inet_ntoa(d->GetAddr().sin_addr));
			d->DelayedDisconnect(5);
			return 0;
		}
		if (d->FinishHandshake(p->wAgreedLength, p->data, p->wDataLength)) {
			// Handshaking succeeded
			if (g_bAuthServer) {
				d->SetPhase(PHASE_AUTH);
			} else {
				d->SetPhase(PHASE_LOGIN);
			}
		} else {
			sys_log(0, "[CInputHandshake] Key agreement failed: al=%u dl=%u",
				p->wAgreedLength, p->wDataLength);
			d->SetPhase(PHASE_CLOSE);
		}
	}
#endif // _IMPROVED_PACKET_ENCRYPTION_
	else
		sys_err("Handshake phase does not handle packet %d (fd %d)", bHeader, d->GetSocket());

	return 0;
}


