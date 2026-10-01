#include "stdafx.h"
#include "constants.h"
#include "desc.h"
#include "db.h"
#include "utils.h"
#include "config.h"
#include "desc_client.h"
#include "desc_manager.h"
#include "char.h"
#include "char_manager.h"
#include "motion.h"
#include "packet.h"
#include "affect.h"
#include "pvp.h"
#include "cmd.h"
#include "start_position.h"
#include "party.h"
#include "guild_manager.h"
#include "p2p.h"
#include "dungeon.h"
#include "messenger_manager.h"
#include "war_map.h"
#include "questmanager.h"
#include "item_manager.h"
#include "monarch.h"
#include "mob_manager.h"
#include "dev_log.h"
#include "item.h"
#include "log.h"
#include "../../common/VnumHelper.h"
#include "guild.h"
#include "empire_text_convert.h"
#include "castle.h"
#include "locale_service.h"
#include <string>
#include "maintenance.h"
#include "input.h"
extern long int global_time_maintenance = 0;

MaintenanceManager::MaintenanceManager()	{	}
MaintenanceManager::~MaintenanceManager()	{	}

EVENTINFO(maintenanceShutdown_event_data)
{
	long end_time; // absolute get_global_time() moment the maintenance begins

	maintenanceShutdown_event_data()
		: end_time(0)
	{
	}
};
static LPEVENT vegas_maintenance_check = NULL;

/*********
* How many seconds before the announced moment (the banner reaching 00:00:00) the cores are shut down.
* 0 = exactly when the banner runs out. The original package used 45 here, which made the server drop
* 45 seconds before the time the GM typed in.
*/
#define MAINTENANCE_CHECKTIME_SHUTDOWN	0

/*********
* Settings min/max character/second for check in maintenance
*/
#define MAINTENANCE_TEXT_MAX_CHAR 70 // Maximum characters that are allowed in reason maintenance
#define MAINTENANCE_TEXT_MIN_CHAR 5 // Minimum characters that are need in reason maintenance

#define MAINTENANCE_TIME_LEFT_MIN 15 // Seconds minimum how long they are allowed to start maintenance = 30 second
#define MAINTENANCE_TIME_LEFT_MAX 604800 // Seconds maximum how long they are allowed to start maintenance = 1 week

#define MAINTENANCE_TIME_DURATION_MIN 300 // Seconds minimum how long duration for back server online = 5 minute
#define MAINTENANCE_TIME_DURATION_MAX 86400 // Seconds maximum how long duration for back server online = 1 Day

/*********
* Delay before sending the maintenance banner on login. Sending it the instant
* Entergame() runs races the client's own enter-game/phase-switch handling
* (the banner packet can arrive before the client's game UI module exists to
* receive it), so it gets queued a couple of seconds to let that settle first.
*/
#define MAINTENANCE_LOGIN_CHECK_DELAY 3

/*********
* Table with translate for all informations, have careful with %s or %u when you try to translate in other language.
*/
extern const char* maintenance_translate[] = {"-----------------------------------------------------------------------------------",
												"<Syntax> Wrong command! Use: /maintenance 2h 30m",
												"<Syntax> Example: d (day) | h (hour) | m (minutes) | s (second)",
												"<Syntax> Maximum %u second are allowed for left time!",
												"<Syntax> Maximum %u second are allowed for duration time!",
												"<Technical Maintenance> The server will be turned off in %u second(s)!",
												"<Technical Maintenance> Predicted length of maintenance: %u second(s)!",
												"<Syntax> Command wrong! Use: /m_text enable <reason>",
												"<Syntax> Example: /m_text enable Hello player, need to make this maintenance for solve problem with spider dungeon 3.",
												"<Syntax> Maximum %u characters are allowed for reason!",
												"<Syntax> You must enter at least %u characters!",
												"<Technical Maintenance> The reason was successfully removed!",
												"<Technical Maintenance> The reason was successfully added!",
												"<Technical Maintenance> Reason added: %s",
												"<Technical Maintenance> It was stopped succes!",
												"<Syntax> Minimum %u second need for left time!",
												"<Syntax> Minimum %u second need duration time!",
												"<Technical Maintenance> Could not save the schedule to player.maintenance (see syserr)!",
												"<Player Login> Syntax: /player_login on | off | status",
												"<Player Login> Players can log in again.",
												"<Player Login> Players are locked out now - only GM accounts can log in.",
												"<Player Login> Could not save the setting - run player_login_setup.sql on the player DB (see syserr)!",
												"<Player Login> Currently OPEN: players can log in.",
												"<Player Login> Currently LOCKED: only GM accounts can log in. Use /player_login on to open it."
											};

/*********
* player.maintenance holds a single row:
*   time     - ABSOLUTE moment (get_global_time() scale) the maintenance begins, 0 = nothing scheduled
*   duration - predicted length of the maintenance in seconds
*   reason   - banner text ('//' stands for a space)
* `time` used to be a "seconds left" value that a per-second event kept rewriting. That froze the moment
* the event stopped (core restart/crash, a second /maintenance orphaning the first event, core lag) and
* every login then restarted the banner from the frozen value, so it never ran out. An absolute moment
* cannot freeze: once it lies in the past the row is recognised as stale and cleared.
*/
struct TMaintenanceRow
{
	long		end_time;
	long		duration;
	std::string	reason;

	TMaintenanceRow() : end_time(0), duration(0), reason("no_reason") {}
};

static bool LoadMaintenanceRow(TMaintenanceRow& rRow)
{
	std::unique_ptr<SQLMsg> pMsg(DBManager::instance().DirectQuery("SELECT time,duration,reason FROM player.maintenance LIMIT 1"));

	if (!pMsg->Get() || !pMsg->Get()->pSQLResult || pMsg->Get()->uiNumRows == 0)
		return false;

	MYSQL_ROW row = mysql_fetch_row(pMsg->Get()->pSQLResult);

	if (!row)
		return false;

	rRow.end_time = 0;
	rRow.duration = 0;

	if (row[0])
		str_to_number(rRow.end_time, row[0]);

	if (row[1])
		str_to_number(rRow.duration, row[1]);

	rRow.reason = row[2] ? row[2] : "no_reason";
	return true;
}

static void ResetMaintenanceRow()
{
	std::unique_ptr<SQLMsg> pMsg(DBManager::instance().DirectQuery("UPDATE player.maintenance SET time = 0, duration = 0, reason = 'no_reason'"));
}

// Writes the schedule and reads it back: the blind UPDATE silently does nothing when the table is empty or
// the write fails, which would leave the GM believing a maintenance is scheduled when none is.
static bool SaveMaintenanceSchedule(long lEndTime, long lDuration)
{
	{
		std::unique_ptr<SQLMsg> pMsg(DBManager::instance().DirectQuery("UPDATE player.maintenance SET time = %ld, duration = %ld", lEndTime, lDuration));
	}

	TMaintenanceRow kRow;

	if (!LoadMaintenanceRow(kRow))
	{
		// no row to update - seed the single row the blind UPDATEs elsewhere rely on
		std::unique_ptr<SQLMsg> pMsg(DBManager::instance().DirectQuery("INSERT INTO player.maintenance (time, duration, reason) VALUES (%ld, %ld, 'no_reason')", lEndTime, lDuration));

		if (!LoadMaintenanceRow(kRow))
			return false;
	}

	return kRow.end_time == lEndTime && kRow.duration == lDuration;
}

EVENTFUNC(maintenanceDown_event)
{
	maintenanceShutdown_event_data* info = dynamic_cast<maintenanceShutdown_event_data*>(event->info);

	if (info == NULL)
	{
		sys_err("maintenanceDown_event> <Factor> Time 0 - Error");
		vegas_maintenance_check = NULL;
		return 0;
	}

	// Wall-clock based on purpose: counting pulses falls behind the banner (which runs on the client's
	// clock) whenever the core lags.
	if (info->end_time - get_global_time() > MAINTENANCE_CHECKTIME_SHUTDOWN)
		return passes_per_sec;

	// The schedule may have been cancelled or replaced from another core since this event was armed - the
	// table is the source of truth, so look before pulling the plug.
	TMaintenanceRow kRow;

	if (LoadMaintenanceRow(kRow) && kRow.end_time != info->end_time)
	{
		if (kRow.end_time > get_global_time() && kRow.duration > 0)
		{
			info->end_time = kRow.end_time;
			return passes_per_sec;
		}

		vegas_maintenance_check = NULL;
		return 0;
	}

	ResetMaintenanceRow();

	// The server is going down for maintenance: after the restart normal players stay out until a GM opens
	// the gate with /player_login on (GM accounts can always log in).
	MaintenanceManager::instance().SetPlayerLoginOpen(false);

	TPacketGGShutdown p;
	p.bHeader = HEADER_GG_SHUTDOWN;
	P2P_MANAGER::instance().Send(&p, sizeof(TPacketGGShutdown));
	g_bNoMoreClient = true;
	Shutdown(MAINTENANCE_CHECKTIME_SHUTDOWN);

	vegas_maintenance_check = NULL;
	return 0;
}

// Only ever one countdown: an earlier one that is still running can no longer be cancelled once its
// pointer is overwritten, and would keep firing (and shut the core down) on the old schedule.
static void ArmMaintenanceEvent(long lEndTime)
{
	if (vegas_maintenance_check)
		event_cancel(&vegas_maintenance_check);

	maintenanceShutdown_event_data* info = AllocEventInfo<maintenanceShutdown_event_data>();
	info->end_time = lEndTime;
	vegas_maintenance_check = event_create(maintenanceDown_event, info, 1);
}

void StartMaintenance(long lEndTime)
{
	if (g_bNoMoreClient)
	{
		thecore_shutdown();
		return;
	}

	CWarMapManager::instance().OnShutdown();

	ArmMaintenanceEvent(lEndTime);
}

void MaintenanceManager::Send_DisableSecurity(LPCHARACTER ch)
{
	if (vegas_maintenance_check)
		event_cancel(&vegas_maintenance_check);

	ResetMaintenanceRow();

	ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT(maintenance_translate[14]));
}

void MaintenanceManager::Send_ActiveMaintenance(LPCHARACTER ch, long int time_maintenance, long int duration_maintenance)
{
	if (NULL == ch)
		return;

	if (!ch->IsPC())
		return;

	if (!time_maintenance || time_maintenance < 1)
	{
		ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT(maintenance_translate[0]));
		ch->ChatPacket(CHAT_TYPE_NOTICE, LC_TEXT(maintenance_translate[1]));
		ch->ChatPacket(CHAT_TYPE_NOTICE, LC_TEXT(maintenance_translate[2]));
		return;
	}

	else if (!duration_maintenance || duration_maintenance < 1)
	{
		ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT(maintenance_translate[0]));
		ch->ChatPacket(CHAT_TYPE_NOTICE, LC_TEXT(maintenance_translate[1]));
		ch->ChatPacket(CHAT_TYPE_NOTICE, LC_TEXT(maintenance_translate[2]));
		return;
	}

	else if (time_maintenance < MAINTENANCE_TIME_LEFT_MIN)
	{
		ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT(maintenance_translate[0]));
		ch->ChatPacket(CHAT_TYPE_NOTICE, LC_TEXT(maintenance_translate[15]), MAINTENANCE_TIME_LEFT_MIN);
		return;
	}

	else if (time_maintenance > MAINTENANCE_TIME_LEFT_MAX)
	{
		ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT(maintenance_translate[0]));
		ch->ChatPacket(CHAT_TYPE_NOTICE, LC_TEXT(maintenance_translate[3]), MAINTENANCE_TIME_LEFT_MAX);
		return;
	}

	else if (duration_maintenance < MAINTENANCE_TIME_DURATION_MIN)
	{
		ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT(maintenance_translate[0]));
		ch->ChatPacket(CHAT_TYPE_NOTICE, LC_TEXT(maintenance_translate[16]), MAINTENANCE_TIME_DURATION_MIN);
		return;
	}

	else if (duration_maintenance > MAINTENANCE_TIME_DURATION_MAX)
	{
		ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT(maintenance_translate[0]));
		ch->ChatPacket(CHAT_TYPE_NOTICE, LC_TEXT(maintenance_translate[4]), MAINTENANCE_TIME_DURATION_MAX);
		return;
	}
	else
	{
		const long lEndTime = get_global_time() + time_maintenance;

		if (!SaveMaintenanceSchedule(lEndTime, duration_maintenance))
		{
			ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT(maintenance_translate[0]));
			ch->ChatPacket(CHAT_TYPE_NOTICE, LC_TEXT(maintenance_translate[17]));
			return;
		}

		global_time_maintenance = time_maintenance;

		StartMaintenance(lEndTime);

		ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT(maintenance_translate[0]));
		ch->ChatPacket(CHAT_TYPE_NOTICE, LC_TEXT(maintenance_translate[5]), time_maintenance);
		ch->ChatPacket(CHAT_TYPE_NOTICE, LC_TEXT(maintenance_translate[6]), duration_maintenance);
	}
}

void MaintenanceManager::Send_Text(LPCHARACTER ch, const char* reason)
{
	if (NULL == ch)
		return;

	if (!ch->IsPC())
		return;

	if (!*reason)
	{
		ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT(maintenance_translate[0]));
		ch->ChatPacket(CHAT_TYPE_NOTICE, LC_TEXT(maintenance_translate[7]));
		ch->ChatPacket(CHAT_TYPE_NOTICE, LC_TEXT(maintenance_translate[8]));
		return;
	}

	if (strlen(reason) > MAINTENANCE_TEXT_MAX_CHAR)
	{
		ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT(maintenance_translate[0]));
		ch->ChatPacket(CHAT_TYPE_NOTICE, LC_TEXT(maintenance_translate[9]), MAINTENANCE_TEXT_MAX_CHAR);
		return;
	}

	if (strlen(reason) < MAINTENANCE_TEXT_MIN_CHAR && !!strcmp(reason, "rmf"))
	{
		ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT(maintenance_translate[0]));
		ch->ChatPacket(CHAT_TYPE_NOTICE, LC_TEXT(maintenance_translate[10]), MAINTENANCE_TEXT_MIN_CHAR);
		return;
	}

	if (!strcmp(reason, "rmf"))
	{
		char sReason[128];
		snprintf(sReason, sizeof(sReason), "UPDATE player.maintenance SET reason = 'no_reason'");
		std::unique_ptr<SQLMsg> pReason(DBManager::instance().DirectQuery(sReason));

		ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT(maintenance_translate[0]));
		ch->ChatPacket(CHAT_TYPE_NOTICE, LC_TEXT(maintenance_translate[11]));
		return;
	}
			char szEscapedReason[256];
			DBManager::instance().EscapeString(szEscapedReason, sizeof(szEscapedReason), reason, strlen(reason));

			char sReason[512];
			snprintf(sReason, sizeof(sReason), "UPDATE player.maintenance SET `reason` = replace(\"%s\",' ','//')", szEscapedReason);
			std::unique_ptr<SQLMsg> reasonReplace(DBManager::instance().DirectQuery("%s", sReason));

			ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT(maintenance_translate[0]));
			ch->ChatPacket(CHAT_TYPE_NOTICE, LC_TEXT(maintenance_translate[12]));
			ch->ChatPacket(CHAT_TYPE_NOTICE, LC_TEXT(maintenance_translate[13]), reason);
}

void MaintenanceManager::Send_UpdateBinary(LPCHARACTER ch)
{
	if (NULL == ch)
		return;

	if (!ch->IsPC())
		return;

	TMaintenanceRow kRow;

	if (!LoadMaintenanceRow(kRow))
		return;

	// The client counts down from what it is told here, so hand it the time that is really left now.
	const long lLeft = kRow.end_time - get_global_time();

	if (lLeft <= 0 || kRow.duration <= 0)
		return;

	ch->ChatPacket(CHAT_TYPE_COMMAND, "BINARY_Update_Maintenance %ld %ld %s", lLeft, kRow.duration, kRow.reason.c_str());
}

EVENTINFO(maintenanceLoginCheck_event_data)
{
	DWORD dwPID;

	maintenanceLoginCheck_event_data()
		: dwPID(0)
	{
	}
};

EVENTFUNC(maintenanceLoginCheck_event)
{
	maintenanceLoginCheck_event_data* info = dynamic_cast<maintenanceLoginCheck_event_data*>(event->info);

	if (info == NULL)
	{
		sys_err("maintenanceLoginCheck_event> <Factor> Null pointer");
		return 0;
	}

	LPCHARACTER ch = CHARACTER_MANAGER::instance().FindByPID(info->dwPID);

	if (ch)
		MaintenanceManager::instance().Send_UpdateBinary(ch);

	return 0;
}

void MaintenanceManager::Send_CheckTable(LPCHARACTER ch)
{
	if (NULL == ch)
		return;

	if (!ch->IsPC())
		return;

	// A GM who logs in while the gate is shut is told so - forgetting to open it after the maintenance
	// would otherwise only show up as players complaining.
	if (ch->GetGMLevel() > GM_PLAYER && !IsPlayerLoginOpen())
		ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT(maintenance_translate[23]));

	TMaintenanceRow kRow;

	if (!LoadMaintenanceRow(kRow))
		return;

	if (kRow.end_time <= 0 && kRow.duration <= 0)
		return;

	if (kRow.end_time <= get_global_time() || kRow.duration <= 0)
	{
		// Leftover of a maintenance whose time is up (or of a row written when `time` still meant "seconds
		// left"): drop it, otherwise every login would show a banner for something that is long over.
		ResetMaintenanceRow();
		return;
	}

	// The countdown that shuts the core down lives in memory only - after a core restart it is gone while
	// the schedule is still in the table, so pick it up again from here.
	if (!vegas_maintenance_check)
		ArmMaintenanceEvent(kRow.end_time);

	maintenanceLoginCheck_event_data* info = AllocEventInfo<maintenanceLoginCheck_event_data>();
	info->dwPID = ch->GetPlayerID();
	event_create(maintenanceLoginCheck_event, info, MAINTENANCE_LOGIN_CHECK_DELAY * passes_per_sec);
}

/*********
* Login gate for normal players. The state lives in player.login_gate (one row, players_open 1/0) so every
* core - and the auth server - sees the same answer at once and a restart keeps it. The maintenance
* shutdown shuts the gate; `/player_login on` opens it again. It is only checked on a fresh login (auth
* server), never when an already logged-in player warps to a map served by another core.
*/

// Fails OPEN when the table is missing or unreadable, so a broken setup can never lock everybody out.
bool MaintenanceManager::IsPlayerLoginOpen()
{
	std::unique_ptr<SQLMsg> pMsg(DBManager::instance().DirectQuery("SELECT players_open FROM player.login_gate WHERE id = 1"));

	if (pMsg->uiSQLErrno || !pMsg->Get() || !pMsg->Get()->pSQLResult || pMsg->Get()->uiNumRows == 0)
		return true;

	MYSQL_ROW row = mysql_fetch_row(pMsg->Get()->pSQLResult);

	return !row || !row[0] || atoi(row[0]) != 0;
}

bool MaintenanceManager::SetPlayerLoginOpen(bool bOpen)
{
	std::unique_ptr<SQLMsg> pMsg(DBManager::instance().DirectQuery("INSERT INTO player.login_gate (id, players_open) VALUES (1, %d) ON DUPLICATE KEY UPDATE players_open = VALUES(players_open)", bOpen ? 1 : 0));

	return pMsg->uiSQLErrno == 0;
}

// Same idea as the GM check at character select, but by account: the auth server has no GM list in memory
// (it never boots), so ask common.gmlist directly. Only entries the DB core would load as a GM count.
bool MaintenanceManager::IsAccountAllowed(const char* c_pszLogin)
{
	if (IsPlayerLoginOpen())
		return true;

	char szLogin[LOGIN_MAX_LEN * 2 + 1];
	DBManager::instance().EscapeString(szLogin, sizeof(szLogin), c_pszLogin, strlen(c_pszLogin));

	std::unique_ptr<SQLMsg> pMsg(DBManager::instance().DirectQuery("SELECT 1 FROM common.gmlist WHERE LOWER(mAccount) = LOWER('%s') AND mAuthority IN ('IMPLEMENTOR','GOD','HIGH_WIZARD','LOW_WIZARD','WIZARD') LIMIT 1", szLogin));

	// can't tell (no access to common.gmlist?) - let them in rather than lock the GMs out of their own server
	if (pMsg->uiSQLErrno)
	{
		sys_err("MaintenanceManager::IsAccountAllowed> cannot read common.gmlist, letting %s in", c_pszLogin);
		return true;
	}

	return pMsg->Get() && pMsg->Get()->uiNumRows > 0;
}

void MaintenanceManager::Send_PlayerLogin(LPCHARACTER ch, const char* c_pszArg)
{
	if (NULL == ch)
		return;

	if (!ch->IsPC())
		return;

	if (!strcasecmp(c_pszArg, "on") || !strcasecmp(c_pszArg, "off"))
	{
		const bool bOpen = !strcasecmp(c_pszArg, "on");

		ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT(maintenance_translate[0]));

		if (!SetPlayerLoginOpen(bOpen))
		{
			ch->ChatPacket(CHAT_TYPE_NOTICE, LC_TEXT(maintenance_translate[21]));
			return;
		}

		ch->ChatPacket(CHAT_TYPE_NOTICE, LC_TEXT(maintenance_translate[bOpen ? 19 : 20]));
	}
	else if (!*c_pszArg || !strcasecmp(c_pszArg, "status"))
	{
		ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT(maintenance_translate[0]));
		ch->ChatPacket(CHAT_TYPE_NOTICE, LC_TEXT(maintenance_translate[IsPlayerLoginOpen() ? 22 : 23]));
	}
	else
	{
		ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT(maintenance_translate[0]));
		ch->ChatPacket(CHAT_TYPE_NOTICE, LC_TEXT(maintenance_translate[18]));
	}
}
