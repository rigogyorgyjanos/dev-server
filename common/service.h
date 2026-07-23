#ifndef __INC_SERVICE_H__
#define __INC_SERVICE_H__

#define ENABLE_AUTODETECT_INTERNAL_IP
#define ENABLE_PROXY_IP
#define ENABLE_PORT_SECURITY
#define _IMPROVED_PACKET_ENCRYPTION_ // ��Ŷ ��ȣȭ ����
#define __PET_SYSTEM__
#define __UDP_BLOCK__

//////////////////////////////
#define __SEND_TARGET_INFO__
#define __BL_MOVE_CHANNEL__
#define ELEMENT_TARGET
#define __WJ_SHOW_MOB_INFO__
#define CROSS_CHANNEL_FRIEND_REQUEST
#define ENABLE_SORT_INVEN

#define __VIEW_TARGET_HP__ // View Target HP
#if defined(__VIEW_TARGET_HP__)
#	define __VIEW_TARGET_PLAYER_HP__ // View Player Target HP
#endif
#define __IMPROVED_LOGOUT_POINTS__ // Improved Logout Points 
#define __COSTUME_SYSTEM__ // Costume System
#define __WEAPON_COSTUME_SYSTEM__ // Weapon Costume System
#define ENABLE_MOUNT_LIKE_HORSE // Mitachi
#define ENABLE_RENEWAL_SHOPEX
#define __BL_SKILL_BOOK_NEXT_READ_TIME__
#define ENABLE_TAX_CHANGES
#if defined(ENABLE_TAX_CHANGES)
	#define NEW_TAX_VARIABLE 4				// New tax for the bought items in normal shops
#endif
#define ENABLE_PLAYER_PER_ACCOUNT5				// 5 characters per account
#define __MISSION_BOOKS__
#define ENABLE_CMD_WARP_IN_DUNGEON				// Warp in specific Dungeon
#define __AUTO_QUQUE_ATTACK__				// Auto Metin Farm (queued auto-attack)
#define __FARM_SESSION_SYSTEM__			// Farm session stat tracker
#define BL_SORT_LASTPLAYTIME			// Character-select sorted by last play time
#define __BL_ENABLE_PICKUP_ITEM_EFFECT__	// Highlight the inventory slot a freshly picked-up item lands in
#define __BL_HOT_RESTART__			// /hotrestart GM command: self-exec game+db onto the freshly built binary, no manual stop/start

#endif
