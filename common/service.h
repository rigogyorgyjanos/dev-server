#ifndef __INC_SERVICE_H__
#define __INC_SERVICE_H__

#define ENABLE_AUTODETECT_INTERNAL_IP
#define ENABLE_PROXY_IP
#define ENABLE_PORT_SECURITY
#define _IMPROVED_PACKET_ENCRYPTION_ // 패킷 암호화 개선
//#define __AUCTION__
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
//#define __MULTI_LANGUAGE_SYSTEM__ // Multi Language System
//#define __LOCALE_CLIENT__ // Locale Client

#endif
