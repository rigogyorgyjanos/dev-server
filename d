[1mdiff --git a/common/service.h b/common/service.h[m
[1mindex b23f4cd..e496f50 100755[m
[1m--- a/common/service.h[m
[1m+++ b/common/service.h[m
[36m@@ -36,5 +36,6 @@[m
 #define __AUTO_QUQUE_ATTACK__				// Auto Metin Farm (queued auto-attack)[m
 #define __FARM_SESSION_SYSTEM__			// Farm session stat tracker[m
 #define BL_SORT_LASTPLAYTIME			// Character-select sorted by last play time[m
[32m+[m[32m#define __BL_ENABLE_PICKUP_ITEM_EFFECT__	// Highlight the inventory slot a freshly picked-up item lands in[m
 [m
 #endif[m
[1mdiff --git a/game/src/char.h b/game/src/char.h[m
[1mold mode 100644[m
[1mnew mode 100755[m
[1mindex ec3d6ca..bdc85f1[m
[1m--- a/game/src/char.h[m
[1m+++ b/game/src/char.h[m
[36m@@ -85,7 +85,7 @@[m [menum EDamageType[m
 	DAMAGE_TYPE_NONE,[m
 	DAMAGE_TYPE_NORMAL,[m
 	DAMAGE_TYPE_NORMAL_RANGE,[m
[31m-	//½ºÅ³[m
[32m+[m	[32m//ï¿½ï¿½Å³[m
 	DAMAGE_TYPE_MELEE,[m
 	DAMAGE_TYPE_RANGE,[m
 	DAMAGE_TYPE_FIRE,[m
[36m@@ -107,103 +107,103 @@[m [menum EPointTypes[m
 	POINT_MAX_HP,               // 6[m
 	POINT_SP,                   // 7[m
 	POINT_MAX_SP,               // 8  [m
[31m-	POINT_STAMINA,              // 9  ½ºÅ×¹Ì³Ê[m
[31m-	POINT_MAX_STAMINA,          // 10 ÃÖ´ë ½ºÅ×¹Ì³Ê[m
[32m+[m	[32mPOINT_STAMINA,              // 9  ï¿½ï¿½ï¿½×¹Ì³ï¿½[m
[32m+[m	[32mPOINT_MAX_STAMINA,          // 10 ï¿½Ö´ï¿½ ï¿½ï¿½ï¿½×¹Ì³ï¿½[m
 [m
 	POINT_GOLD,                 // 11[m
[31m-	POINT_ST,                   // 12 ±Ù·Â[m
[31m-	POINT_HT,                   // 13 Ã¼·Â[m
[31m-	POINT_DX,                   // 14 ¹ÎÃ¸¼º[m
[31m-	POINT_IQ,                   // 15 Á¤½Å·Â[m
[32m+[m	[32mPOINT_ST,                   // 12 ï¿½Ù·ï¿½[m
[32m+[m	[32mPOINT_HT,                   // 13 Ã¼ï¿½ï¿½[m
[32m+[m	[32mPOINT_DX,                   // 14 ï¿½ï¿½Ã¸ï¿½ï¿½[m
[32m+[m	[32mPOINT_IQ,                   // 15 ï¿½ï¿½ï¿½Å·ï¿½[m
 	POINT_DEF_GRADE,		// 16 ...[m
[31m-	POINT_ATT_SPEED,            // 17 °ø°Ý¼Óµµ[m
[31m-	POINT_ATT_GRADE,		// 18 °ø°Ý·Â MAX[m
[31m-	POINT_MOV_SPEED,            // 19 ÀÌµ¿¼Óµµ[m
[31m-	POINT_CLIENT_DEF_GRADE,	// 20 ¹æ¾îµî±Þ[m
[31m-	POINT_CASTING_SPEED,        // 21 ÁÖ¹®¼Óµµ (Äð´Ù¿îÅ¸ÀÓ*100) / (100 + ÀÌ°ª) = ÃÖÁ¾ Äð´Ù¿î Å¸ÀÓ[m
[31m-	POINT_MAGIC_ATT_GRADE,      // 22 ¸¶¹ý°ø°Ý·Â[m
[31m-	POINT_MAGIC_DEF_GRADE,      // 23 ¸¶¹ý¹æ¾î·Â[m
[31m-	POINT_EMPIRE_POINT,         // 24 Á¦±¹Á¡¼ö[m
[31m-	POINT_LEVEL_STEP,           // 25 ÇÑ ·¹º§¿¡¼­ÀÇ ´Ü°è.. (1 2 3 µÉ ¶§ º¸»ó, 4 µÇ¸é ·¹º§ ¾÷)[m
[31m-	POINT_STAT,                 // 26 ´É·ÂÄ¡ ¿Ã¸± ¼ö ÀÖ´Â °³¼ö[m
[31m-	POINT_SUB_SKILL,		// 27 º¸Á¶ ½ºÅ³ Æ÷ÀÎÆ®[m
[31m-	POINT_SKILL,		// 28 ¾×Æ¼ºê ½ºÅ³ Æ÷ÀÎÆ®[m
[31m-	POINT_WEAPON_MIN,		// 29 ¹«±â ÃÖ¼Ò µ¥¹ÌÁö[m
[31m-	POINT_WEAPON_MAX,		// 30 ¹«±â ÃÖ´ë µ¥¹ÌÁö[m
[31m-	POINT_PLAYTIME,             // 31 ÇÃ·¹ÀÌ½Ã°£[m
[31m-	POINT_HP_REGEN,             // 32 HP È¸º¹·ü[m
[31m-	POINT_SP_REGEN,             // 33 SP È¸º¹·ü[m
[31m-[m
[31m-	POINT_BOW_DISTANCE,         // 34 È° »çÁ¤°Å¸® Áõ°¡Ä¡ (meter)[m
[31m-[m
[31m-	POINT_HP_RECOVERY,          // 35 Ã¼·Â È¸º¹ Áõ°¡·®[m
[31m-	POINT_SP_RECOVERY,          // 36 Á¤½Å·Â È¸º¹ Áõ°¡·®[m
[31m-[m
[31m-	POINT_POISON_PCT,           // 37 µ¶ È®·ü[m
[31m-	POINT_STUN_PCT,             // 38 ±âÀý È®·ü[m
[31m-	POINT_SLOW_PCT,             // 39 ½½·Î¿ì È®·ü[m
[31m-	POINT_CRITICAL_PCT,         // 40 Å©¸®Æ¼ÄÃ È®·ü[m
[31m-	POINT_PENETRATE_PCT,        // 41 °üÅëÅ¸°Ý È®·ü[m
[31m-	POINT_CURSE_PCT,            // 42 ÀúÁÖ È®·ü[m
[31m-[m
[31m-	POINT_ATTBONUS_HUMAN,       // 43 ÀÎ°£¿¡°Ô °­ÇÔ[m
[31m-	POINT_ATTBONUS_ANIMAL,      // 44 µ¿¹°¿¡°Ô µ¥¹ÌÁö % Áõ°¡[m
[31m-	POINT_ATTBONUS_ORC,         // 45 ¿õ±Í¿¡°Ô µ¥¹ÌÁö % Áõ°¡[m
[31m-	POINT_ATTBONUS_MILGYO,      // 46 ¹Ð±³¿¡°Ô µ¥¹ÌÁö % Áõ°¡[m
[31m-	POINT_ATTBONUS_UNDEAD,      // 47 ½ÃÃ¼¿¡°Ô µ¥¹ÌÁö % Áõ°¡[m
[31m-	POINT_ATTBONUS_DEVIL,       // 48 ¸¶±Í(¾Ç¸¶)¿¡°Ô µ¥¹ÌÁö % Áõ°¡[m
[31m-	POINT_ATTBONUS_INSECT,      // 49 ¹ú·¹Á·[m
[31m-	POINT_ATTBONUS_FIRE,        // 50 È­¿°Á·[m
[31m-	POINT_ATTBONUS_ICE,         // 51 ºù¼³Á·[m
[31m-	POINT_ATTBONUS_DESERT,      // 52 »ç¸·Á·[m
[31m-	POINT_ATTBONUS_MONSTER,     // 53 ¸ðµç ¸ó½ºÅÍ¿¡°Ô °­ÇÔ[m
[31m-	POINT_ATTBONUS_WARRIOR,     // 54 ¹«»ç¿¡°Ô °­ÇÔ[m
[31m-	POINT_ATTBONUS_ASSASSIN,	// 55 ÀÚ°´¿¡°Ô °­ÇÔ[m
[31m-	POINT_ATTBONUS_SURA,		// 56 ¼ö¶ó¿¡°Ô °­ÇÔ[m
[31m-	POINT_ATTBONUS_SHAMAN,		// 57 ¹«´ç¿¡°Ô °­ÇÔ[m
[31m-	POINT_ATTBONUS_TREE,     	// 58 ³ª¹«¿¡°Ô °­ÇÔ 20050729.myevan UNUSED5 [m
[31m-[m
[31m-	POINT_RESIST_WARRIOR,		// 59 ¹«»ç¿¡°Ô ÀúÇ×[m
[31m-	POINT_RESIST_ASSASSIN,		// 60 ÀÚ°´¿¡°Ô ÀúÇ×[m
[31m-	POINT_RESIST_SURA,			// 61 ¼ö¶ó¿¡°Ô ÀúÇ×[m
[31m-	POINT_RESIST_SHAMAN,		// 62 ¹«´ç¿¡°Ô ÀúÇ×[m
[31m-[m
[31m-	POINT_STEAL_HP,             // 63 »ý¸í·Â Èí¼ö[m
[31m-	POINT_STEAL_SP,             // 64 Á¤½Å·Â Èí¼ö[m
[31m-[m
[31m-	POINT_MANA_BURN_PCT,        // 65 ¸¶³ª ¹ø[m
[31m-[m
[31m-	/// ÇÇÇØ½Ã º¸³Ê½º ///[m
[31m-[m
[31m-	POINT_DAMAGE_SP_RECOVER,    // 66 °ø°Ý´çÇÒ ½Ã Á¤½Å·Â È¸º¹ È®·ü[m
[31m-[m
[31m-	POINT_BLOCK,                // 67 ºí·°À²[m
[31m-	POINT_DODGE,                // 68 È¸ÇÇÀ²[m
[32m+[m	[32mPOINT_ATT_SPEED,            // 17 ï¿½ï¿½ï¿½Ý¼Óµï¿½[m
[32m+[m	[32mPOINT_ATT_GRADE,		// 18 ï¿½ï¿½ï¿½Ý·ï¿½ MAX[m
[32m+[m	[32mPOINT_MOV_SPEED,            // 19 ï¿½Ìµï¿½ï¿½Óµï¿½[m
[32m+[m	[32mPOINT_CLIENT_DEF_GRADE,	// 20 ï¿½ï¿½ï¿½ï¿½ï¿½[m
[32m+[m	[32mPOINT_CASTING_SPEED,        // 21 ï¿½Ö¹ï¿½ï¿½Óµï¿½ (ï¿½ï¿½Ù¿ï¿½Å¸ï¿½ï¿½*100) / (100 + ï¿½Ì°ï¿½) = ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½Ù¿ï¿½ Å¸ï¿½ï¿½[m
[32m+[m	[32mPOINT_MAGIC_ATT_GRADE,      // 22 ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½Ý·ï¿½[m
[32m+[m	[32mPOINT_MAGIC_DEF_GRADE,      // 23 ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½[m
[32m+[m	[32mPOINT_EMPIRE_POINT,         // 24 ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½[m
[32m+[m	[32mPOINT_LEVEL_STEP,           // 25 ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ü°ï¿½.. (1 2 3 ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½, 4 ï¿½Ç¸ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½)[m
[32m+[m	[32mPOINT_STAT,                 // 26 ï¿½É·ï¿½Ä¡ ï¿½Ã¸ï¿½ ï¿½ï¿½ ï¿½Ö´ï¿½ ï¿½ï¿½ï¿½ï¿½[m
[32m+[m	[32mPOINT_SUB_SKILL,		// 27 ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½Å³ ï¿½ï¿½ï¿½ï¿½Æ®[m
[32m+[m	[32mPOINT_SKILL,		// 28 ï¿½ï¿½Æ¼ï¿½ï¿½ ï¿½ï¿½Å³ ï¿½ï¿½ï¿½ï¿½Æ®[m
[32m+[m	[32mPOINT_WEAPON_MIN,		// 29 ï¿½ï¿½ï¿½ï¿½ ï¿½Ö¼ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½[m
[32m+[m	[32mPOINT_WEAPON_MAX,		// 30 ï¿½ï¿½ï¿½ï¿½ ï¿½Ö´ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½[m
[32m+[m	[32mPOINT_PLAYTIME,             // 31 ï¿½Ã·ï¿½ï¿½Ì½Ã°ï¿½[m
[32m+[m	[32mPOINT_HP_REGEN,             // 32 HP È¸ï¿½ï¿½ï¿½ï¿½[m
[32m+[m	[32mPOINT_SP_REGEN,             // 33 SP È¸ï¿½ï¿½ï¿½ï¿½[m
[32m+[m
[32m+[m	[32mPOINT_BOW_DISTANCE,         // 34 È° ï¿½ï¿½ï¿½ï¿½ï¿½Å¸ï¿½ ï¿½ï¿½ï¿½ï¿½Ä¡ (meter)[m
[32m+[m
[32m+[m	[32mPOINT_HP_RECOVERY,          // 35 Ã¼ï¿½ï¿½ È¸ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½[m
[32m+[m	[32mPOINT_SP_RECOVERY,          // 36 ï¿½ï¿½ï¿½Å·ï¿½ È¸ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½[m
[32m+[m
[32m+[m	[32mPOINT_POISON_PCT,           // 37 ï¿½ï¿½ È®ï¿½ï¿½[m
[32m+[m	[32mPOINT_STUN_PCT,             // 38 ï¿½ï¿½ï¿½ï¿½ È®ï¿½ï¿½[m
[32m+[m	[32mPOINT_SLOW_PCT,             // 39 ï¿½ï¿½ï¿½Î¿ï¿½ È®ï¿½ï¿½[m
[32m+[m	[32mPOINT_CRITICAL_PCT,         // 40 Å©ï¿½ï¿½Æ¼ï¿½ï¿½ È®ï¿½ï¿½[m
[32m+[m	[32mPOINT_PENETRATE_PCT,        // 41 ï¿½ï¿½ï¿½ï¿½Å¸ï¿½ï¿½ È®ï¿½ï¿½[m
[32m+[m	[32mPOINT_CURSE_PCT,            // 42 ï¿½ï¿½ï¿½ï¿½ È®ï¿½ï¿½[m
[32m+[m
[32m+[m	[32mPOINT_ATTBONUS_HUMAN,       // 43 ï¿½Î°ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½[m
[32m+[m	[32mPOINT_ATTBONUS_ANIMAL,      // 44 ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ % ï¿½ï¿½ï¿½ï¿½[m
[32m+[m	[32mPOINT_ATTBONUS_ORC,         // 45 ï¿½ï¿½ï¿½Í¿ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ % ï¿½ï¿½ï¿½ï¿½[m
[32m+[m	[32mPOINT_ATTBONUS_MILGYO,      // 46 ï¿½Ð±ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ % ï¿½ï¿½ï¿½ï¿½[m
[32m+[m	[32mPOINT_ATTBONUS_UNDEAD,      // 47 ï¿½ï¿½Ã¼ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ % ï¿½ï¿½ï¿½ï¿½[m
[32m+[m	[32mPOINT_ATTBONUS_DEVIL,       // 48 ï¿½ï¿½ï¿½ï¿½(ï¿½Ç¸ï¿½)ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ % ï¿½ï¿½ï¿½ï¿½[m
[32m+[m	[32mPOINT_ATTBONUS_INSECT,      // 49 ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½[m
[32m+[m	[32mPOINT_ATTBONUS_FIRE,        // 50 È­ï¿½ï¿½ï¿½ï¿½[m
[32m+[m	[32mPOINT_ATTBONUS_ICE,         // 51 ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½[m
[32m+[m	[32mPOINT_ATTBONUS_DESERT,      // 52 ï¿½ç¸·ï¿½ï¿½[m
[32m+[m	[32mPOINT_ATTBONUS_MONSTER,     // 53 ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Í¿ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½[m
[32m+[m	[32mPOINT_ATTBONUS_WARRIOR,     // 54 ï¿½ï¿½ï¿½ç¿¡ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½[m
[32m+[m	[32mPOINT_ATTBONUS_ASSASSIN,	// 55 ï¿½Ú°ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½[m
[32m+[m	[32mPOINT_ATTBONUS_SURA,		// 56 ï¿½ï¿½ï¿½ó¿¡°ï¿½ ï¿½ï¿½ï¿½ï¿½[m
[32m+[m	[32mPOINT_ATTBONUS_SHAMAN,		// 57 ï¿½ï¿½ï¿½ç¿¡ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½[m
[32m+[m	[32mPOINT_ATTBONUS_TREE,     	// 58 ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ 20050729.myevan UNUSED5[m[41m [m
[32m+[m
[32m+[m	[32mPOINT_RESIST_WARRIOR,		// 59 ï¿½ï¿½ï¿½ç¿¡ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½[m
[32m+[m	[32mPOINT_RESIST_ASSASSIN,		// 60 ï¿½Ú°ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½[m
[32m+[m	[32mPOINT_RESIST_SURA,			// 61 ï¿½ï¿½ï¿½ó¿¡°ï¿½ ï¿½ï¿½ï¿½ï¿½[m
[32m+[m	[32mPOINT_RESIST_SHAMAN,		// 62 ï¿½ï¿½ï¿½ç¿¡ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½[m
[32m+[m
[32m+[m	[32mPOINT_STEAL_HP,             // 63 ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½[m
[32m+[m	[32mPOINT_STEAL_SP,             // 64 ï¿½ï¿½ï¿½Å·ï¿½ ï¿½ï¿½ï¿½ï¿½[m
[32m+[m
[32m+[m	[32mPOINT_MANA_BURN_PCT,        // 65 ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½[m
[32m+[m
[32m+[m	[32m/// ï¿½ï¿½ï¿½Ø½ï¿½ ï¿½ï¿½ï¿½Ê½ï¿½ ///[m
[32m+[m
[32m+[m	[32mPOINT_DAMAGE_SP_RECOVER,    // 66 ï¿½ï¿½ï¿½Ý´ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½Å·ï¿½ È¸ï¿½ï¿½ È®ï¿½ï¿½[m
[32m+[m
[32m+[m	[32mPOINT_BLOCK,                // 67 ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½[m
[32m+[m	[32mPOINT_DODGE,                // 68 È¸ï¿½ï¿½ï¿½ï¿½[m
 [m
 	POINT_RESIST_SWORD,         // 69[m
 	POINT_RESIST_TWOHAND,       // 70[m
 	POINT_RESIST_DAGGER,        // 71[m
 	POINT_RESIST_BELL,          // 72[m
 	POINT_RESIST_FAN,           // 73[m
[31m-	POINT_RESIST_BOW,           // 74  È­»ì   ÀúÇ×   : ´ë¹ÌÁö °¨¼Ò[m
[31m-	POINT_RESIST_FIRE,          // 75  È­¿°   ÀúÇ×   : È­¿°°ø°Ý¿¡ ´ëÇÑ ´ë¹ÌÁö °¨¼Ò[m
[31m-	POINT_RESIST_ELEC,          // 76  Àü±â   ÀúÇ×   : Àü±â°ø°Ý¿¡ ´ëÇÑ ´ë¹ÌÁö °¨¼Ò[m
[31m-	POINT_RESIST_MAGIC,         // 77  ¼ú¹ý   ÀúÇ×   : ¸ðµç¼ú¹ý¿¡ ´ëÇÑ ´ë¹ÌÁö °¨¼Ò[m
[31m-	POINT_RESIST_WIND,          // 78  ¹Ù¶÷   ÀúÇ×   : ¹Ù¶÷°ø°Ý¿¡ ´ëÇÑ ´ë¹ÌÁö °¨¼Ò[m
[32m+[m	[32mPOINT_RESIST_BOW,           // 74  È­ï¿½ï¿½   ï¿½ï¿½ï¿½ï¿½   : ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½[m
[32m+[m	[32mPOINT_RESIST_FIRE,          // 75  È­ï¿½ï¿½   ï¿½ï¿½ï¿½ï¿½   : È­ï¿½ï¿½ï¿½ï¿½ï¿½Ý¿ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½[m
[32m+[m	[32mPOINT_RESIST_ELEC,          // 76  ï¿½ï¿½ï¿½ï¿½   ï¿½ï¿½ï¿½ï¿½   : ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½Ý¿ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½[m
[32m+[m	[32mPOINT_RESIST_MAGIC,         // 77  ï¿½ï¿½ï¿½ï¿½   ï¿½ï¿½ï¿½ï¿½   : ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½[m
[32m+[m	[32mPOINT_RESIST_WIND,          // 78  ï¿½Ù¶ï¿½   ï¿½ï¿½ï¿½ï¿½   : ï¿½Ù¶ï¿½ï¿½ï¿½ï¿½Ý¿ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½[m
 [m
[31m-	POINT_REFLECT_MELEE,        // 79 °ø°Ý ¹Ý»ç[m
[32m+[m	[32mPOINT_REFLECT_MELEE,        // 79 ï¿½ï¿½ï¿½ï¿½ ï¿½Ý»ï¿½[m
 [m
[31m-	/// Æ¯¼ö ÇÇÇØ½Ã ///[m
[31m-	POINT_REFLECT_CURSE,		// 80 ÀúÁÖ ¹Ý»ç[m
[31m-	POINT_POISON_REDUCE,		// 81 µ¶µ¥¹ÌÁö °¨¼Ò[m
[32m+[m	[32m/// Æ¯ï¿½ï¿½ ï¿½ï¿½ï¿½Ø½ï¿½ ///[m
[32m+[m	[32mPOINT_REFLECT_CURSE,		// 80 ï¿½ï¿½ï¿½ï¿½ ï¿½Ý»ï¿½[m
[32m+[m	[32mPOINT_POISON_REDUCE,		// 81 ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½[m
 [m
[31m-	/// Àû ¼Ò¸ê½Ã ///[m
[31m-	POINT_KILL_SP_RECOVER,		// 82 Àû ¼Ò¸ê½Ã MP È¸º¹[m
[32m+[m	[32m/// ï¿½ï¿½ ï¿½Ò¸ï¿½ï¿½ ///[m
[32m+[m	[32mPOINT_KILL_SP_RECOVER,		// 82 ï¿½ï¿½ ï¿½Ò¸ï¿½ï¿½ MP È¸ï¿½ï¿½[m
 	POINT_EXP_DOUBLE_BONUS,		// 83[m
 	POINT_GOLD_DOUBLE_BONUS,		// 84[m
 	POINT_ITEM_DROP_BONUS,		// 85[m
 [m
[31m-	/// È¸º¹ °ü·Ã ///[m
[32m+[m	[32m/// È¸ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ///[m
 	POINT_POTION_BONUS,			// 86[m
 	POINT_KILL_HP_RECOVERY,		// 87[m
 [m
[36m@@ -227,7 +227,7 @@[m [menum EPointTypes[m
 [m
 	POINT_HIT_HP_RECOVERY,		// 100[m
 	POINT_HIT_SP_RECOVERY, 		// 101[m
[31m-	POINT_MANASHIELD,			// 102 Èæ½Å¼öÈ£ ½ºÅ³¿¡ ÀÇÇÑ ¸¶³ª½¯µå È¿°ú Á¤µµ[m
[32m+[m	[32mPOINT_MANASHIELD,			// 102 ï¿½ï¿½Å¼ï¿½È£ ï¿½ï¿½Å³ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ È¿ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½[m
 [m
 	POINT_PARTY_BUFFER_BONUS,		// 103[m
 	POINT_PARTY_SKILL_MASTER_BONUS,	// 104[m
[36m@@ -236,56 +236,56 @@[m [menum EPointTypes[m
 	POINT_SP_RECOVER_CONTINUE,		// 106[m
 [m
 	POINT_STEAL_GOLD,			// 107 [m
[31m-	POINT_POLYMORPH,			// 108 º¯½ÅÇÑ ¸ó½ºÅÍ ¹øÈ£[m
[31m-	POINT_MOUNT,			// 109 Å¸°íÀÖ´Â ¸ó½ºÅÍ ¹øÈ£[m
[32m+[m	[32mPOINT_POLYMORPH,			// 108 ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½È£[m
[32m+[m	[32mPOINT_MOUNT,			// 109 Å¸ï¿½ï¿½ï¿½Ö´ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½È£[m
 [m
 	POINT_PARTY_HASTE_BONUS,		// 110[m
 	POINT_PARTY_DEFENDER_BONUS,		// 111[m
[31m-	POINT_STAT_RESET_COUNT,		// 112 ÇÇÀÇ ´Ü¾à »ç¿ëÀ» ÅëÇÑ ½ºÅÝ ¸®¼Â Æ÷ÀÎÆ® (1´ç 1Æ÷ÀÎÆ® ¸®¼Â°¡´É)[m
[32m+[m	[32mPOINT_STAT_RESET_COUNT,		// 112 ï¿½ï¿½ï¿½ï¿½ ï¿½Ü¾ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½Æ® (1ï¿½ï¿½ 1ï¿½ï¿½ï¿½ï¿½Æ® ï¿½ï¿½ï¿½Â°ï¿½ï¿½ï¿½)[m
 [m
 	POINT_HORSE_SKILL,			// 113[m
 [m
[31m-	POINT_MALL_ATTBONUS,		// 114 °ø°Ý·Â +x%[m
[31m-	POINT_MALL_DEFBONUS,		// 115 ¹æ¾î·Â +x%[m
[31m-	POINT_MALL_EXPBONUS,		// 116 °æÇèÄ¡ +x%[m
[31m-	POINT_MALL_ITEMBONUS,		// 117 ¾ÆÀÌÅÛ µå·ÓÀ² x/10¹è[m
[31m-	POINT_MALL_GOLDBONUS,		// 118 µ· µå·ÓÀ² x/10¹è[m
[32m+[m	[32mPOINT_MALL_ATTBONUS,		// 114 ï¿½ï¿½ï¿½Ý·ï¿½ +x%[m
[32m+[m	[32mPOINT_MALL_DEFBONUS,		// 115 ï¿½ï¿½ï¿½ï¿½ +x%[m
[32m+[m	[32mPOINT_MALL_EXPBONUS,		// 116 ï¿½ï¿½ï¿½ï¿½Ä¡ +x%[m
[32m+[m	[32mPOINT_MALL_ITEMBONUS,		// 117 ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ x/10ï¿½ï¿½[m
[32m+[m	[32mPOINT_MALL_GOLDBONUS,		// 118 ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ x/10ï¿½ï¿½[m
 [m
[31m-	POINT_MAX_HP_PCT,			// 119 ÃÖ´ë»ý¸í·Â +x%[m
[31m-	POINT_MAX_SP_PCT,			// 120 ÃÖ´ëÁ¤½Å·Â +x%[m
[32m+[m	[32mPOINT_MAX_HP_PCT,			// 119 ï¿½Ö´ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ +x%[m
[32m+[m	[32mPOINT_MAX_SP_PCT,			// 120 ï¿½Ö´ï¿½ï¿½ï¿½ï¿½Å·ï¿½ +x%[m
 [m
[31m-	POINT_SKILL_DAMAGE_BONUS,		// 121 ½ºÅ³ µ¥¹ÌÁö *(100+x)%[m
[31m-	POINT_NORMAL_HIT_DAMAGE_BONUS,	// 122 ÆòÅ¸ µ¥¹ÌÁö *(100+x)%[m
[32m+[m	[32mPOINT_SKILL_DAMAGE_BONUS,		// 121 ï¿½ï¿½Å³ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ *(100+x)%[m
[32m+[m	[32mPOINT_NORMAL_HIT_DAMAGE_BONUS,	// 122 ï¿½ï¿½Å¸ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ *(100+x)%[m
 [m
 	// DEFEND_BONUS_ATTRIBUTES[m
[31m-	POINT_SKILL_DEFEND_BONUS,		// 123 ½ºÅ³ ¹æ¾î µ¥¹ÌÁö[m
[31m-	POINT_NORMAL_HIT_DEFEND_BONUS,	// 124 ÆòÅ¸ ¹æ¾î µ¥¹ÌÁö[m
[32m+[m	[32mPOINT_SKILL_DEFEND_BONUS,		// 123 ï¿½ï¿½Å³ ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½[m
[32m+[m	[32mPOINT_NORMAL_HIT_DEFEND_BONUS,	// 124 ï¿½ï¿½Å¸ ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½[m
 	// END_OF_DEFEND_BONUS_ATTRIBUTES[m
 [m
 	// PC_BANG_ITEM_ADD [m
[31m-	POINT_PC_BANG_EXP_BONUS,		// 125 PC¹æ Àü¿ë °æÇèÄ¡ º¸³Ê½º[m
[31m-	POINT_PC_BANG_DROP_BONUS,		// 126 PC¹æ Àü¿ë µå·Ó·ü º¸³Ê½º[m
[32m+[m	[32mPOINT_PC_BANG_EXP_BONUS,		// 125 PCï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½Ä¡ ï¿½ï¿½ï¿½Ê½ï¿½[m
[32m+[m	[32mPOINT_PC_BANG_DROP_BONUS,		// 126 PCï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½Ó·ï¿½ ï¿½ï¿½ï¿½Ê½ï¿½[m
 	// END_PC_BANG_ITEM_ADD[m
[31m-	POINT_RAMADAN_CANDY_BONUS_EXP,			// ¶ó¸¶´Ü »çÅÁ °æÇèÄ¡ Áõ°¡¿ë[m
[32m+[m	[32mPOINT_RAMADAN_CANDY_BONUS_EXP,			// ï¿½ó¸¶´ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½Ä¡ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½[m
 [m
[31m-	POINT_ENERGY = 128,					// 128 ±â·Â[m
[32m+[m	[32mPOINT_ENERGY = 128,					// 128 ï¿½ï¿½ï¿½[m
 [m
[31m-	// ±â·Â ui ¿ë.[m
[31m-	// ¼­¹ö¿¡¼­ ¾²Áö ¾Ê±â¸¸, Å¬¶óÀÌ¾ðÆ®¿¡¼­ ±â·ÂÀÇ ³¡ ½Ã°£À» POINT·Î °ü¸®ÇÏ±â ¶§¹®¿¡ ÀÌ·¸°Ô ÇÑ´Ù.[m
[31m-	// ¾Æ ºÎ²ô·´´Ù[m
[31m-	POINT_ENERGY_END_TIME = 129,					// 129 ±â·Â Á¾·á ½Ã°£[m
[32m+[m	[32m// ï¿½ï¿½ï¿½ ui ï¿½ï¿½.[m
[32m+[m	[32m// ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½Ê±â¸¸, Å¬ï¿½ï¿½ï¿½Ì¾ï¿½Æ®ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½Ã°ï¿½ï¿½ï¿½ POINTï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï±ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ì·ï¿½ï¿½ï¿½ ï¿½Ñ´ï¿½.[m
[32m+[m	[32m// ï¿½ï¿½ ï¿½Î²ï¿½ï¿½ï¿½ï¿½ï¿½[m
[32m+[m	[32mPOINT_ENERGY_END_TIME = 129,					// 129 ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½Ã°ï¿½[m
 [m
 	POINT_COSTUME_ATTR_BONUS = 130,[m
 	POINT_MAGIC_ATT_BONUS_PER = 131,[m
 	POINT_MELEE_MAGIC_ATT_BONUS_PER = 132,[m
 [m
[31m-	// Ãß°¡ ¼Ó¼º ÀúÇ×[m
[31m-	POINT_RESIST_ICE = 133,          //   ³Ã±â ÀúÇ×   : ¾óÀ½°ø°Ý¿¡ ´ëÇÑ ´ë¹ÌÁö °¨¼Ò[m
[31m-	POINT_RESIST_EARTH = 134,        //   ´ëÁö ÀúÇ×   : ¾óÀ½°ø°Ý¿¡ ´ëÇÑ ´ë¹ÌÁö °¨¼Ò[m
[31m-	POINT_RESIST_DARK = 135,         //   ¾îµÒ ÀúÇ×   : ¾óÀ½°ø°Ý¿¡ ´ëÇÑ ´ë¹ÌÁö °¨¼Ò[m
[32m+[m	[32m// ï¿½ß°ï¿½ ï¿½Ó¼ï¿½ ï¿½ï¿½ï¿½ï¿½[m
[32m+[m	[32mPOINT_RESIST_ICE = 133,          //   ï¿½Ã±ï¿½ ï¿½ï¿½ï¿½ï¿½   : ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½Ý¿ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½[m
[32m+[m	[32mPOINT_RESIST_EARTH = 134,        //   ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½   : ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½Ý¿ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½[m
[32m+[m	[32mPOINT_RESIST_DARK = 135,         //   ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½   : ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½Ý¿ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½[m
 [m
[31m-	POINT_RESIST_CRITICAL = 136,		// Å©¸®Æ¼ÄÃ ÀúÇ×	: »ó´ëÀÇ Å©¸®Æ¼ÄÃ È®·üÀ» °¨¼Ò[m
[31m-	POINT_RESIST_PENETRATE = 137,		// °üÅëÅ¸°Ý ÀúÇ×	: »ó´ëÀÇ °üÅëÅ¸°Ý È®·üÀ» °¨¼Ò[m
[32m+[m	[32mPOINT_RESIST_CRITICAL = 136,		// Å©ï¿½ï¿½Æ¼ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½	: ï¿½ï¿½ï¿½ï¿½ï¿½ Å©ï¿½ï¿½Æ¼ï¿½ï¿½ È®ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½[m
[32m+[m	[32mPOINT_RESIST_PENETRATE = 137,		// ï¿½ï¿½ï¿½ï¿½Å¸ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½	: ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½Å¸ï¿½ï¿½ È®ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½[m
 [m
 	//POINT_MAX_NUM = 129	common/length.h[m
 };[m
[36m@@ -354,7 +354,7 @@[m [mstruct DynamicCharacterPtr {[m
 	uint32_t id;[m
 };[m
 [m
[31m-/* ÀúÀåÇÏ´Â µ¥ÀÌÅÍ */[m
[32m+[m[32m/* ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ */[m
 typedef struct character_point[m
 {[m
 	long			points[POINT_MAX_NUM];[m
[36m@@ -377,7 +377,7 @@[m [mtypedef struct character_point[m
 	BYTE			skill_group;[m
 } CHARACTER_POINT;[m
 [m
[31m-/* ÀúÀåµÇÁö ¾Ê´Â Ä³¸¯ÅÍ µ¥ÀÌÅÍ */[m
[32m+[m[32m/* ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ê´ï¿½ Ä³ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ */[m
 typedef struct character_point_instant[m
 {[m
 	long			points[POINT_MAX_NUM];[m
[36m@@ -399,7 +399,7 @@[m [mtypedef struct character_point_instant[m
 	LPITEM			pItems[INVENTORY_AND_EQUIP_SLOT_MAX];[m
 	BYTE			bItemGrid[INVENTORY_AND_EQUIP_SLOT_MAX];[m
 [m
[31m-	// ¿ëÈ¥¼® ÀÎº¥Åä¸®.[m
[32m+[m	[32m// ï¿½ï¿½È¥ï¿½ï¿½ ï¿½Îºï¿½ï¿½ä¸®.[m
 	LPITEM			pDSItems[DRAGON_SOUL_INVENTORY_MAX_NUM];[m
 	WORD			wDSItemGrid[DRAGON_SOUL_INVENTORY_MAX_NUM];[m
 [m
[36m@@ -411,7 +411,7 @@[m [mtypedef struct character_point_instant[m
 [m
 	BYTE			gm_level;[m
 [m
[31m-	BYTE			bBasePart;	// Æò»óº¹ ¹øÈ£[m
[32m+[m	[32mBYTE			bBasePart;	// ï¿½ï¿½ï¿½ ï¿½ï¿½È£[m
 [m
 	int				iMaxStamina;[m
 [m
[36m@@ -509,7 +509,7 @@[m [mclass CHARACTER : public CEntity, public CFSM, public CHorseRider[m
 {[m
 	protected:[m
 		//////////////////////////////////////////////////////////////////////////////////[m
[31m-		// Entity °ü·Ã[m
[32m+[m		[32m// Entity ï¿½ï¿½ï¿½ï¿½[m
 		virtual void	EncodeInsertPacket(LPENTITY entity);[m
 		virtual void	EncodeRemovePacket(LPENTITY entity);[m
 		//////////////////////////////////////////////////////////////////////////////////[m
[36m@@ -519,7 +519,7 @@[m [mclass CHARACTER : public CEntity, public CFSM, public CHorseRider[m
 		void				UpdatePacket();[m
 [m
 		//////////////////////////////////////////////////////////////////////////////////[m
[31m-		// FSM (Finite State Machine) °ü·Ã[m
[32m+[m		[32m// FSM (Finite State Machine) ï¿½ï¿½ï¿½ï¿½[m
 	protected:[m
 		CStateTemplate<CHARACTER>	m_stateMove;[m
 		CStateTemplate<CHARACTER>	m_stateBattle;[m
[36m@@ -598,13 +598,13 @@[m [mclass CHARACTER : public CEntity, public CFSM, public CHorseRider[m
 		DWORD			GetPlayerID() const	{ return m_dwPlayerID; }[m
 [m
 		void			SetPlayerProto(const TPlayerTable * table);[m
[31m-		void			CreatePlayerProto(TPlayerTable & tab);	// ÀúÀå ½Ã »ç¿ë[m
[32m+[m		[32mvoid			CreatePlayerProto(TPlayerTable & tab);	// ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½[m
 [m
 		void			SetProto(const CMob * c_pkMob);[m
 		WORD			GetRaceNum() const;[m
 [m
 		void			Save();		// DelayedSave[m
[31m-		void			SaveReal();	// ½ÇÁ¦ ÀúÀå[m
[32m+[m		[32mvoid			SaveReal();	// ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½[m
 		void			FlushDelayedSaveItem();[m
 [m
 		const char *	GetName() const;[m
[36m@@ -645,7 +645,7 @@[m [mclass CHARACTER : public CEntity, public CFSM, public CHorseRider[m
 		DWORD			GetExp() const		{ return m_points.exp;	}[m
 		void			SetExp(DWORD exp)	{ m_points.exp = exp;	}[m
 		DWORD			GetNextExp() const;[m
[31m-		LPCHARACTER		DistributeExp();	// Á¦ÀÏ ¸¹ÀÌ ¶§¸° »ç¶÷À» ¸®ÅÏÇÑ´Ù.[m
[32m+[m		[32mLPCHARACTER		DistributeExp();	// ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ñ´ï¿½.[m
 		void			DistributeHP(LPCHARACTER pkKiller);[m
 		void			DistributeSP(LPCHARACTER pkKiller, int iMethod=0);[m
 [m
[36m@@ -728,14 +728,14 @@[m [mclass CHARACTER : public CEntity, public CFSM, public CHorseRider[m
 		DWORD			GetPolymorphItemVnum() const;[m
 		DWORD			GetMonsterDrainSPPoint() const;[m
 [m
[31m-		void			MainCharacterPacket();	// ³»°¡ ¸ÞÀÎÄ³¸¯ÅÍ¶ó°í º¸³»ÁØ´Ù.[m
[32m+[m		[32mvoid			MainCharacterPacket();	// ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½Ä³ï¿½ï¿½ï¿½Í¶ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ø´ï¿½.[m
 [m
 		void			ComputePoints();[m
 		void			ComputeBattlePoints();[m
 		void			PointChange(BYTE type, int amount, bool bAmount = false, bool bBroadcast = false);[m
 		void			PointsPacket();[m
 		void			ApplyPoint(BYTE bApplyType, int iVal);[m
[31m-		void			CheckMaximumPoints();	// HP, SP µîÀÇ ÇöÀç °ªÀÌ ÃÖ´ë°ª º¸´Ù ³ôÀºÁö °Ë»çÇÏ°í ³ô´Ù¸é ³·Ãá´Ù.[m
[32m+[m		[32mvoid			CheckMaximumPoints();	// HP, SP ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½Ö´ë°ª ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ë»ï¿½ï¿½Ï°ï¿½ ï¿½ï¿½ï¿½Ù¸ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½.[m
 [m
 		bool			Show(long lMapIndex, long x, long y, long z = LONG_MAX, bool bShowSpawnMotion = false);[m
 [m
[36m@@ -760,7 +760,7 @@[m [mclass CHARACTER : public CEntity, public CFSM, public CHorseRider[m
 		bool			IsBlockMode(BYTE bFlag) const	{ return (m_pointsInstant.bBlockMode & bFlag)?true:false; }[m
 [m
 		bool			IsPolymorphed() const		{ return m_dwPolymorphRace>0; }[m
[31m-		bool			IsPolyMaintainStat() const	{ return m_bPolyMaintainStat; } // ÀÌÀü ½ºÅÝÀ» À¯ÁöÇÏ´Â Æú¸®¸ðÇÁ.[m
[32m+[m		[32mbool			IsPolyMaintainStat() const	{ return m_bPolyMaintainStat; } // ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½.[m
 		void			SetPolymorph(DWORD dwRaceNum, bool bMaintainStat = false);[m
 		DWORD			GetPolymorphVnum() const	{ return m_dwPolymorphRace; }[m
 		int				GetPolymorphPower() const;[m
[36m@@ -817,15 +817,15 @@[m [mclass CHARACTER : public CEntity, public CFSM, public CHorseRider[m
 		void			SetNowWalking(bool bWalkFlag);	[m
 		void			ResetWalking()			{ SetNowWalking(m_bWalking); }[m
 [m
[31m-		bool			Goto(long x, long y);	// ¹Ù·Î ÀÌµ¿ ½ÃÅ°Áö ¾Ê°í ¸ñÇ¥ À§Ä¡·Î BLENDING ½ÃÅ²´Ù.[m
[32m+[m		[32mbool			Goto(long x, long y);	// ï¿½Ù·ï¿½ ï¿½Ìµï¿½ ï¿½ï¿½Å°ï¿½ï¿½ ï¿½Ê°ï¿½ ï¿½ï¿½Ç¥ ï¿½ï¿½Ä¡ï¿½ï¿½ BLENDING ï¿½ï¿½Å²ï¿½ï¿½.[m
 		void			Stop();[m
 [m
[31m-		bool			CanMove() const;		// ÀÌµ¿ÇÒ ¼ö ÀÖ´Â°¡?[m
[32m+[m		[32mbool			CanMove() const;		// ï¿½Ìµï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½Ö´Â°ï¿½?[m
 [m
 		void			SyncPacket();[m
[31m-		bool			Sync(long x, long y);	// ½ÇÁ¦ ÀÌ ¸Þ¼Òµå·Î ÀÌµ¿ ÇÑ´Ù (°¢ Á¾ Á¶°Ç¿¡ ÀÇÇÑ ÀÌµ¿ ºÒ°¡°¡ ¾øÀ½)[m
[31m-		bool			Move(long x, long y);	// Á¶°ÇÀ» °Ë»çÇÏ°í Sync ¸Þ¼Òµå¸¦ ÅëÇØ ÀÌµ¿ ÇÑ´Ù.[m
[31m-		void			OnMove(bool bIsAttack = false);	// ¿òÁ÷ÀÏ¶§ ºÒ¸°´Ù. Move() ¸Þ¼Òµå ÀÌ¿Ü¿¡¼­µµ ºÒ¸± ¼ö ÀÖ´Ù.[m
[32m+[m		[32mbool			Sync(long x, long y);	// ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½Þ¼Òµï¿½ï¿½ ï¿½Ìµï¿½ ï¿½Ñ´ï¿½ (ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½Ç¿ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½Ìµï¿½ ï¿½Ò°ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½)[m
[32m+[m		[32mbool			Move(long x, long y);	// ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ë»ï¿½ï¿½Ï°ï¿½ Sync ï¿½Þ¼Òµå¸¦ ï¿½ï¿½ï¿½ï¿½ ï¿½Ìµï¿½ ï¿½Ñ´ï¿½.[m
[32m+[m		[32mvoid			OnMove(bool bIsAttack = false);	// ï¿½ï¿½ï¿½ï¿½ï¿½Ï¶ï¿½ ï¿½Ò¸ï¿½ï¿½ï¿½. Move() ï¿½Þ¼Òµï¿½ ï¿½Ì¿Ü¿ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ò¸ï¿½ ï¿½ï¿½ ï¿½Ö´ï¿½.[m
 		DWORD			GetMotionMode() const;[m
 		float			GetMoveMotionSpeed() const;[m
 		float			GetMoveSpeed() const;[m
[36m@@ -836,7 +836,7 @@[m [mclass CHARACTER : public CEntity, public CFSM, public CHorseRider[m
 		DWORD			GetLastMoveTime() const		{ return m_dwLastMoveTime; }[m
 		DWORD			GetLastAttackTime() const	{ return m_dwLastAttackTime; }[m
 [m
[31m-		void			SetLastAttacked(DWORD time);	// ¸¶Áö¸·À¸·Î °ø°Ý¹ÞÀº ½Ã°£ ¹× À§Ä¡¸¦ ÀúÀåÇÔ[m
[32m+[m		[32mvoid			SetLastAttacked(DWORD time);	// ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Ý¹ï¿½ï¿½ï¿½ ï¿½Ã°ï¿½ ï¿½ï¿½ ï¿½ï¿½Ä¡ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½[m
 [m
 		bool			SetSyncOwner(LPCHARACTER ch, bool bRemoveFromList = true);[m
 		bool			IsSyncOwner(LPCHARACTER ch) const;[m
[36m@@ -868,7 +868,7 @@[m [mclass CHARACTER : public CEntity, public CFSM, public CHorseRider[m
 [m
 		float			m_fSyncTime;[m
 		LPCHARACTER		m_pkChrSyncOwner;[m
[31m-		CHARACTER_LIST	m_kLst_pkChrSyncOwned;	// ³»°¡ SyncOwnerÀÎ ÀÚµé[m
[32m+[m		[32mCHARACTER_LIST	m_kLst_pkChrSyncOwned;	// ï¿½ï¿½ï¿½ï¿½ SyncOwnerï¿½ï¿½ ï¿½Úµï¿½[m
 [m
 		PIXEL_POSITION	m_posDest;[m
 		PIXEL_POSITION	m_posStart;[m
[36m@@ -891,7 +891,7 @@[m [mclass CHARACTER : public CEntity, public CFSM, public CHorseRider[m
 		bool			m_bStaminaConsume;[m
 		// End[m
 [m
[31m-		// Quickslot °ü·Ã[m
[32m+[m		[32m// Quickslot ï¿½ï¿½ï¿½ï¿½[m
 	public:[m
 		void			SyncQuickslot(BYTE bType, BYTE bOldPos, BYTE bNewPos);[m
 		bool			GetQuickslot(BYTE pos, TQuickslot ** ppSlot);[m
[36m@@ -920,7 +920,7 @@[m [mclass CHARACTER : public CEntity, public CFSM, public CHorseRider[m
 		void			LoadAffect(DWORD dwCount, TPacketAffectElement * pElements);[m
 		void			SaveAffect();[m
 [m
[31m-		// Affect loadingÀÌ ³¡³­ »óÅÂÀÎ°¡?[m
[32m+[m		[32m// Affect loadingï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Î°ï¿½?[m
 		bool			IsLoadedAffect() const	{ return m_bIsLoadedAffect; }		[m
 [m
 		bool			IsGoodAffect(BYTE bAffectType) const;[m
[36m@@ -946,25 +946,25 @@[m [mclass CHARACTER : public CEntity, public CFSM, public CHorseRider[m
 		void			DenyToParty(LPCHARACTER member);[m
 		void			AcceptToParty(LPCHARACTER member);[m
 [m
[31m-		/// ÀÚ½ÅÀÇ ÆÄÆ¼¿¡ ´Ù¸¥ character ¸¦ ÃÊ´ëÇÑ´Ù.[m
[32m+[m		[32m/// ï¿½Ú½ï¿½ï¿½ï¿½ ï¿½ï¿½Æ¼ï¿½ï¿½ ï¿½Ù¸ï¿½ character ï¿½ï¿½ ï¿½Ê´ï¿½ï¿½Ñ´ï¿½.[m
 		/**[m
[31m-		 * @param	pchInvitee ÃÊ´ëÇÒ ´ë»ó character. ÆÄÆ¼¿¡ Âü¿© °¡´ÉÇÑ »óÅÂÀÌ¾î¾ß ÇÑ´Ù.[m
[32m+[m		[32m * @param	pchInvitee ï¿½Ê´ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ character. ï¿½ï¿½Æ¼ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ì¾ï¿½ï¿½ ï¿½Ñ´ï¿½.[m
 		 *[m
[31m-		 * ¾çÃø character ÀÇ »óÅÂ°¡ ÆÄÆ¼¿¡ ÃÊ´ëÇÏ°í ÃÊ´ë¹ÞÀ» ¼ö ÀÖ´Â »óÅÂ°¡ ¾Æ´Ï¶ó¸é ÃÊ´ëÇÏ´Â Ä³¸¯ÅÍ¿¡°Ô ÇØ´çÇÏ´Â Ã¤ÆÃ ¸Þ¼¼Áö¸¦ Àü¼ÛÇÑ´Ù.[m
[32m+[m		[32m * ï¿½ï¿½ï¿½ï¿½ character ï¿½ï¿½ ï¿½ï¿½ï¿½Â°ï¿½ ï¿½ï¿½Æ¼ï¿½ï¿½ ï¿½Ê´ï¿½ï¿½Ï°ï¿½ ï¿½Ê´ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½Ö´ï¿½ ï¿½ï¿½ï¿½Â°ï¿½ ï¿½Æ´Ï¶ï¿½ï¿½ ï¿½Ê´ï¿½ï¿½Ï´ï¿½ Ä³ï¿½ï¿½ï¿½Í¿ï¿½ï¿½ï¿½ ï¿½Ø´ï¿½ï¿½Ï´ï¿½ Ã¤ï¿½ï¿½ ï¿½Þ¼ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ñ´ï¿½.[m
 		 */[m
 		void			PartyInvite(LPCHARACTER pchInvitee);[m
 [m
[31m-		/// ÃÊ´ëÇß´ø character ÀÇ ¼ö¶ôÀ» Ã³¸®ÇÑ´Ù.[m
[32m+[m		[32m/// ï¿½Ê´ï¿½ï¿½ß´ï¿½ character ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ Ã³ï¿½ï¿½ï¿½Ñ´ï¿½.[m
 		/**[m
[31m-		 * @param	pchInvitee ÆÄÆ¼¿¡ Âü¿©ÇÒ character. ÆÄÆ¼¿¡ Âü¿©°¡´ÉÇÑ »óÅÂÀÌ¾î¾ß ÇÑ´Ù.[m
[32m+[m		[32m * @param	pchInvitee ï¿½ï¿½Æ¼ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ character. ï¿½ï¿½Æ¼ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ì¾ï¿½ï¿½ ï¿½Ñ´ï¿½.[m
 		 *[m
[31m-		 * pchInvitee °¡ ÆÄÆ¼¿¡ °¡ÀÔÇÒ ¼ö ÀÖ´Â »óÈ²ÀÌ ¾Æ´Ï¶ó¸é ÇØ´çÇÏ´Â Ã¤ÆÃ ¸Þ¼¼Áö¸¦ Àü¼ÛÇÑ´Ù.[m
[32m+[m		[32m * pchInvitee ï¿½ï¿½ ï¿½ï¿½Æ¼ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½Ö´ï¿½ ï¿½ï¿½È²ï¿½ï¿½ ï¿½Æ´Ï¶ï¿½ï¿½ ï¿½Ø´ï¿½ï¿½Ï´ï¿½ Ã¤ï¿½ï¿½ ï¿½Þ¼ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ñ´ï¿½.[m
 		 */[m
 		void			PartyInviteAccept(LPCHARACTER pchInvitee);[m
 [m
[31m-		/// ÃÊ´ëÇß´ø character ÀÇ ÃÊ´ë °ÅºÎ¸¦ Ã³¸®ÇÑ´Ù.[m
[32m+[m		[32m/// ï¿½Ê´ï¿½ï¿½ß´ï¿½ character ï¿½ï¿½ ï¿½Ê´ï¿½ ï¿½ÅºÎ¸ï¿½ Ã³ï¿½ï¿½ï¿½Ñ´ï¿½.[m
 		/**[m
[31m-		 * @param [in]	dwPID ÃÊ´ë Çß´ø character ÀÇ PID[m
[32m+[m		[32m * @param [in]	dwPID ï¿½Ê´ï¿½ ï¿½ß´ï¿½ character ï¿½ï¿½ PID[m
 		 */[m
 		void			PartyInviteDeny(DWORD dwPID);[m
 [m
[36m@@ -977,45 +977,45 @@[m [mclass CHARACTER : public CEntity, public CFSM, public CHorseRider[m
 [m
 	protected:[m
 [m
[31m-		/// ÆÄÆ¼¿¡ °¡ÀÔÇÑ´Ù.[m
[32m+[m		[32m/// ï¿½ï¿½Æ¼ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ñ´ï¿½.[m
 		/**[m
[31m-		 * @param	pkLeader °¡ÀÔÇÒ ÆÄÆ¼ÀÇ ¸®´õ[m
[32m+[m		[32m * @param	pkLeader ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½Æ¼ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½[m
 		 */[m
 		void			PartyJoin(LPCHARACTER pkLeader);[m
 [m
 		/**[m
[31m-		 * ÆÄÆ¼ °¡ÀÔÀ» ÇÒ ¼ö ¾øÀ» °æ¿ìÀÇ ¿¡·¯ÄÚµå.[m
[31m-		 * Error code ´Â ½Ã°£¿¡ ÀÇÁ¸ÀûÀÎ°¡¿¡ µû¶ó º¯°æ°¡´ÉÇÑ(mutable) type °ú Á¤Àû(static) type À¸·Î ³ª´¶´Ù.[m
[31m-		 * Error code ÀÇ °ªÀÌ PERR_SEPARATOR º¸´Ù ³·À¸¸é º¯°æ°¡´ÉÇÑ type ÀÌ°í ³ôÀ¸¸é Á¤Àû type ÀÌ´Ù.[m
[32m+[m		[32m * ï¿½ï¿½Æ¼ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Úµï¿½.[m
[32m+[m		[32m * Error code ï¿½ï¿½ ï¿½Ã°ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½Î°ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½æ°¡ï¿½ï¿½ï¿½ï¿½(mutable) type ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½(static) type ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½.[m
[32m+[m		[32m * Error code ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ PERR_SEPARATOR ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½æ°¡ï¿½ï¿½ï¿½ï¿½ type ï¿½Ì°ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ type ï¿½Ì´ï¿½.[m
 		 */[m
 		enum PartyJoinErrCode {[m
[31m-			PERR_NONE		= 0,	///< Ã³¸®¼º°ø[m
[31m-			PERR_SERVER,			///< ¼­¹ö¹®Á¦·Î ÆÄÆ¼°ü·Ã Ã³¸® ºÒ°¡[m
[31m-			PERR_DUNGEON,			///< Ä³¸¯ÅÍ°¡ ´øÀü¿¡ ÀÖÀ½[m
[31m-			PERR_OBSERVER,			///< °üÀü¸ðµåÀÓ[m
[31m-			PERR_LVBOUNDARY,		///< »ó´ë Ä³¸¯ÅÍ¿Í ·¹º§Â÷ÀÌ°¡ ³²[m
[31m-			PERR_LOWLEVEL,			///< »ó´ëÆÄÆ¼ÀÇ ÃÖ°í·¹º§º¸´Ù 30·¹º§ ³·À½[m
[31m-			PERR_HILEVEL,			///< »ó´ëÆÄÆ¼ÀÇ ÃÖÀú·¹º§º¸´Ù 30·¹º§ ³ôÀ½[m
[31m-			PERR_ALREADYJOIN,		///< ÆÄÆ¼°¡ÀÔ ´ë»ó Ä³¸¯ÅÍ°¡ ÀÌ¹Ì ÆÄÆ¼Áß[m
[31m-			PERR_PARTYISFULL,		///< ÆÄÆ¼ÀÎ¿ø Á¦ÇÑ ÃÊ°ú[m
[32m+[m			[32mPERR_NONE		= 0,	///< Ã³ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½[m
[32m+[m			[32mPERR_SERVER,			///< ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½Æ¼ï¿½ï¿½ï¿½ï¿½ Ã³ï¿½ï¿½ ï¿½Ò°ï¿½[m
[32m+[m			[32mPERR_DUNGEON,			///< Ä³ï¿½ï¿½ï¿½Í°ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½[m
[32m+[m			[32mPERR_OBSERVER,			///< ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½[m
[32m+[m			[32mPERR_LVBOUNDARY,		///< ï¿½ï¿½ï¿½ Ä³ï¿½ï¿½ï¿½Í¿ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½Ì°ï¿½ ï¿½ï¿½[m
[32m+[m			[32mPERR_LOWLEVEL,			///< ï¿½ï¿½ï¿½ï¿½ï¿½Æ¼ï¿½ï¿½ ï¿½Ö°ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ 30ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½[m
[32m+[m			[32mPERR_HILEVEL,			///< ï¿½ï¿½ï¿½ï¿½ï¿½Æ¼ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ 30ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½[m
[32m+[m			[32mPERR_ALREADYJOIN,		///< ï¿½ï¿½Æ¼ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ Ä³ï¿½ï¿½ï¿½Í°ï¿½ ï¿½Ì¹ï¿½ ï¿½ï¿½Æ¼ï¿½ï¿½[m
[32m+[m			[32mPERR_PARTYISFULL,		///< ï¿½ï¿½Æ¼ï¿½Î¿ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½Ê°ï¿½[m
 			PERR_SEPARATOR,			///< Error type separator.[m
[31m-			PERR_DIFFEMPIRE,		///< »ó´ë Ä³¸¯ÅÍ¿Í ´Ù¸¥ Á¦±¹ÀÓ[m
[31m-			PERR_MAX				///< Error code ÃÖ°íÄ¡. ÀÌ ¾Õ¿¡ Error code ¸¦ Ãß°¡ÇÑ´Ù.[m
[32m+[m			[32mPERR_DIFFEMPIRE,		///< ï¿½ï¿½ï¿½ Ä³ï¿½ï¿½ï¿½Í¿ï¿½ ï¿½Ù¸ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½[m
[32m+[m			[32mPERR_MAX				///< Error code ï¿½Ö°ï¿½Ä¡. ï¿½ï¿½ ï¿½Õ¿ï¿½ Error code ï¿½ï¿½ ï¿½ß°ï¿½ï¿½Ñ´ï¿½.[m
 		};[m
 [m
[31m-		/// ÆÄÆ¼ °¡ÀÔÀÌ³ª °á¼º °¡´ÉÇÑ Á¶°ÇÀ» °Ë»çÇÑ´Ù.[m
[32m+[m		[32m/// ï¿½ï¿½Æ¼ ï¿½ï¿½ï¿½ï¿½ï¿½Ì³ï¿½ ï¿½á¼º ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ë»ï¿½ï¿½Ñ´ï¿½.[m
 		/**[m
[31m-		 * @param 	pchLeader ÆÄÆ¼ÀÇ leader ÀÌ°Å³ª ÃÊ´ëÇÑ character[m
[31m-		 * @param	pchGuest ÃÊ´ë¹Þ´Â character[m
[31m-		 * @return	¸ðµç PartyJoinErrCode °¡ ¹ÝÈ¯µÉ ¼ö ÀÖ´Ù.[m
[32m+[m		[32m * @param 	pchLeader ï¿½ï¿½Æ¼ï¿½ï¿½ leader ï¿½Ì°Å³ï¿½ ï¿½Ê´ï¿½ï¿½ï¿½ character[m
[32m+[m		[32m * @param	pchGuest ï¿½Ê´ï¿½Þ´ï¿½ character[m
[32m+[m		[32m * @return	ï¿½ï¿½ï¿½ PartyJoinErrCode ï¿½ï¿½ ï¿½ï¿½È¯ï¿½ï¿½ ï¿½ï¿½ ï¿½Ö´ï¿½.[m
 		 */[m
 		static PartyJoinErrCode	IsPartyJoinableCondition(const LPCHARACTER pchLeader, const LPCHARACTER pchGuest);[m
 [m
[31m-		/// ÆÄÆ¼ °¡ÀÔÀÌ³ª °á¼º °¡´ÉÇÑ µ¿ÀûÀÎ Á¶°ÇÀ» °Ë»çÇÑ´Ù.[m
[32m+[m		[32m/// ï¿½ï¿½Æ¼ ï¿½ï¿½ï¿½ï¿½ï¿½Ì³ï¿½ ï¿½á¼º ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ë»ï¿½ï¿½Ñ´ï¿½.[m
 		/**[m
[31m-		 * @param 	pchLeader ÆÄÆ¼ÀÇ leader ÀÌ°Å³ª ÃÊ´ëÇÑ character[m
[31m-		 * @param	pchGuest ÃÊ´ë¹Þ´Â character[m
[31m-		 * @return	mutable type ÀÇ code ¸¸ ¹ÝÈ¯ÇÑ´Ù.[m
[32m+[m		[32m * @param 	pchLeader ï¿½ï¿½Æ¼ï¿½ï¿½ leader ï¿½Ì°Å³ï¿½ ï¿½Ê´ï¿½ï¿½ï¿½ character[m
[32m+[m		[32m * @param	pchGuest ï¿½Ê´ï¿½Þ´ï¿½ character[m
[32m+[m		[32m * @return	mutable type ï¿½ï¿½ code ï¿½ï¿½ ï¿½ï¿½È¯ï¿½Ñ´ï¿½.[m
 		 */[m
 		static PartyJoinErrCode	IsPartyJoinableMutableCondition(const LPCHARACTER pchLeader, const LPCHARACTER pchGuest);[m
 [m
[36m@@ -1024,11 +1024,11 @@[m [mclass CHARACTER : public CEntity, public CFSM, public CHorseRider[m
 		LPEVENT			m_pkPartyRequestEvent;[m
 [m
 		/**[m
[31m-		 * ÆÄÆ¼ÃÊÃ» Event map.[m
[31m-		 * key: ÃÊ´ë¹ÞÀº Ä³¸¯ÅÍÀÇ PID[m
[31m-		 * value: eventÀÇ pointer[m
[32m+[m		[32m * ï¿½ï¿½Æ¼ï¿½ï¿½Ã» Event map.[m
[32m+[m		[32m * key: ï¿½Ê´ï¿½ï¿½ï¿½ï¿½ Ä³ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ PID[m
[32m+[m		[32m * value: eventï¿½ï¿½ pointer[m
 		 *[m
[31m-		 * ÃÊ´ëÇÑ Ä³¸¯ÅÍµé¿¡ ´ëÇÑ event map.[m
[32m+[m		[32m * ï¿½Ê´ï¿½ï¿½ï¿½ Ä³ï¿½ï¿½ï¿½Íµé¿¡ ï¿½ï¿½ï¿½ï¿½ event map.[m
 		 */[m
 		typedef std::map< DWORD, LPEVENT >	EventMap;[m
 		EventMap		m_PartyInviteEventMap;[m
[36m@@ -1062,7 +1062,7 @@[m [mclass CHARACTER : public CEntity, public CFSM, public CHorseRider[m
 		////////////////////////////////////////////////////////////////////////////////////////[m
 		// Item related[m
 	public:[m
[31m-		bool			CanHandleItem(bool bSkipRefineCheck = false, bool bSkipObserver = false); // ¾ÆÀÌÅÛ °ü·Ã ÇàÀ§¸¦ ÇÒ ¼ö ÀÖ´Â°¡?[m
[32m+[m		[32mbool			CanHandleItem(bool bSkipRefineCheck = false, bool bSkipObserver = false); // ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ ï¿½Ö´Â°ï¿½?[m
 [m
 		bool			IsItemLoaded() const	{ return m_bItemLoaded; }[m
 		void			SetItemLoaded()	{ m_bItemLoaded = true; }[m
[36m@@ -1073,7 +1073,11 @@[m [mclass CHARACTER : public CEntity, public CFSM, public CHorseRider[m
 #endif[m
 [m
 		void			ClearItem();[m
[32m+[m[32m#if defined(__BL_ENABLE_PICKUP_ITEM_EFFECT__)[m
[32m+[m		[32mvoid			SetItem(TItemPos Cell, LPITEM item, bool bHighlight = true);[m
[32m+[m[32m#else[m
 		void			SetItem(TItemPos Cell, LPITEM item);[m
[32m+[m[32m#endif[m
 		LPITEM			GetItem(TItemPos Cell) const;[m
 		LPITEM			GetInventoryItem(WORD wCell) const;[m
 		bool			IsEmptyItemGrid(TItemPos Cell, BYTE size, int iExceptionCell = -1) const;[m
[36m@@ -1082,14 +1086,14 @@[m [mclass CHARACTER : public CEntity, public CFSM, public CHorseRider[m
 		LPITEM			GetWear(BYTE bCell) const;[m
 [m
 		// MYSHOP_PRICE_LIST[m
[31m-		void			UseSilkBotary(void); 		/// ºñ´Ü º¸µû¸® ¾ÆÀÌÅÛÀÇ »ç¿ë[m
[32m+[m		[32mvoid			UseSilkBotary(void); 		/// ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½[m
 [m
[31m-		/// DB Ä³½Ã·Î ºÎÅÍ ¹Þ¾Æ¿Â °¡°ÝÁ¤º¸ ¸®½ºÆ®¸¦ À¯Àú¿¡°Ô Àü¼ÛÇÏ°í º¸µû¸® ¾ÆÀÌÅÛ »ç¿ëÀ» Ã³¸®ÇÑ´Ù.[m
[32m+[m		[32m/// DB Ä³ï¿½Ã·ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½Þ¾Æ¿ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½Æ®ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï°ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ Ã³ï¿½ï¿½ï¿½Ñ´ï¿½.[m
 		/**[m
[31m-		 * @param [in] p	°¡°ÝÁ¤º¸ ¸®½ºÆ® ÆÐÅ¶[m
[32m+[m		[32m * @param [in] p	ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½Æ® ï¿½ï¿½Å¶[m
 		 *[m
[31m-		 * Á¢¼ÓÇÑ ÈÄ Ã³À½ ºñ´Ü º¸µû¸® ¾ÆÀÌÅÛ »ç¿ë ½Ã UseSilkBotary ¿¡¼­ DB Ä³½Ã·Î °¡°ÝÁ¤º¸ ¸®½ºÆ®¸¦ ¿äÃ»ÇÏ°í[m
[31m-		 * ÀÀ´ä¹ÞÀº ½ÃÁ¡¿¡ ÀÌ ÇÔ¼ö¿¡¼­ ½ÇÁ¦ ºñ´Üº¸µû¸® »ç¿ëÀ» Ã³¸®ÇÑ´Ù.[m
[32m+[m		[32m * ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ Ã³ï¿½ï¿½ ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ ï¿½ï¿½ UseSilkBotary ï¿½ï¿½ï¿½ï¿½ DB Ä³ï¿½Ã·ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½Æ®ï¿½ï¿½ ï¿½ï¿½Ã»ï¿½Ï°ï¿½[m
[32m+[m		[32m * ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½Ô¼ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½Üºï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ Ã³ï¿½ï¿½ï¿½Ñ´ï¿½.[m
 		 */[m
 		void			UseSilkBotaryReal(const TPacketMyshopPricelistHeader* p);[m
 		// END_OF_MYSHOP_PRICE_LIST[m
[36m@@ -1136,10 +1140,10 @@[m [mclass CHARACTER : public CEntity, public CFSM, public CHorseRider[m
 		bool			EquipItem(LPITEM item, int iCandidateCell = -1);[m
 		bool			UnequipItem(LPITEM item);[m
 [m
[31m-		// ÇöÀç itemÀ» Âø¿ëÇÒ ¼ö ÀÖ´Â Áö È®ÀÎÇÏ°í, ºÒ°¡´É ÇÏ´Ù¸é Ä³¸¯ÅÍ¿¡°Ô ÀÌÀ¯¸¦ ¾Ë·ÁÁÖ´Â ÇÔ¼ö[m
[32m+[m		[32m// ï¿½ï¿½ï¿½ï¿½ itemï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½Ö´ï¿½ ï¿½ï¿½ È®ï¿½ï¿½ï¿½Ï°ï¿½, ï¿½Ò°ï¿½ï¿½ï¿½ ï¿½Ï´Ù¸ï¿½ Ä³ï¿½ï¿½ï¿½Í¿ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ë·ï¿½ï¿½Ö´ï¿½ ï¿½Ô¼ï¿½[m
 		bool			CanEquipNow(const LPITEM item, const TItemPos& srcCell = NPOS, const TItemPos& destCell = NPOS);[m
 [m
[31m-		// Âø¿ëÁßÀÎ itemÀ» ¹þÀ» ¼ö ÀÖ´Â Áö È®ÀÎÇÏ°í, ºÒ°¡´É ÇÏ´Ù¸é Ä³¸¯ÅÍ¿¡°Ô ÀÌÀ¯¸¦ ¾Ë·ÁÁÖ´Â ÇÔ¼ö[m
[32m+[m		[32m// ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ itemï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½Ö´ï¿½ ï¿½ï¿½ È®ï¿½ï¿½ï¿½Ï°ï¿½, ï¿½Ò°ï¿½ï¿½ï¿½ ï¿½Ï´Ù¸ï¿½ Ä³ï¿½ï¿½ï¿½Í¿ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ë·ï¿½ï¿½Ö´ï¿½ ï¿½Ô¼ï¿½[m
 		bool			CanUnequipNow(const LPITEM item, const TItemPos& srcCell = NPOS, const TItemPos& destCell = NPOS);[m
 [m
 		bool			SwapItem(BYTE bCell, BYTE bDestCell);[m
[36m@@ -1171,14 +1175,14 @@[m [mclass CHARACTER : public CEntity, public CFSM, public CHorseRider[m
 [m
 	protected:[m
 [m
[31m-		/// ÇÑ ¾ÆÀÌÅÛ¿¡ ´ëÇÑ °¡°ÝÁ¤º¸¸¦ Àü¼ÛÇÑ´Ù.[m
[32m+[m		[32m/// ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Û¿ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ñ´ï¿½.[m
 		/**[m
[31m-		 * @param [in]	dwItemVnum ¾ÆÀÌÅÛ vnum[m
[31m-		 * @param [in]	dwItemPrice ¾ÆÀÌÅÛ °¡°Ý[m
[32m+[m		[32m * @param [in]	dwItemVnum ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ vnum[m
[32m+[m		[32m * @param [in]	dwItemPrice ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½[m
 		 */[m
 		void			SendMyShopPriceListCmd(DWORD dwItemVnum, DWORD dwItemPrice);[m
 [m
[31m-		bool			m_bNoOpenedShop;	///< ÀÌ¹ø Á¢¼Ó ÈÄ °³ÀÎ»óÁ¡À» ¿¬ ÀûÀÌ ÀÖ´ÂÁöÀÇ ¿©ºÎ(¿­¾ú´ø ÀûÀÌ ¾ø´Ù¸é true)[m
[32m+[m		[32mbool			m_bNoOpenedShop;	///< ï¿½Ì¹ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½Î»ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½Ö´ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½(ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Ù¸ï¿½ true)[m
 [m
 		bool			m_bItemLoaded;[m
 		int				m_iRefineAdditionalCell;[m
[36m@@ -1192,7 +1196,7 @@[m [mclass CHARACTER : public CEntity, public CFSM, public CHorseRider[m
 		void			SetGold(INT gold)	{ m_points.gold = gold;	}[m
 		bool			DropGold(INT gold);[m
 		INT				GetAllowedGold() const;[m
[31m-		void			GiveGold(INT iAmount);	// ÆÄÆ¼°¡ ÀÖÀ¸¸é ÆÄÆ¼ ºÐ¹è, ·Î±× µîÀÇ Ã³¸®[m
[32m+[m		[32mvoid			GiveGold(INT iAmount);	// ï¿½ï¿½Æ¼ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½Æ¼ ï¿½Ð¹ï¿½, ï¿½Î±ï¿½ ï¿½ï¿½ï¿½ï¿½ Ã³ï¿½ï¿½[m
 		// End of Money[m
 [m
 		////////////////////////////////////////////////////////////////////////////////////////[m
[36m@@ -1258,9 +1262,9 @@[m [mclass CHARACTER : public CEntity, public CFSM, public CHorseRider[m
 		bool				CanFight() const;[m
 [m
 		bool				CanBeginFight() const;[m
[31m-		void				BeginFight(LPCHARACTER pkVictim); // pkVictimr°ú ½Î¿ì±â ½ÃÀÛÇÑ´Ù. (°­Á¦ÀûÀÓ, ½ÃÀÛÇÒ ¼ö ÀÖ³ª Ã¼Å©ÇÏ·Á¸é CanBeginFightÀ» »ç¿ë)[m
[32m+[m		[32mvoid				BeginFight(LPCHARACTER pkVictim); // pkVictimrï¿½ï¿½ ï¿½Î¿ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ñ´ï¿½. (ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½, ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½Ö³ï¿½ Ã¼Å©ï¿½Ï·ï¿½ï¿½ï¿½ CanBeginFightï¿½ï¿½ ï¿½ï¿½ï¿½)[m
 [m
[31m-		bool				CounterAttack(LPCHARACTER pkChr); // ¹Ý°ÝÇÏ±â (¸ó½ºÅÍ¸¸ »ç¿ë)[m
[32m+[m		[32mbool				CounterAttack(LPCHARACTER pkChr); // ï¿½Ý°ï¿½ï¿½Ï±ï¿½ (ï¿½ï¿½ï¿½Í¸ï¿½ ï¿½ï¿½ï¿½)[m
 [m
 		bool				IsStun() const;[m
 		void				Stun();[m
[36m@@ -1290,7 +1294,7 @@[m [mclass CHARACTER : public CEntity, public CFSM, public CHorseRider[m
 		void				UpdateAlignment(int iAmount);[m
 		int					GetAlignment() const;[m
 [m
[31m-		//¼±¾ÇÄ¡ ¾ò±â [m
[32m+[m		[32m//ï¿½ï¿½ï¿½ï¿½Ä¡ ï¿½ï¿½ï¿½[m[41m [m
 		int					GetRealAlignment() const;[m
 		void				ShowAlignment(bool bShow);[m
 [m
[36m@@ -1339,7 +1343,7 @@[m [mclass CHARACTER : public CEntity, public CFSM, public CHorseRider[m
 [m
 		DWORD				m_dwFlyTargetID;[m
 		std::vector<DWORD>	m_vec_dwFlyTargets;[m
[31m-		TDamageMap			m_map_kDamage;	// ¾î¶² Ä³¸¯ÅÍ°¡ ³ª¿¡°Ô ¾ó¸¶¸¸Å­ÀÇ µ¥¹ÌÁö¸¦ ÁÖ¾ú´Â°¡?[m
[32m+[m		[32mTDamageMap			m_map_kDamage;	// ï¿½î¶² Ä³ï¿½ï¿½ï¿½Í°ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ó¸¶¸ï¿½Å­ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ö¾ï¿½ï¿½Â°ï¿½?[m
 //		AttackLog			m_kAttackLog;[m
 		DWORD				m_dwKillerPID;[m
 [m
[36m@@ -1362,8 +1366,8 @@[m [mclass CHARACTER : public CEntity, public CFSM, public CHorseRider[m
 		BYTE				GetDropMetinStonePct() const { return m_bDropMetinStonePct; }[m
 [m
 	protected:[m
[31m-		LPCHARACTER			m_pkChrStone;		// ³ª¸¦ ½ºÆùÇÑ µ¹[m
[31m-		CHARACTER_SET		m_set_pkChrSpawnedBy;	// ³»°¡ ½ºÆùÇÑ ³ðµé[m
[32m+[m		[32mLPCHARACTER			m_pkChrStone;		// ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½[m
[32m+[m		[32mCHARACTER_SET		m_set_pkChrSpawnedBy;	// ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½[m
 		DWORD				m_dwDropMetinStone;[m
 		BYTE				m_bDropMetinStonePct;[m
 		// End of Stone[m
[36m@@ -1421,7 +1425,7 @@[m [mclass CHARACTER : public CEntity, public CFSM, public CHorseRider[m
 [m
 	private:[m
 		bool				m_bDisableCooltime;[m
[31m-		DWORD				m_dwLastSkillTime;	///< ¸¶Áö¸·À¸·Î skill À» ¾´ ½Ã°£(millisecond).[m
[32m+[m		[32mDWORD				m_dwLastSkillTime;	///< ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ skill ï¿½ï¿½ ï¿½ï¿½ ï¿½Ã°ï¿½(millisecond).[m
 		// End of Skill[m
 #ifdef ENABLE_SORT_INVEN[m
 		DWORD				m_dwLastSortTime;[m
[36m@@ -1480,10 +1484,10 @@[m [mclass CHARACTER : public CEntity, public CFSM, public CHorseRider[m
 		// AI related[m
 	public:[m
 		void			AssignTriggers(const TMobTable * table);[m
[31m-		LPCHARACTER		GetVictim() const;	// °ø°ÝÇÒ ´ë»ó ¸®ÅÏ[m
[32m+[m		[32mLPCHARACTER		GetVictim() const;	// ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½[m
 		void			SetVictim(LPCHARACTER pkVictim);[m
 		LPCHARACTER		GetNearestVictim(LPCHARACTER pkChr);[m
[31m-		LPCHARACTER		GetProtege() const;	// º¸È£ÇØ¾ß ÇÒ ´ë»ó ¸®ÅÏ[m
[32m+[m		[32mLPCHARACTER		GetProtege() const;	// ï¿½ï¿½È£ï¿½Ø¾ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½[m
 [m
 		bool			Follow(LPCHARACTER pkChr, float fMinimumDistance = 150.0f);[m
 		bool			Return();[m
[36m@@ -1507,8 +1511,8 @@[m [mclass CHARACTER : public CEntity, public CFSM, public CHorseRider[m
 		////////////////////////////////////////////////////////////////////////////////////////[m
 		// Target[m
 	protected:[m
[31m-		LPCHARACTER				m_pkChrTarget;		// ³» Å¸°Ù[m
[31m-		CHARACTER_SET	m_set_pkChrTargetedBy;	// ³ª¸¦ Å¸°ÙÀ¸·Î °¡Áö°í ÀÖ´Â »ç¶÷µé[m
[32m+[m		[32mLPCHARACTER				m_pkChrTarget;		// ï¿½ï¿½ Å¸ï¿½ï¿½[m
[32m+[m		[32mCHARACTER_SET	m_set_pkChrTargetedBy;	// ï¿½ï¿½ï¿½ï¿½ Å¸ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ö´ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½[m
 [m
 	public:[m
 		void				SetTarget(LPCHARACTER pkChrTarget);[m
[36m@@ -1529,19 +1533,19 @@[m [mclass CHARACTER : public CEntity, public CFSM, public CHorseRider[m
 		void				ChangeSafeboxSize(BYTE bSize);[m
 		void				CloseSafebox();[m
 [m
[31m-		/// Ã¢°í ¿­±â ¿äÃ»[m
[32m+[m		[32m/// Ã¢ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½Ã»[m
 		/**[m
[31m-		 * @param [in]	pszPassword 1ÀÚ ÀÌ»ó 6ÀÚ ÀÌÇÏÀÇ Ã¢°í ºñ¹Ð¹øÈ£[m
[32m+[m		[32m * @param [in]	pszPassword 1ï¿½ï¿½ ï¿½Ì»ï¿½ 6ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ Ã¢ï¿½ï¿½ ï¿½ï¿½Ð¹ï¿½È£[m
 		 *[m
[31m-		 * DB ¿¡ Ã¢°í¿­±â¸¦ ¿äÃ»ÇÑ´Ù.[m
[31m-		 * Ã¢°í´Â Áßº¹À¸·Î ¿­Áö ¸øÇÏ¸ç, ÃÖ±Ù Ã¢°í¸¦ ´ÝÀº ½Ã°£À¸·Î ºÎÅÍ 10ÃÊ ÀÌ³»¿¡´Â ¿­ Áö ¸øÇÑ´Ù.[m
[32m+[m		[32m * DB ï¿½ï¿½ Ã¢ï¿½ï¿½ï¿½ï¿½ï¿½â¸¦ ï¿½ï¿½Ã»ï¿½Ñ´ï¿½.[m
[32m+[m		[32m * Ã¢ï¿½ï¿½ï¿½ï¿½ ï¿½ßºï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Ï¸ï¿½, ï¿½Ö±ï¿½ Ã¢ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½Ã°ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ 10ï¿½ï¿½ ï¿½Ì³ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½Ñ´ï¿½.[m
 		 */[m
 		void				ReqSafeboxLoad(const char* pszPassword);[m
 [m
[31m-		/// Ã¢°í ¿­±â ¿äÃ»ÀÇ Ãë¼Ò[m
[32m+[m		[32m/// Ã¢ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½Ã»ï¿½ï¿½ ï¿½ï¿½ï¿½[m
 		/**[m
[31m-		 * ReqSafeboxLoad ¸¦ È£ÃâÇÏ°í CloseSafebox ÇÏÁö ¾Ê¾ÒÀ» ¶§ ÀÌ ÇÔ¼ö¸¦ È£ÃâÇÏ¸é Ã¢°í¸¦ ¿­ ¼ö ÀÖ´Ù.[m
[31m-		 * Ã¢°í¿­±âÀÇ ¿äÃ»ÀÌ DB ¼­¹ö¿¡¼­ ½ÇÆÐÀÀ´äÀ» ¹Þ¾ÒÀ» °æ¿ì ÀÌ ÇÔ¼ö¸¦ »ç¿ëÇØ¼­ ¿äÃ»À» ÇÒ ¼ö ÀÖ°Ô ÇØÁØ´Ù.[m
[32m+[m		[32m * ReqSafeboxLoad ï¿½ï¿½ È£ï¿½ï¿½ï¿½Ï°ï¿½ CloseSafebox ï¿½ï¿½ï¿½ï¿½ ï¿½Ê¾ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ ï¿½Ô¼ï¿½ï¿½ï¿½ È£ï¿½ï¿½ï¿½Ï¸ï¿½ Ã¢ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ ï¿½Ö´ï¿½.[m
[32m+[m		[32m * Ã¢ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½Ã»ï¿½ï¿½ DB ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Þ¾ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½Ô¼ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½Ø¼ï¿½ ï¿½ï¿½Ã»ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ ï¿½Ö°ï¿½ ï¿½ï¿½ï¿½Ø´ï¿½.[m
 		 */[m
 		void				CancelSafeboxLoad( void ) { m_bOpeningSafebox = false; }[m
 [m
[36m@@ -1559,7 +1563,7 @@[m [mclass CHARACTER : public CEntity, public CFSM, public CHorseRider[m
 		CSafebox *			m_pkSafebox;[m
 		int					m_iSafeboxSize;[m
 		int					m_iSafeboxLoadTime;[m
[31m-		bool				m_bOpeningSafebox;	///< Ã¢°í°¡ ¿­±â ¿äÃ» ÁßÀÌ°Å³ª ¿­·ÁÀÖ´Â°¡ ¿©ºÎ, true ÀÏ °æ¿ì ¿­±â¿äÃ»ÀÌ°Å³ª ¿­·ÁÀÖÀ½.[m
[32m+[m		[32mbool				m_bOpeningSafebox;	///< Ã¢ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½Ã» ï¿½ï¿½ï¿½Ì°Å³ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ö´Â°ï¿½ ï¿½ï¿½ï¿½ï¿½, true ï¿½ï¿½ ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ã»ï¿½Ì°Å³ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½.[m
 [m
 		CSafebox *			m_pkMall;[m
 		int					m_iMallLoadTime;[m
[36m@@ -1593,7 +1597,7 @@[m [mclass CHARACTER : public CEntity, public CFSM, public CHorseRider[m
 [m
 		void				HorseSummon(bool bSummon, bool bFromFar = false, DWORD dwVnum = 0, const char* name = 0);[m
 [m
[31m-		LPCHARACTER			GetHorse() const			{ return m_chHorse; }	 // ÇöÀç ¼ÒÈ¯ÁßÀÎ ¸»[m
[32m+[m		[32mLPCHARACTER			GetHorse() const			{ return m_chHorse; }	 // ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½È¯ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½[m
 		LPCHARACTER			GetRider() const; // rider on horse[m
 		void				SetRider(LPCHARACTER ch);[m
 [m
[36m@@ -1655,7 +1659,7 @@[m [mclass CHARACTER : public CEntity, public CFSM, public CHorseRider[m
 		////////////////////////////////////////////////////////////////////////////////////////[m
 		// Resists & Proofs[m
 	public:[m
[31m-		bool				CannotMoveByAffect() const;	// Æ¯Á¤ È¿°ú¿¡ ÀÇÇØ ¿òÁ÷ÀÏ ¼ö ¾ø´Â »óÅÂÀÎ°¡?[m
[32m+[m		[32mbool				CannotMoveByAffect() const;	// Æ¯ï¿½ï¿½ È¿ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Î°ï¿½?[m
 		bool				IsImmune(DWORD dwImmuneFlag);[m
 		void				SetImmuneFlag(DWORD dw) { m_pointsInstant.dwImmuneFlag = dw; }[m
 [m
[36m@@ -1695,7 +1699,7 @@[m [mclass CHARACTER : public CEntity, public CFSM, public CHorseRider[m
 		void				UpdateStateMachine(DWORD dwPulse);[m
 		void				SetNextStatePulse(int iPulseNext);[m
 [m
[31m-		// Ä³¸¯ÅÍ ÀÎ½ºÅÏ½º ¾÷µ¥ÀÌÆ® ÇÔ¼ö. ±âÁ¸¿£ ÀÌ»óÇÑ »ó¼Ó±¸Á¶·Î CFSM::Update ÇÔ¼ö¸¦ È£ÃâÇÏ°Å³ª UpdateStateMachine ÇÔ¼ö¸¦ »ç¿ëÇß´Âµ¥, º°°³ÀÇ ¾÷µ¥ÀÌÆ® ÇÔ¼ö Ãß°¡ÇÔ.[m
[32m+[m		[32m// Ä³ï¿½ï¿½ï¿½ï¿½ ï¿½Î½ï¿½ï¿½Ï½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½Æ® ï¿½Ô¼ï¿½. ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ì»ï¿½ï¿½ï¿½ ï¿½ï¿½Ó±ï¿½ï¿½ï¿½ï¿½ï¿½ CFSM::Update ï¿½Ô¼ï¿½ï¿½ï¿½ È£ï¿½ï¿½ï¿½Ï°Å³ï¿½ UpdateStateMachine ï¿½Ô¼ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ß´Âµï¿½, ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½Æ® ï¿½Ô¼ï¿½ ï¿½ß°ï¿½ï¿½ï¿½.[m
 		void				UpdateCharacter(DWORD dwPulse);[m
 [m
 	protected:[m
[36m@@ -1765,9 +1769,9 @@[m [mclass CHARACTER : public CEntity, public CFSM, public CHorseRider[m
 		int				m_aiPremiumTimes[PREMIUM_MAX_NUM];[m
 [m
 		// CHANGE_ITEM_ATTRIBUTES[m
[31m-		static const DWORD		msc_dwDefaultChangeItemAttrCycle;	///< µðÆúÆ® ¾ÆÀÌÅÛ ¼Ó¼ºº¯°æ °¡´É ÁÖ±â[m
[31m-		static const char		msc_szLastChangeItemAttrFlag[];		///< ÃÖ±Ù ¾ÆÀÌÅÛ ¼Ó¼ºÀ» º¯°æÇÑ ½Ã°£ÀÇ Quest Flag ÀÌ¸§[m
[31m-		static const char		msc_szChangeItemAttrCycleFlag[];		///< ¾ÆÀÌÅÛ ¼Ó¼ºº´°æ °¡´É ÁÖ±âÀÇ Quest Flag ÀÌ¸§[m
[32m+[m		[32mstatic const DWORD		msc_dwDefaultChangeItemAttrCycle;	///< ï¿½ï¿½ï¿½ï¿½Æ® ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ó¼ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½Ö±ï¿½[m
[32m+[m		[32mstatic const char		msc_szLastChangeItemAttrFlag[];		///< ï¿½Ö±ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ó¼ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ã°ï¿½ï¿½ï¿½ Quest Flag ï¿½Ì¸ï¿½[m
[32m+[m		[32mstatic const char		msc_szChangeItemAttrCycleFlag[];		///< ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ó¼ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½Ö±ï¿½ï¿½ï¿½ Quest Flag ï¿½Ì¸ï¿½[m
 		// END_OF_CHANGE_ITEM_ATTRIBUTES[m
 [m
 		// NEW_HAIR_STYLE_ADD[m
[36m@@ -1839,7 +1843,7 @@[m [mclass CHARACTER : public CEntity, public CFSM, public CHorseRider[m
 		int		GetMyShopTime() const	{ return m_iMyShopTime; }[m
 		void	SetMyShopTime() { m_iMyShopTime = thecore_pulse(); }[m
 [m
[31m-		// Hack ¹æÁö¸¦ À§ÇÑ Ã¼Å©.[m
[32m+[m		[32m// Hack ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ Ã¼Å©.[m
 		bool	IsHack(bool bSendMsg = true, bool bCheckShopOwner = true, int limittime = g_nPortalLimitTime);[m
 [m
 		// MONARCH[m
[36m@@ -1889,9 +1893,9 @@[m [mclass CHARACTER : public CEntity, public CFSM, public CHorseRider[m
 		bool IsSiegeNPC() const;[m
 [m
 	private:[m
[31m-		//Áß±¹ Àü¿ë[m
[31m-		//18¼¼ ¹Ì¸¸ Àü¿ë[m
[31m-		//3½Ã°£ : 50 % 5 ½Ã°£ 0%[m
[32m+[m		[32m//ï¿½ß±ï¿½ ï¿½ï¿½ï¿½ï¿½[m
[32m+[m		[32m//18ï¿½ï¿½ ï¿½Ì¸ï¿½ ï¿½ï¿½ï¿½ï¿½[m
[32m+[m		[32m//3ï¿½Ã°ï¿½ : 50 % 5 ï¿½Ã°ï¿½ 0%[m
 		e_overtime m_eOverTime;[m
 [m
 	public:[m
[36m@@ -1979,7 +1983,7 @@[m [mclass CHARACTER : public CEntity, public CFSM, public CHorseRider[m
 [m
 		typedef std::map <BYTE, CBuffOnAttributes*> TMapBuffOnAttrs;[m
 		TMapBuffOnAttrs m_map_buff_on_attrs;[m
[31m-		// ¹«Àû : ¿øÈ°ÇÑ Å×½ºÆ®¸¦ À§ÇÏ¿©.[m
[32m+[m		[32m// ï¿½ï¿½ï¿½ï¿½ : ï¿½ï¿½È°ï¿½ï¿½ ï¿½×½ï¿½Æ®ï¿½ï¿½ ï¿½ï¿½ï¿½Ï¿ï¿½.[m
 	public:[m
 		void SetArmada() { cannot_dead = true; }[m
 		void ResetArmada() { cannot_dead = false; }[m
[36m@@ -1994,7 +1998,7 @@[m [mclass CHARACTER : public CEntity, public CFSM, public CHorseRider[m
 		bool IsPet() { return m_bIsPet; }[m
 #endif[m
 [m
[31m-	//ÃÖÁ¾ µ¥¹ÌÁö º¸Á¤.[m
[32m+[m	[32m//ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½.[m
 	private:[m
 		float m_fAttMul;[m
 		float m_fDamMul;[m
[36m@@ -2007,7 +2011,7 @@[m [mclass CHARACTER : public CEntity, public CFSM, public CHorseRider[m
 	private:[m
 		bool IsValidItemPosition(TItemPos Pos) const;[m
 [m
[31m-		//µ¶ÀÏ ¼±¹° ±â´É ÆÐÅ¶ ÀÓ½Ã ÀúÀå[m
[32m+[m		[32m//ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ ï¿½ï¿½Å¶ ï¿½Ó½ï¿½ ï¿½ï¿½ï¿½ï¿½[m
 	private:[m
 		unsigned int itemAward_vnum;[m
 		char		 itemAward_cmd[20];[m
[36m@@ -2021,10 +2025,10 @@[m [mclass CHARACTER : public CEntity, public CFSM, public CHorseRider[m
 		//void		 SetItemAward_flag(bool flag) { itemAward_flag = flag; }[m
 [m
 	public:[m
[31m-		//¿ëÈ¥¼®[m
[32m+[m		[32m//ï¿½ï¿½È¥ï¿½ï¿½[m
 		[m
[31m-		// Ä³¸¯ÅÍÀÇ affect, quest°¡ load µÇ±â Àü¿¡ DragonSoul_Initialize¸¦ È£ÃâÇÏ¸é ¾ÈµÈ´Ù.[m
[31m-		// affect°¡ °¡Àå ¸¶Áö¸·¿¡ ·ÎµåµÇ¾î LoadAffect¿¡¼­ È£ÃâÇÔ.[m
[32m+[m		[32m// Ä³ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ affect, questï¿½ï¿½ load ï¿½Ç±ï¿½ ï¿½ï¿½ï¿½ï¿½ DragonSoul_Initializeï¿½ï¿½ È£ï¿½ï¿½ï¿½Ï¸ï¿½ ï¿½ÈµÈ´ï¿½.[m
[32m+[m		[32m// affectï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Îµï¿½Ç¾ï¿½ LoadAffectï¿½ï¿½ï¿½ï¿½ È£ï¿½ï¿½ï¿½ï¿½.[m
 		void	DragonSoul_Initialize();[m
 [m
 		bool	DragonSoul_IsQualified() const;[m
[36m@@ -2035,17 +2039,17 @@[m [mclass CHARACTER : public CEntity, public CFSM, public CHorseRider[m
 		bool	DragonSoul_ActivateDeck(int deck_idx);[m
 [m
 		void	DragonSoul_DeactivateAll();[m
[31m-		// ¹Ýµå½Ã ClearItem Àü¿¡ ºÒ·¯¾ß ÇÑ´Ù.[m
[31m-		// ¿Ö³ÄÇÏ¸é....[m
[31m-		// ¿ëÈ¥¼® ÇÏ³ª ÇÏ³ª¸¦ deactivateÇÒ ¶§¸¶´Ù µ¦¿¡ activeÀÎ ¿ëÈ¥¼®ÀÌ ÀÖ´ÂÁö È®ÀÎÇÏ°í,[m
[31m-		// activeÀÎ ¿ëÈ¥¼®ÀÌ ÇÏ³ªµµ ¾ø´Ù¸é, Ä³¸¯ÅÍÀÇ ¿ëÈ¥¼® affect¿Í, È°¼º »óÅÂ¸¦ Á¦°ÅÇÑ´Ù.[m
[32m+[m		[32m// ï¿½Ýµï¿½ï¿½ ClearItem ï¿½ï¿½ï¿½ï¿½ ï¿½Ò·ï¿½ï¿½ï¿½ ï¿½Ñ´ï¿½.[m
[32m+[m		[32m// ï¿½Ö³ï¿½ï¿½Ï¸ï¿½....[m
[32m+[m		[32m// ï¿½ï¿½È¥ï¿½ï¿½ ï¿½Ï³ï¿½ ï¿½Ï³ï¿½ï¿½ï¿½ deactivateï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ activeï¿½ï¿½ ï¿½ï¿½È¥ï¿½ï¿½ï¿½ï¿½ ï¿½Ö´ï¿½ï¿½ï¿½ È®ï¿½ï¿½ï¿½Ï°ï¿½,[m
[32m+[m		[32m// activeï¿½ï¿½ ï¿½ï¿½È¥ï¿½ï¿½ï¿½ï¿½ ï¿½Ï³ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Ù¸ï¿½, Ä³ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½È¥ï¿½ï¿½ affectï¿½ï¿½, È°ï¿½ï¿½ ï¿½ï¿½ï¿½Â¸ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ñ´ï¿½.[m
 		// [m
[31m-		// ÇÏÁö¸¸ ClearItem ½Ã, Ä³¸¯ÅÍ°¡ Âø¿ëÇÏ°í ÀÖ´Â ¸ðµç ¾ÆÀÌÅÛÀ» unequipÇÏ´Â ¹Ù¶÷¿¡,[m
[31m-		// ¿ëÈ¥¼® Affect°¡ Á¦°ÅµÇ°í, °á±¹ ·Î±×ÀÎ ½Ã, ¿ëÈ¥¼®ÀÌ È°¼ºÈ­µÇÁö ¾Ê´Â´Ù.[m
[31m-		// (UnequipÇÒ ¶§¿¡´Â ·Î±×¾Æ¿ô »óÅÂÀÎÁö, ¾Æ´ÑÁö ¾Ë ¼ö ¾ø´Ù.)[m
[31m-		// ¿ëÈ¥¼®¸¸ deactivate½ÃÅ°°í Ä³¸¯ÅÍÀÇ ¿ëÈ¥¼® µ¦ È°¼º »óÅÂ´Â °Çµå¸®Áö ¾Ê´Â´Ù.[m
[32m+[m		[32m// ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ClearItem ï¿½ï¿½, Ä³ï¿½ï¿½ï¿½Í°ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï°ï¿½ ï¿½Ö´ï¿½ ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ unequipï¿½Ï´ï¿½ ï¿½Ù¶ï¿½ï¿½ï¿½,[m
[32m+[m		[32m// ï¿½ï¿½È¥ï¿½ï¿½ Affectï¿½ï¿½ ï¿½ï¿½ï¿½ÅµÇ°ï¿½, ï¿½á±¹ ï¿½Î±ï¿½ï¿½ï¿½ ï¿½ï¿½, ï¿½ï¿½È¥ï¿½ï¿½ï¿½ï¿½ È°ï¿½ï¿½È­ï¿½ï¿½ï¿½ï¿½ ï¿½Ê´Â´ï¿½.[m
[32m+[m		[32m// (Unequipï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Î±×¾Æ¿ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½, ï¿½Æ´ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½.)[m
[32m+[m		[32m// ï¿½ï¿½È¥ï¿½ï¿½ï¿½ï¿½ deactivateï¿½ï¿½Å°ï¿½ï¿½ Ä³ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½È¥ï¿½ï¿½ ï¿½ï¿½ È°ï¿½ï¿½ ï¿½ï¿½ï¿½Â´ï¿½ ï¿½Çµå¸®ï¿½ï¿½ ï¿½Ê´Â´ï¿½.[m
 		void	DragonSoul_CleanUp();[m
[31m-		// ¿ëÈ¥¼® °­È­Ã¢[m
[32m+[m		[32m// ï¿½ï¿½È¥ï¿½ï¿½ ï¿½ï¿½È­Ã¢[m
 	public:[m
 		bool		DragonSoul_RefineWindow_Open(LPENTITY pEntity);[m
 		bool		DragonSoul_RefineWindow_Close();[m
[36m@@ -2053,8 +2057,8 @@[m [mclass CHARACTER : public CEntity, public CFSM, public CHorseRider[m
 		bool		DragonSoul_RefineWindow_CanRefine();[m
 [m
 	private:[m
[31m-		// SyncPositionÀ» ¾Ç¿ëÇÏ¿© Å¸À¯Àú¸¦ ÀÌ»óÇÑ °÷À¸·Î º¸³»´Â ÇÙ ¹æ¾îÇÏ±â À§ÇÏ¿©,[m
[31m-		// SyncPositionÀÌ ÀÏ¾î³¯ ¶§¸¦ ±â·Ï.[m
[32m+[m		[32m// SyncPositionï¿½ï¿½ ï¿½Ç¿ï¿½ï¿½Ï¿ï¿½ Å¸ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ì»ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½Ï±ï¿½ ï¿½ï¿½ï¿½Ï¿ï¿½,[m
[32m+[m		[32m// SyncPositionï¿½ï¿½ ï¿½Ï¾î³¯ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½.[m
 		timeval		m_tvLastSyncTime;[m
 		int			m_iSyncHackCount;[m
 	public:[m
[1mdiff --git a/game/src/char_item.cpp b/game/src/char_item.cpp[m
[1mold mode 100644[m
[1mnew mode 100755[m
[1mindex af8b2e4..6ec264a[m
[1m--- a/game/src/char_item.cpp[m
[1m+++ b/game/src/char_item.cpp[m
[36m@@ -107,38 +107,38 @@[m [mstatic bool IS_MONKEY_DUNGEON(int map_index)[m
 [m
 bool IS_SUMMONABLE_ZONE(int map_index)[m
 {[m
[31m-	// ¸ùÅ°´øÀü[m
[32m+[m	[32m// ï¿½ï¿½Å°ï¿½ï¿½ï¿½ï¿½[m
 	if (IS_MONKEY_DUNGEON(map_index))[m
 		return false;[m
[31m-	// ¼º[m
[32m+[m	[32m// ï¿½ï¿½[m
 	if (IS_CASTLE_MAP(map_index))[m
 		return false;[m
 [m
 	switch (map_index)[m
 	{[m
[31m-		case 66 : // »ç±ÍÅ¸¿ö[m
[31m-		case 71 : // °Å¹Ì ´øÀü 2Ãþ[m
[31m-		case 72 : // ÃµÀÇ µ¿±¼[m
[31m-		case 73 : // ÃµÀÇ µ¿±¼ 2Ãþ[m
[31m-		case 193 : // °Å¹Ì ´øÀü 2-1Ãþ[m
[32m+[m		[32mcase 66 : // ï¿½ï¿½ï¿½Å¸ï¿½ï¿½[m
[32m+[m		[32mcase 71 : // ï¿½Å¹ï¿½ ï¿½ï¿½ï¿½ï¿½ 2ï¿½ï¿½[m
[32m+[m		[32mcase 72 : // Ãµï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½[m
[32m+[m		[32mcase 73 : // Ãµï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ 2ï¿½ï¿½[m
[32m+[m		[32mcase 193 : // ï¿½Å¹ï¿½ ï¿½ï¿½ï¿½ï¿½ 2-1ï¿½ï¿½[m
 #if 0[m
[31m-		case 184 : // ÃµÀÇ µ¿±¼(½Å¼ö)[m
[31m-		case 185 : // ÃµÀÇ µ¿±¼ 2Ãþ(½Å¼ö)[m
[31m-		case 186 : // ÃµÀÇ µ¿±¼(ÃµÁ¶)[m
[31m-		case 187 : // ÃµÀÇ µ¿±¼ 2Ãþ(ÃµÁ¶)[m
[31m-		case 188 : // ÃµÀÇ µ¿±¼(Áø³ë)[m
[31m-		case 189 : // ÃµÀÇ µ¿±¼ 2Ãþ(Áø³ë)[m
[32m+[m		[32mcase 184 : // Ãµï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½(ï¿½Å¼ï¿½)[m
[32m+[m		[32mcase 185 : // Ãµï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ 2ï¿½ï¿½(ï¿½Å¼ï¿½)[m
[32m+[m		[32mcase 186 : // Ãµï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½(Ãµï¿½ï¿½)[m
[32m+[m		[32mcase 187 : // Ãµï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ 2ï¿½ï¿½(Ãµï¿½ï¿½)[m
[32m+[m		[32mcase 188 : // Ãµï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½(ï¿½ï¿½ï¿½ï¿½)[m
[32m+[m		[32mcase 189 : // Ãµï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ 2ï¿½ï¿½(ï¿½ï¿½ï¿½ï¿½)[m
 #endif[m
[31m-//		case 206 : // ¾Æ±Íµ¿±¼[m
[31m-		case 216 : // ¾Æ±Íµ¿±¼[m
[31m-		case 217 : // °Å¹Ì ´øÀü 3Ãþ[m
[31m-		case 208 : // ÃµÀÇ µ¿±¼ (¿ë¹æ)[m
[32m+[m[32m//		case 206 : // ï¿½Æ±Íµï¿½ï¿½ï¿½[m
[32m+[m		[32mcase 216 : // ï¿½Æ±Íµï¿½ï¿½ï¿½[m
[32m+[m		[32mcase 217 : // ï¿½Å¹ï¿½ ï¿½ï¿½ï¿½ï¿½ 3ï¿½ï¿½[m
[32m+[m		[32mcase 208 : // Ãµï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ (ï¿½ï¿½ï¿½)[m
 			return false;[m
 	}[m
 [m
 	if (CBattleArena::IsBattleArenaMap(map_index)) return false;[m
 [m
[31m-	// ¸ðµç private ¸ÊÀ¸·Ð ¿öÇÁ ºÒ°¡´É[m
[32m+[m	[32m// ï¿½ï¿½ï¿½ private ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½Ò°ï¿½ï¿½ï¿½[m
 	if (map_index > 10000) return false;[m
 [m
 	return true;[m
[36m@@ -162,7 +162,7 @@[m [mbool IS_BOTARYABLE_ZONE(int nMapIndex)[m
 	return false;[m
 }[m
 [m
[31m-// item socket ÀÌ ÇÁ·ÎÅäÅ¸ÀÔ°ú °°ÀºÁö Ã¼Å© -- by mhh[m
[32m+[m[32m// item socket ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½Å¸ï¿½Ô°ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ Ã¼Å© -- by mhh[m
 static bool FN_check_item_socket(LPITEM item)[m
 {[m
 	for (int i = 0; i < ITEM_SOCKET_MAX_NUM; ++i)[m
[36m@@ -174,7 +174,7 @@[m [mstatic bool FN_check_item_socket(LPITEM item)[m
 	return true;[m
 }[m
 [m
[31m-// item socket º¹»ç -- by mhh[m
[32m+[m[32m// item socket ï¿½ï¿½ï¿½ï¿½ -- by mhh[m
 static void FN_copy_item_socket(LPITEM dest, LPITEM src)[m
 {[m
 	for (int i = 0; i < ITEM_SOCKET_MAX_NUM; ++i)[m
[36m@@ -184,13 +184,13 @@[m [mstatic void FN_copy_item_socket(LPITEM dest, LPITEM src)[m
 }[m
 static bool FN_check_item_sex(LPCHARACTER ch, LPITEM item)[m
 {[m
[31m-	// ³²ÀÚ ±ÝÁö[m
[32m+[m	[32m// ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½[m
 	if (IS_SET(item->GetAntiFlag(), ITEM_ANTIFLAG_MALE))[m
 	{[m
 		if (SEX_MALE==GET_SEX(ch))[m
 			return false;[m
 	}[m
[31m-	// ¿©ÀÚ±ÝÁö[m
[32m+[m	[32m// ï¿½ï¿½ï¿½Ú±ï¿½ï¿½ï¿½[m
 	if (IS_SET(item->GetAntiFlag(), ITEM_ANTIFLAG_FEMALE)) [m
 	{[m
 		if (SEX_FEMALE==GET_SEX(ch))[m
[36m@@ -260,7 +260,11 @@[m [mLPITEM CHARACTER::GetItem(TItemPos Cell) const[m
 	return NULL;[m
 }[m
 [m
[32m+[m[32m#if defined(__BL_ENABLE_PICKUP_ITEM_EFFECT__)[m
[32m+[m[32mvoid CHARACTER::SetItem(TItemPos Cell, LPITEM pItem, bool bHighlight)[m
[32m+[m[32m#else[m
 void CHARACTER::SetItem(TItemPos Cell, LPITEM pItem)[m
[32m+[m[32m#endif[m
 {[m
 	WORD wCell = Cell.cell;[m
 	BYTE window_type = Cell.window_type;[m
[36m@@ -276,7 +280,7 @@[m [mvoid CHARACTER::SetItem(TItemPos Cell, LPITEM pItem)[m
 		assert(!"GetOwner exist");[m
 		return;[m
 	}[m
[31m-	// ±âº» ÀÎº¥Åä¸®[m
[32m+[m	[32m// ï¿½âº» ï¿½Îºï¿½ï¿½ä¸®[m
 	switch(window_type)[m
 	{[m
 	case INVENTORY:[m
[36m@@ -322,8 +326,8 @@[m [mvoid CHARACTER::SetItem(TItemPos Cell, LPITEM pItem)[m
 						if (p >= INVENTORY_MAX_NUM)[m
 							continue;[m
 [m
[31m-						// wCell + 1 ·Î ÇÏ´Â °ÍÀº ºó°÷À» Ã¼Å©ÇÒ ¶§ °°Àº[m
[31m-						// ¾ÆÀÌÅÛÀº ¿¹¿ÜÃ³¸®ÇÏ±â À§ÇÔ[m
[32m+[m						[32m// wCell + 1 ï¿½ï¿½ ï¿½Ï´ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ Ã¼Å©ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½[m
[32m+[m						[32m// ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½Ã³ï¿½ï¿½ï¿½Ï±ï¿½ ï¿½ï¿½ï¿½ï¿½[m
 						m_pointsInstant.bItemGrid[p] = wCell + 1;[m
 					}[m
 				}[m
[36m@@ -334,7 +338,7 @@[m [mvoid CHARACTER::SetItem(TItemPos Cell, LPITEM pItem)[m
 			m_pointsInstant.pItems[wCell] = pItem;[m
 		}[m
 		break;[m
[31m-	// ¿ëÈ¥¼® ÀÎº¥Åä¸®[m
[32m+[m	[32m// ï¿½ï¿½È¥ï¿½ï¿½ ï¿½Îºï¿½ï¿½ä¸®[m
 	case DRAGON_SOUL_INVENTORY:[m
 		{[m
 			LPITEM pOld = m_pointsInstant.pDSItems[wCell];[m
[36m@@ -377,8 +381,8 @@[m [mvoid CHARACTER::SetItem(TItemPos Cell, LPITEM pItem)[m
 						if (p >= DRAGON_SOUL_INVENTORY_MAX_NUM)[m
 							continue;[m
 [m
[31m-						// wCell + 1 ·Î ÇÏ´Â °ÍÀº ºó°÷À» Ã¼Å©ÇÒ ¶§ °°Àº[m
[31m-						// ¾ÆÀÌÅÛÀº ¿¹¿ÜÃ³¸®ÇÏ±â À§ÇÔ[m
[32m+[m						[32m// wCell + 1 ï¿½ï¿½ ï¿½Ï´ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ Ã¼Å©ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½[m
[32m+[m						[32m// ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½Ã³ï¿½ï¿½ï¿½Ï±ï¿½ ï¿½ï¿½ï¿½ï¿½[m
 						m_pointsInstant.wDSItemGrid[p] = wCell + 1;[m
 					}[m
 				}[m
[36m@@ -396,7 +400,7 @@[m [mvoid CHARACTER::SetItem(TItemPos Cell, LPITEM pItem)[m
 [m
 	if (GetDesc())[m
 	{[m
[31m-		// È®Àå ¾ÆÀÌÅÛ: ¼­¹ö¿¡¼­ ¾ÆÀÌÅÛ ÇÃ·¡±× Á¤º¸¸¦ º¸³½´Ù[m
[32m+[m		[32m// È®ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½: ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ã·ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½[m
 		if (pItem)[m
 		{[m
 			TPacketGCItemSet pack;[m
[36m@@ -407,7 +411,11 @@[m [mvoid CHARACTER::SetItem(TItemPos Cell, LPITEM pItem)[m
 			pack.vnum = pItem->GetVnum();[m
 			pack.flags = pItem->GetFlag();[m
 			pack.anti_flags	= pItem->GetAntiFlag();[m
[32m+[m[32m#if defined(__BL_ENABLE_PICKUP_ITEM_EFFECT__)[m
[32m+[m			[32mpack.highlight = bHighlight;[m
[32m+[m[32m#else[m
 			pack.highlight = (Cell.window_type == DRAGON_SOUL_INVENTORY);[m
[32m+[m[32m#endif[m
 [m
 [m
 			thecore_memcpy(pack.alSockets, pItem->GetSockets(), sizeof(pack.alSockets));[m
[36m@@ -450,7 +458,7 @@[m [mvoid CHARACTER::SetItem(TItemPos Cell, LPITEM pItem)[m
 [m
 LPITEM CHARACTER::GetWear(BYTE bCell) const[m
 {[m
[31m-	// > WEAR_MAX_NUM : ¿ëÈ¥¼® ½½·Ôµé.[m
[32m+[m	[32m// > WEAR_MAX_NUM : ï¿½ï¿½È¥ï¿½ï¿½ ï¿½ï¿½ï¿½Ôµï¿½.[m
 	if (bCell >= WEAR_MAX_NUM + DRAGON_SOUL_DECK_MAX_NUM * DS_SLOT_MAX)[m
 	{[m
 		sys_err("CHARACTER::GetWear: invalid wear cell %d", bCell);[m
[36m@@ -462,18 +470,22 @@[m [mLPITEM CHARACTER::GetWear(BYTE bCell) const[m
 [m
 void CHARACTER::SetWear(BYTE bCell, LPITEM item)[m
 {[m
[31m-	// > WEAR_MAX_NUM : ¿ëÈ¥¼® ½½·Ôµé.[m
[32m+[m	[32m// > WEAR_MAX_NUM : ï¿½ï¿½È¥ï¿½ï¿½ ï¿½ï¿½ï¿½Ôµï¿½.[m
 	if (bCell >= WEAR_MAX_NUM + DRAGON_SOUL_DECK_MAX_NUM * DS_SLOT_MAX)[m
 	{[m
 		sys_err("CHARACTER::SetItem: invalid item cell %d", bCell);[m
 		return;[m
 	}[m
 [m
[32m+[m[32m#if defined(__BL_ENABLE_PICKUP_ITEM_EFFECT__)[m
[32m+[m	[32mSetItem(TItemPos(INVENTORY, INVENTORY_MAX_NUM + bCell), item, false);[m
[32m+[m[32m#else[m
 	SetItem(TItemPos (INVENTORY, INVENTORY_MAX_NUM + bCell), item);[m
[32m+[m[32m#endif[m
 [m
 	if (!item && bCell == WEAR_WEAPON)[m
 	{[m
[31m-		// ±Í°Ë »ç¿ë ½Ã ¹þ´Â °ÍÀÌ¶ó¸é È¿°ú¸¦ ¾ø¾Ö¾ß ÇÑ´Ù.[m
[32m+[m		[32m// ï¿½Í°ï¿½ ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Ì¶ï¿½ï¿½ È¿ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Ö¾ï¿½ ï¿½Ñ´ï¿½.[m
 		if (IsAffectFlag(AFF_GWIGUM))[m
 			RemoveAffect(SKILL_GWIGEOM);[m
 [m
[36m@@ -526,8 +538,8 @@[m [mbool CHARACTER::IsEmptyItemGrid(TItemPos Cell, BYTE bSize, int iExceptionCell) c[m
 		{[m
 			BYTE bCell = Cell.cell;[m
 [m
[31m-			// bItemCellÀº 0ÀÌ falseÀÓÀ» ³ªÅ¸³»±â À§ÇØ + 1 ÇØ¼­ Ã³¸®ÇÑ´Ù.[m
[31m-			// µû¶ó¼­ iExceptionCell¿¡ 1À» ´õÇØ ºñ±³ÇÑ´Ù.[m
[32m+[m			[32m// bItemCellï¿½ï¿½ 0ï¿½ï¿½ falseï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½Å¸ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ + 1 ï¿½Ø¼ï¿½ Ã³ï¿½ï¿½ï¿½Ñ´ï¿½.[m
[32m+[m			[32m// ï¿½ï¿½ï¿½ï¿½ iExceptionCellï¿½ï¿½ 1ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Ñ´ï¿½.[m
 			++iExceptionCell;[m
 [m
 			if (Cell.IsBeltInventoryPosition())[m
[36m@@ -587,7 +599,7 @@[m [mbool CHARACTER::IsEmptyItemGrid(TItemPos Cell, BYTE bSize, int iExceptionCell) c[m
 					return false;[m
 			}[m
 [m
[31m-			// Å©±â°¡ 1ÀÌ¸é ÇÑÄ­À» Â÷ÁöÇÏ´Â °ÍÀÌ¹Ç·Î ±×³É ¸®ÅÏ[m
[32m+[m			[32m// Å©ï¿½â°¡ 1ï¿½Ì¸ï¿½ ï¿½ï¿½Ä­ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½ ï¿½ï¿½ï¿½Ì¹Ç·ï¿½ ï¿½×³ï¿½ ï¿½ï¿½ï¿½ï¿½[m
 			if (1 == bSize)[m
 				return true;[m
 			else[m
[36m@@ -621,8 +633,8 @@[m [mbool CHARACTER::IsEmptyItemGrid(TItemPos Cell, BYTE bSize, int iExceptionCell) c[m
 			if (wCell >= DRAGON_SOUL_INVENTORY_MAX_NUM)[m
 				return false;[m
 [m
[31m-			// bItemCellÀº 0ÀÌ falseÀÓÀ» ³ªÅ¸³»±â À§ÇØ + 1 ÇØ¼­ Ã³¸®ÇÑ´Ù.[m
[31m-			// µû¶ó¼­ iExceptionCell¿¡ 1À» ´õÇØ ºñ±³ÇÑ´Ù.[m
[32m+[m			[32m// bItemCellï¿½ï¿½ 0ï¿½ï¿½ falseï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½Å¸ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ + 1 ï¿½Ø¼ï¿½ Ã³ï¿½ï¿½ï¿½Ñ´ï¿½.[m
[32m+[m			[32m// ï¿½ï¿½ï¿½ï¿½ iExceptionCellï¿½ï¿½ 1ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Ñ´ï¿½.[m
 			iExceptionCell++;[m
 [m
 			if (m_pointsInstant.wDSItemGrid[wCell])[m
[36m@@ -653,7 +665,7 @@[m [mbool CHARACTER::IsEmptyItemGrid(TItemPos Cell, BYTE bSize, int iExceptionCell) c[m
 					return false;[m
 			}[m
 [m
[31m-			// Å©±â°¡ 1ÀÌ¸é ÇÑÄ­À» Â÷ÁöÇÏ´Â °ÍÀÌ¹Ç·Î ±×³É ¸®ÅÏ[m
[32m+[m			[32m// Å©ï¿½â°¡ 1ï¿½Ì¸ï¿½ ï¿½ï¿½Ä­ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½ ï¿½ï¿½ï¿½Ì¹Ç·ï¿½ ï¿½×³ï¿½ ï¿½ï¿½ï¿½ï¿½[m
 			if (1 == bSize)[m
 				return true;[m
 			else[m
[36m@@ -681,8 +693,8 @@[m [mbool CHARACTER::IsEmptyItemGrid(TItemPos Cell, BYTE bSize, int iExceptionCell) c[m
 [m
 int CHARACTER::GetEmptyInventory(BYTE size) const[m
 {[m
[31m-	// NOTE: ÇöÀç ÀÌ ÇÔ¼ö´Â ¾ÆÀÌÅÛ Áö±Þ, È¹µæ µîÀÇ ÇàÀ§¸¦ ÇÒ ¶§ ÀÎº¥Åä¸®ÀÇ ºó Ä­À» Ã£±â À§ÇØ »ç¿ëµÇ°í ÀÖ´Âµ¥,[m
[31m-	//		º§Æ® ÀÎº¥Åä¸®´Â Æ¯¼ö ÀÎº¥Åä¸®ÀÌ¹Ç·Î °Ë»çÇÏÁö ¾Êµµ·Ï ÇÑ´Ù. (±âº» ÀÎº¥Åä¸®: INVENTORY_MAX_NUM ±îÁö¸¸ °Ë»ç)[m
[32m+[m	[32m// NOTE: ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½Ô¼ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½, È¹ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ ï¿½Îºï¿½ï¿½ä¸®ï¿½ï¿½ ï¿½ï¿½ Ä­ï¿½ï¿½ Ã£ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Ç°ï¿½ ï¿½Ö´Âµï¿½,[m
[32m+[m	[32m//		ï¿½ï¿½Æ® ï¿½Îºï¿½ï¿½ä¸®ï¿½ï¿½ Æ¯ï¿½ï¿½ ï¿½Îºï¿½ï¿½ä¸®ï¿½Ì¹Ç·ï¿½ ï¿½Ë»ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Êµï¿½ï¿½ï¿½ ï¿½Ñ´ï¿½. (ï¿½âº» ï¿½Îºï¿½ï¿½ä¸®: INVENTORY_MAX_NUM ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ë»ï¿½)[m
 	for ( int i = 0; i < INVENTORY_MAX_NUM; ++i)[m
 		if (IsEmptyItemGrid(TItemPos (INVENTORY, i), size))[m
 			return i;[m
[36m@@ -742,7 +754,7 @@[m [mvoid TransformRefineItem(LPITEM pkOldItem, LPITEM pkNewItem)[m
 	// END_OF_ACCESSORY_REFINE[m
 	else[m
 	{[m
[31m-		// ¿©±â¼­ ±úÁø¼®ÀÌ ÀÚµ¿ÀûÀ¸·Î Ã»¼Ò µÊ[m
[32m+[m		[32m// ï¿½ï¿½ï¿½â¼­ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Úµï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ Ã»ï¿½ï¿½ ï¿½ï¿½[m
 		for (int i = 0; i < ITEM_SOCKET_MAX_NUM; ++i)[m
 		{[m
 			if (!pkOldItem->GetSocket(i))[m
[36m@@ -751,7 +763,7 @@[m [mvoid TransformRefineItem(LPITEM pkOldItem, LPITEM pkNewItem)[m
 				pkNewItem->SetSocket(i, 1);[m
 		}[m
 [m
[31m-		// ¼ÒÄÏ ¼³Á¤[m
[32m+[m		[32m// ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½[m
 		int slot = 0;[m
 [m
 		for (int i = 0; i < ITEM_SOCKET_MAX_NUM; ++i)[m
[36m@@ -764,7 +776,7 @@[m [mvoid TransformRefineItem(LPITEM pkOldItem, LPITEM pkNewItem)[m
 [m
 	}[m
 [m
[31m-	// ¸ÅÁ÷ ¾ÆÀÌÅÛ ¼³Á¤[m
[32m+[m	[32m// ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½[m
 	pkOldItem->CopyAttributeTo(pkNewItem);[m
 }[m
 [m
[36m@@ -811,12 +823,12 @@[m [mbool CHARACTER::DoRefine(LPITEM item, bool bMoneyOnly)[m
 	DWORD pos = GetEmptyInventory(item->GetSize());[m
 [m
 	if (-1 == pos){[m
[31m-		ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¼ÒÁöÇÏ°í ÀÖ´Â ¾ÆÀÌÅÛÀÌ ³Ê¹« ¸¹½À´Ï´Ù."));[m
[32m+[m		[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½Ï°ï¿½ ï¿½Ö´ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ê¹ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 		return false;[m
 	}[m
 	[m
[31m-	//°³·® ½Ã°£Á¦ÇÑ : upgrade_refine_scroll.quest ¿¡¼­ °³·®ÈÄ 5ºÐÀÌ³»¿¡ ÀÏ¹Ý °³·®À» [m
[31m-	//ÁøÇàÇÒ¼ö ¾øÀ½[m
[32m+[m	[32m//ï¿½ï¿½ï¿½ï¿½ ï¿½Ã°ï¿½ï¿½ï¿½ï¿½ï¿½ : upgrade_refine_scroll.quest ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ 5ï¿½ï¿½ï¿½Ì³ï¿½ï¿½ï¿½ ï¿½Ï¹ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½[m[41m [m
[32m+[m	[32m//ï¿½ï¿½ï¿½ï¿½ï¿½Ò¼ï¿½ ï¿½ï¿½ï¿½ï¿½[m
 	if (quest::CQuestManager::instance().GetEventFlag("update_refine_time") != 0)[m
 	{[m
 		if (get_global_time() < quest::CQuestManager::instance().GetEventFlag("update_refine_time") + (60 * 5))[m
[36m@@ -842,7 +854,7 @@[m [mbool CHARACTER::DoRefine(LPITEM item, bool bMoneyOnly)[m
 	{[m
 		if (!item->CheckItemUseLevel(20) || item->GetType() != ITEM_WEAPON)[m
 		{[m
[31m-			ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¹«·á °³·® ±âÈ¸´Â 20 ÀÌÇÏÀÇ ¹«±â¸¸ °¡´ÉÇÕ´Ï´Ù"));[m
[32m+[m			[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½È¸ï¿½ï¿½ 20 ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½â¸¸ ï¿½ï¿½ï¿½ï¿½ï¿½Õ´Ï´ï¿½"));[m
 			return false;[m
 		}[m
 [m
[36m@@ -853,7 +865,7 @@[m [mbool CHARACTER::DoRefine(LPITEM item, bool bMoneyOnly)[m
 [m
 	if (result_vnum == 0)[m
 	{[m
[31m-		ChatPacket(CHAT_TYPE_INFO, LC_TEXT("´õ ÀÌ»ó °³·®ÇÒ ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m		[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ ï¿½Ì»ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 		return false;[m
 	}[m
 [m
[36m@@ -865,7 +877,7 @@[m [mbool CHARACTER::DoRefine(LPITEM item, bool bMoneyOnly)[m
 	if (!pProto)[m
 	{[m
 		sys_err("DoRefine NOT GET ITEM PROTO %d", item->GetRefinedVnum());[m
[31m-		ChatPacket(CHAT_TYPE_INFO, LC_TEXT("ÀÌ ¾ÆÀÌÅÛÀº °³·®ÇÒ ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m		[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 		return false;[m
 	}[m
 [m
[36m@@ -881,7 +893,7 @@[m [mbool CHARACTER::DoRefine(LPITEM item, bool bMoneyOnly)[m
 				case LIMIT_LEVEL:[m
 					if (GetLevel() < limit)[m
 					{[m
[31m-						ChatPacket(CHAT_TYPE_INFO, LC_TEXT("°³·®µÈ ÈÄ ¾ÆÀÌÅÛÀÇ ·¹º§ Á¦ÇÑº¸´Ù ·¹º§ÀÌ ³·½À´Ï´Ù."));[m
[32m+[m						[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Ñºï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 						return false;[m
 					}[m
 					break;[m
[36m@@ -892,7 +904,7 @@[m [mbool CHARACTER::DoRefine(LPITEM item, bool bMoneyOnly)[m
 	// REFINE_COST[m
 	if (GetGold() < cost)[m
 	{[m
[31m-		ChatPacket(CHAT_TYPE_INFO, LC_TEXT("°³·®À» ÇÏ±â À§ÇÑ µ·ÀÌ ºÎÁ·ÇÕ´Ï´Ù."));[m
[32m+[m		[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ï±ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Õ´Ï´ï¿½."));[m
 		return false;[m
 	}[m
 [m
[36m@@ -906,7 +918,7 @@[m [mbool CHARACTER::DoRefine(LPITEM item, bool bMoneyOnly)[m
 				{[m
 					ChatPacket(CHAT_TYPE_INFO, "Find %d, count %d, require %d", prt->materials[i].vnum, CountSpecifyItem(prt->materials[i].vnum), prt->materials[i].count);[m
 				}[m
[31m-				ChatPacket(CHAT_TYPE_INFO, LC_TEXT("°³·®À» ÇÏ±â À§ÇÑ Àç·á°¡ ºÎÁ·ÇÕ´Ï´Ù."));[m
[32m+[m				[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ï±ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½á°¡ ï¿½ï¿½ï¿½ï¿½ï¿½Õ´Ï´ï¿½."));[m
 				return false;[m
 			}[m
 		}[m
[36m@@ -924,7 +936,7 @@[m [mbool CHARACTER::DoRefine(LPITEM item, bool bMoneyOnly)[m
 [m
 	if (prob <= prt->prob)[m
 	{[m
[31m-		// ¼º°ø! ¸ðµç ¾ÆÀÌÅÛÀÌ »ç¶óÁö°í, °°Àº ¼Ó¼ºÀÇ ´Ù¸¥ ¾ÆÀÌÅÛ È¹µæ[m
[32m+[m		[32m// ï¿½ï¿½ï¿½ï¿½! ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½, ï¿½ï¿½ï¿½ï¿½ ï¿½Ó¼ï¿½ï¿½ï¿½ ï¿½Ù¸ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ È¹ï¿½ï¿½[m
 		LPITEM pkNewItem = ITEM_MANAGER::instance().CreateItem(result_vnum, 1, 0, false);[m
 [m
 		if (pkNewItem)[m
[36m@@ -962,7 +974,7 @@[m [mbool CHARACTER::DoRefine(LPITEM item, bool bMoneyOnly)[m
 		else[m
 		{[m
 			// DETAIL_REFINE_LOG[m
[31m-			// ¾ÆÀÌÅÛ »ý¼º¿¡ ½ÇÆÐ -> °³·® ½ÇÆÐ·Î °£ÁÖ[m
[32m+[m			[32m// ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ -> ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Ð·ï¿½ ï¿½ï¿½ï¿½ï¿½[m
 			sys_err("cannot create item %u", result_vnum);[m
 			NotifyRefineFail(this, item, IsRefineThroughGuild() ? "GUILD" : "POWER");[m
 			// END_OF_DETAIL_REFINE_LOG[m
[36m@@ -970,7 +982,7 @@[m [mbool CHARACTER::DoRefine(LPITEM item, bool bMoneyOnly)[m
 	}[m
 	else[m
 	{[m
[31m-		// ½ÇÆÐ! ¸ðµç ¾ÆÀÌÅÛÀÌ »ç¶óÁü.[m
[32m+[m		[32m// ï¿½ï¿½ï¿½ï¿½! ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½.[m
 		DBManager::instance().SendMoneyLog(MONEY_LOG_REFINE, item->GetVnum(), -cost);[m
 		NotifyRefineFail(this, item, IsRefineThroughGuild() ? "GUILD" : "POWER");[m
 		item->AttrLog();[m
[36m@@ -985,7 +997,7 @@[m [mbool CHARACTER::DoRefine(LPITEM item, bool bMoneyOnly)[m
 enum enum_RefineScrolls[m
 {[m
 	CHUKBOK_SCROLL = 0,[m
[31m-	HYUNIRON_CHN   = 1, // Áß±¹¿¡¼­¸¸ »ç¿ë[m
[32m+[m	[32mHYUNIRON_CHN   = 1, // ï¿½ß±ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½[m
 	YONGSIN_SCROLL = 2,[m
 	MUSIN_SCROLL   = 3,[m
 	YAGONG_SCROLL  = 4,[m
[36m@@ -1003,14 +1015,14 @@[m [mbool CHARACTER::DoRefineWithScroll(LPITEM item)[m
 	[m
 	DWORD pos = GetEmptyInventory(item->GetSize());[m
 	if (-1 == pos){[m
[31m-		ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¼ÒÁöÇÏ°í ÀÖ´Â ¾ÆÀÌÅÛÀÌ ³Ê¹« ¸¹½À´Ï´Ù."));[m
[32m+[m		[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½Ï°ï¿½ ï¿½Ö´ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ê¹ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 		return false;[m
 	}[m
 [m
 	ClearRefineMode();[m
 [m
[31m-	//°³·® ½Ã°£Á¦ÇÑ : upgrade_refine_scroll.quest ¿¡¼­ °³·®ÈÄ 5ºÐÀÌ³»¿¡ ÀÏ¹Ý °³·®À» [m
[31m-	//ÁøÇàÇÒ¼ö ¾øÀ½[m
[32m+[m	[32m//ï¿½ï¿½ï¿½ï¿½ ï¿½Ã°ï¿½ï¿½ï¿½ï¿½ï¿½ : upgrade_refine_scroll.quest ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ 5ï¿½ï¿½ï¿½Ì³ï¿½ï¿½ï¿½ ï¿½Ï¹ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½[m[41m [m
[32m+[m	[32m//ï¿½ï¿½ï¿½ï¿½ï¿½Ò¼ï¿½ ï¿½ï¿½ï¿½ï¿½[m
 	if (quest::CQuestManager::instance().GetEventFlag("update_refine_time") != 0)[m
 	{[m
 		if (get_global_time() < quest::CQuestManager::instance().GetEventFlag("update_refine_time") + (60 * 5))[m
[36m@@ -1027,7 +1039,7 @@[m [mbool CHARACTER::DoRefineWithScroll(LPITEM item)[m
 [m
 	LPITEM pkItemScroll;[m
 [m
[31m-	// °³·®¼­ Ã¼Å©[m
[32m+[m	[32m// ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ Ã¼Å©[m
 	if (m_iRefineAdditionalCell < 0)[m
 		return false;[m
 [m
[36m@@ -1047,7 +1059,7 @@[m [mbool CHARACTER::DoRefineWithScroll(LPITEM item)[m
 [m
 	if (result_vnum == 0)[m
 	{[m
[31m-		ChatPacket(CHAT_TYPE_INFO, LC_TEXT("´õ ÀÌ»ó °³·®ÇÒ ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m		[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ ï¿½Ì»ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 		return false;[m
 	}[m
 [m
[36m@@ -1056,7 +1068,7 @@[m [mbool CHARACTER::DoRefineWithScroll(LPITEM item)[m
 	{[m
 		if (item->GetRefineLevel() >= 4)[m
 		{[m
[31m-			ChatPacket(CHAT_TYPE_INFO, LC_TEXT("ÀÌ °³·®¼­·Î ´õ ÀÌ»ó °³·®ÇÒ ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m			[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½Ì»ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 			return false;[m
 		}[m
 	}[m
[36m@@ -1066,7 +1078,7 @@[m [mbool CHARACTER::DoRefineWithScroll(LPITEM item)[m
 	{[m
 		if (item->GetRefineLevel() != pkItemScroll->GetValue(1))[m
 		{[m
[31m-			ChatPacket(CHAT_TYPE_INFO, LC_TEXT("ÀÌ °³·®¼­·Î °³·®ÇÒ ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m			[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 			return false;[m
 		}[m
 	}[m
[36m@@ -1074,7 +1086,7 @@[m [mbool CHARACTER::DoRefineWithScroll(LPITEM item)[m
 	{[m
 		if (item->GetType() != ITEM_METIN || item->GetRefineLevel() != 4)[m
 		{[m
[31m-			ChatPacket(CHAT_TYPE_INFO, LC_TEXT("ÀÌ ¾ÆÀÌÅÛÀ¸·Î °³·®ÇÒ ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m			[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 			return false;[m
 		}[m
 	}[m
[36m@@ -1084,7 +1096,7 @@[m [mbool CHARACTER::DoRefineWithScroll(LPITEM item)[m
 	if (!pProto)[m
 	{[m
 		sys_err("DoRefineWithScroll NOT GET ITEM PROTO %d", item->GetRefinedVnum());[m
[31m-		ChatPacket(CHAT_TYPE_INFO, LC_TEXT("ÀÌ ¾ÆÀÌÅÛÀº °³·®ÇÒ ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m		[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 		return false;[m
 	}[m
 [m
[36m@@ -1100,7 +1112,7 @@[m [mbool CHARACTER::DoRefineWithScroll(LPITEM item)[m
 				case LIMIT_LEVEL:[m
 					if (GetLevel() < limit)[m
 					{[m
[31m-						ChatPacket(CHAT_TYPE_INFO, LC_TEXT("°³·®µÈ ÈÄ ¾ÆÀÌÅÛÀÇ ·¹º§ Á¦ÇÑº¸´Ù ·¹º§ÀÌ ³·½À´Ï´Ù."));[m
[32m+[m						[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Ñºï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 						return false;[m
 					}[m
 					break;[m
[36m@@ -1110,7 +1122,7 @@[m [mbool CHARACTER::DoRefineWithScroll(LPITEM item)[m
 [m
 	if (GetGold() < prt->cost)[m
 	{[m
[31m-		ChatPacket(CHAT_TYPE_INFO, LC_TEXT("°³·®À» ÇÏ±â À§ÇÑ µ·ÀÌ ºÎÁ·ÇÕ´Ï´Ù."));[m
[32m+[m		[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ï±ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Õ´Ï´ï¿½."));[m
 		return false;[m
 	}[m
 [m
[36m@@ -1122,7 +1134,7 @@[m [mbool CHARACTER::DoRefineWithScroll(LPITEM item)[m
 			{[m
 				ChatPacket(CHAT_TYPE_INFO, "Find %d, count %d, require %d", prt->materials[i].vnum, CountSpecifyItem(prt->materials[i].vnum), prt->materials[i].count);[m
 			}[m
[31m-			ChatPacket(CHAT_TYPE_INFO, LC_TEXT("°³·®À» ÇÏ±â À§ÇÑ Àç·á°¡ ºÎÁ·ÇÕ´Ï´Ù."));[m
[32m+[m			[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ï±ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½á°¡ ï¿½ï¿½ï¿½ï¿½ï¿½Õ´Ï´ï¿½."));[m
 			return false;[m
 		}[m
 	}[m
[36m@@ -1138,7 +1150,7 @@[m [mbool CHARACTER::DoRefineWithScroll(LPITEM item)[m
 [m
 	if (pkItemScroll->GetValue(0) == HYUNIRON_CHN || [m
 		pkItemScroll->GetValue(0) == YONGSIN_SCROLL || [m
[31m-		pkItemScroll->GetValue(0) == YAGONG_SCROLL) // ÇöÃ¶, ¿ë½ÅÀÇ Ãàº¹¼­, ¾ß°øÀÇ ºñÀü¼­  Ã³¸®[m
[32m+[m		[32mpkItemScroll->GetValue(0) == YAGONG_SCROLL) // ï¿½ï¿½Ã¶, ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½àº¹ï¿½ï¿½, ï¿½ß°ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½  Ã³ï¿½ï¿½[m
 	{[m
 		const char hyuniron_prob[9] = { 100, 75, 65, 55, 45, 40, 35, 25, 20 };[m
 		const char hyuniron_prob_euckr[9] = { 100, 75, 65, 55, 45, 40, 35, 30, 25 };[m
[36m@@ -1169,7 +1181,7 @@[m [mbool CHARACTER::DoRefineWithScroll(LPITEM item)[m
 		{[m
 			ChatPacket(CHAT_TYPE_INFO, "[Only Test] Success_Prob %d, RefineLevel %d ", success_prob, item->GetRefineLevel());[m
 		}[m
[31m-		if (pkItemScroll->GetValue(0) == HYUNIRON_CHN) // ÇöÃ¶Àº ¾ÆÀÌÅÛÀÌ ºÎ¼­Á®¾ß ÇÑ´Ù.[m
[32m+[m		[32mif (pkItemScroll->GetValue(0) == HYUNIRON_CHN) // ï¿½ï¿½Ã¶ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Î¼ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ñ´ï¿½.[m
 			bDestroyWhenFail = true;[m
 [m
 		// DETAIL_REFINE_LOG[m
[36m@@ -1189,7 +1201,7 @@[m [mbool CHARACTER::DoRefineWithScroll(LPITEM item)[m
 	}[m
 [m
 	// DETAIL_REFINE_LOG[m
[31m-	if (pkItemScroll->GetValue(0) == MUSIN_SCROLL) // ¹«½ÅÀÇ Ãàº¹¼­´Â 100% ¼º°ø (+4±îÁö¸¸)[m
[32m+[m	[32mif (pkItemScroll->GetValue(0) == MUSIN_SCROLL) // ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½àº¹ï¿½ï¿½ï¿½ï¿½ 100% ï¿½ï¿½ï¿½ï¿½ (+4ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½)[m
 	{[m
 		success_prob = 100;[m
 [m
[36m@@ -1211,7 +1223,7 @@[m [mbool CHARACTER::DoRefineWithScroll(LPITEM item)[m
 [m
 	if (prob <= success_prob)[m
 	{[m
[31m-		// ¼º°ø! ¸ðµç ¾ÆÀÌÅÛÀÌ »ç¶óÁö°í, °°Àº ¼Ó¼ºÀÇ ´Ù¸¥ ¾ÆÀÌÅÛ È¹µæ[m
[32m+[m		[32m// ï¿½ï¿½ï¿½ï¿½! ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½, ï¿½ï¿½ï¿½ï¿½ ï¿½Ó¼ï¿½ï¿½ï¿½ ï¿½Ù¸ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ È¹ï¿½ï¿½[m
 		LPITEM pkNewItem = ITEM_MANAGER::instance().CreateItem(result_vnum, 1, 0, false);[m
 [m
 		if (pkNewItem)[m
[36m@@ -1243,14 +1255,14 @@[m [mbool CHARACTER::DoRefineWithScroll(LPITEM item)[m
 		}[m
 		else[m
 		{[m
[31m-			// ¾ÆÀÌÅÛ »ý¼º¿¡ ½ÇÆÐ -> °³·® ½ÇÆÐ·Î °£ÁÖ[m
[32m+[m			[32m// ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ -> ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Ð·ï¿½ ï¿½ï¿½ï¿½ï¿½[m
 			sys_err("cannot create item %u", result_vnum);[m
 			NotifyRefineFail(this, item, szRefineType);[m
 		}[m
 	}[m
 	else if (!bDestroyWhenFail && result_fail_vnum)[m
 	{[m
[31m-		// ½ÇÆÐ! ¸ðµç ¾ÆÀÌÅÛÀÌ »ç¶óÁö°í, °°Àº ¼Ó¼ºÀÇ ³·Àº µî±ÞÀÇ ¾ÆÀÌÅÛ È¹µæ[m
[32m+[m		[32m// ï¿½ï¿½ï¿½ï¿½! ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½, ï¿½ï¿½ï¿½ï¿½ ï¿½Ó¼ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ È¹ï¿½ï¿½[m
 		LPITEM pkNewItem = ITEM_MANAGER::instance().CreateItem(result_fail_vnum, 1, 0, false);[m
 [m
 		if (pkNewItem)[m
[36m@@ -1283,14 +1295,14 @@[m [mbool CHARACTER::DoRefineWithScroll(LPITEM item)[m
 		}[m
 		else[m
 		{[m
[31m-			// ¾ÆÀÌÅÛ »ý¼º¿¡ ½ÇÆÐ -> °³·® ½ÇÆÐ·Î °£ÁÖ[m
[32m+[m			[32m// ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ -> ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Ð·ï¿½ ï¿½ï¿½ï¿½ï¿½[m
 			sys_err("cannot create item %u", result_fail_vnum);[m
 			NotifyRefineFail(this, item, szRefineType);[m
 		}[m
 	}[m
 	else[m
 	{[m
[31m-		NotifyRefineFail(this, item, szRefineType); // °³·®½Ã ¾ÆÀÌÅÛ »ç¶óÁöÁö ¾ÊÀ½[m
[32m+[m		[32mNotifyRefineFail(this, item, szRefineType); // ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½[m
 		[m
 		PayRefineFee(prt->cost);[m
 	}[m
[36m@@ -1311,7 +1323,7 @@[m [mbool CHARACTER::RefineInformation(BYTE bCell, BYTE bType, int iAdditionalCell)[m
 	// REFINE_COST[m
 	if (bType == REFINE_TYPE_MONEY_ONLY && !GetQuestFlag("deviltower_zone.can_refine"))[m
 	{[m
[31m-		ChatPacket(CHAT_TYPE_INFO, LC_TEXT("»ç±Í Å¸¿ö ¿Ï·á º¸»óÀº ÇÑ¹ø±îÁö »ç¿ë°¡´ÉÇÕ´Ï´Ù."));[m
[32m+[m		[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ Å¸ï¿½ï¿½ ï¿½Ï·ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ñ¹ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ë°¡ï¿½ï¿½ï¿½Õ´Ï´ï¿½."));[m
 		return false;[m
 	}[m
 	// END_OF_REFINE_COST[m
[36m@@ -1327,7 +1339,7 @@[m [mbool CHARACTER::RefineInformation(BYTE bCell, BYTE bType, int iAdditionalCell)[m
 	if (p.result_vnum == 0)[m
 	{[m
 		sys_err("RefineInformation p.result_vnum == 0");[m
[31m-		ChatPacket(CHAT_TYPE_INFO, LC_TEXT("ÀÌ ¾ÆÀÌÅÛÀº °³·®ÇÒ ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m		[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 		return false;[m
 	}[m
 [m
[36m@@ -1335,7 +1347,7 @@[m [mbool CHARACTER::RefineInformation(BYTE bCell, BYTE bType, int iAdditionalCell)[m
 	{[m
 		if (bType == 0)[m
 		{[m
[31m-			ChatPacket(CHAT_TYPE_INFO, LC_TEXT("ÀÌ ¾ÆÀÌÅÛÀº ÀÌ ¹æ½ÄÀ¸·Î´Â °³·®ÇÒ ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m			[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½Î´ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 			return false;[m
 		}[m
 		else[m
[36m@@ -1343,8 +1355,8 @@[m [mbool CHARACTER::RefineInformation(BYTE bCell, BYTE bType, int iAdditionalCell)[m
 			LPITEM itemScroll = GetInventoryItem(iAdditionalCell);[m
 			if (!itemScroll || item->GetVnum() == itemScroll->GetVnum())[m
 			{[m
[31m-				ChatPacket(CHAT_TYPE_INFO, LC_TEXT("°°Àº °³·®¼­¸¦ ÇÕÄ¥ ¼ö´Â ¾ø½À´Ï´Ù."));[m
[31m-				ChatPacket(CHAT_TYPE_INFO, LC_TEXT("Ãàº¹ÀÇ ¼­¿Í ÇöÃ¶À» ÇÕÄ¥ ¼ö ÀÖ½À´Ï´Ù."));[m
[32m+[m				[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½Ä¥ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
[32m+[m				[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½àº¹ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½Ã¶ï¿½ï¿½ ï¿½ï¿½Ä¥ ï¿½ï¿½ ï¿½Ö½ï¿½ï¿½Ï´ï¿½."));[m
 				return false;[m
 			}[m
 		}[m
[36m@@ -1357,7 +1369,7 @@[m [mbool CHARACTER::RefineInformation(BYTE bCell, BYTE bType, int iAdditionalCell)[m
 	if (!prt)[m
 	{[m
 		sys_err("RefineInformation NOT GET REFINE SET %d", item->GetRefineSet());[m
[31m-		ChatPacket(CHAT_TYPE_INFO, LC_TEXT("ÀÌ ¾ÆÀÌÅÛÀº °³·®ÇÒ ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m		[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 		return false;[m
 	}[m
 [m
[36m@@ -1366,10 +1378,10 @@[m [mbool CHARACTER::RefineInformation(BYTE bCell, BYTE bType, int iAdditionalCell)[m
 	//MAIN_QUEST_LV7[m
 	if (GetQuestFlag("main_quest_lv7.refine_chance") > 0)[m
 	{[m
[31m-		// ÀÏº»Àº Á¦¿Ü[m
[32m+[m		[32m// ï¿½Ïºï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½[m
 		if (!item->CheckItemUseLevel(20) || item->GetType() != ITEM_WEAPON)[m
 		{[m
[31m-			ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¹«·á °³·® ±âÈ¸´Â 20 ÀÌÇÏÀÇ ¹«±â¸¸ °¡´ÉÇÕ´Ï´Ù"));[m
[32m+[m			[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½È¸ï¿½ï¿½ 20 ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½â¸¸ ï¿½ï¿½ï¿½ï¿½ï¿½Õ´Ï´ï¿½"));[m
 			return false;[m
 		}[m
 		p.cost = 0;[m
[36m@@ -1404,8 +1416,8 @@[m [mbool CHARACTER::RefineItem(LPITEM pkItem, LPITEM pkTarget)[m
 [m
 	if (pkItem->GetSubType() == USE_TUNING)[m
 	{[m
[31m-		// XXX ¼º´É, ¼ÒÄÏ °³·®¼­´Â »ç¶óÁ³½À´Ï´Ù...[m
[31m-		// XXX ¼º´É°³·®¼­´Â Ãàº¹ÀÇ ¼­°¡ µÇ¾ú´Ù![m
[32m+[m		[32m// XXX ï¿½ï¿½ï¿½ï¿½, ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½...[m
[32m+[m		[32m// XXX ï¿½ï¿½ï¿½É°ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½àº¹ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½Ç¾ï¿½ï¿½ï¿½![m
 		// MUSIN_SCROLL[m
 		if (pkItem->GetValue(0) == MUSIN_SCROLL)[m
 			RefineInformation(pkTarget->GetCell(), REFINE_TYPE_MUSIN, pkItem->GetCell());[m
[36m@@ -1449,7 +1461,7 @@[m [mbool CHARACTER::RefineItem(LPITEM pkItem, LPITEM pkTarget)[m
 					AutoGiveItem(socket);[m
 					//TItemTable* pTable = ITEM_MANAGER::instance().GetTable(pkTarget->GetSocket(i));[m
 					//pkTarget->SetSocket(i, pTable->alValues[2]);[m
[31m-					// ±úÁøµ¹·Î ´ëÃ¼ÇØÁØ´Ù[m
[32m+[m					[32m// ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½Ã¼ï¿½ï¿½ï¿½Ø´ï¿½[m
 					pkTarget->SetSocket(i, ITEM_BROKEN_METIN_VNUM);[m
 				}[m
 			}[m
[36m@@ -1458,7 +1470,7 @@[m [mbool CHARACTER::RefineItem(LPITEM pkItem, LPITEM pkTarget)[m
 		}[m
 		else[m
 		{[m
[31m-			ChatPacket(CHAT_TYPE_INFO, LC_TEXT("»©³¾ ¼ö ÀÖ´Â ¸ÞÆ¾¼®ÀÌ ¾ø½À´Ï´Ù."));[m
[32m+[m			[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½Ö´ï¿½ ï¿½ï¿½Æ¾ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 			return false;[m
 		}[m
 	}[m
[36m@@ -1510,18 +1522,18 @@[m [mbool CHARACTER::GiveRecallItem(LPITEM item)[m
 [m
 	if (iEmpireByMapIndex && GetEmpire() != iEmpireByMapIndex)[m
 	{[m
[31m-		ChatPacket(CHAT_TYPE_INFO, LC_TEXT("±â¾ïÇØ µÑ ¼ö ¾ø´Â À§Ä¡ ÀÔ´Ï´Ù."));[m
[32m+[m		[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½Ä¡ ï¿½Ô´Ï´ï¿½."));[m
 		return false;[m
 	}[m
 [m
 	int pos;[m
 [m
[31m-	if (item->GetCount() == 1)	// ¾ÆÀÌÅÛÀÌ ÇÏ³ª¶ó¸é ±×³É ¼ÂÆÃ.[m
[32m+[m	[32mif (item->GetCount() == 1)	// ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ï³ï¿½ï¿½ï¿½ï¿½ ï¿½×³ï¿½ ï¿½ï¿½ï¿½ï¿½.[m
 	{[m
 		item->SetSocket(0, GetX());[m
 		item->SetSocket(1, GetY());[m
 	}[m
[31m-	else if ((pos = GetEmptyInventory(item->GetSize())) != -1) // ±×·¸Áö ¾Ê´Ù¸é ´Ù¸¥ ÀÎº¥Åä¸® ½½·ÔÀ» Ã£´Â´Ù.[m
[32m+[m	[32melse if ((pos = GetEmptyInventory(item->GetSize())) != -1) // ï¿½×·ï¿½ï¿½ï¿½ ï¿½Ê´Ù¸ï¿½ ï¿½Ù¸ï¿½ ï¿½Îºï¿½ï¿½ä¸® ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ Ã£ï¿½Â´ï¿½.[m
 	{[m
 		LPITEM item2 = ITEM_MANAGER::instance().CreateItem(item->GetVnum(), 1);[m
 [m
[36m@@ -1536,7 +1548,7 @@[m [mbool CHARACTER::GiveRecallItem(LPITEM item)[m
 	}[m
 	else[m
 	{[m
[31m-		ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¼ÒÁöÇ°¿¡ ºó °ø°£ÀÌ ¾ø½À´Ï´Ù."));[m
[32m+[m		[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½Ç°ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 		return false;[m
 	}[m
 [m
[36m@@ -1567,14 +1579,14 @@[m [mvoid CHARACTER::ProcessRecallItem(LPITEM item)[m
 		case 216:[m
 			iEmpireByMapIndex = -1;[m
 			break;[m
[31m-		// ¾Ç·æ±ºµµ ÀÏ¶§[m
[32m+[m		[32m// ï¿½Ç·æ±ºï¿½ï¿½ ï¿½Ï¶ï¿½[m
 		case 301:[m
 		case 302:[m
 		case 303:[m
 		case 304:[m
 			if( GetLevel() < 90 )[m
 			{[m
[31m-				ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¾ÆÀÌÅÛÀÇ ·¹º§ Á¦ÇÑº¸´Ù ·¹º§ÀÌ ³·½À´Ï´Ù."));[m
[32m+[m				[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Ñºï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 				return;[m
 			}[m
 			else[m
[36m@@ -1583,7 +1595,7 @@[m [mvoid CHARACTER::ProcessRecallItem(LPITEM item)[m
 [m
 	if (iEmpireByMapIndex && GetEmpire() != iEmpireByMapIndex)[m
 	{[m
[31m-		ChatPacket(CHAT_TYPE_INFO, LC_TEXT("±â¾ïµÈ À§Ä¡°¡ Å¸Á¦±¹¿¡ ¼ÓÇØ ÀÖ¾î¼­ ±ÍÈ¯ÇÒ ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m		[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½Ä¡ï¿½ï¿½ Å¸ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½Ö¾î¼­ ï¿½ï¿½È¯ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 		item->SetSocket(0, 0);[m
 		item->SetSocket(1, 0);[m
 	}[m
[36m@@ -1606,7 +1618,7 @@[m [mvoid CHARACTER::__OpenPrivateShop()[m
 			ChatPacket(CHAT_TYPE_COMMAND, "OpenPrivateShop");[m
 			break;[m
 		default:[m
[31m-			ChatPacket(CHAT_TYPE_INFO, LC_TEXT("°©¿ÊÀ» ¹þ¾î¾ß °³ÀÎ »óÁ¡À» ¿­ ¼ö ÀÖ½À´Ï´Ù."));[m
[32m+[m			[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ ï¿½Ö½ï¿½ï¿½Ï´ï¿½."));[m
 			break;[m
 	}[m
 }[m
[36m@@ -1621,14 +1633,14 @@[m [mvoid CHARACTER::SendMyShopPriceListCmd(DWORD dwItemVnum, DWORD dwItemPrice)[m
 }[m
 [m
 //[m
[31m-// DB Ä³½Ã·Î ºÎÅÍ ¹ÞÀº ¸®½ºÆ®¸¦ User ¿¡°Ô Àü¼ÛÇÏ°í »óÁ¡À» ¿­¶ó´Â Ä¿¸Çµå¸¦ º¸³½´Ù.[m
[32m+[m[32m// DB Ä³ï¿½Ã·ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½Æ®ï¿½ï¿½ User ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï°ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ Ä¿ï¿½Çµå¸¦ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½.[m
 //[m
 void CHARACTER::UseSilkBotaryReal(const TPacketMyshopPricelistHeader* p)[m
 {[m
 	const TItemPriceInfo* pInfo = (const TItemPriceInfo*)(p + 1);[m
 [m
 	if (!p->byCount)[m
[31m-		// °¡°Ý ¸®½ºÆ®°¡ ¾ø´Ù. dummy µ¥ÀÌÅÍ¸¦ ³ÖÀº Ä¿¸Çµå¸¦ º¸³»ÁØ´Ù.[m
[32m+[m		[32m// ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½Æ®ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½. dummy ï¿½ï¿½ï¿½ï¿½ï¿½Í¸ï¿½ ï¿½ï¿½ï¿½ï¿½ Ä¿ï¿½Çµå¸¦ ï¿½ï¿½ï¿½ï¿½ï¿½Ø´ï¿½.[m
 		SendMyShopPriceListCmd(1, 0);[m
 	else {[m
 		for (int idx = 0; idx < p->byCount; idx++)[m
[36m@@ -1639,8 +1651,8 @@[m [mvoid CHARACTER::UseSilkBotaryReal(const TPacketMyshopPricelistHeader* p)[m
 }[m
 [m
 //[m
[31m-// ÀÌ¹ø Á¢¼Ó ÈÄ Ã³À½ »óÁ¡À» Open ÇÏ´Â °æ¿ì ¸®½ºÆ®¸¦ Load ÇÏ±â À§ÇØ DB Ä³½Ã¿¡ °¡°ÝÁ¤º¸ ¸®½ºÆ® ¿äÃ» ÆÐÅ¶À» º¸³½´Ù.[m
[31m-// ÀÌÈÄºÎÅÍ´Â ¹Ù·Î »óÁ¡À» ¿­¶ó´Â ÀÀ´äÀ» º¸³½´Ù.[m
[32m+[m[32m// ï¿½Ì¹ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ Ã³ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ Open ï¿½Ï´ï¿½ ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½Æ®ï¿½ï¿½ Load ï¿½Ï±ï¿½ ï¿½ï¿½ï¿½ï¿½ DB Ä³ï¿½Ã¿ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½Æ® ï¿½ï¿½Ã» ï¿½ï¿½Å¶ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½.[m
[32m+[m[32m// ï¿½ï¿½ï¿½Äºï¿½ï¿½Í´ï¿½ ï¿½Ù·ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½.[m
 //[m
 void CHARACTER::UseSilkBotary(void)[m
 {[m
[36m@@ -1668,14 +1680,14 @@[m [mint CalculateConsume(LPCHARACTER ch)[m
 		const int needLife = ch->GetMaxHP() * needPercent / 100;[m
 		if (curLife < needLife)[m
 		{[m
[31m-			ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("³²Àº »ý¸í·Â ¾çÀÌ ¸ðÀÚ¶ó »ç¿ëÇÒ ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m			[32mch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Ú¶ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 			return -1;[m
 		}[m
 [m
 		consumeLife = needLife;[m
 [m
 [m
[31m-		// CheckMinLifeForWarp: µ¶¿¡ ÀÇÇØ¼­ Á×À¸¸é ¾ÈµÇ¹Ç·Î »ý¸í·Â ÃÖ¼Ò·®´Â ³²°ÜÁØ´Ù[m
[32m+[m		[32m// CheckMinLifeForWarp: ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Ø¼ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ÈµÇ¹Ç·ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ö¼Ò·ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ø´ï¿½[m
 		const int minPercent	= WARP_MIN_LIFE_PERCENT;[m
 		const int minLife	= ch->GetMaxHP() * minPercent / 100;[m
 		if (curLife - needLife < minLife)[m
[36m@@ -1697,7 +1709,7 @@[m [mint CalculateConsumeSP(LPCHARACTER lpChar)[m
 [m
 	if (curSP < needSP)[m
 	{[m
[31m-		lpChar->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("³²Àº Á¤½Å·Â ¾çÀÌ ¸ðÀÚ¶ó »ç¿ëÇÒ ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m		[32mlpChar->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Å·ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Ú¶ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 		return -1;[m
 	}[m
 [m
[36m@@ -1720,7 +1732,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 			case LIMIT_LEVEL:[m
 				if (GetLevel() < limitValue)[m
 				{[m
[31m-					ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¾ÆÀÌÅÛÀÇ ·¹º§ Á¦ÇÑº¸´Ù ·¹º§ÀÌ ³·½À´Ï´Ù."));[m
[32m+[m					[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Ñºï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 					return false;[m
 				}[m
 				break;[m
[36m@@ -1742,17 +1754,17 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 [m
 	if ( CArenaManager::instance().IsLimitedItem( GetMapIndex(), item->GetVnum() ) == true )[m
 	{[m
[31m-		ChatPacket(CHAT_TYPE_INFO, LC_TEXT("´ë·Ã Áß¿¡´Â ÀÌ¿ëÇÒ ¼ö ¾ø´Â ¹°Ç°ÀÔ´Ï´Ù."));[m
[32m+[m		[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ ï¿½ß¿ï¿½ï¿½ï¿½ ï¿½Ì¿ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½Ç°ï¿½Ô´Ï´ï¿½."));[m
 		return false;[m
 	}[m
 [m
[31m-	// ¾ÆÀÌÅÛ ÃÖÃÊ »ç¿ë ÀÌÈÄºÎÅÍ´Â »ç¿ëÇÏÁö ¾Ê¾Æµµ ½Ã°£ÀÌ Â÷°¨µÇ´Â ¹æ½Ä Ã³¸®. [m
[32m+[m	[32m// ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Äºï¿½ï¿½Í´ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ê¾Æµï¿½ ï¿½Ã°ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ç´ï¿½ ï¿½ï¿½ï¿½ Ã³ï¿½ï¿½.[m[41m [m
 	if (-1 != iLimitRealtimeStartFirstUseFlagIndex)[m
 	{[m
[31m-		// ÇÑ ¹øÀÌ¶óµµ »ç¿ëÇÑ ¾ÆÀÌÅÛÀÎÁö ¿©ºÎ´Â Socket1À» º¸°í ÆÇ´ÜÇÑ´Ù. (Socket1¿¡ »ç¿ëÈ½¼ö ±â·Ï)[m
[32m+[m		[32m// ï¿½ï¿½ ï¿½ï¿½ï¿½Ì¶ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Î´ï¿½ Socket1ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½Ç´ï¿½ï¿½Ñ´ï¿½. (Socket1ï¿½ï¿½ ï¿½ï¿½ï¿½È½ï¿½ï¿½ ï¿½ï¿½ï¿½)[m
 		if (0 == item->GetSocket(1))[m
 		{[m
[31m-			// »ç¿ë°¡´É½Ã°£Àº Default °ªÀ¸·Î Limit Value °ªÀ» »ç¿ëÇÏµÇ, Socket0¿¡ °ªÀÌ ÀÖÀ¸¸é ±× °ªÀ» »ç¿ëÇÏµµ·Ï ÇÑ´Ù. (´ÜÀ§´Â ÃÊ)[m
[32m+[m			[32m// ï¿½ï¿½ë°¡ï¿½É½Ã°ï¿½ï¿½ï¿½ Default ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ Limit Value ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½Ïµï¿½, Socket0ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½Ïµï¿½ï¿½ï¿½ ï¿½Ñ´ï¿½. (ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½)[m
 			long duration = (0 != item->GetSocket(0)) ? item->GetSocket(0) : item->GetProto()->aLimits[iLimitRealtimeStartFirstUseFlagIndex].lValue;[m
 [m
 			if (0 == duration)[m
[36m@@ -1810,7 +1822,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 			{[m
 				if (item->GetVnum() == 50051 || item->GetVnum() == 50052 || item->GetVnum() == 50053)[m
 				{[m
[31m-					ChatPacket(CHAT_TYPE_INFO, LC_TEXT("´ë·Ã Áß¿¡´Â ÀÌ¿ëÇÒ ¼ö ¾ø´Â ¹°Ç°ÀÔ´Ï´Ù."));[m
[32m+[m					[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ ï¿½ß¿ï¿½ï¿½ï¿½ ï¿½Ì¿ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½Ç°ï¿½Ô´Ï´ï¿½."));[m
 					return false;[m
 				}[m
 			}[m
[36m@@ -1837,13 +1849,13 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 [m
 				if (!tree)[m
 				{[m
[31m-					ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¸ð´ÚºÒÀ» ÇÇ¿ï ¼ö ¾ø´Â ÁöÁ¡ÀÔ´Ï´Ù."));[m
[32m+[m					[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½Úºï¿½ï¿½ï¿½ ï¿½Ç¿ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ô´Ï´ï¿½."));[m
 					return false;[m
 				}[m
 [m
 				if (tree->IsAttr((long)(GetX()+fx), (long)(GetY()+fy), ATTR_WATER))[m
 				{[m
[31m-					ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¹° ¼Ó¿¡ ¸ð´ÚºÒÀ» ÇÇ¿ï ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m					[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ ï¿½Ó¿ï¿½ ï¿½ï¿½Úºï¿½ï¿½ï¿½ ï¿½Ç¿ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 					return false;[m
 				}[m
 [m
[36m@@ -1928,7 +1940,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 [m
 								switch (item->GetVnum())[m
 								{[m
[31m-									case 71049: // ºñ´Üº¸µû¸®[m
[32m+[m									[32mcase 71049: // ï¿½ï¿½Üºï¿½ï¿½ï¿½ï¿½ï¿½[m
 										if (LC_IsYMIR() == true || LC_IsKorea() == true)[m
 										{[m
 											if (IS_BOTARYABLE_ZONE(GetMapIndex()) == true)[m
[36m@@ -1937,7 +1949,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 											}[m
 											else[m
 											{[m
[31m-												ChatPacket(CHAT_TYPE_INFO, LC_TEXT("°³ÀÎ »óÁ¡À» ¿­ ¼ö ¾ø´Â Áö¿ªÀÔ´Ï´Ù"));[m
[32m+[m												[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ô´Ï´ï¿½"));[m
 											}[m
 										}[m
 										else[m
[36m@@ -1964,8 +1976,8 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 		case ITEM_WEAPON:[m
 		case ITEM_ARMOR:[m
 		case ITEM_ROD:[m
[31m-		case ITEM_RING:		// ½Å±Ô ¹ÝÁö ¾ÆÀÌÅÛ[m
[31m-		case ITEM_BELT:		// ½Å±Ô º§Æ® ¾ÆÀÌÅÛ[m
[32m+[m		[32mcase ITEM_RING:		// ï¿½Å±ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½[m
[32m+[m		[32mcase ITEM_BELT:		// ï¿½Å±ï¿½ ï¿½ï¿½Æ® ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½[m
 			// MINING[m
 		case ITEM_PICK:[m
 			// END_OF_MINING[m
[36m@@ -1974,10 +1986,10 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 			else[m
 				UnequipItem(item);[m
 			break;[m
[31m-			// Âø¿ëÇÏÁö ¾ÊÀº ¿ëÈ¥¼®Àº »ç¿ëÇÒ ¼ö ¾ø´Ù.[m
[31m-			// Á¤»óÀûÀÎ Å¬¶ó¶ó¸é, ¿ëÈ¥¼®¿¡ °üÇÏ¿© item use ÆÐÅ¶À» º¸³¾ ¼ö ¾ø´Ù.[m
[31m-			// ¿ëÈ¥¼® Âø¿ëÀº item move ÆÐÅ¶À¸·Î ÇÑ´Ù.[m
[31m-			// Âø¿ëÇÑ ¿ëÈ¥¼®Àº ÃßÃâÇÑ´Ù.[m
[32m+[m			[32m// ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½È¥ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½.[m
[32m+[m			[32m// ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ Å¬ï¿½ï¿½ï¿½ï¿½, ï¿½ï¿½È¥ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Ï¿ï¿½ item use ï¿½ï¿½Å¶ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½.[m
[32m+[m			[32m// ï¿½ï¿½È¥ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ item move ï¿½ï¿½Å¶ï¿½ï¿½ï¿½ï¿½ ï¿½Ñ´ï¿½.[m
[32m+[m			[32m// ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½È¥ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ñ´ï¿½.[m
 		case ITEM_DS:[m
 			{[m
 				if (!item->IsEquipped())[m
[36m@@ -1996,7 +2008,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 			{[m
 				if (CArenaManager::instance().IsArenaMap(GetMapIndex()) == true)[m
 				{[m
[31m-					ChatPacket(CHAT_TYPE_INFO, LC_TEXT("´ë·Ã Áß¿¡´Â ÀÌ¿ëÇÒ ¼ö ¾ø´Â ¹°Ç°ÀÔ´Ï´Ù."));[m
[32m+[m					[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ ï¿½ß¿ï¿½ï¿½ï¿½ ï¿½Ì¿ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½Ç°ï¿½Ô´Ï´ï¿½."));[m
 					return false;[m
 				}[m
 [m
[36m@@ -2008,7 +2020,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 		case ITEM_TREASURE_BOX:[m
 			{[m
 				return false;[m
[31m-				//ChatPacket(CHAT_TYPE_TALKING, LC_TEXT("¿­¼è·Î Àá°Ü ÀÖ¾î¼­ ¿­¸®Áö ¾Ê´Â°Í °°´Ù. ¿­¼è¸¦ ±¸ÇØº¸ÀÚ."));[m
[32m+[m				[32m//ChatPacket(CHAT_TYPE_TALKING, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ ï¿½Ö¾î¼­ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ê´Â°ï¿½ ï¿½ï¿½ï¿½ï¿½. ï¿½ï¿½ï¿½è¸¦ ï¿½ï¿½ï¿½Øºï¿½ï¿½ï¿½."));[m
 			}[m
 			break;[m
 [m
[36m@@ -2024,13 +2036,13 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 [m
 				if (item2->GetType() != ITEM_TREASURE_BOX)[m
 				{[m
[31m-					ChatPacket(CHAT_TYPE_TALKING, LC_TEXT("¿­¼è·Î ¿©´Â ¹°°ÇÀÌ ¾Æ´Ñ°Í °°´Ù."));[m
[32m+[m					[32mChatPacket(CHAT_TYPE_TALKING, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Æ´Ñ°ï¿½ ï¿½ï¿½ï¿½ï¿½."));[m
 					return false;[m
 				}[m
 [m
 				if (item->GetValue(0) == item2->GetValue(0))[m
 				{[m
[31m-					//ChatPacket(CHAT_TYPE_TALKING, LC_TEXT("¿­¼è´Â ¸ÂÀ¸³ª ¾ÆÀÌÅÛ ÁÖ´Â ºÎºÐ ±¸ÇöÀÌ ¾ÈµÇ¾ú½À´Ï´Ù."));[m
[32m+[m					[32m//ChatPacket(CHAT_TYPE_TALKING, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ö´ï¿½ ï¿½Îºï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ÈµÇ¾ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 					DWORD dwBoxVnum = item2->GetVnum();[m
 					std::vector <DWORD> dwVnums;[m
 					std::vector <DWORD> dwCounts;[m
[36m@@ -2046,34 +2058,34 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 							switch (dwVnums[i])[m
 							{[m
 								case CSpecialItemGroup::GOLD:[m
[31m-									ChatPacket(CHAT_TYPE_INFO, LC_TEXT("µ· %d ³ÉÀ» È¹µæÇß½À´Ï´Ù."), dwCounts[i]);[m
[32m+[m									[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ %d ï¿½ï¿½ï¿½ï¿½ È¹ï¿½ï¿½ï¿½ß½ï¿½ï¿½Ï´ï¿½."), dwCounts[i]);[m
 									break;[m
 								case CSpecialItemGroup::EXP:[m
[31m-									ChatPacket(CHAT_TYPE_INFO, LC_TEXT("»óÀÚ¿¡¼­ ºÎÅÍ ½ÅºñÇÑ ºûÀÌ ³ª¿É´Ï´Ù."));[m
[31m-									ChatPacket(CHAT_TYPE_INFO, LC_TEXT("%dÀÇ °æÇèÄ¡¸¦ È¹µæÇß½À´Ï´Ù."), dwCounts[i]);[m
[32m+[m									[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½Ú¿ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½Åºï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½É´Ï´ï¿½."));[m
[32m+[m									[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("%dï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½Ä¡ï¿½ï¿½ È¹ï¿½ï¿½ï¿½ß½ï¿½ï¿½Ï´ï¿½."), dwCounts[i]);[m
 									break;[m
 								case CSpecialItemGroup::MOB:[m
[31m-									ChatPacket(CHAT_TYPE_INFO, LC_TEXT("»óÀÚ¿¡¼­ ¸ó½ºÅÍ°¡ ³ªÅ¸³µ½À´Ï´Ù!"));[m
[32m+[m									[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½Ú¿ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Í°ï¿½ ï¿½ï¿½Å¸ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½!"));[m
 									break;[m
 								case CSpecialItemGroup::SLOW:[m
[31m-									ChatPacket(CHAT_TYPE_INFO, LC_TEXT("»óÀÚ¿¡¼­ ³ª¿Â »¡°£ ¿¬±â¸¦ µéÀÌ¸¶½ÃÀÚ ¿òÁ÷ÀÌ´Â ¼Óµµ°¡ ´À·ÁÁ³½À´Ï´Ù!"));[m
[32m+[m									[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½Ú¿ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½â¸¦ ï¿½ï¿½ï¿½Ì¸ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ì´ï¿½ ï¿½Óµï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½!"));[m
 									break;[m
 								case CSpecialItemGroup::DRAIN_HP:[m
[31m-									ChatPacket(CHAT_TYPE_INFO, LC_TEXT("»óÀÚ°¡ °©ÀÚ±â Æø¹ßÇÏ¿´½À´Ï´Ù! »ý¸í·ÂÀÌ °¨¼ÒÇß½À´Ï´Ù."));[m
[32m+[m									[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½Ú°ï¿½ ï¿½ï¿½ï¿½Ú±ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï¿ï¿½ï¿½ï¿½ï¿½Ï´ï¿½! ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ß½ï¿½ï¿½Ï´ï¿½."));[m
 									break;[m
 								case CSpecialItemGroup::POISON:[m
[31m-									ChatPacket(CHAT_TYPE_INFO, LC_TEXT("»óÀÚ¿¡¼­ ³ª¿Â ³ì»ö ¿¬±â¸¦ µéÀÌ¸¶½ÃÀÚ µ¶ÀÌ ¿Â¸öÀ¸·Î ÆÛÁý´Ï´Ù!"));[m
[32m+[m									[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½Ú¿ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½â¸¦ ï¿½ï¿½ï¿½Ì¸ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½Â¸ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½!"));[m
 									break;[m
 								case CSpecialItemGroup::MOB_GROUP:[m
[31m-									ChatPacket(CHAT_TYPE_INFO, LC_TEXT("»óÀÚ¿¡¼­ ¸ó½ºÅÍ°¡ ³ªÅ¸³µ½À´Ï´Ù!"));[m
[32m+[m									[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½Ú¿ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Í°ï¿½ ï¿½ï¿½Å¸ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½!"));[m
 									break;[m
 								default:[m
 									if (item_gets[i])[m
 									{[m
 										if (dwCounts[i] > 1)[m
[31m-											ChatPacket(CHAT_TYPE_INFO, LC_TEXT("»óÀÚ¿¡¼­ %s °¡ %d °³ ³ª¿Ô½À´Ï´Ù."), item_gets[i]->GetName(), dwCounts[i]);[m
[32m+[m											[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½Ú¿ï¿½ï¿½ï¿½ %s ï¿½ï¿½ %d ï¿½ï¿½ ï¿½ï¿½ï¿½Ô½ï¿½ï¿½Ï´ï¿½."), item_gets[i]->GetName(), dwCounts[i]);[m
 										else[m
[31m-											ChatPacket(CHAT_TYPE_INFO, LC_TEXT("»óÀÚ¿¡¼­ %s °¡ ³ª¿Ô½À´Ï´Ù."), item_gets[i]->GetName());[m
[32m+[m											[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½Ú¿ï¿½ï¿½ï¿½ %s ï¿½ï¿½ ï¿½ï¿½ï¿½Ô½ï¿½ï¿½Ï´ï¿½."), item_gets[i]->GetName());[m
 [m
 									}[m
 							}[m
[36m@@ -2081,13 +2093,13 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 					}[m
 					else[m
 					{[m
[31m-						ChatPacket(CHAT_TYPE_TALKING, LC_TEXT("¿­¼è°¡ ¸ÂÁö ¾Ê´Â °Í °°´Ù."));[m
[32m+[m						[32mChatPacket(CHAT_TYPE_TALKING, LC_TEXT("ï¿½ï¿½ï¿½è°¡ ï¿½ï¿½ï¿½ï¿½ ï¿½Ê´ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½."));[m
 						return false;[m
 					}[m
 				}[m
 				else[m
 				{[m
[31m-					ChatPacket(CHAT_TYPE_TALKING, LC_TEXT("¿­¼è°¡ ¸ÂÁö ¾Ê´Â °Í °°´Ù."));[m
[32m+[m					[32mChatPacket(CHAT_TYPE_TALKING, LC_TEXT("ï¿½ï¿½ï¿½è°¡ ï¿½ï¿½ï¿½ï¿½ ï¿½Ê´ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½."));[m
 					return false;[m
 				}[m
 			}[m
[36m@@ -2101,20 +2113,20 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 				std::vector <LPITEM> item_gets;[m
 				int count = 0;[m
 [m
[31m-				if (dwBoxVnum == 50033 && LC_IsYMIR()) // ¾Ë¼ö¾ø´Â »óÀÚ[m
[32m+[m				[32mif (dwBoxVnum == 50033 && LC_IsYMIR()) // ï¿½Ë¼ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½[m
 				{[m
 					if (GetLevel() < 15)[m
 					{[m
[31m-						ChatPacket(CHAT_TYPE_INFO, "15·¹º§ ÀÌÇÏ¿¡¼­´Â »ç¿ëÇÒ ¼ö ¾ø½À´Ï´Ù.");[m
[32m+[m						[32mChatPacket(CHAT_TYPE_INFO, "15ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Ï¿ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½.");[m
 						return false;[m
 					}[m
 				}[m
 [m
[31m-				if( (dwBoxVnum > 51500 && dwBoxVnum < 52000) || (dwBoxVnum >= 50255 && dwBoxVnum <= 50260) )	// ¿ëÈ¥¿ø¼®µé[m
[32m+[m				[32mif( (dwBoxVnum > 51500 && dwBoxVnum < 52000) || (dwBoxVnum >= 50255 && dwBoxVnum <= 50260) )	// ï¿½ï¿½È¥ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½[m
 				{[m
 					if( !(this->DragonSoul_IsQualified()) )[m
 					{[m
[31m-						ChatPacket(CHAT_TYPE_INFO,LC_TEXT("¸ÕÀú ¿ëÈ¥¼® Äù½ºÆ®¸¦ ¿Ï·áÇÏ¼Å¾ß ÇÕ´Ï´Ù."));[m
[32m+[m						[32mChatPacket(CHAT_TYPE_INFO,LC_TEXT("ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½È¥ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½Æ®ï¿½ï¿½ ï¿½Ï·ï¿½ï¿½Ï¼Å¾ï¿½ ï¿½Õ´Ï´ï¿½."));[m
 						return false;[m
 					}[m
 				}[m
[36m@@ -2127,41 +2139,41 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 						switch (dwVnums[i])[m
 						{[m
 						case CSpecialItemGroup::GOLD:[m
[31m-							ChatPacket(CHAT_TYPE_INFO, LC_TEXT("µ· %d ³ÉÀ» È¹µæÇß½À´Ï´Ù."), dwCounts[i]);[m
[32m+[m							[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ %d ï¿½ï¿½ï¿½ï¿½ È¹ï¿½ï¿½ï¿½ß½ï¿½ï¿½Ï´ï¿½."), dwCounts[i]);[m
 							break;[m
 						case CSpecialItemGroup::EXP:[m
[31m-							ChatPacket(CHAT_TYPE_INFO, LC_TEXT("»óÀÚ¿¡¼­ ºÎÅÍ ½ÅºñÇÑ ºûÀÌ ³ª¿É´Ï´Ù."));[m
[31m-							ChatPacket(CHAT_TYPE_INFO, LC_TEXT("%dÀÇ °æÇèÄ¡¸¦ È¹µæÇß½À´Ï´Ù."), dwCounts[i]);[m
[32m+[m							[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½Ú¿ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½Åºï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½É´Ï´ï¿½."));[m
[32m+[m							[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("%dï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½Ä¡ï¿½ï¿½ È¹ï¿½ï¿½ï¿½ß½ï¿½ï¿½Ï´ï¿½."), dwCounts[i]);[m
 							break;[m
 						case CSpecialItemGroup::MOB:[m
[31m-							ChatPacket(CHAT_TYPE_INFO, LC_TEXT("»óÀÚ¿¡¼­ ¸ó½ºÅÍ°¡ ³ªÅ¸³µ½À´Ï´Ù!"));[m
[32m+[m							[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½Ú¿ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Í°ï¿½ ï¿½ï¿½Å¸ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½!"));[m
 							break;[m
 						case CSpecialItemGroup::SLOW:[m
[31m-							ChatPacket(CHAT_TYPE_INFO, LC_TEXT("»óÀÚ¿¡¼­ ³ª¿Â »¡°£ ¿¬±â¸¦ µéÀÌ¸¶½ÃÀÚ ¿òÁ÷ÀÌ´Â ¼Óµµ°¡ ´À·ÁÁ³½À´Ï´Ù!"));[m
[32m+[m							[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½Ú¿ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½â¸¦ ï¿½ï¿½ï¿½Ì¸ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ì´ï¿½ ï¿½Óµï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½!"));[m
 							break;[m
 						case CSpecialItemGroup::DRAIN_HP:[m
[31m-							ChatPacket(CHAT_TYPE_INFO, LC_TEXT("»óÀÚ°¡ °©ÀÚ±â Æø¹ßÇÏ¿´½À´Ï´Ù! »ý¸í·ÂÀÌ °¨¼ÒÇß½À´Ï´Ù."));[m
[32m+[m							[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½Ú°ï¿½ ï¿½ï¿½ï¿½Ú±ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï¿ï¿½ï¿½ï¿½ï¿½Ï´ï¿½! ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ß½ï¿½ï¿½Ï´ï¿½."));[m
 							break;[m
 						case CSpecialItemGroup::POISON:[m
[31m-							ChatPacket(CHAT_TYPE_INFO, LC_TEXT("»óÀÚ¿¡¼­ ³ª¿Â ³ì»ö ¿¬±â¸¦ µéÀÌ¸¶½ÃÀÚ µ¶ÀÌ ¿Â¸öÀ¸·Î ÆÛÁý´Ï´Ù!"));[m
[32m+[m							[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½Ú¿ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½â¸¦ ï¿½ï¿½ï¿½Ì¸ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½Â¸ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½!"));[m
 							break;[m
 						case CSpecialItemGroup::MOB_GROUP:[m
[31m-							ChatPacket(CHAT_TYPE_INFO, LC_TEXT("»óÀÚ¿¡¼­ ¸ó½ºÅÍ°¡ ³ªÅ¸³µ½À´Ï´Ù!"));[m
[32m+[m							[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½Ú¿ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Í°ï¿½ ï¿½ï¿½Å¸ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½!"));[m
 							break;[m
 						default:[m
 							if (item_gets[i])[m
 							{[m
 								if (dwCounts[i] > 1)[m
[31m-									ChatPacket(CHAT_TYPE_INFO, LC_TEXT("»óÀÚ¿¡¼­ %s °¡ %d °³ ³ª¿Ô½À´Ï´Ù."), item_gets[i]->GetName(), dwCounts[i]);[m
[32m+[m									[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½Ú¿ï¿½ï¿½ï¿½ %s ï¿½ï¿½ %d ï¿½ï¿½ ï¿½ï¿½ï¿½Ô½ï¿½ï¿½Ï´ï¿½."), item_gets[i]->GetName(), dwCounts[i]);[m
 								else[m
[31m-									ChatPacket(CHAT_TYPE_INFO, LC_TEXT("»óÀÚ¿¡¼­ %s °¡ ³ª¿Ô½À´Ï´Ù."), item_gets[i]->GetName());[m
[32m+[m									[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½Ú¿ï¿½ï¿½ï¿½ %s ï¿½ï¿½ ï¿½ï¿½ï¿½Ô½ï¿½ï¿½Ï´ï¿½."), item_gets[i]->GetName());[m
 							}[m
 						}[m
 					}[m
 				}[m
 				else[m
 				{[m
[31m-					ChatPacket(CHAT_TYPE_TALKING, LC_TEXT("¾Æ¹«°Íµµ ¾òÀ» ¼ö ¾ø¾ú½À´Ï´Ù."));[m
[32m+[m					[32mChatPacket(CHAT_TYPE_TALKING, LC_TEXT("ï¿½Æ¹ï¿½ï¿½Íµï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 					return false;[m
 				}[m
 			}[m
[36m@@ -2180,10 +2192,10 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 				if (SkillLevelDown(dwVnum))[m
 				{[m
 					ITEM_MANAGER::instance().RemoveItem(item);[m
[31m-					ChatPacket(CHAT_TYPE_INFO, LC_TEXT("½ºÅ³ ·¹º§À» ³»¸®´Âµ¥ ¼º°øÇÏ¿´½À´Ï´Ù."));[m
[32m+[m					[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½Å³ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Âµï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï¿ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 				}[m
 				else[m
[31m-					ChatPacket(CHAT_TYPE_INFO, LC_TEXT("½ºÅ³ ·¹º§À» ³»¸± ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m					[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½Å³ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 			}[m
 			break;[m
 [m
[36m@@ -2191,7 +2203,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 			{[m
 				if (IsPolymorphed())[m
 				{[m
[31m-					ChatPacket(CHAT_TYPE_INFO, LC_TEXT("º¯½ÅÁß¿¡´Â Ã¥À» ÀÐÀ»¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m					[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½ß¿ï¿½ï¿½ï¿½ Ã¥ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 					return false;[m
 				}[m
 [m
[36m@@ -2203,7 +2215,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 				}[m
 				else[m
 				{[m
[31m-					// »õ·Î¿î ¼ö·Ã¼­´Â value 0 ¿¡ ½ºÅ³ ¹øÈ£°¡ ÀÖÀ¸¹Ç·Î ±×°ÍÀ» »ç¿ë.[m
[32m+[m					[32m// ï¿½ï¿½ï¿½Î¿ï¿½ ï¿½ï¿½ï¿½Ã¼ï¿½ï¿½ï¿½ value 0 ï¿½ï¿½ ï¿½ï¿½Å³ ï¿½ï¿½È£ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ç·ï¿½ ï¿½×°ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½.[m
 					dwVnum = item->GetValue(0);[m
 				}[m
 [m
[36m@@ -2223,7 +2235,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 					if (distribution_test_server)[m
 						iReadDelay /= 3;[m
 [m
[31m-					//ÇÑ±¹ º»¼·ÀÇ °æ¿ì¿¡´Â ½Ã°£À» 24½Ã°£ °íÁ¤[m
[32m+[m					[32m//ï¿½Ñ±ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ì¿¡ï¿½ï¿½ ï¿½Ã°ï¿½ï¿½ï¿½ 24ï¿½Ã°ï¿½ ï¿½ï¿½ï¿½ï¿½[m
 					if (LC_IsKorea())[m
 						iReadDelay = 86400;[m
 [m
[36m@@ -2249,7 +2261,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 						case USE_ABILITY_UP:[m
 							if (FindAffect(affect_type, apply_type))[m
 							{[m
[31m-								ChatPacket(CHAT_TYPE_INFO, LC_TEXT("ÀÌ¹Ì È¿°ú°¡ °É·Á ÀÖ½À´Ï´Ù."));[m
[32m+[m								[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½Ì¹ï¿½ È¿ï¿½ï¿½ï¿½ï¿½ ï¿½É·ï¿½ ï¿½Ö½ï¿½ï¿½Ï´ï¿½."));[m
 								return false;[m
 							}[m
 [m
[36m@@ -2290,7 +2302,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 						{[m
 							if (FindAffect(AFFECT_EXP_BONUS_EURO_FREE, aApplyInfo[item->GetValue(1)].bPointType))[m
 							{[m
[31m-								ChatPacket(CHAT_TYPE_INFO, LC_TEXT("ÀÌ¹Ì È¿°ú°¡ °É·Á ÀÖ½À´Ï´Ù."));[m
[32m+[m								[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½Ì¹ï¿½ È¿ï¿½ï¿½ï¿½ï¿½ ï¿½É·ï¿½ ï¿½Ö½ï¿½ï¿½Ï´ï¿½."));[m
 							}[m
 							else[m
 							{[m
[36m@@ -2306,7 +2318,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 							{[m
 								if (quest::CQuestManager::instance().GetEventFlag("arena_potion_limit") > 0)[m
 								{[m
[31m-									ChatPacket(CHAT_TYPE_INFO, LC_TEXT("´ë·ÃÀå¿¡¼­ »ç¿ëÇÏ½Ç ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m									[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½å¿¡ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½Ï½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 									return false;[m
 								}[m
 [m
[36m@@ -2320,14 +2332,14 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 										{[m
 											if (m_nPotionLimit <= 0)[m
 											{[m
[31m-												ChatPacket(CHAT_TYPE_INFO, LC_TEXT("»ç¿ë Á¦ÇÑ·®À» ÃÊ°úÇÏ¿´½À´Ï´Ù."));[m
[32m+[m												[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Ñ·ï¿½ï¿½ï¿½ ï¿½Ê°ï¿½ï¿½Ï¿ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 												return false;[m
 											}[m
 										}[m
 										break;[m
 [m
 									default :[m
[31m-										ChatPacket(CHAT_TYPE_INFO, LC_TEXT("´ë·ÃÀå¿¡¼­ »ç¿ëÇÏ½Ç ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m										[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½å¿¡ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½Ï½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 										return false;[m
 										break;[m
 								}[m
[36m@@ -2335,7 +2347,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 [m
 							bool used = false;[m
 [m
[31m-							if (item->GetValue(0) != 0) // HP Àý´ë°ª È¸º¹[m
[32m+[m							[32mif (item->GetValue(0) != 0) // HP ï¿½ï¿½ï¿½ë°ª È¸ï¿½ï¿½[m
 							{[m
 								if (GetHP() < GetMaxHP())[m
 								{[m
[36m@@ -2345,7 +2357,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 								}[m
 							}[m
 [m
[31m-							if (item->GetValue(1) != 0)	// SP Àý´ë°ª È¸º¹[m
[32m+[m							[32mif (item->GetValue(1) != 0)	// SP ï¿½ï¿½ï¿½ë°ª È¸ï¿½ï¿½[m
 							{[m
 								if (GetSP() < GetMaxSP())[m
 								{[m
[36m@@ -2355,7 +2367,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 								}[m
 							}[m
 [m
[31m-							if (item->GetValue(3) != 0) // HP % È¸º¹[m
[32m+[m							[32mif (item->GetValue(3) != 0) // HP % È¸ï¿½ï¿½[m
 							{[m
 								if (GetHP() < GetMaxHP())[m
 								{[m
[36m@@ -2365,7 +2377,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 								}[m
 							}[m
 [m
[31m-							if (item->GetValue(4) != 0) // SP % È¸º¹[m
[32m+[m							[32mif (item->GetValue(4) != 0) // SP % È¸ï¿½ï¿½[m
 							{[m
 								if (GetSP() < GetMaxSP())[m
 								{[m
[36m@@ -2380,7 +2392,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 								if (item->GetVnum() == 50085 || item->GetVnum() == 50086)[m
 								{[m
 									if (test_server)[m
[31m-										ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¿ùº´ ¶Ç´Â Á¾ÀÚ ¸¦ »ç¿ëÇÏ¿´½À´Ï´Ù"));[m
[32m+[m										[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ ï¿½Ç´ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½Ï¿ï¿½ï¿½ï¿½ï¿½Ï´ï¿½"));[m
 									SetUseSeedOrMoonBottleTime();[m
 								}[m
 								if (GetDungeon())[m
[36m@@ -2407,7 +2419,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 				{[m
 					if (CArenaManager::instance().IsArenaMap(GetMapIndex()) == true)[m
 					{[m
[31m-						ChatPacket(CHAT_TYPE_INFO, LC_TEXT("´ë·Ã Áß¿¡´Â ÀÌ¿ëÇÒ ¼ö ¾ø´Â ¹°Ç°ÀÔ´Ï´Ù."));[m
[32m+[m						[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ ï¿½ß¿ï¿½ï¿½ï¿½ ï¿½Ì¿ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½Ç°ï¿½Ô´Ï´ï¿½."));[m
 						return false;[m
 					}[m
 				}[m
[36m@@ -2426,7 +2438,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 							{[m
 								return false;[m
 							}[m
[31m-							// ¿ì¼± ¿ëÈ¥¼®¿¡ °üÇØ¼­¸¸ ÇÏµµ·Ï ÇÑ´Ù.[m
[32m+[m							[32m// ï¿½ì¼± ï¿½ï¿½È¥ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Ø¼ï¿½ï¿½ï¿½ ï¿½Ïµï¿½ï¿½ï¿½ ï¿½Ñ´ï¿½.[m
 							if (pDestItem->IsDragonSoul())[m
 							{[m
 								int ret;[m
[36m@@ -2450,7 +2462,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 										sprintf(buf, "Inc %ds by item{VN:%d VAL%d:%d}", ret, item->GetVnum(), ITEM_VALUE_CHARGING_AMOUNT_IDX, item->GetValue(ITEM_VALUE_CHARGING_AMOUNT_IDX));[m
 									}[m
 [m
[31m-									ChatPacket(CHAT_TYPE_INFO, LC_TEXT("%dÃÊ ¸¸Å­ ÃæÀüµÇ¾ú½À´Ï´Ù."), ret);[m
[32m+[m									[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("%dï¿½ï¿½ ï¿½ï¿½Å­ ï¿½ï¿½ï¿½ï¿½ï¿½Ç¾ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."), ret);[m
 									item->SetCount(item->GetCount() - 1);[m
 									LogManager::instance().ItemLog(this, item, "DS_CHARGING_SUCCESS", buf);[m
 									return true;[m
[36m@@ -2466,7 +2478,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 										sprintf(buf, "No change by item{VN:%d VAL%d:%d}", item->GetVnum(), ITEM_VALUE_CHARGING_AMOUNT_IDX, item->GetValue(ITEM_VALUE_CHARGING_AMOUNT_IDX));[m
 									}[m
 [m
[31m-									ChatPacket(CHAT_TYPE_INFO, LC_TEXT("ÃæÀüÇÒ ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m									[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 									LogManager::instance().ItemLog(this, item, "DS_CHARGING_FAILED", buf);[m
 									return false;[m
 								}[m
[36m@@ -2482,14 +2494,14 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 							{[m
 								return false;[m
 							}[m
[31m-							// ¿ì¼± ¿ëÈ¥¼®¿¡ °üÇØ¼­¸¸ ÇÏµµ·Ï ÇÑ´Ù.[m
[32m+[m							[32m// ï¿½ì¼± ï¿½ï¿½È¥ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Ø¼ï¿½ï¿½ï¿½ ï¿½Ïµï¿½ï¿½ï¿½ ï¿½Ñ´ï¿½.[m
 							if (pDestItem->IsDragonSoul())[m
 							{[m
 								int ret = pDestItem->GiveMoreTime_Fix(item->GetValue(ITEM_VALUE_CHARGING_AMOUNT_IDX));[m
 								char buf[128];[m
 								if (ret)[m
 								{[m
[31m-									ChatPacket(CHAT_TYPE_INFO, LC_TEXT("%dÃÊ ¸¸Å­ ÃæÀüµÇ¾ú½À´Ï´Ù."), ret);[m
[32m+[m									[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("%dï¿½ï¿½ ï¿½ï¿½Å­ ï¿½ï¿½ï¿½ï¿½ï¿½Ç¾ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."), ret);[m
 									sprintf(buf, "Increase %ds by item{VN:%d VAL%d:%d}", ret, item->GetVnum(), ITEM_VALUE_CHARGING_AMOUNT_IDX, item->GetValue(ITEM_VALUE_CHARGING_AMOUNT_IDX));[m
 									LogManager::instance().ItemLog(this, item, "DS_CHARGING_SUCCESS", buf);[m
 									item->SetCount(item->GetCount() - 1);[m
[36m@@ -2497,7 +2509,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 								}[m
 								else[m
 								{[m
[31m-									ChatPacket(CHAT_TYPE_INFO, LC_TEXT("ÃæÀüÇÒ ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m									[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 									sprintf(buf, "No change by item{VN:%d VAL%d:%d}", item->GetVnum(), ITEM_VALUE_CHARGING_AMOUNT_IDX, item->GetValue(ITEM_VALUE_CHARGING_AMOUNT_IDX));[m
 									LogManager::instance().ItemLog(this, item, "DS_CHARGING_FAILED", buf);[m
 									return false;[m
[36m@@ -2511,20 +2523,20 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 						[m
 						switch (item->GetVnum())[m
 						{[m
[31m-							//Å©¸®½º¸¶½º ¶õÁÖ[m
[32m+[m							[32m//Å©ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½[m
 							case ITEM_NOG_POCKET:[m
 								{[m
 									/*[m
[31m-									¶õÁÖ´É·ÂÄ¡ : item_proto value ÀÇ¹Ì[m
[31m-										ÀÌµ¿¼Óµµ  value 1[m
[31m-										°ø°Ý·Â	  value 2[m
[31m-										°æÇèÄ¡    value 3[m
[31m-										Áö¼Ó½Ã°£  value 0 (´ÜÀ§ ÃÊ)[m
[32m+[m									[32mï¿½ï¿½ï¿½Ö´É·ï¿½Ä¡ : item_proto value ï¿½Ç¹ï¿½[m
[32m+[m										[32mï¿½Ìµï¿½ï¿½Óµï¿½  value 1[m
[32m+[m										[32mï¿½ï¿½ï¿½Ý·ï¿½	  value 2[m
[32m+[m										[32mï¿½ï¿½ï¿½ï¿½Ä¡    value 3[m
[32m+[m										[32mï¿½ï¿½ï¿½Ó½Ã°ï¿½  value 0 (ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½)[m
 [m
 									*/[m
 									if (FindAffect(AFFECT_NOG_ABILITY))[m
 									{[m
[31m-										ChatPacket(CHAT_TYPE_INFO, LC_TEXT("ÀÌ¹Ì È¿°ú°¡ °É·Á ÀÖ½À´Ï´Ù."));[m
[32m+[m										[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½Ì¹ï¿½ È¿ï¿½ï¿½ï¿½ï¿½ ï¿½É·ï¿½ ï¿½Ö½ï¿½ï¿½Ï´ï¿½."));[m
 										return false;[m
 									}[m
 									long time = item->GetValue(0);[m
[36m@@ -2538,15 +2550,15 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 								}[m
 								break;[m
 								[m
[31m-							//¶ó¸¶´Ü¿ë »çÅÁ[m
[32m+[m							[32m//ï¿½ó¸¶´Ü¿ï¿½ ï¿½ï¿½ï¿½ï¿½[m
 							case ITEM_RAMADAN_CANDY:[m
 								{[m
 									/*[m
[31m-									»çÅÁ´É·ÂÄ¡ : item_proto value ÀÇ¹Ì[m
[31m-										ÀÌµ¿¼Óµµ  value 1[m
[31m-										°ø°Ý·Â	  value 2[m
[31m-										°æÇèÄ¡    value 3[m
[31m-										Áö¼Ó½Ã°£  value 0 (´ÜÀ§ ÃÊ)[m
[32m+[m									[32mï¿½ï¿½ï¿½ï¿½ï¿½É·ï¿½Ä¡ : item_proto value ï¿½Ç¹ï¿½[m
[32m+[m										[32mï¿½Ìµï¿½ï¿½Óµï¿½  value 1[m
[32m+[m										[32mï¿½ï¿½ï¿½Ý·ï¿½	  value 2[m
[32m+[m										[32mï¿½ï¿½ï¿½ï¿½Ä¡    value 3[m
[32m+[m										[32mï¿½ï¿½ï¿½Ó½Ã°ï¿½  value 0 (ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½)[m
 [m
 									*/[m
 									long time = item->GetValue(0);[m
[36m@@ -2568,7 +2580,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 										{[m
 											if (CArenaManager::instance().IsArenaMap(pMarriage->ch1->GetMapIndex()) == true)[m
 											{[m
[31m-												ChatPacket(CHAT_TYPE_INFO, LC_TEXT("´ë·Ã Áß¿¡´Â ÀÌ¿ëÇÒ ¼ö ¾ø´Â ¹°Ç°ÀÔ´Ï´Ù."));[m
[32m+[m												[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ ï¿½ß¿ï¿½ï¿½ï¿½ ï¿½Ì¿ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½Ç°ï¿½Ô´Ï´ï¿½."));[m
 												break;[m
 											}[m
 										}[m
[36m@@ -2577,7 +2589,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 										{[m
 											if (CArenaManager::instance().IsArenaMap(pMarriage->ch2->GetMapIndex()) == true)[m
 											{[m
[31m-												ChatPacket(CHAT_TYPE_INFO, LC_TEXT("´ë·Ã Áß¿¡´Â ÀÌ¿ëÇÒ ¼ö ¾ø´Â ¹°Ç°ÀÔ´Ï´Ù."));[m
[32m+[m												[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ ï¿½ß¿ï¿½ï¿½ï¿½ ï¿½Ì¿ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½Ç°ï¿½Ô´Ï´ï¿½."));[m
 												break;[m
 											}[m
 										}[m
[36m@@ -2592,13 +2604,13 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 										WarpToPID(pMarriage->GetOther(GetPlayerID()));[m
 									}[m
 									else[m
[31m-										ChatPacket(CHAT_TYPE_INFO, LC_TEXT("°áÈ¥ »óÅÂ°¡ ¾Æ´Ï¸é °áÈ¥¹ÝÁö¸¦ »ç¿ëÇÒ ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m										[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½È¥ ï¿½ï¿½ï¿½Â°ï¿½ ï¿½Æ´Ï¸ï¿½ ï¿½ï¿½È¥ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 								}[m
 								break;[m
 [m
[31m-								//±âÁ¸ ¿ë±âÀÇ ¸ÁÅä[m
[32m+[m								[32m//ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½[m
 							case UNIQUE_ITEM_CAPE_OF_COURAGE:[m
[31m-								//¶ó¸¶´Ü º¸»ó¿ë ¿ë±âÀÇ ¸ÁÅä[m
[32m+[m								[32m//ï¿½ó¸¶´ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½[m
 							case 70057:[m
 							case REWARD_BOX_UNIQUE_ITEM_CAPE_OF_COURAGE:[m
 								AggregateMonster();[m
[36m@@ -2617,7 +2629,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 							case 30094:[m
 							case 30095:[m
 							case 30096:[m
[31m-								// º¹ÁÖ¸Ó´Ï[m
[32m+[m								[32m// ï¿½ï¿½ï¿½Ö¸Ó´ï¿½[m
 								{[m
 									const int MAX_BAG_INFO = 26;[m
 									static struct LuckyBagInfo[m
[36m@@ -2705,7 +2717,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 [m
 									if (bi[i].vnum == 50300)[m
 									{[m
[31m-										// ½ºÅ³¼ö·Ã¼­´Â Æ¯¼öÇÏ°Ô ÁØ´Ù.[m
[32m+[m										[32m// ï¿½ï¿½Å³ï¿½ï¿½ï¿½Ã¼ï¿½ï¿½ï¿½ Æ¯ï¿½ï¿½ï¿½Ï°ï¿½ ï¿½Ø´ï¿½.[m
 										GiveRandomSkillBook();[m
 									}[m
 									else if (bi[i].vnum == 1)[m
[36m@@ -2720,7 +2732,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 								}[m
 								break;[m
 [m
[31m-							case 50004: // ÀÌº¥Æ®¿ë °¨Áö±â[m
[32m+[m							[32mcase 50004: // ï¿½Ìºï¿½Æ®ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½[m
 								{[m
 									if (item->GetSocket(0))[m
 									{[m
[36m@@ -2728,7 +2740,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 									}[m
 									else[m
 									{[m
[31m-										// Ã³À½ »ç¿ë½Ã[m
[32m+[m										[32m// Ã³ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½[m
 										int iMapIndex = GetMapIndex();[m
 [m
 										PIXEL_POSITION pos;[m
[36m@@ -2741,7 +2753,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 										}[m
 										else[m
 										{[m
[31m-											ChatPacket(CHAT_TYPE_INFO, LC_TEXT("ÀÌ °÷¿¡¼± ÀÌº¥Æ®¿ë °¨Áö±â°¡ µ¿ÀÛÇÏÁö ¾Ê´Â°Í °°½À´Ï´Ù."));[m
[32m+[m											[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ìºï¿½Æ®ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½â°¡ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ê´Â°ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 											return false;[m
 										}[m
 									}[m
[36m@@ -2751,10 +2763,10 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 [m
 									if (distance < 1000.0f)[m
 									{[m
[31m-										// ¹ß°ß![m
[31m-										ChatPacket(CHAT_TYPE_INFO, LC_TEXT("ÀÌº¥Æ®¿ë °¨Áö±â°¡ ½Åºñ·Î¿î ºûÀ» ³»¸ç »ç¶óÁý´Ï´Ù."));[m
[32m+[m										[32m// ï¿½ß°ï¿½![m
[32m+[m										[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½Ìºï¿½Æ®ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½â°¡ ï¿½Åºï¿½Î¿ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 [m
[31m-										// »ç¿ëÈ½¼ö¿¡ µû¶ó ÁÖ´Â ¾ÆÀÌÅÛÀ» ´Ù¸£°Ô ÇÑ´Ù.[m
[32m+[m										[32m// ï¿½ï¿½ï¿½È½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½Ö´ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ù¸ï¿½ï¿½ï¿½ ï¿½Ñ´ï¿½.[m
 										struct TEventStoneInfo[m
 										{[m
 											DWORD dwVnum;[m
[36m@@ -2853,7 +2865,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 														pdw[0] = info[i].dwVnum;[m
 														pdw[1] = info[i].count;[m
 [m
[31m-														// ÃßÃ·¼­´Â ¼ÒÄÏÀ» ¼³Á¤ÇÑ´Ù[m
[32m+[m														[32m// ï¿½ï¿½Ã·ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ñ´ï¿½[m
 														DBManager::instance().ReturnQuery(QID_LOTTO, GetPlayerID(), pdw,[m
 																"INSERT INTO lotto_list VALUES(0, 'server%s', %u, NOW())", [m
 																get_table_postfix(), GetPlayerID());[m
[36m@@ -2873,7 +2885,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 										if (len < 0 || len >= (int) sizeof(chatbuf))[m
 											len = sizeof(chatbuf) - 1;[m
 [m
[31m-										++len;  // \0 ¹®ÀÚ±îÁö º¸³»±â[m
[32m+[m										[32m++len;  // \0 ï¿½ï¿½ï¿½Ú±ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½[m
 [m
 										TPacketGCChat pack_chat;[m
 										pack_chat.header	= HEADER_GC_CHAT;[m
[36m@@ -2899,11 +2911,11 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 									else[m
 										dist = 3;[m
 [m
[31m-									// ¸¹ÀÌ »ç¿ëÇßÀ¸¸é »ç¶óÁø´Ù.[m
[32m+[m									[32m// ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½.[m
 									const int STONE_DETECT_MAX_TRY = 10;[m
 									if (item->GetSocket(0) >= STONE_DETECT_MAX_TRY)[m
 									{[m
[31m-										ChatPacket(CHAT_TYPE_INFO, LC_TEXT("ÀÌº¥Æ®¿ë °¨Áö±â°¡ ÈçÀûµµ ¾øÀÌ »ç¶óÁý´Ï´Ù."));[m
[32m+[m										[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½Ìºï¿½Æ®ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½â°¡ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 										ITEM_MANAGER::instance().RemoveItem(item, "REMOVE (DETECT_EVENT_STONE) 0");[m
 										AutoGiveItem(27002);[m
 										return true;[m
[36m@@ -2919,7 +2931,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 										if (len < 0 || len >= (int) sizeof(chatbuf))[m
 											len = sizeof(chatbuf) - 1;[m
 [m
[31m-										++len;  // \0 ¹®ÀÚ±îÁö º¸³»±â[m
[32m+[m										[32m++len;  // \0 ï¿½ï¿½ï¿½Ú±ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½[m
 [m
 										TPacketGCChat pack_chat;[m
 										pack_chat.header	= HEADER_GC_CHAT;[m
[36m@@ -2939,8 +2951,8 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 								}[m
 								break;[m
 [m
[31m-							case 27989: // ¿µ¼®°¨Áö±â[m
[31m-							case 76006: // ¼±¹°¿ë ¿µ¼®°¨Áö±â[m
[32m+[m							[32mcase 27989: // ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½[m
[32m+[m							[32mcase 76006: // ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½[m
 								{[m
 									LPSECTREE_MAP pMap = SECTREE_MANAGER::instance().GetMap(GetMapIndex());[m
 [m
[36m@@ -2984,12 +2996,12 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 											}[m
 											else[m
 											{[m
[31m-												ChatPacket(CHAT_TYPE_INFO, LC_TEXT("°¨Áö±â¸¦ ÀÛ¿ëÇÏ¿´À¸³ª °¨ÁöµÇ´Â ¿µ¼®ÀÌ ¾ø½À´Ï´Ù."));[m
[32m+[m												[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½â¸¦ ï¿½Û¿ï¿½ï¿½Ï¿ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ç´ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 											}[m
 										}[m
 										else[m
 										{[m
[31m-											ChatPacket(CHAT_TYPE_INFO, LC_TEXT("°¨Áö±â¸¦ ÀÛ¿ëÇÏ¿´À¸³ª °¨ÁöµÇ´Â ¿µ¼®ÀÌ ¾ø½À´Ï´Ù."));[m
[32m+[m											[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½â¸¦ ï¿½Û¿ï¿½ï¿½Ï¿ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ç´ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 										}[m
 [m
 										if (item->GetSocket(0) >= 6)[m
[36m@@ -3002,13 +3014,13 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 								}[m
 								break;[m
 [m
[31m-							case 27996: // µ¶º´[m
[32m+[m							[32mcase 27996: // ï¿½ï¿½ï¿½ï¿½[m
 								item->SetCount(item->GetCount() - 1);[m
 								/*if (GetSkillLevel(SKILL_CREATE_POISON))[m
 								  AddAffect(AFFECT_ATT_GRADE, POINT_ATT_GRADE, 3, AFF_DRINK_POISON, 15*60, 0, true);[m
 								  else[m
 								  {[m
[31m-								// µ¶´Ù·ç±â°¡ ¾øÀ¸¸é 50% Áï»ç 50% °ø°Ý·Â +2[m
[32m+[m								[32m// ï¿½ï¿½ï¿½Ù·ï¿½â°¡ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ 50% ï¿½ï¿½ï¿½ 50% ï¿½ï¿½ï¿½Ý·ï¿½ +2[m
 								if (number(0, 1))[m
 								{[m
 								if (GetHP() > 100)[m
[36m@@ -3021,12 +3033,12 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 								}*/[m
 								break;[m
 [m
[31m-							case 27987: // Á¶°³[m
[31m-								// 50  µ¹Á¶°¢ 47990[m
[31m-								// 30  ²Î[m
[31m-								// 10  ¹éÁøÁÖ 47992[m
[31m-								// 7   Ã»ÁøÁÖ 47993[m
[31m-								// 3   ÇÇÁøÁÖ 47994[m
[32m+[m							[32mcase 27987: // ï¿½ï¿½ï¿½ï¿½[m
[32m+[m								[32m// 50  ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ 47990[m
[32m+[m								[32m// 30  ï¿½ï¿½[m
[32m+[m								[32m// 10  ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ 47992[m
[32m+[m								[32m// 7   Ã»ï¿½ï¿½ï¿½ï¿½ 47993[m
[32m+[m								[32m// 3   ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ 47994[m
 								{[m
 									item->SetCount(item->GetCount() - 1);[m
 [m
[36m@@ -3034,7 +3046,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 [m
 									if (r <= 50)[m
 									{[m
[31m-										ChatPacket(CHAT_TYPE_INFO, LC_TEXT("Á¶°³¿¡¼­ µ¹Á¶°¢ÀÌ ³ª¿Ô½À´Ï´Ù."));[m
[32m+[m										[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Ô½ï¿½ï¿½Ï´ï¿½."));[m
 										AutoGiveItem(27990);[m
 									}[m
 									else[m
[36m@@ -3053,33 +3065,33 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 [m
 										if (r <= prob_table[0])[m
 										{[m
[31m-											ChatPacket(CHAT_TYPE_INFO, LC_TEXT("Á¶°³°¡ ÈçÀûµµ ¾øÀÌ »ç¶óÁý´Ï´Ù."));[m
[32m+[m											[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 										}[m
 										else if (r <= prob_table[1])[m
 										{[m
[31m-											ChatPacket(CHAT_TYPE_INFO, LC_TEXT("Á¶°³¿¡¼­ ¹éÁøÁÖ°¡ ³ª¿Ô½À´Ï´Ù."));[m
[32m+[m											[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ö°ï¿½ ï¿½ï¿½ï¿½Ô½ï¿½ï¿½Ï´ï¿½."));[m
 											AutoGiveItem(27992);[m
 										}[m
 										else if (r <= prob_table[2])[m
 										{[m
[31m-											ChatPacket(CHAT_TYPE_INFO, LC_TEXT("Á¶°³¿¡¼­ Ã»ÁøÁÖ°¡ ³ª¿Ô½À´Ï´Ù."));[m
[32m+[m											[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ Ã»ï¿½ï¿½ï¿½Ö°ï¿½ ï¿½ï¿½ï¿½Ô½ï¿½ï¿½Ï´ï¿½."));[m
 											AutoGiveItem(27993);[m
 										}[m
 										else[m
 										{[m
[31m-											ChatPacket(CHAT_TYPE_INFO, LC_TEXT("Á¶°³¿¡¼­ ÇÇÁøÁÖ°¡ ³ª¿Ô½À´Ï´Ù."));[m
[32m+[m											[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ö°ï¿½ ï¿½ï¿½ï¿½Ô½ï¿½ï¿½Ï´ï¿½."));[m
 											AutoGiveItem(27994);[m
 										}[m
 									}[m
 								}[m
 								break;[m
 [m
[31m-							case 71013: // ÃàÁ¦¿ëÆøÁ×[m
[32m+[m							[32mcase 71013: // ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½[m
 								CreateFly(number(FLY_FIREWORK1, FLY_FIREWORK6), this);[m
 								item->SetCount(item->GetCount() - 1);[m
 								break;[m
 [m
[31m-							case 50100: // ÆøÁ×[m
[32m+[m							[32mcase 50100: // ï¿½ï¿½ï¿½ï¿½[m
 							case 50101:[m
 							case 50102:[m
 							case 50103:[m
[36m@@ -3090,7 +3102,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 								item->SetCount(item->GetCount() - 1);[m
 								break;[m
 [m
[31m-							case 50200: // º¸µû¸®[m
[32m+[m							[32mcase 50200: // ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½[m
 								if (LC_IsYMIR() == true || LC_IsKorea() == true)[m
 								{[m
 									if (IS_BOTARYABLE_ZONE(GetMapIndex()) == true)[m
[36m@@ -3099,7 +3111,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 									}[m
 									else[m
 									{[m
[31m-										ChatPacket(CHAT_TYPE_INFO, LC_TEXT("°³ÀÎ »óÁ¡À» ¿­ ¼ö ¾ø´Â Áö¿ªÀÔ´Ï´Ù"));[m
[32m+[m										[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ô´Ï´ï¿½"));[m
 									}[m
 								}[m
 								else[m
[36m@@ -3113,13 +3125,13 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 								item->SetCount(item->GetCount() - 1);[m
 								break;[m
 [m
[31m-							case 50301: // Åë¼Ö·Â ¼ö·Ã¼­[m
[32m+[m							[32mcase 50301: // ï¿½ï¿½Ö·ï¿½ ï¿½ï¿½ï¿½Ã¼ï¿½[m
 							case 50302:[m
 							case 50303:[m
 								{[m
 									if (IsPolymorphed() == true)[m
 									{[m
[31m-										ChatPacket(CHAT_TYPE_INFO, LC_TEXT("µÐ°© Áß¿¡´Â ´É·ÂÀ» ¿Ã¸± ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m										[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½Ð°ï¿½ ï¿½ß¿ï¿½ï¿½ï¿½ ï¿½É·ï¿½ï¿½ï¿½ ï¿½Ã¸ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 										return false;[m
 									}[m
 [m
[36m@@ -3127,13 +3139,13 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 [m
 									if (lv < item->GetValue(0))[m
 									{[m
[31m-										ChatPacket(CHAT_TYPE_INFO, LC_TEXT("ÀÌ Ã¥Àº ³Ê¹« ¾î·Á¿ö ÀÌÇØÇÏ±â°¡ Èûµì´Ï´Ù."));[m
[32m+[m										[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ Ã¥ï¿½ï¿½ ï¿½Ê¹ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï±â°¡ ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 										return false;[m
 									}[m
 [m
 									if (lv >= item->GetValue(1))[m
 									{[m
[31m-										ChatPacket(CHAT_TYPE_INFO, LC_TEXT("ÀÌ Ã¥Àº ¾Æ¹«¸® ºÁµµ µµ¿òÀÌ µÉ °Í °°Áö ¾Ê½À´Ï´Ù."));[m
[32m+[m										[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ Ã¥ï¿½ï¿½ ï¿½Æ¹ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½Ê½ï¿½ï¿½Ï´ï¿½."));[m
 										return false;[m
 									}[m
 [m
[36m@@ -3149,31 +3161,31 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 								}[m
 								break;[m
 [m
[31m-							case 50304: // ¿¬°è±â ¼ö·Ã¼­[m
[32m+[m							[32mcase 50304: // ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Ã¼ï¿½[m
 							case 50305:[m
 							case 50306:[m
 								{[m
 									if (IsPolymorphed())[m
 									{[m
[31m-										ChatPacket(CHAT_TYPE_INFO, LC_TEXT("º¯½ÅÁß¿¡´Â Ã¥À» ÀÐÀ»¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m										[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½ß¿ï¿½ï¿½ï¿½ Ã¥ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 										return false;[m
 										[m
 									}[m
 									if (GetSkillLevel(SKILL_COMBO) == 0 && GetLevel() < 30)[m
 									{[m
[31m-										ChatPacket(CHAT_TYPE_INFO, LC_TEXT("·¹º§ 30ÀÌ µÇ±â Àü¿¡´Â ½ÀµæÇÒ ¼ö ÀÖÀ» °Í °°Áö ¾Ê½À´Ï´Ù."));[m
[32m+[m										[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ 30ï¿½ï¿½ ï¿½Ç±ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½Ê½ï¿½ï¿½Ï´ï¿½."));[m
 										return false;[m
 									}[m
 [m
 									if (GetSkillLevel(SKILL_COMBO) == 1 && GetLevel() < 50)[m
 									{[m
[31m-										ChatPacket(CHAT_TYPE_INFO, LC_TEXT("·¹º§ 50ÀÌ µÇ±â Àü¿¡´Â ½ÀµæÇÒ ¼ö ÀÖÀ» °Í °°Áö ¾Ê½À´Ï´Ù."));[m
[32m+[m										[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ 50ï¿½ï¿½ ï¿½Ç±ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½Ê½ï¿½ï¿½Ï´ï¿½."));[m
 										return false;[m
 									}[m
 [m
 									if (GetSkillLevel(SKILL_COMBO) >= 2)[m
 									{[m
[31m-										ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¿¬°è±â´Â ´õÀÌ»ó ¼ö·ÃÇÒ ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m										[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Ì»ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 										return false;[m
 									}[m
 [m
[36m@@ -3190,13 +3202,13 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 									}[m
 								}[m
 								break;[m
[31m-							case 50311: // ¾ð¾î ¼ö·Ã¼­[m
[32m+[m							[32mcase 50311: // ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Ã¼ï¿½[m
 							case 50312:[m
 							case 50313:[m
 								{[m
 									if (IsPolymorphed())[m
 									{[m
[31m-										ChatPacket(CHAT_TYPE_INFO, LC_TEXT("º¯½ÅÁß¿¡´Â Ã¥À» ÀÐÀ»¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m										[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½ß¿ï¿½ï¿½ï¿½ Ã¥ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 										return false;[m
 										[m
 									}[m
[36m@@ -3204,7 +3216,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 									int iPct = MINMAX(0, item->GetValue(1), 100);[m
 									if (GetSkillLevel(dwSkillVnum)>=20 || dwSkillVnum-SKILL_LANGUAGE1+1 == GetEmpire())[m
 									{[m
[31m-										ChatPacket(CHAT_TYPE_INFO, LC_TEXT("ÀÌ¹Ì ¿Ïº®ÇÏ°Ô ¾Ë¾ÆµéÀ» ¼ö ÀÖ´Â ¾ð¾îÀÌ´Ù."));[m
[32m+[m										[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½Ì¹ï¿½ ï¿½Ïºï¿½ï¿½Ï°ï¿½ ï¿½Ë¾Æµï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½Ö´ï¿½ ï¿½ï¿½ï¿½ï¿½Ì´ï¿½."));[m
 										return false;[m
 									}[m
 [m
[36m@@ -3220,11 +3232,11 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 								}[m
 								break;[m
 [m
[31m-							case 50061 : // ÀÏº» ¸» ¼ÒÈ¯ ½ºÅ³ ¼ö·Ã¼­[m
[32m+[m							[32mcase 50061 : // ï¿½Ïºï¿½ ï¿½ï¿½ ï¿½ï¿½È¯ ï¿½ï¿½Å³ ï¿½ï¿½ï¿½Ã¼ï¿½[m
 								{[m
 									if (IsPolymorphed())[m
 									{[m
[31m-										ChatPacket(CHAT_TYPE_INFO, LC_TEXT("º¯½ÅÁß¿¡´Â Ã¥À» ÀÐÀ»¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m										[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½ß¿ï¿½ï¿½ï¿½ Ã¥ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 										return false;[m
 										[m
 									}[m
[36m@@ -3233,7 +3245,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 [m
 									if (GetSkillLevel(dwSkillVnum) >= 10)[m
 									{[m
[31m-										ChatPacket(CHAT_TYPE_INFO, LC_TEXT("´õ ÀÌ»ó ¼ö·ÃÇÒ ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m										[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ ï¿½Ì»ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 										return false;[m
 									}[m
 [m
[36m@@ -3249,13 +3261,13 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 								}[m
 								break;[m
 [m
[31m-							case 50314: case 50315: case 50316: // º¯½Å ¼ö·Ã¼­[m
[31m-							case 50323: case 50324: // ÁõÇ÷ ¼ö·Ã¼­[m
[31m-							case 50325: case 50326: // Ã¶Åë ¼ö·Ã¼­[m
[32m+[m							[32mcase 50314: case 50315: case 50316: // ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Ã¼ï¿½[m
[32m+[m							[32mcase 50323: case 50324: // ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Ã¼ï¿½[m
[32m+[m							[32mcase 50325: case 50326: // Ã¶ï¿½ï¿½ ï¿½ï¿½ï¿½Ã¼ï¿½[m
 								{[m
 									if (IsPolymorphed() == true)[m
 									{[m
[31m-										ChatPacket(CHAT_TYPE_INFO, LC_TEXT("µÐ°© Áß¿¡´Â ´É·ÂÀ» ¿Ã¸± ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m										[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½Ð°ï¿½ ï¿½ß¿ï¿½ï¿½ï¿½ ï¿½É·ï¿½ï¿½ï¿½ ï¿½Ã¸ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 										return false;[m
 									}[m
 									[m
[36m@@ -3288,25 +3300,25 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 [m
 									if (GetLevel() < iLevelLimit)[m
 									{[m
[31m-										ChatPacket(CHAT_TYPE_INFO, LC_TEXT("ÀÌ Ã¥À» ÀÐÀ¸·Á¸é ·¹º§À» ´õ ¿Ã·Á¾ß ÇÕ´Ï´Ù."));[m
[32m+[m										[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ Ã¥ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½Ã·ï¿½ï¿½ï¿½ ï¿½Õ´Ï´ï¿½."));[m
 										return false;[m
 									}[m
 [m
 									if (GetSkillLevel(dwSkillVnum) >= 40)[m
 									{[m
[31m-										ChatPacket(CHAT_TYPE_INFO, LC_TEXT("´õ ÀÌ»ó ¼ö·ÃÇÒ ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m										[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ ï¿½Ì»ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 										return false;[m
 									}[m
 [m
 									if (GetSkillLevel(dwSkillVnum) < iSkillLevelLowLimit)[m
 									{[m
[31m-										ChatPacket(CHAT_TYPE_INFO, LC_TEXT("ÀÌ Ã¥Àº ³Ê¹« ¾î·Á¿ö ÀÌÇØÇÏ±â°¡ Èûµì´Ï´Ù."));[m
[32m+[m										[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ Ã¥ï¿½ï¿½ ï¿½Ê¹ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï±â°¡ ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 										return false;[m
 									}[m
 [m
 									if (GetSkillLevel(dwSkillVnum) >= iSkillLevelHighLimit)[m
 									{[m
[31m-										ChatPacket(CHAT_TYPE_INFO, LC_TEXT("ÀÌ Ã¥À¸·Î´Â ´õ ÀÌ»ó ¼ö·ÃÇÒ ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m										[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ Ã¥ï¿½ï¿½ï¿½Î´ï¿½ ï¿½ï¿½ ï¿½Ì»ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 										return false;[m
 									}[m
 [m
[36m@@ -3328,7 +3340,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 								{[m
 									if (IsPolymorphed())[m
 									{[m
[31m-										ChatPacket(CHAT_TYPE_INFO, LC_TEXT("º¯½ÅÁß¿¡´Â Ã¥À» ÀÐÀ»¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m										[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½ß¿ï¿½ï¿½ï¿½ Ã¥ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 										return false;[m
 										[m
 									}[m
[36m@@ -3337,7 +3349,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 [m
 									if (GetSkillLevel(dwSkillVnum)>=40)[m
 									{[m
[31m-										ChatPacket(CHAT_TYPE_INFO, LC_TEXT("´õ ÀÌ»ó ¼ö·ÃÇÒ ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m										[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ ï¿½Ì»ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 										return false;[m
 									}[m
 [m
[36m@@ -3370,7 +3382,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 								{[m
 									if (IsPolymorphed())[m
 									{[m
[31m-										ChatPacket(CHAT_TYPE_INFO, LC_TEXT("º¯½ÅÁß¿¡´Â Ã¥À» ÀÐÀ»¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m										[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½ß¿ï¿½ï¿½ï¿½ Ã¥ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 										return false;[m
 										[m
 									}[m
[36m@@ -3379,7 +3391,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 [m
 									if (GetSkillLevel(dwSkillVnum)>=40)[m
 									{[m
[31m-										ChatPacket(CHAT_TYPE_INFO, LC_TEXT("´õ ÀÌ»ó ¼ö·ÃÇÒ ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m										[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ ï¿½Ì»ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 										return false;[m
 									}[m
 [m
[36m@@ -3400,7 +3412,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 								{[m
 									if (IsPolymorphed())[m
 									{[m
[31m-										ChatPacket(CHAT_TYPE_INFO, LC_TEXT("º¯½ÅÁß¿¡´Â Ã¥À» ÀÐÀ»¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m										[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½ß¿ï¿½ï¿½ï¿½ Ã¥ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 										return false;[m
 										[m
 									}[m
[36m@@ -3409,7 +3421,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 [m
 									if (GetLevel() < 50)[m
 									{[m
[31m-										ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¾ÆÁ÷ ½Â¸¶ ½ºÅ³À» ¼ö·ÃÇÒ ¼ö ÀÖ´Â ·¹º§ÀÌ ¾Æ´Õ´Ï´Ù."));[m
[32m+[m										[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ ï¿½Â¸ï¿½ ï¿½ï¿½Å³ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½Ö´ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Æ´Õ´Ï´ï¿½."));[m
 										return false;[m
 									}[m
 [m
[36m@@ -3417,9 +3429,9 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 									{[m
 										if (FindAffect(AFFECT_SKILL_NO_BOOK_DELAY))[m
 										{[m
[31m-											// ÁÖ¾È¼ú¼­ »ç¿ëÁß¿¡´Â ½Ã°£ Á¦ÇÑ ¹«½Ã[m
[32m+[m											[32m// ï¿½Ö¾È¼ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ß¿ï¿½ï¿½ï¿½ ï¿½Ã°ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½[m
 											RemoveAffect(AFFECT_SKILL_NO_BOOK_DELAY);[m
[31m-											ChatPacket(CHAT_TYPE_INFO, LC_TEXT("ÁÖ¾È¼ú¼­¸¦ ÅëÇØ ÁÖÈ­ÀÔ¸¶¿¡¼­ ºüÁ®³ª¿Ô½À´Ï´Ù."));[m
[32m+[m											[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½Ö¾È¼ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½È­ï¿½Ô¸ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½Ô½ï¿½ï¿½Ï´ï¿½."));[m
 										}[m
 										else[m
 										{[m
[36m@@ -3432,14 +3444,14 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 											GetSkillLevel(SKILL_HORSE_WILDATTACK) + GetSkillLevel(SKILL_HORSE_CHARGE) + GetSkillLevel(SKILL_HORSE_ESCAPE) >= 60 ||[m
 											GetSkillLevel(SKILL_HORSE_WILDATTACK_RANGE) + GetSkillLevel(SKILL_HORSE_CHARGE) + GetSkillLevel(SKILL_HORSE_ESCAPE) >= 60)[m
 									{[m
[31m-										ChatPacket(CHAT_TYPE_INFO, LC_TEXT("´õ ÀÌ»ó ½Â¸¶ ¼ö·Ã¼­¸¦ ÀÐÀ» ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m										[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ ï¿½Ì»ï¿½ ï¿½Â¸ï¿½ ï¿½ï¿½ï¿½Ã¼ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 										return false;[m
 									}[m
 [m
 									if (number(1, 100) <= iPct)[m
 									{[m
[31m-										ChatPacket(CHAT_TYPE_INFO, LC_TEXT("½Â¸¶ ¼ö·Ã¼­¸¦ ÀÐ¾î ½Â¸¶ ½ºÅ³ Æ÷ÀÎÆ®¸¦ ¾ò¾ú½À´Ï´Ù."));[m
[31m-										ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¾òÀº Æ÷ÀÎÆ®·Î´Â ½Â¸¶ ½ºÅ³ÀÇ ·¹º§À» ¿Ã¸± ¼ö ÀÖ½À´Ï´Ù."));[m
[32m+[m										[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½Â¸ï¿½ ï¿½ï¿½ï¿½Ã¼ï¿½ï¿½ï¿½ ï¿½Ð¾ï¿½ ï¿½Â¸ï¿½ ï¿½ï¿½Å³ ï¿½ï¿½ï¿½ï¿½Æ®ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
[32m+[m										[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½Æ®ï¿½Î´ï¿½ ï¿½Â¸ï¿½ ï¿½ï¿½Å³ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ã¸ï¿½ ï¿½ï¿½ ï¿½Ö½ï¿½ï¿½Ï´ï¿½."));[m
 										PointChange(POINT_HORSE_SKILL, 1);[m
 [m
 										int iReadDelay = number(SKILLBOOK_DELAY_MIN, SKILLBOOK_DELAY_MAX);[m
[36m@@ -3450,15 +3462,15 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 									}[m
 									else[m
 									{[m
[31m-										ChatPacket(CHAT_TYPE_INFO, LC_TEXT("½Â¸¶ ¼ö·Ã¼­ ÀÌÇØ¿¡ ½ÇÆÐÇÏ¿´½À´Ï´Ù."));[m
[32m+[m										[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½Â¸ï¿½ ï¿½ï¿½ï¿½Ã¼ï¿½ ï¿½ï¿½ï¿½Ø¿ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï¿ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 									}[m
 [m
 									ITEM_MANAGER::instance().RemoveItem(item);[m
 								}[m
 								break;[m
 [m
[31m-							case 70102: // ¼±µÎ[m
[31m-							case 70103: // ¼±µÎ[m
[32m+[m							[32mcase 70102: // ï¿½ï¿½ï¿½ï¿½[m
[32m+[m							[32mcase 70103: // ï¿½ï¿½ï¿½ï¿½[m
 								{[m
 									if (GetAlignment() >= 0)[m
 										return false;[m
[36m@@ -3472,13 +3484,13 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 [m
 									if (delta / 10 > 0)[m
 									{[m
[31m-										ChatPacket(CHAT_TYPE_TALKING, LC_TEXT("¸¶À½ÀÌ ¸¼¾ÆÁö´Â±º. °¡½¿À» Áþ´©¸£´ø ¹«¾ð°¡°¡ Á» °¡º­¿öÁø ´À³¦ÀÌ¾ß."));[m
[31m-										ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¼±¾ÇÄ¡°¡ %d Áõ°¡ÇÏ¿´½À´Ï´Ù."), delta/10);[m
[32m+[m										[32mChatPacket(CHAT_TYPE_TALKING, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½Â±ï¿½. ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ð°¡°ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ì¾ï¿½."));[m
[32m+[m										[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½Ä¡ï¿½ï¿½ %d ï¿½ï¿½ï¿½ï¿½ï¿½Ï¿ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."), delta/10);[m
 									}[m
 								}[m
 								break;[m
 [m
[31m-							case 71107: // Ãµµµº¹¼þ¾Æ[m
[32m+[m							[32mcase 71107: // Ãµï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½[m
 								{[m
 									int val = item->GetValue(0);[m
 									int interval = item->GetValue(1);[m
[36m@@ -3489,18 +3501,18 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 									{[m
 										if (test_server == false)[m
 										{[m
[31m-											ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¾ÆÁ÷ »ç¿ëÇÒ ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m											[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 											return false;[m
 										}[m
 										else[m
 										{[m
[31m-											ChatPacket(CHAT_TYPE_INFO, LC_TEXT("Å×½ºÆ® ¼­¹ö ½Ã°£Á¦ÇÑ Åë°ú"));[m
[32m+[m											[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½×½ï¿½Æ® ï¿½ï¿½ï¿½ï¿½ ï¿½Ã°ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½"));[m
 										}[m
 									}[m
 									[m
 									if (GetAlignment() == 200000)[m
 									{[m
[31m-										ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¼±¾ÇÄ¡¸¦ ´õ ÀÌ»ó ¿Ã¸± ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m										[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½Ä¡ï¿½ï¿½ ï¿½ï¿½ ï¿½Ì»ï¿½ ï¿½Ã¸ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 										return false;[m
 									}[m
 									[m
[36m@@ -3516,8 +3528,8 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 									item->SetCount(item->GetCount()-1);[m
 									pPC->SetFlag("mythical_peach.last_use_time", get_global_time());[m
 [m
[31m-									ChatPacket(CHAT_TYPE_TALKING, LC_TEXT("¸¶À½ÀÌ ¸¼¾ÆÁö´Â±º. °¡½¿À» Áþ´©¸£´ø ¹«¾ð°¡°¡ Á» °¡º­¿öÁø ´À³¦ÀÌ¾ß."));[m
[31m-									ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¼±¾ÇÄ¡°¡ %d Áõ°¡ÇÏ¿´½À´Ï´Ù."), val);[m
[32m+[m									[32mChatPacket(CHAT_TYPE_TALKING, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½Â±ï¿½. ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ð°¡°ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ì¾ï¿½."));[m
[32m+[m									[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½Ä¡ï¿½ï¿½ %d ï¿½ï¿½ï¿½ï¿½ï¿½Ï¿ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."), val);[m
 [m
 									char buf[256 + 1];[m
 									snprintf(buf, sizeof(buf), "%d %d", old_alignment, GetAlignment() / 10);[m
[36m@@ -3525,7 +3537,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 								}[m
 								break;[m
 [m
[31m-							case 71109: // Å»¼®¼­[m
[32m+[m							[32mcase 71109: // Å»ï¿½ï¿½ï¿½ï¿½[m
 							case 72719:[m
 								{[m
 									LPITEM item2;[m
[36m@@ -3549,7 +3561,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 											case ARMOR_EAR:[m
 											case ARMOR_WRIST:[m
 											case ARMOR_NECK:[m
[31m-												ChatPacket(CHAT_TYPE_INFO, LC_TEXT("»©³¾ ¿µ¼®ÀÌ ¾ø½À´Ï´Ù"));[m
[32m+[m												[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½"));[m
 												return false;[m
 											}[m
 											break;[m
[36m@@ -3576,7 +3588,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 [m
 									if (socket.size() == 0)[m
 									{[m
[31m-										ChatPacket(CHAT_TYPE_INFO, LC_TEXT("»©³¾ ¿µ¼®ÀÌ ¾ø½À´Ï´Ù"));[m
[32m+[m										[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½"));[m
 										return false;[m
 									}[m
 [m
[36m@@ -3596,17 +3608,17 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 								}[m
 								break;[m
 [m
[31m-							case 70201:   // Å»»öÁ¦[m
[31m-							case 70202:   // ¿°»ö¾à(Èò»ö)[m
[31m-							case 70203:   // ¿°»ö¾à(±Ý»ö)[m
[31m-							case 70204:   // ¿°»ö¾à(»¡°£»ö)[m
[31m-							case 70205:   // ¿°»ö¾à(°¥»ö)[m
[31m-							case 70206:   // ¿°»ö¾à(°ËÀº»ö)[m
[32m+[m							[32mcase 70201:   // Å»ï¿½ï¿½ï¿½ï¿½[m
[32m+[m							[32mcase 70202:   // ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½(ï¿½ï¿½ï¿½)[m
[32m+[m							[32mcase 70203:   // ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½(ï¿½Ý»ï¿½)[m
[32m+[m							[32mcase 70204:   // ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½(ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½)[m
[32m+[m							[32mcase 70205:   // ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½(ï¿½ï¿½ï¿½ï¿½)[m
[32m+[m							[32mcase 70206:   // ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½(ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½)[m
 								{[m
 									// NEW_HAIR_STYLE_ADD[m
 									if (GetPart(PART_HAIR) >= 1001)[m
 									{[m
[31m-										ChatPacket(CHAT_TYPE_INFO, LC_TEXT("ÇöÀç Çì¾î½ºÅ¸ÀÏ¿¡¼­´Â ¿°»ö°ú Å»»öÀÌ ºÒ°¡´ÉÇÕ´Ï´Ù."));[m
[32m+[m										[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½î½ºÅ¸ï¿½Ï¿ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ Å»ï¿½ï¿½ï¿½ï¿½ ï¿½Ò°ï¿½ï¿½ï¿½ï¿½Õ´Ï´ï¿½."));[m
 									}[m
 									// END_NEW_HAIR_STYLE_ADD[m
 									else[m
[36m@@ -3634,7 +3646,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 											}[m
 											else[m
 											{[m
[31m-												ChatPacket(CHAT_TYPE_INFO, LC_TEXT("%d ·¹º§ÀÌ µÇ¾î¾ß ´Ù½Ã ¿°»öÇÏ½Ç ¼ö ÀÖ½À´Ï´Ù."), last_dye_level+3);[m
[32m+[m												[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("%d ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ç¾ï¿½ï¿½ ï¿½Ù½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï½ï¿½ ï¿½ï¿½ ï¿½Ö½ï¿½ï¿½Ï´ï¿½."), last_dye_level+3);[m
 											}[m
 										}[m
 									}[m
[36m@@ -3654,7 +3666,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 										for (int i = 0; i < count; i++)[m
 										{[m
 											if (dwVnums[i] == CSpecialItemGroup::GOLD)[m
[31m-												ChatPacket(CHAT_TYPE_INFO, LC_TEXT("µ· %d ³ÉÀ» È¹µæÇß½À´Ï´Ù."), dwCounts[i]);[m
[32m+[m												[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ %d ï¿½ï¿½ï¿½ï¿½ È¹ï¿½ï¿½ï¿½ß½ï¿½ï¿½Ï´ï¿½."), dwCounts[i]);[m
 										}[m
 [m
 										item->SetCount(item->GetCount() - 1);[m
[36m@@ -3675,8 +3687,8 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 									if (item->GetVnum() == ITEM_VALENTINE_ROSE && SEX_MALE==GET_SEX(this) ||[m
 										item->GetVnum() == ITEM_VALENTINE_CHOCOLATE && SEX_FEMALE==GET_SEX(this))[m
 									{[m
[31m-										// ¼ºº°ÀÌ ¸ÂÁö¾Ê¾Æ ¾µ ¼ö ¾ø´Ù.[m
[31m-										ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¼ºº°ÀÌ ¸ÂÁö¾Ê¾Æ ÀÌ ¾ÆÀÌÅÛÀ» ¿­ ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m										[32m// ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ê¾ï¿½ ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½.[m
[32m+[m										[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ê¾ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 										return false;[m
 									}[m
 [m
[36m@@ -3699,8 +3711,8 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 									if (item->GetVnum() == ITEM_WHITEDAY_CANDY && SEX_MALE==GET_SEX(this) ||[m
 										item->GetVnum() == ITEM_WHITEDAY_ROSE && SEX_FEMALE==GET_SEX(this))[m
 									{[m
[31m-										// ¼ºº°ÀÌ ¸ÂÁö¾Ê¾Æ ¾µ ¼ö ¾ø´Ù.[m
[31m-										ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¼ºº°ÀÌ ¸ÂÁö¾Ê¾Æ ÀÌ ¾ÆÀÌÅÛÀ» ¿­ ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m										[32m// ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ê¾ï¿½ ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½.[m
[32m+[m										[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ê¾ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 										return false;[m
 									}[m
 [m
[36m@@ -3710,7 +3722,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 								}[m
 								break;[m
 [m
[31m-							case 50011: // ¿ù±¤º¸ÇÕ[m
[32m+[m							[32mcase 50011: // ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½[m
 								{[m
 									DWORD dwBoxVnum = 50011;[m
 									std::vector <DWORD> dwVnums;[m
[36m@@ -3732,41 +3744,41 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 											switch (dwVnums[i])[m
 											{[m
 											case CSpecialItemGroup::GOLD:[m
[31m-												ChatPacket(CHAT_TYPE_INFO, LC_TEXT("µ· %d ³ÉÀ» È¹µæÇß½À´Ï´Ù."), dwCounts[i]);[m
[32m+[m												[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ %d ï¿½ï¿½ï¿½ï¿½ È¹ï¿½ï¿½ï¿½ß½ï¿½ï¿½Ï´ï¿½."), dwCounts[i]);[m
 												break;[m
 [m
 											case CSpecialItemGroup::EXP:[m
[31m-												ChatPacket(CHAT_TYPE_INFO, LC_TEXT("»óÀÚ¿¡¼­ ºÎÅÍ ½ÅºñÇÑ ºûÀÌ ³ª¿É´Ï´Ù."));[m
[31m-												ChatPacket(CHAT_TYPE_INFO, LC_TEXT("%dÀÇ °æÇèÄ¡¸¦ È¹µæÇß½À´Ï´Ù."), dwCounts[i]);[m
[32m+[m												[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½Ú¿ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½Åºï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½É´Ï´ï¿½."));[m
[32m+[m												[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("%dï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½Ä¡ï¿½ï¿½ È¹ï¿½ï¿½ï¿½ß½ï¿½ï¿½Ï´ï¿½."), dwCounts[i]);[m
 												break;[m
 [m
 											case CSpecialItemGroup::MOB:[m
[31m-												ChatPacket(CHAT_TYPE_INFO, LC_TEXT("»óÀÚ¿¡¼­ ¸ó½ºÅÍ°¡ ³ªÅ¸³µ½À´Ï´Ù!"));[m
[32m+[m												[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½Ú¿ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Í°ï¿½ ï¿½ï¿½Å¸ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½!"));[m
 												break;[m
 [m
 											case CSpecialItemGroup::SLOW:[m
[31m-												ChatPacket(CHAT_TYPE_INFO, LC_TEXT("»óÀÚ¿¡¼­ ³ª¿Â »¡°£ ¿¬±â¸¦ µéÀÌ¸¶½ÃÀÚ ¿òÁ÷ÀÌ´Â ¼Óµµ°¡ ´À·ÁÁ³½À´Ï´Ù!"));[m
[32m+[m												[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½Ú¿ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½â¸¦ ï¿½ï¿½ï¿½Ì¸ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ì´ï¿½ ï¿½Óµï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½!"));[m
 												break;[m
 [m
 											case CSpecialItemGroup::DRAIN_HP:[m
[31m-												ChatPacket(CHAT_TYPE_INFO, LC_TEXT("»óÀÚ°¡ °©ÀÚ±â Æø¹ßÇÏ¿´½À´Ï´Ù! »ý¸í·ÂÀÌ °¨¼ÒÇß½À´Ï´Ù."));[m
[32m+[m												[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½Ú°ï¿½ ï¿½ï¿½ï¿½Ú±ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï¿ï¿½ï¿½ï¿½ï¿½Ï´ï¿½! ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ß½ï¿½ï¿½Ï´ï¿½."));[m
 												break;[m
 [m
 											case CSpecialItemGroup::POISON:[m
[31m-												ChatPacket(CHAT_TYPE_INFO, LC_TEXT("»óÀÚ¿¡¼­ ³ª¿Â ³ì»ö ¿¬±â¸¦ µéÀÌ¸¶½ÃÀÚ µ¶ÀÌ ¿Â¸öÀ¸·Î ÆÛÁý´Ï´Ù!"));[m
[32m+[m												[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½Ú¿ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½â¸¦ ï¿½ï¿½ï¿½Ì¸ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½Â¸ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½!"));[m
 												break;[m
 [m
 											case CSpecialItemGroup::MOB_GROUP:[m
[31m-												ChatPacket(CHAT_TYPE_INFO, LC_TEXT("»óÀÚ¿¡¼­ ¸ó½ºÅÍ°¡ ³ªÅ¸³µ½À´Ï´Ù!"));[m
[32m+[m												[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½Ú¿ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Í°ï¿½ ï¿½ï¿½Å¸ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½!"));[m
 												break;[m
 [m
 											default:[m
 												if (item_gets[i])[m
 												{[m
 													if (dwCounts[i] > 1)[m
[31m-														ChatPacket(CHAT_TYPE_INFO, LC_TEXT("»óÀÚ¿¡¼­ %s °¡ %d °³ ³ª¿Ô½À´Ï´Ù."), item_gets[i]->GetName(), dwCounts[i]);[m
[32m+[m														[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½Ú¿ï¿½ï¿½ï¿½ %s ï¿½ï¿½ %d ï¿½ï¿½ ï¿½ï¿½ï¿½Ô½ï¿½ï¿½Ï´ï¿½."), item_gets[i]->GetName(), dwCounts[i]);[m
 													else[m
[31m-														ChatPacket(CHAT_TYPE_INFO, LC_TEXT("»óÀÚ¿¡¼­ %s °¡ ³ª¿Ô½À´Ï´Ù."), item_gets[i]->GetName());[m
[32m+[m														[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½Ú¿ï¿½ï¿½ï¿½ %s ï¿½ï¿½ ï¿½ï¿½ï¿½Ô½ï¿½ï¿½Ï´ï¿½."), item_gets[i]->GetName());[m
 												}[m
 												break;[m
 											}[m
[36m@@ -3774,7 +3786,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 									}[m
 									else[m
 									{[m
[31m-										ChatPacket(CHAT_TYPE_TALKING, LC_TEXT("¾Æ¹«°Íµµ ¾òÀ» ¼ö ¾ø¾ú½À´Ï´Ù."));[m
[32m+[m										[32mChatPacket(CHAT_TYPE_TALKING, LC_TEXT("ï¿½Æ¹ï¿½ï¿½Íµï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 										return false;[m
 									}[m
 								}[m
[36m@@ -3791,7 +3803,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 							case 50107:[m
 								{[m
 									EffectPacket(SE_CHINA_FIREWORK);[m
[31m-									// ½ºÅÏ °ø°ÝÀ» ¿Ã·ÁÁØ´Ù[m
[32m+[m									[32m// ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ã·ï¿½ï¿½Ø´ï¿½[m
 									AddAffect(AFFECT_CHINA_FIREWORK, POINT_STUN_PCT, 30, AFF_CHINA_FIREWORK, 5*60, 0, true);[m
 									item->SetCount(item->GetCount()-1);[m
 								}[m
[36m@@ -3801,12 +3813,12 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 								{[m
 									if (CArenaManager::instance().IsArenaMap(GetMapIndex()) == true)[m
 									{[m
[31m-										ChatPacket(CHAT_TYPE_INFO, LC_TEXT("´ë·Ã Áß¿¡´Â ÀÌ¿ëÇÒ ¼ö ¾ø´Â ¹°Ç°ÀÔ´Ï´Ù."));[m
[32m+[m										[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ ï¿½ß¿ï¿½ï¿½ï¿½ ï¿½Ì¿ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½Ç°ï¿½Ô´Ï´ï¿½."));[m
 										return false;[m
 									}[m
 [m
 									EffectPacket(SE_SPIN_TOP);[m
[31m-									// ½ºÅÏ °ø°ÝÀ» ¿Ã·ÁÁØ´Ù[m
[32m+[m									[32m// ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ã·ï¿½ï¿½Ø´ï¿½[m
 									AddAffect(AFFECT_CHINA_FIREWORK, POINT_STUN_PCT, 30, AFF_CHINA_FIREWORK, 5*60, 0, true);[m
 									item->SetCount(item->GetCount()-1);[m
 								}[m
[36m@@ -3827,16 +3839,16 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 								item->SetCount(item->GetCount()-1);[m
 								break;[m
 [m
[31m-							case ITEM_ELK_VNUM: // µ·²Ù·¯¹Ì[m
[32m+[m							[32mcase ITEM_ELK_VNUM: // ï¿½ï¿½ï¿½Ù·ï¿½ï¿½ï¿½[m
 								{[m
 									int iGold = item->GetSocket(0);[m
 									ITEM_MANAGER::instance().RemoveItem(item);[m
[31m-									ChatPacket(CHAT_TYPE_INFO, LC_TEXT("µ· %d ³ÉÀ» È¹µæÇß½À´Ï´Ù."), iGold);[m
[32m+[m									[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ %d ï¿½ï¿½ï¿½ï¿½ È¹ï¿½ï¿½ï¿½ß½ï¿½ï¿½Ï´ï¿½."), iGold);[m
 									PointChange(POINT_GOLD, iGold);[m
 								}[m
 								break;[m
 [m
[31m-								//±ºÁÖÀÇ ÁõÇ¥ [m
[32m+[m								[32m//ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½Ç¥[m[41m [m
 							case 70021:[m
 								{[m
 									int HealPrice = quest::CQuestManager::instance().GetEventFlag("MonarchHealGold");[m
[36m@@ -3846,10 +3858,10 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 									if (CMonarch::instance().HealMyEmpire(this, HealPrice))[m
 									{[m
 										char szNotice[256];[m
[31m-										snprintf(szNotice, sizeof(szNotice), LC_TEXT("±ºÁÖÀÇ Ãàº¹À¸·Î ÀÌÁö¿ª %s À¯Àú´Â HP,SP°¡ ¸ðµÎ Ã¤¿öÁý´Ï´Ù."), EMPIRE_NAME(GetEmpire()));[m
[32m+[m										[32msnprintf(szNotice, sizeof(szNotice), LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½àº¹ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ %s ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ HP,SPï¿½ï¿½ ï¿½ï¿½ï¿½ Ã¤ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."), EMPIRE_NAME(GetEmpire()));[m
 										SendNoticeMap(szNotice, GetMapIndex(), false);[m
 										[m
[31m-										ChatPacket(CHAT_TYPE_INFO, LC_TEXT("±ºÁÖÀÇ Ãàº¹À» »ç¿ëÇÏ¿´½À´Ï´Ù."));[m
[32m+[m										[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½àº¹ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½Ï¿ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 									}[m
 								}[m
 								break;[m
[36m@@ -3859,7 +3871,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 								}[m
 								break;[m
 [m
[31m-							case 71092 : // º¯½Å ÇØÃ¼ºÎ ÀÓ½Ã[m
[32m+[m							[32mcase 71092 : // ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½Ã¼ï¿½ï¿½ ï¿½Ó½ï¿½[m
 								{[m
 									if (m_pkChrTarget != NULL)[m
 									{[m
[36m@@ -3880,9 +3892,9 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 								}[m
 								break;[m
 [m
[31m-							case 71051 : // ÁøÀç°¡[m
[32m+[m							[32mcase 71051 : // ï¿½ï¿½ï¿½ç°¡[m
 								{[m
[31m-									// À¯·´, ½Ì°¡Æú, º£Æ®³² ÁøÀç°¡ »ç¿ë±ÝÁö[m
[32m+[m									[32m// ï¿½ï¿½ï¿½ï¿½, ï¿½Ì°ï¿½ï¿½ï¿½, ï¿½ï¿½Æ®ï¿½ï¿½ ï¿½ï¿½ï¿½ç°¡ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½[m
 									// if (LC_IsEurope() || LC_IsSingapore() || LC_IsVietnam())[m
 										// return false;[m
 [m
[36m@@ -3902,13 +3914,13 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 [m
 									if (item2->GetAttributeSetIndex() == -1)[m
 									{[m
[31m-										ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¼Ó¼ºÀ» º¯°æÇÒ ¼ö ¾ø´Â ¾ÆÀÌÅÛÀÔ´Ï´Ù."));[m
[32m+[m										[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½Ó¼ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½Ô´Ï´ï¿½."));[m
 										return false;[m
 									}[m
 [m
 									if (item2->AddRareAttribute() == true)[m
 									{[m
[31m-										ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¼º°øÀûÀ¸·Î ¼Ó¼ºÀÌ Ãß°¡ µÇ¾ú½À´Ï´Ù"));[m
[32m+[m										[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ó¼ï¿½ï¿½ï¿½ ï¿½ß°ï¿½ ï¿½Ç¾ï¿½ï¿½ï¿½ï¿½Ï´ï¿½"));[m
 [m
 										int iAddedIdx = item2->GetRareAttrCount() + 4;[m
 										char buf[21];[m
[36m@@ -3928,14 +3940,14 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 									}[m
 									else[m
 									{[m
[31m-										ChatPacket(CHAT_TYPE_INFO, LC_TEXT("´õ ÀÌ»ó ÀÌ ¾ÆÀÌÅÛÀ¸·Î ¼Ó¼ºÀ» Ãß°¡ÇÒ ¼ö ¾ø½À´Ï´Ù"));[m
[32m+[m										[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ ï¿½Ì»ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ó¼ï¿½ï¿½ï¿½ ï¿½ß°ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½"));[m
 									}[m
 								}[m
 								break;[m
 [m
[31m-							case 71052 : // ÁøÀç°æ[m
[32m+[m							[32mcase 71052 : // ï¿½ï¿½ï¿½ï¿½ï¿½[m
 								{[m
[31m-									// À¯·´, ½Ì°¡Æú, º£Æ®³² ÁøÀç°¡ »ç¿ë±ÝÁö[m
[32m+[m									[32m// ï¿½ï¿½ï¿½ï¿½, ï¿½Ì°ï¿½ï¿½ï¿½, ï¿½ï¿½Æ®ï¿½ï¿½ ï¿½ï¿½ï¿½ç°¡ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½[m
 									// if (LC_IsEurope() || LC_IsSingapore() || LC_IsVietnam())[m
 										// return false;[m
 [m
[36m@@ -3955,7 +3967,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 [m
 									if (item2->GetAttributeSetIndex() == -1)[m
 									{[m
[31m-										ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¼Ó¼ºÀ» º¯°æÇÒ ¼ö ¾ø´Â ¾ÆÀÌÅÛÀÔ´Ï´Ù."));[m
[32m+[m										[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½Ó¼ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½Ô´Ï´ï¿½."));[m
 										return false;[m
 									}[m
 [m
[36m@@ -3969,7 +3981,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 									}[m
 									else[m
 									{[m
[31m-										ChatPacket(CHAT_TYPE_INFO, LC_TEXT("º¯°æ ½ÃÅ³ ¼Ó¼ºÀÌ ¾ø½À´Ï´Ù"));[m
[32m+[m										[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½Å³ ï¿½Ó¼ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½"));[m
 									}[m
 								}[m
 								break;[m
[36m@@ -3982,8 +3994,8 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 							case ITEM_AUTO_SP_RECOVERY_M:[m
 							case ITEM_AUTO_SP_RECOVERY_L:[m
 							case ITEM_AUTO_SP_RECOVERY_X:[m
[31m-							// ¹«½Ã¹«½ÃÇÏÁö¸¸ ÀÌÀü¿¡ ÇÏ´ø °É °íÄ¡±â´Â ¹«¼·°í...[m
[31m-							// ±×·¡¼­ ±×³É ÇÏµå ÄÚµù. ¼±¹° »óÀÚ¿ë ÀÚµ¿¹°¾à ¾ÆÀÌÅÛµé.[m
[32m+[m							[32m// ï¿½ï¿½ï¿½Ã¹ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ï´ï¿½ ï¿½ï¿½ ï¿½ï¿½Ä¡ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½...[m
[32m+[m							[32m// ï¿½×·ï¿½ï¿½ï¿½ ï¿½×³ï¿½ ï¿½Ïµï¿½ ï¿½Úµï¿½. ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Ú¿ï¿½ ï¿½Úµï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ûµï¿½.[m
 							case REWARD_BOX_ITEM_AUTO_SP_RECOVERY_XS: [m
 							case REWARD_BOX_ITEM_AUTO_SP_RECOVERY_S: [m
 							case REWARD_BOX_ITEM_AUTO_HP_RECOVERY_XS: [m
[36m@@ -3993,7 +4005,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 								{[m
 									if (CArenaManager::instance().IsArenaMap(GetMapIndex()) == true)[m
 									{[m
[31m-										ChatPacket(CHAT_TYPE_INFO, LC_TEXT("´ë·ÃÀå¿¡¼­ »ç¿ëÇÏ½Ç ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m										[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½å¿¡ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½Ï½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 										return false;[m
 									}[m
 [m
[36m@@ -4036,7 +4048,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 [m
 										if (-1 == pos)[m
 										{[m
[31m-											ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¼ÒÁöÇ°¿¡ ºó °ø°£ÀÌ ¾ø½À´Ï´Ù."));[m
[32m+[m											[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½Ç°ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 											break;[m
 										}[m
 [m
[36m@@ -4146,7 +4158,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 [m
 									if (get_global_time() - last_use_time < 10*60)[m
 									{[m
[31m-										ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¾ÆÁ÷ »ç¿ëÇÒ ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m										[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 										return false;[m
 									}[m
 [m
[36m@@ -4165,7 +4177,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 							{[m
 								if (quest::CQuestManager::instance().GetEventFlag("arena_potion_limit") > 0)[m
 								{[m
[31m-									ChatPacket(CHAT_TYPE_INFO, LC_TEXT("´ë·ÃÀå¿¡¼­ »ç¿ëÇÏ½Ç ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m									[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½å¿¡ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½Ï½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 									return false;[m
 								}[m
 [m
[36m@@ -4179,21 +4191,21 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 										{[m
 											if (m_nPotionLimit <= 0)[m
 											{[m
[31m-												ChatPacket(CHAT_TYPE_INFO, LC_TEXT("»ç¿ë Á¦ÇÑ·®À» ÃÊ°úÇÏ¿´½À´Ï´Ù."));[m
[32m+[m												[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Ñ·ï¿½ï¿½ï¿½ ï¿½Ê°ï¿½ï¿½Ï¿ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 												return false;[m
 											}[m
 										}[m
 										break;[m
 [m
 									default :[m
[31m-										ChatPacket(CHAT_TYPE_INFO, LC_TEXT("´ë·ÃÀå¿¡¼­ »ç¿ëÇÏ½Ç ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m										[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½å¿¡ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½Ï½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 										return false;[m
 								}[m
 							}[m
 [m
 							bool used = false;[m
 [m
[31m-							if (item->GetValue(0) != 0) // HP Àý´ë°ª È¸º¹[m
[32m+[m							[32mif (item->GetValue(0) != 0) // HP ï¿½ï¿½ï¿½ë°ª È¸ï¿½ï¿½[m
 							{[m
 								if (GetHP() < GetMaxHP())[m
 								{[m
[36m@@ -4203,7 +4215,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 								}[m
 							}[m
 [m
[31m-							if (item->GetValue(1) != 0)	// SP Àý´ë°ª È¸º¹[m
[32m+[m							[32mif (item->GetValue(1) != 0)	// SP ï¿½ï¿½ï¿½ë°ª È¸ï¿½ï¿½[m
 							{[m
 								if (GetSP() < GetMaxSP())[m
 								{[m
[36m@@ -4213,7 +4225,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 								}[m
 							}[m
 [m
[31m-							if (item->GetValue(3) != 0) // HP % È¸º¹[m
[32m+[m							[32mif (item->GetValue(3) != 0) // HP % È¸ï¿½ï¿½[m
 							{[m
 								if (GetHP() < GetMaxHP())[m
 								{[m
[36m@@ -4223,7 +4235,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 								}[m
 							}[m
 [m
[31m-							if (item->GetValue(4) != 0) // SP % È¸º¹[m
[32m+[m							[32mif (item->GetValue(4) != 0) // SP % È¸ï¿½ï¿½[m
 							{[m
 								if (GetSP() < GetMaxSP())[m
 								{[m
[36m@@ -4238,7 +4250,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 								if (item->GetVnum() == 50085 || item->GetVnum() == 50086)[m
 								{[m
 									if (test_server)[m
[31m-										ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¿ùº´ ¶Ç´Â Á¾ÀÚ ¸¦ »ç¿ëÇÏ¿´½À´Ï´Ù"));[m
[32m+[m										[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ ï¿½Ç´ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½Ï¿ï¿½ï¿½ï¿½ï¿½Ï´ï¿½"));[m
 									SetUseSeedOrMoonBottleTime();[m
 								}[m
 								if (GetDungeon())[m
[36m@@ -4261,7 +4273,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 						{[m
 							if (quest::CQuestManager::instance().GetEventFlag("arena_potion_limit") > 0)[m
 							{[m
[31m-								ChatPacket(CHAT_TYPE_INFO, LC_TEXT("´ë·ÃÀå¿¡¼­ »ç¿ëÇÏ½Ç ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m								[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½å¿¡ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½Ï½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 								return false;[m
 							}[m
 						[m
[36m@@ -4277,14 +4289,14 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 									{[m
 										if (m_nPotionLimit <= 0)[m
 										{[m
[31m-											ChatPacket(CHAT_TYPE_INFO, LC_TEXT("»ç¿ë Á¦ÇÑ·®À» ÃÊ°úÇÏ¿´½À´Ï´Ù."));[m
[32m+[m											[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Ñ·ï¿½ï¿½ï¿½ ï¿½Ê°ï¿½ï¿½Ï¿ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 											return false;[m
 										}[m
 									}[m
 									break;[m
 [m
 								default :[m
[31m-									ChatPacket(CHAT_TYPE_INFO, LC_TEXT("´ë·ÃÀå¿¡¼­ »ç¿ëÇÏ½Ç ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m									[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½å¿¡ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½Ï½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 									return false;[m
 							}[m
 						}[m
[36m@@ -4405,22 +4417,22 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 							const int MEMORY_PORTAL = 2;[m
 [m
 [m
[31m-							// gm_guild_build, oxevent ¸Ê¿¡¼­ ±ÍÈ¯ºÎ ±ÍÈ¯±â¾ïºÎ ¸¦ »ç¿ë¸øÇÏ°Ô ¸·À½[m
[32m+[m							[32m// gm_guild_build, oxevent ï¿½Ê¿ï¿½ï¿½ï¿½ ï¿½ï¿½È¯ï¿½ï¿½ ï¿½ï¿½È¯ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï°ï¿½ ï¿½ï¿½ï¿½ï¿½[m
 							if (GetMapIndex() == 200 || GetMapIndex() == 113)[m
 							{[m
[31m-								ChatPacket(CHAT_TYPE_INFO, LC_TEXT("ÇöÀç À§Ä¡¿¡¼­ »ç¿ëÇÒ ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m								[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½Ä¡ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 								return false;[m
 							}[m
 [m
 							if (CArenaManager::instance().IsArenaMap(GetMapIndex()) == true)[m
 							{[m
[31m-								ChatPacket(CHAT_TYPE_INFO, LC_TEXT("´ë·Ã Áß¿¡´Â ÀÌ¿ëÇÒ ¼ö ¾ø´Â ¹°Ç°ÀÔ´Ï´Ù."));[m
[32m+[m								[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ ï¿½ß¿ï¿½ï¿½ï¿½ ï¿½Ì¿ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½Ç°ï¿½Ô´Ï´ï¿½."));[m
 								return false;[m
 							}[m
 [m
 							if (m_pkWarpEvent)[m
 							{[m
[31m-								ChatPacket(CHAT_TYPE_INFO, LC_TEXT("ÀÌµ¿ÇÒ ÁØºñ°¡ µÇ¾îÀÖÀ½À¸·Î ±ÍÈ¯ºÎ¸¦ »ç¿ëÇÒ¼ö ¾ø½À´Ï´Ù"));[m
[32m+[m								[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½Ìµï¿½ï¿½ï¿½ ï¿½Øºï¿½ ï¿½Ç¾ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½È¯ï¿½Î¸ï¿½ ï¿½ï¿½ï¿½ï¿½Ò¼ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½"));[m
 								return false;[m
 							}[m
 [m
[36m@@ -4431,7 +4443,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 								return false;[m
 							// END_OF_CONSUME_LIFE_WHEN_USE_WARP_ITEM[m
 [m
[31m-							if (item->GetValue(0) == TOWN_PORTAL) // ±ÍÈ¯ºÎ[m
[32m+[m							[32mif (item->GetValue(0) == TOWN_PORTAL) // ï¿½ï¿½È¯ï¿½ï¿½[m
 							{[m
 								if (item->GetSocket(0) == 0)[m
 								{[m
[36m@@ -4457,20 +4469,20 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 								else[m
 								{[m
 									if (test_server)[m
[31m-										ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¿ø·¡ À§Ä¡·Î º¹±Í"));	[m
[32m+[m										[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½Ä¡ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½"));[m[41m	[m
 [m
 									ProcessRecallItem(item);[m
 								}[m
 							}[m
[31m-							else if (item->GetValue(0) == MEMORY_PORTAL) // ±ÍÈ¯±â¾ïºÎ[m
[32m+[m							[32melse if (item->GetValue(0) == MEMORY_PORTAL) // ï¿½ï¿½È¯ï¿½ï¿½ï¿½ï¿½[m
 							{[m
 								if (item->GetSocket(0) == 0)[m
 								{[m
 									if (GetDungeon())[m
 									{[m
[31m-										ChatPacket(CHAT_TYPE_INFO, LC_TEXT("´øÀü ¾È¿¡¼­´Â %s%s »ç¿ëÇÒ ¼ö ¾ø½À´Ï´Ù."),[m
[32m+[m										[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ ï¿½È¿ï¿½ï¿½ï¿½ï¿½ï¿½ %s%s ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."),[m
 												item->GetName(),[m
[31m-												g_iUseLocale ? "" : (under_han(item->GetName()) ? LC_TEXT("À»") : LC_TEXT("¸¦")));[m
[32m+[m												[32mg_iUseLocale ? "" : (under_han(item->GetName()) ? LC_TEXT("ï¿½ï¿½") : LC_TEXT("ï¿½ï¿½")));[m
 										return false;[m
 									}[m
 [m
[36m@@ -4503,21 +4515,21 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 							if (item2->IsEquipped()) // Fix[m
 								return false;[m
 	[m
[31m-							if (item2->GetVnum() >= 28330 && item2->GetVnum() <= 28343) // ¿µ¼®+3[m
[32m+[m							[32mif (item2->GetVnum() >= 28330 && item2->GetVnum() <= 28343) // ï¿½ï¿½ï¿½ï¿½+3[m
 							{[m
[31m-								ChatPacket(CHAT_TYPE_INFO, LC_TEXT("+3 ¿µ¼®Àº ÀÌ ¾ÆÀÌÅÛÀ¸·Î °³·®ÇÒ ¼ö ¾ø½À´Ï´Ù"));[m
[32m+[m								[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("+3 ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½"));[m
 								return false;[m
 							}[m
 							[m
[31m-							if (item2->GetVnum() >= 28430 && item2->GetVnum() <= 28443)  // ¿µ¼®+4[m
[32m+[m							[32mif (item2->GetVnum() >= 28430 && item2->GetVnum() <= 28443)  // ï¿½ï¿½ï¿½ï¿½+4[m
 							{[m
[31m-								if (item->GetVnum() == 71056) // Ã»·æÀÇ¼û°á[m
[32m+[m								[32mif (item->GetVnum() == 71056) // Ã»ï¿½ï¿½ï¿½Ç¼ï¿½ï¿½ï¿½[m
 								{[m
 									RefineItem(item, item2);[m
 								}[m
 								else[m
 								{[m
[31m-									ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¿µ¼®Àº ÀÌ ¾ÆÀÌÅÛÀ¸·Î °³·®ÇÒ ¼ö ¾ø½À´Ï´Ù"));[m
[32m+[m									[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½"));[m
 								}[m
 							}[m
 							else[m
[36m@@ -4547,12 +4559,12 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 								BuffOnAttr_RemoveBuffsFromItem(item2);[m
 							}[m
 [m
[31m-							// [NOTE] ÄÚ½ºÆ¬ ¾ÆÀÌÅÛ¿¡´Â ¾ÆÀÌÅÛ ÃÖÃÊ »ý¼º½Ã ·£´ý ¼Ó¼ºÀ» ºÎ¿©ÇÏµÇ, Àç°æÀç°¡ µîµîÀº ¸·¾Æ´Þ¶ó´Â ¿äÃ»ÀÌ ÀÖ¾úÀ½.[m
[31m-							// ¿ø·¡ ANTI_CHANGE_ATTRIBUTE °°Àº ¾ÆÀÌÅÛ Flag¸¦ Ãß°¡ÇÏ¿© ±âÈ¹ ·¹º§¿¡¼­ À¯¿¬ÇÏ°Ô ÄÁÆ®·Ñ ÇÒ ¼ö ÀÖµµ·Ï ÇÒ ¿¹Á¤ÀÌ¾úÀ¸³ª[m
[31m-							// ±×µý°Å ÇÊ¿ä¾øÀ¸´Ï ´ÚÄ¡°í »¡¸® ÇØ´Þ·¡¼­ ±×³É ¿©±â¼­ ¸·À½... -_-[m
[32m+[m							[32m// [NOTE] ï¿½Ú½ï¿½Æ¬ ï¿½ï¿½ï¿½ï¿½ï¿½Û¿ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½Ó¼ï¿½ï¿½ï¿½ ï¿½Î¿ï¿½ï¿½Ïµï¿½, ï¿½ï¿½ï¿½ï¿½ç°¡ ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Æ´Þ¶ï¿½ï¿½ ï¿½ï¿½Ã»ï¿½ï¿½ ï¿½Ö¾ï¿½ï¿½ï¿½.[m
[32m+[m							[32m// ï¿½ï¿½ï¿½ï¿½ ANTI_CHANGE_ATTRIBUTE ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ Flagï¿½ï¿½ ï¿½ß°ï¿½ï¿½Ï¿ï¿½ ï¿½ï¿½È¹ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï°ï¿½ ï¿½ï¿½Æ®ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ ï¿½Öµï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ì¾ï¿½ï¿½ï¿½ï¿½ï¿½[m
[32m+[m							[32m// ï¿½×µï¿½ï¿½ï¿½ ï¿½Ê¿ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½Ä¡ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½Ø´Þ·ï¿½ï¿½ï¿½ ï¿½×³ï¿½ ï¿½ï¿½ï¿½â¼­ ï¿½ï¿½ï¿½ï¿½... -_-[m
 							if (ITEM_COSTUME == item2->GetType())[m
 							{[m
[31m-								ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¼Ó¼ºÀ» º¯°æÇÒ ¼ö ¾ø´Â ¾ÆÀÌÅÛÀÔ´Ï´Ù."));[m
[32m+[m								[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½Ó¼ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½Ô´Ï´ï¿½."));[m
 								return false;[m
 							}[m
 [m
[36m@@ -4575,7 +4587,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 [m
 										if (i == ITEM_SOCKET_MAX_NUM)[m
 										{[m
[31m-											ChatPacket(CHAT_TYPE_INFO, LC_TEXT("Ã»¼ÒÇÒ ¼®ÀÌ ¹ÚÇôÀÖÁö ¾Ê½À´Ï´Ù."));[m
[32m+[m											[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("Ã»ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ê½ï¿½ï¿½Ï´ï¿½."));[m
 											return false;[m
 										}[m
 [m
[36m@@ -4607,21 +4619,21 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 								case USE_CHANGE_ATTRIBUTE :[m
 									if (item2->GetAttributeSetIndex() == -1)[m
 									{[m
[31m-										ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¼Ó¼ºÀ» º¯°æÇÒ ¼ö ¾ø´Â ¾ÆÀÌÅÛÀÔ´Ï´Ù."));[m
[32m+[m										[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½Ó¼ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½Ô´Ï´ï¿½."));[m
 										return false;[m
 									}[m
 [m
 									if (item2->GetAttributeCount() == 0)[m
 									{[m
[31m-										ChatPacket(CHAT_TYPE_INFO, LC_TEXT("º¯°æÇÒ ¼Ó¼ºÀÌ ¾ø½À´Ï´Ù."));[m
[32m+[m										[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ó¼ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 										return false;[m
 									}[m
 [m
 									if (GM_PLAYER == GetGMLevel() && false == test_server)[m
 									{[m
 										//[m
[31m-										// Event Flag ¸¦ ÅëÇØ ÀÌÀü¿¡ ¾ÆÀÌÅÛ ¼Ó¼º º¯°æÀ» ÇÑ ½Ã°£À¸·Î ºÎÅÍ ÃæºÐÇÑ ½Ã°£ÀÌ Èê·¶´ÂÁö °Ë»çÇÏ°í[m
[31m-										// ½Ã°£ÀÌ ÃæºÐÈ÷ Èê·¶´Ù¸é ÇöÀç ¼Ó¼ºº¯°æ¿¡ ´ëÇÑ ½Ã°£À» ¼³Á¤ÇØ ÁØ´Ù.[m
[32m+[m										[32m// Event Flag ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ó¼ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½Ã°ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ã°ï¿½ï¿½ï¿½ ï¿½ê·¶ï¿½ï¿½ï¿½ï¿½ ï¿½Ë»ï¿½ï¿½Ï°ï¿½[m
[32m+[m										[32m// ï¿½Ã°ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ê·¶ï¿½Ù¸ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½Ó¼ï¿½ï¿½ï¿½ï¿½æ¿¡ ï¿½ï¿½ï¿½ï¿½ ï¿½Ã°ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ø´ï¿½.[m
 										//[m
 [m
 										DWORD dwChangeItemAttrCycle = quest::CQuestManager::instance().GetEventFlag(msc_szChangeItemAttrCycleFlag);[m
[36m@@ -4638,7 +4650,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 [m
 											// if (dwLastChangeItemAttrMin + dwChangeItemAttrCycle > dwNowMin)[m
 											// {[m
[31m-												// ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¼Ó¼ºÀ» ¹Ù²ÛÁö %dºÐ ÀÌ³»¿¡´Â ´Ù½Ã º¯°æÇÒ ¼ö ¾ø½À´Ï´Ù.(%d ºÐ ³²À½)"),[m
[32m+[m												[32m// ChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½Ó¼ï¿½ï¿½ï¿½ ï¿½Ù²ï¿½ï¿½ï¿½ %dï¿½ï¿½ ï¿½Ì³ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ù½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½.(%d ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½)"),[m
 														// dwChangeItemAttrCycle, dwChangeItemAttrCycle - (dwNowMin - dwLastChangeItemAttrMin));[m
 												// return false;[m
 											// }[m
[36m@@ -4668,8 +4680,8 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 [m
 									else[m
 									{[m
[31m-										// ¿¬Àç°æ Æ¯¼öÃ³¸®[m
[31m-										// Àý´ë·Î ¿¬Àç°¡ Ãß°¡ ¾ÈµÉ°Å¶ó ÇÏ¿© ÇÏµå ÄÚµùÇÔ.[m
[32m+[m										[32m// ï¿½ï¿½ï¿½ï¿½ï¿½ Æ¯ï¿½ï¿½Ã³ï¿½ï¿½[m
[32m+[m										[32m// ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ç°¡ ï¿½ß°ï¿½ ï¿½ÈµÉ°Å¶ï¿½ ï¿½Ï¿ï¿½ ï¿½Ïµï¿½ ï¿½Úµï¿½ï¿½ï¿½.[m
 										if (item->GetVnum() == 71151 || item->GetVnum() == 76023)[m
 										{[m
 											if ((item2->GetType() == ITEM_WEAPON)[m
[36m@@ -4686,20 +4698,20 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 												}[m
 												if (false == bCanUse)[m
 												{[m
[31m-													ChatPacket(CHAT_TYPE_INFO, LC_TEXT("Àû¿ë ·¹º§º¸´Ù ³ô¾Æ »ç¿ëÀÌ ºÒ°¡´ÉÇÕ´Ï´Ù."));[m
[32m+[m													[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ò°ï¿½ï¿½ï¿½ï¿½Õ´Ï´ï¿½."));[m
 													break;[m
 												}[m
 											}[m
 											else[m
 											{[m
[31m-												ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¹«±â¿Í °©¿Ê¿¡¸¸ »ç¿ë °¡´ÉÇÕ´Ï´Ù."));[m
[32m+[m												[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Ê¿ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Õ´Ï´ï¿½."));[m
 												break;[m
 											}[m
 										}[m
 										item2->ChangeAttribute();[m
 									}[m
 [m
[31m-									ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¼Ó¼ºÀ» º¯°æÇÏ¿´½À´Ï´Ù."));[m
[32m+[m									[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½Ó¼ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï¿ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 									{[m
 										char buf[21];[m
 										snprintf(buf, sizeof(buf), "%u", item2->GetID());[m
[36m@@ -4712,14 +4724,14 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 								case USE_ADD_ATTRIBUTE :[m
 									if (item2->GetAttributeSetIndex() == -1)[m
 									{[m
[31m-										ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¼Ó¼ºÀ» º¯°æÇÒ ¼ö ¾ø´Â ¾ÆÀÌÅÛÀÔ´Ï´Ù."));[m
[32m+[m										[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½Ó¼ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½Ô´Ï´ï¿½."));[m
 										return false;[m
 									}[m
 [m
 									if (item2->GetAttributeCount() < 4)[m
 									{[m
[31m-										// ¿¬Àç°¡ Æ¯¼öÃ³¸®[m
[31m-										// Àý´ë·Î ¿¬Àç°¡ Ãß°¡ ¾ÈµÉ°Å¶ó ÇÏ¿© ÇÏµå ÄÚµùÇÔ.[m
[32m+[m										[32m// ï¿½ï¿½ï¿½ç°¡ Æ¯ï¿½ï¿½Ã³ï¿½ï¿½[m
[32m+[m										[32m// ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ç°¡ ï¿½ß°ï¿½ ï¿½ÈµÉ°Å¶ï¿½ ï¿½Ï¿ï¿½ ï¿½Ïµï¿½ ï¿½Úµï¿½ï¿½ï¿½.[m
 										if (item->GetVnum() == 71152 || item->GetVnum() == 76024)[m
 										{[m
 											if ((item2->GetType() == ITEM_WEAPON)[m
[36m@@ -4736,13 +4748,13 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 												}[m
 												if (false == bCanUse)[m
 												{[m
[31m-													ChatPacket(CHAT_TYPE_INFO, LC_TEXT("Àû¿ë ·¹º§º¸´Ù ³ô¾Æ »ç¿ëÀÌ ºÒ°¡´ÉÇÕ´Ï´Ù."));[m
[32m+[m													[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ò°ï¿½ï¿½ï¿½ï¿½Õ´Ï´ï¿½."));[m
 													break;[m
 												}[m
 											}[m
 											else[m
 											{[m
[31m-												ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¹«±â¿Í °©¿Ê¿¡¸¸ »ç¿ë °¡´ÉÇÕ´Ï´Ù."));[m
[32m+[m												[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Ê¿ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Õ´Ï´ï¿½."));[m
 												break;[m
 											}[m
 										}[m
[36m@@ -4752,7 +4764,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 										if (number(1, 100) <= aiItemAttributeAddPercent[item2->GetAttributeCount()])[m
 										{[m
 											item2->AddAttribute();[m
[31m-											ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¼Ó¼º Ãß°¡¿¡ ¼º°øÇÏ¿´½À´Ï´Ù."));[m
[32m+[m											[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½Ó¼ï¿½ ï¿½ß°ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï¿ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 [m
 											int iAddedIdx = item2->GetAttributeCount() - 1;[m
 											LogManager::instance().ItemLog([m
[36m@@ -4767,7 +4779,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 										}[m
 										else[m
 										{[m
[31m-											ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¼Ó¼º Ãß°¡¿¡ ½ÇÆÐÇÏ¿´½À´Ï´Ù."));[m
[32m+[m											[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½Ó¼ï¿½ ï¿½ß°ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï¿ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 											LogManager::instance().ItemLog(this, item, "ADD_ATTRIBUTE_FAIL", buf);[m
 										}[m
 [m
[36m@@ -4775,20 +4787,20 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 									}[m
 									else[m
 									{[m
[31m-										ChatPacket(CHAT_TYPE_INFO, LC_TEXT("´õÀÌ»ó ÀÌ ¾ÆÀÌÅÛÀ» ÀÌ¿ëÇÏ¿© ¼Ó¼ºÀ» Ãß°¡ÇÒ ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m										[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½Ì»ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ì¿ï¿½ï¿½Ï¿ï¿½ ï¿½Ó¼ï¿½ï¿½ï¿½ ï¿½ß°ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 									}[m
 									break;[m
 [m
 								case USE_ADD_ATTRIBUTE2 :[m
[31m-									// Ãàº¹ÀÇ ±¸½½ [m
[31m-									// Àç°¡ºñ¼­¸¦ ÅëÇØ ¼Ó¼ºÀ» 4°³ Ãß°¡ ½ÃÅ² ¾ÆÀÌÅÛ¿¡ ´ëÇØ¼­ ÇÏ³ªÀÇ ¼Ó¼ºÀ» ´õ ºÙ¿©ÁØ´Ù.[m
[32m+[m									[32m// ï¿½àº¹ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½[m[41m [m
[32m+[m									[32m// ï¿½ç°¡ï¿½ñ¼­¸ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½Ó¼ï¿½ï¿½ï¿½ 4ï¿½ï¿½ ï¿½ß°ï¿½ ï¿½ï¿½Å² ï¿½ï¿½ï¿½ï¿½ï¿½Û¿ï¿½ ï¿½ï¿½ï¿½Ø¼ï¿½ ï¿½Ï³ï¿½ï¿½ï¿½ ï¿½Ó¼ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½Ù¿ï¿½ï¿½Ø´ï¿½.[m
 									if (item2->GetAttributeSetIndex() == -1)[m
 									{[m
[31m-										ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¼Ó¼ºÀ» º¯°æÇÒ ¼ö ¾ø´Â ¾ÆÀÌÅÛÀÔ´Ï´Ù."));[m
[32m+[m										[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½Ó¼ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½Ô´Ï´ï¿½."));[m
 										return false;[m
 									}[m
 [m
[31m-									// ¼Ó¼ºÀÌ ÀÌ¹Ì 4°³ Ãß°¡ µÇ¾úÀ» ¶§¸¸ ¼Ó¼ºÀ» Ãß°¡ °¡´ÉÇÏ´Ù.[m
[32m+[m									[32m// ï¿½Ó¼ï¿½ï¿½ï¿½ ï¿½Ì¹ï¿½ 4ï¿½ï¿½ ï¿½ß°ï¿½ ï¿½Ç¾ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½Ó¼ï¿½ï¿½ï¿½ ï¿½ß°ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½.[m
 									if (item2->GetAttributeCount() == 4)[m
 									{[m
 										char buf[21];[m
[36m@@ -4797,7 +4809,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 										if (number(1, 100) <= aiItemAttributeAddPercent[item2->GetAttributeCount()])[m
 										{[m
 											item2->AddAttribute();[m
[31m-											ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¼Ó¼º Ãß°¡¿¡ ¼º°øÇÏ¿´½À´Ï´Ù."));[m
[32m+[m											[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½Ó¼ï¿½ ï¿½ß°ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï¿ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 [m
 											int iAddedIdx = item2->GetAttributeCount() - 1;[m
 											LogManager::instance().ItemLog([m
[36m@@ -4812,7 +4824,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 										}[m
 										else[m
 										{[m
[31m-											ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¼Ó¼º Ãß°¡¿¡ ½ÇÆÐÇÏ¿´½À´Ï´Ù."));[m
[32m+[m											[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½Ó¼ï¿½ ï¿½ß°ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï¿ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 											LogManager::instance().ItemLog(this, item, "ADD_ATTRIBUTE2_FAIL", buf);[m
 										}[m
 [m
[36m@@ -4820,11 +4832,11 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 									}[m
 									else if (item2->GetAttributeCount() == 5)[m
 									{[m
[31m-										ChatPacket(CHAT_TYPE_INFO, LC_TEXT("´õ ÀÌ»ó ÀÌ ¾ÆÀÌÅÛÀ» ÀÌ¿ëÇÏ¿© ¼Ó¼ºÀ» Ãß°¡ÇÒ ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m										[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ ï¿½Ì»ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ì¿ï¿½ï¿½Ï¿ï¿½ ï¿½Ó¼ï¿½ï¿½ï¿½ ï¿½ß°ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 									}[m
 									else if (item2->GetAttributeCount() < 4)[m
 									{[m
[31m-										ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¸ÕÀú Àç°¡ºñ¼­¸¦ ÀÌ¿ëÇÏ¿© ¼Ó¼ºÀ» Ãß°¡½ÃÄÑ ÁÖ¼¼¿ä."));[m
[32m+[m										[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ ï¿½ç°¡ï¿½ñ¼­¸ï¿½ ï¿½Ì¿ï¿½ï¿½Ï¿ï¿½ ï¿½Ó¼ï¿½ï¿½ï¿½ ï¿½ß°ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ö¼ï¿½ï¿½ï¿½."));[m
 									}[m
 									else[m
 									{[m
[36m@@ -4845,12 +4857,12 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 												if (number(1, 100) <= 50)[m
 												{[m
 													item2->SetAccessorySocketMaxGrade(item2->GetAccessorySocketMaxGrade() + 1);[m
[31m-													ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¼ÒÄÏÀÌ ¼º°øÀûÀ¸·Î Ãß°¡µÇ¾ú½À´Ï´Ù."));[m
[32m+[m													[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ß°ï¿½ï¿½Ç¾ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 													LogManager::instance().ItemLog(this, item, "ADD_SOCKET_SUCCESS", buf);[m
 												}[m
 												else[m
 												{[m
[31m-													ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¼ÒÄÏ Ãß°¡¿¡ ½ÇÆÐÇÏ¿´½À´Ï´Ù."));[m
[32m+[m													[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ ï¿½ß°ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï¿ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 													LogManager::instance().ItemLog(this, item, "ADD_SOCKET_FAIL", buf);[m
 												}[m
 [m
[36m@@ -4858,12 +4870,12 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 											}[m
 											else[m
 											{[m
[31m-												ChatPacket(CHAT_TYPE_INFO, LC_TEXT("ÀÌ ¾×¼¼¼­¸®¿¡´Â ´õÀÌ»ó ¼ÒÄÏÀ» Ãß°¡ÇÒ °ø°£ÀÌ ¾ø½À´Ï´Ù."));[m
[32m+[m												[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ ï¿½×¼ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Ì»ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ß°ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 											}[m
 										}[m
 										else[m
 										{[m
[31m-											ChatPacket(CHAT_TYPE_INFO, LC_TEXT("ÀÌ ¾ÆÀÌÅÛÀ¸·Î ¼ÒÄÏÀ» Ãß°¡ÇÒ ¼ö ¾ø´Â ¾ÆÀÌÅÛÀÔ´Ï´Ù."));[m
[32m+[m											[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ß°ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½Ô´Ï´ï¿½."));[m
 										}[m
 									}[m
 									break;[m
[36m@@ -4880,12 +4892,12 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 											if (number(1, 100) <= aiAccessorySocketPutPct[item2->GetAccessorySocketGrade()])[m
 											{[m
 												item2->SetAccessorySocketGrade(item2->GetAccessorySocketGrade() + 1);[m
[31m-												ChatPacket(CHAT_TYPE_INFO, LC_TEXT("ÀåÂø¿¡ ¼º°øÇÏ¿´½À´Ï´Ù."));[m
[32m+[m												[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï¿ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 												LogManager::instance().ItemLog(this, item, "PUT_SOCKET_SUCCESS", buf);[m
 											}[m
 											else[m
 											{[m
[31m-												ChatPacket(CHAT_TYPE_INFO, LC_TEXT("ÀåÂø¿¡ ½ÇÆÐÇÏ¿´½À´Ï´Ù."));[m
[32m+[m												[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï¿ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 												LogManager::instance().ItemLog(this, item, "PUT_SOCKET_FAIL", buf);[m
 											}[m
 [m
[36m@@ -4894,19 +4906,19 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 										else[m
 										{[m
 											if (item2->GetAccessorySocketMaxGrade() == 0)[m
[31m-												ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¸ÕÀú ´ÙÀÌ¾Æ¸óµå·Î ¾Ç¼¼¼­¸®¿¡ ¼ÒÄÏÀ» Ãß°¡ÇØ¾ßÇÕ´Ï´Ù."));[m
[32m+[m												[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Ì¾Æ¸ï¿½ï¿½ï¿½ ï¿½Ç¼ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ß°ï¿½ï¿½Ø¾ï¿½ï¿½Õ´Ï´ï¿½."));[m
 											else if (item2->GetAccessorySocketMaxGrade() < ITEM_ACCESSORY_SOCKET_MAX_NUM)[m
 											{[m
[31m-												ChatPacket(CHAT_TYPE_INFO, LC_TEXT("ÀÌ ¾×¼¼¼­¸®¿¡´Â ´õÀÌ»ó ÀåÂøÇÒ ¼ÒÄÏÀÌ ¾ø½À´Ï´Ù."));[m
[31m-												ChatPacket(CHAT_TYPE_INFO, LC_TEXT("´ÙÀÌ¾Æ¸óµå·Î ¼ÒÄÏÀ» Ãß°¡ÇØ¾ßÇÕ´Ï´Ù."));[m
[32m+[m												[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ ï¿½×¼ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Ì»ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
[32m+[m												[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½Ì¾Æ¸ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ß°ï¿½ï¿½Ø¾ï¿½ï¿½Õ´Ï´ï¿½."));[m
 											}[m
 											else[m
[31m-												ChatPacket(CHAT_TYPE_INFO, LC_TEXT("ÀÌ ¾×¼¼¼­¸®¿¡´Â ´õÀÌ»ó º¸¼®À» ÀåÂøÇÒ ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m												[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ ï¿½×¼ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Ì»ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 										}[m
 									}[m
 									else[m
 									{[m
[31m-										ChatPacket(CHAT_TYPE_INFO, LC_TEXT("ÀÌ ¾ÆÀÌÅÛÀ» ÀåÂøÇÒ ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m										[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 									}[m
 									break;[m
 							}[m
[36m@@ -4923,7 +4935,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 [m
 							if (m_pkFishingEvent)[m
 							{[m
[31m-								ChatPacket(CHAT_TYPE_INFO, LC_TEXT("³¬½Ã Áß¿¡ ¹Ì³¢¸¦ °¥¾Æ³¢¿ï ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m								[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ ï¿½ß¿ï¿½ ï¿½Ì³ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Æ³ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 								return false;[m
 							}[m
 [m
[36m@@ -4934,11 +4946,11 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 [m
 							if (weapon->GetSocket(2))[m
 							{[m
[31m-								ChatPacket(CHAT_TYPE_INFO, LC_TEXT("ÀÌ¹Ì ²ÈÇôÀÖ´ø ¹Ì³¢¸¦ »©°í %s¸¦ ³¢¿ó´Ï´Ù."), item->GetName());[m
[32m+[m								[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½Ì¹ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ö´ï¿½ ï¿½Ì³ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ %sï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."), item->GetName());[m
 							}[m
 							else[m
 							{[m
[31m-								ChatPacket(CHAT_TYPE_INFO, LC_TEXT("³¬½Ã´ë¿¡ %s¸¦ ¹Ì³¢·Î ³¢¿ó´Ï´Ù."), item->GetName());[m
[32m+[m								[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½Ã´ë¿¡ %sï¿½ï¿½ ï¿½Ì³ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."), item->GetName());[m
 							}[m
 [m
 							weapon->SetSocket(2, item->GetValue(0));[m
[36m@@ -4955,7 +4967,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 						{[m
 							if (FindAffect(item->GetValue(0), aApplyInfo[item->GetValue(1)].bPointType))[m
 							{[m
[31m-								ChatPacket(CHAT_TYPE_INFO, LC_TEXT("ÀÌ¹Ì È¿°ú°¡ °É·Á ÀÖ½À´Ï´Ù."));[m
[32m+[m								[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½Ì¹ï¿½ È¿ï¿½ï¿½ï¿½ï¿½ ï¿½É·ï¿½ ï¿½Ö½ï¿½ï¿½Ï´ï¿½."));[m
 							}[m
 							else[m
 							{[m
[36m@@ -4970,7 +4982,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 						item->SetCount(item->GetCount() - 1);[m
 						break;[m
 [m
[31m-					// ¹°¾à Á¦Á¶ ½ºÅ³¿ë ·¹½ÃÇÇ Ã³¸®	[m
[32m+[m					[32m// ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½Å³ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ Ã³ï¿½ï¿½[m[41m	[m
 					case USE_RECIPE :[m
 						{[m
 							LPITEM pSource1 = FindSpecifyItem(item->GetValue(1));[m
[36m@@ -4983,7 +4995,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 							{[m
 								if (pSource1 == NULL)[m
 								{[m
[31m-									ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¹°¾à Á¶ÇÕÀ» À§ÇÑ Àç·á°¡ ºÎÁ·ÇÕ´Ï´Ù."));[m
[32m+[m									[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½á°¡ ï¿½ï¿½ï¿½ï¿½ï¿½Õ´Ï´ï¿½."));[m
 									return false;[m
 								}[m
 							}[m
[36m@@ -4992,7 +5004,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 							{[m
 								if (pSource2 == NULL)[m
 								{[m
[31m-									ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¹°¾à Á¶ÇÕÀ» À§ÇÑ Àç·á°¡ ºÎÁ·ÇÕ´Ï´Ù."));[m
[32m+[m									[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½á°¡ ï¿½ï¿½ï¿½ï¿½ï¿½Õ´Ï´ï¿½."));[m
 									return false;[m
 								}[m
 							}[m
[36m@@ -5001,7 +5013,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 							{[m
 								if (pSource1->GetCount() < dwSourceCount1)[m
 								{[m
[31m-									ChatPacket(CHAT_TYPE_INFO, LC_TEXT("Àç·á(%s)°¡ ºÎÁ·ÇÕ´Ï´Ù."), pSource1->GetName());[m
[32m+[m									[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½(%s)ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Õ´Ï´ï¿½."), pSource1->GetName());[m
 									return false;[m
 								}[m
 [m
[36m@@ -5012,7 +5024,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 							{[m
 								if (pSource2->GetCount() < dwSourceCount2)[m
 								{[m
[31m-									ChatPacket(CHAT_TYPE_INFO, LC_TEXT("Àç·á(%s)°¡ ºÎÁ·ÇÕ´Ï´Ù."), pSource2->GetName());[m
[32m+[m									[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½(%s)ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Õ´Ï´ï¿½."), pSource2->GetName());[m
 									return false;[m
 								}[m
 [m
[36m@@ -5023,7 +5035,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 [m
 							if (!pBottle || pBottle->GetCount() < 1)[m
 							{[m
[31m-								ChatPacket(CHAT_TYPE_INFO, LC_TEXT("ºó º´ÀÌ ¸ðÀÚ¸¨´Ï´Ù."));[m
[32m+[m								[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Ú¸ï¿½ï¿½Ï´ï¿½."));[m
 								return false;[m
 							}[m
 [m
[36m@@ -5031,7 +5043,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 [m
 							if (number(1, 100) > item->GetValue(5))[m
 							{[m
[31m-								ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¹°¾à Á¦Á¶¿¡ ½ÇÆÐÇß½À´Ï´Ù."));[m
[32m+[m								[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ß½ï¿½ï¿½Ï´ï¿½."));[m
 								return false;[m
 							}[m
 [m
[36m@@ -5074,7 +5086,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 [m
 					if (item->GetValue(5) == p->alValues[5])[m
 					{[m
[31m-						ChatPacket(CHAT_TYPE_INFO, LC_TEXT("°°Àº Á¾·ùÀÇ ¸ÞÆ¾¼®Àº ¿©·¯°³ ºÎÂøÇÒ ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m						[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½Æ¾ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 						return false;[m
 					}[m
 				}[m
[36m@@ -5083,7 +5095,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 				{[m
 					if (!IS_SET(item->GetWearFlag(), WEARABLE_BODY) || !IS_SET(item2->GetWearFlag(), WEARABLE_BODY))[m
 					{[m
[31m-						ChatPacket(CHAT_TYPE_INFO, LC_TEXT("ÀÌ ¸ÞÆ¾¼®Àº Àåºñ¿¡ ºÎÂøÇÒ ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m						[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ ï¿½ï¿½Æ¾ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 						return false;[m
 					}[m
 				}[m
[36m@@ -5091,28 +5103,28 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 				{[m
 					if (!IS_SET(item->GetWearFlag(), WEARABLE_WEAPON))[m
 					{[m
[31m-						ChatPacket(CHAT_TYPE_INFO, LC_TEXT("ÀÌ ¸ÞÆ¾¼®Àº ¹«±â¿¡ ºÎÂøÇÒ ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m						[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ ï¿½ï¿½Æ¾ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½â¿¡ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 						return false;[m
 					}[m
 				}[m
 				else[m
 				{[m
[31m-					ChatPacket(CHAT_TYPE_INFO, LC_TEXT("ºÎÂøÇÒ ¼ö ÀÖ´Â ½½·ÔÀÌ ¾ø½À´Ï´Ù."));[m
[32m+[m					[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½Ö´ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 					return false;[m
 				}[m
 [m
 				for (i = 0; i < ITEM_SOCKET_MAX_NUM; ++i)[m
 					if (item2->GetSocket(i) >= 1 && item2->GetSocket(i) <= 2 && item2->GetSocket(i) >= item->GetValue(2))[m
 					{[m
[31m-						// ¼® È®·ü[m
[32m+[m						[32m// ï¿½ï¿½ È®ï¿½ï¿½[m
 						if (number(1, 100) <= 30)[m
 						{[m
[31m-							ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¸ÞÆ¾¼® ºÎÂø¿¡ ¼º°øÇÏ¿´½À´Ï´Ù."));[m
[32m+[m							[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½Æ¾ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï¿ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 							item2->SetSocket(i, item->GetVnum());[m
 						}[m
 						else[m
 						{[m
[31m-							ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¸ÞÆ¾¼® ºÎÂø¿¡ ½ÇÆÐÇÏ¿´½À´Ï´Ù."));[m
[32m+[m							[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½Æ¾ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï¿ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 							item2->SetSocket(i, ITEM_BROKEN_METIN_VNUM);[m
 						}[m
 [m
[36m@@ -5122,7 +5134,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 					}[m
 [m
 				if (i == ITEM_SOCKET_MAX_NUM)[m
[31m-					ChatPacket(CHAT_TYPE_INFO, LC_TEXT("ºÎÂøÇÒ ¼ö ÀÖ´Â ½½·ÔÀÌ ¾ø½À´Ï´Ù."));[m
[32m+[m					[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½Ö´ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 			}[m
 			break;[m
 [m
[36m@@ -5141,7 +5153,7 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 			break;[m
 [m
 		case ITEM_BLEND:[m
[31m-			// »õ·Î¿î ¾àÃÊµé[m
[32m+[m			[32m// ï¿½ï¿½ï¿½Î¿ï¿½ ï¿½ï¿½ï¿½Êµï¿½[m
 			sys_log(0,"ITEM_BLEND!!");[m
 			if (Blend_Item_find(item->GetVnum()))[m
 			{[m
[36m@@ -5157,13 +5169,13 @@[m [mbool CHARACTER::UseItemEx(LPITEM item, TItemPos DestCell)[m
 				[m
 				if (FindAffect(affect_type, apply_type))[m
 				{[m
[31m-					ChatPacket(CHAT_TYPE_INFO, LC_TEXT("ÀÌ¹Ì È¿°ú°¡ °É·Á ÀÖ½À´Ï´Ù."));[m
[32m+[m					[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½Ì¹ï¿½ È¿ï¿½ï¿½ï¿½ï¿½ ï¿½É·ï¿½ ï¿½Ö½ï¿½ï¿½Ï´ï¿½."));[m
 				}[m
 				else[m
 				{[m
 					if (FindAffect(AFFECT_EXP_BONUS_EURO_FREE, POINT_RESIST_MAGIC))[m
 					{[m
[31m-						ChatPacket(CHAT_TYPE_INFO, LC_TEXT("ÀÌ¹Ì È¿°ú°¡ °É·Á ÀÖ½À´Ï´Ù."));[m
[32m+[m						[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½Ì¹ï¿½ È¿ï¿½ï¿½ï¿½ï¿½ ï¿½É·ï¿½ ï¿½Ö½ï¿½ï¿½Ï´ï¿½."));[m
 					}[m
 					else[m
 					{[m
[36m@@ -5235,7 +5247,7 @@[m [mbool CHARACTER::UseItem(TItemPos Cell, TItemPos DestCell)[m
 [m
 	if (!item->CanUsedBy(this))[m
 	{[m
[31m-		ChatPacket(CHAT_TYPE_INFO, LC_TEXT("±ºÁ÷ÀÌ ¸ÂÁö¾Ê¾Æ ÀÌ ¾ÆÀÌÅÛÀ» »ç¿ëÇÒ ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m		[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ê¾ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 		return false;[m
 	}[m
 [m
[36m@@ -5244,7 +5256,7 @@[m [mbool CHARACTER::UseItem(TItemPos Cell, TItemPos DestCell)[m
 [m
 	if (false == FN_check_item_sex(this, item))[m
 	{[m
[31m-		ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¼ºº°ÀÌ ¸ÂÁö¾Ê¾Æ ÀÌ ¾ÆÀÌÅÛÀ» »ç¿ëÇÒ ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m		[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ê¾ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 		return false;[m
 	}[m
 [m
[36m@@ -5253,43 +5265,43 @@[m [mbool CHARACTER::UseItem(TItemPos Cell, TItemPos DestCell)[m
 	{[m
 		if (false == IS_SUMMONABLE_ZONE(GetMapIndex()))[m
 		{[m
[31m-			ChatPacket(CHAT_TYPE_INFO, LC_TEXT("»ç¿ëÇÒ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m			[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½Ò¼ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 			return false;[m
 		}[m
 [m
[31m-		// °æÈ¥¹ÝÁö »ç¿ëÁö »ó´ë¹æÀÌ SUMMONABLE_ZONE¿¡ ÀÖ´Â°¡´Â WarpToPC()¿¡¼­ Ã¼Å©[m
[32m+[m		[32m// ï¿½ï¿½È¥ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ SUMMONABLE_ZONEï¿½ï¿½ ï¿½Ö´Â°ï¿½ï¿½ï¿½ WarpToPC()ï¿½ï¿½ï¿½ï¿½ Ã¼Å©[m
 		[m
[31m-		//»ï°Å¸® °ü·Á ¸Ê¿¡¼­´Â ±ÍÈ¯ºÎ¸¦ ¸·¾Æ¹ö¸°´Ù.[m
[32m+[m		[32m//ï¿½ï¿½Å¸ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½Ê¿ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½È¯ï¿½Î¸ï¿½ ï¿½ï¿½ï¿½Æ¹ï¿½ï¿½ï¿½ï¿½ï¿½.[m
 		if (CThreeWayWar::instance().IsThreeWayWarMapIndex(GetMapIndex()))[m
 		{[m
[31m-			ChatPacket(CHAT_TYPE_INFO, LC_TEXT("»ï°Å¸® ÀüÅõ Âü°¡Áß¿¡´Â ±ÍÈ¯ºÎ,±ÍÈ¯±â¾ïºÎ¸¦ »ç¿ëÇÒ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m			[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½Å¸ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ß¿ï¿½ï¿½ï¿½ ï¿½ï¿½È¯ï¿½ï¿½,ï¿½ï¿½È¯ï¿½ï¿½ï¿½Î¸ï¿½ ï¿½ï¿½ï¿½ï¿½Ò¼ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 			return false;[m
 		}[m
 		int iPulse = thecore_pulse();[m
 [m
[31m-		//Ã¢°í ¿¬ÈÄ Ã¼Å©[m
[32m+[m		[32m//Ã¢ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ Ã¼Å©[m
 		if (iPulse - GetSafeboxLoadTime() < PASSES_PER_SEC(g_nPortalLimitTime))[m
 		{[m
[31m-			ChatPacket(CHAT_TYPE_INFO, LC_TEXT("Ã¢°í¸¦ ¿¬ÈÄ %dÃÊ ÀÌ³»¿¡´Â ±ÍÈ¯ºÎ,±ÍÈ¯±â¾ïºÎ¸¦ »ç¿ëÇÒ ¼ö ¾ø½À´Ï´Ù."), g_nPortalLimitTime);[m
[32m+[m			[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("Ã¢ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ %dï¿½ï¿½ ï¿½Ì³ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½È¯ï¿½ï¿½,ï¿½ï¿½È¯ï¿½ï¿½ï¿½Î¸ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."), g_nPortalLimitTime);[m
 [m
 			if (test_server)[m
 				ChatPacket(CHAT_TYPE_INFO, "[TestOnly]Pulse %d LoadTime %d PASS %d", iPulse, GetSafeboxLoadTime(), PASSES_PER_SEC(g_nPortalLimitTime));[m
 			return false; [m
 		}[m
 [m
[31m-		//°Å·¡°ü·Ã Ã¢ Ã¼Å©[m
[32m+[m		[32m//ï¿½Å·ï¿½ï¿½ï¿½ï¿½ï¿½ Ã¢ Ã¼Å©[m
 		if (GetExchange() || GetMyShop() || GetShopOwner() || IsOpenSafebox() || IsCubeOpen())[m
 		{[m
[31m-			ChatPacket(CHAT_TYPE_INFO, LC_TEXT("°Å·¡Ã¢,Ã¢°í µîÀ» ¿¬ »óÅÂ¿¡¼­´Â ±ÍÈ¯ºÎ,±ÍÈ¯±â¾ïºÎ ¸¦ »ç¿ëÇÒ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m			[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½Å·ï¿½Ã¢,Ã¢ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½Â¿ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½È¯ï¿½ï¿½,ï¿½ï¿½È¯ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½Ò¼ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 			return false;[m
 		}[m
 [m
 		//PREVENT_REFINE_HACK[m
[31m-		//°³·®ÈÄ ½Ã°£Ã¼Å© [m
[32m+[m		[32m//ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ã°ï¿½Ã¼Å©[m[41m [m
 		{[m
 			if (iPulse - GetRefineTime() < PASSES_PER_SEC(g_nPortalLimitTime))[m
 			{[m
[31m-				ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¾ÆÀÌÅÛ °³·®ÈÄ %dÃÊ ÀÌ³»¿¡´Â ±ÍÈ¯ºÎ,±ÍÈ¯±â¾ïºÎ¸¦ »ç¿ëÇÒ ¼ö ¾ø½À´Ï´Ù."), g_nPortalLimitTime);[m
[32m+[m				[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ %dï¿½ï¿½ ï¿½Ì³ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½È¯ï¿½ï¿½,ï¿½ï¿½È¯ï¿½ï¿½ï¿½Î¸ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."), g_nPortalLimitTime);[m
 				return false;[m
 			}[m
 		}[m
[36m@@ -5300,7 +5312,7 @@[m [mbool CHARACTER::UseItem(TItemPos Cell, TItemPos DestCell)[m
 		{[m
 			if (iPulse - GetMyShopTime() < PASSES_PER_SEC(g_nPortalLimitTime))[m
 			{[m
[31m-				ChatPacket(CHAT_TYPE_INFO, LC_TEXT("°³ÀÎ»óÁ¡ »ç¿ëÈÄ %dÃÊ ÀÌ³»¿¡´Â ±ÍÈ¯ºÎ,±ÍÈ¯±â¾ïºÎ¸¦ »ç¿ëÇÒ ¼ö ¾ø½À´Ï´Ù."), g_nPortalLimitTime);[m
[32m+[m				[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½Î»ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ %dï¿½ï¿½ ï¿½Ì³ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½È¯ï¿½ï¿½,ï¿½ï¿½È¯ï¿½ï¿½ï¿½Î¸ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."), g_nPortalLimitTime);[m
 				return false;[m
 			}[m
 			[m
[36m@@ -5308,7 +5320,7 @@[m [mbool CHARACTER::UseItem(TItemPos Cell, TItemPos DestCell)[m
 		//END_PREVENT_ITEM_COPY[m
 		[m
 [m
[31m-		//±ÍÈ¯ºÎ °Å¸®Ã¼Å©[m
[32m+[m		[32m//ï¿½ï¿½È¯ï¿½ï¿½ ï¿½Å¸ï¿½Ã¼Å©[m
 		if (item->GetVnum() != 70302)[m
 		{[m
 			PIXEL_POSITION posWarp;[m
[36m@@ -5318,13 +5330,13 @@[m [mbool CHARACTER::UseItem(TItemPos Cell, TItemPos DestCell)[m
 [m
 			double nDist = 0;[m
 			const double nDistant = 5000.0;[m
[31m-			//±ÍÈ¯±â¾ïºÎ [m
[32m+[m			[32m//ï¿½ï¿½È¯ï¿½ï¿½ï¿½ï¿½[m[41m [m
 			if (item->GetVnum() == 22010)[m
 			{[m
 				x = item->GetSocket(0) - GetX();[m
 				y = item->GetSocket(1) - GetY();[m
 			}[m
[31m-			//±ÍÈ¯ºÎ[m
[32m+[m			[32m//ï¿½ï¿½È¯ï¿½ï¿½[m
 			else if (item->GetVnum() == 22000) [m
 			{[m
 				SECTREE_MANAGER::instance().GetRecallPositionByEmpire(GetMapIndex(), GetEmpire(), posWarp);[m
[36m@@ -5345,7 +5357,7 @@[m [mbool CHARACTER::UseItem(TItemPos Cell, TItemPos DestCell)[m
 [m
 			if (nDistant > nDist)[m
 			{[m
[31m-				ChatPacket(CHAT_TYPE_INFO, LC_TEXT("ÀÌµ¿ µÇ¾îÁú À§Ä¡¿Í ³Ê¹« °¡±î¿ö ±ÍÈ¯ºÎ¸¦ »ç¿ëÇÒ¼ö ¾ø½À´Ï´Ù."));				[m
[32m+[m				[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½Ìµï¿½ ï¿½Ç¾ï¿½ï¿½ï¿½ ï¿½ï¿½Ä¡ï¿½ï¿½ ï¿½Ê¹ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½È¯ï¿½Î¸ï¿½ ï¿½ï¿½ï¿½ï¿½Ò¼ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m[41m				[m
 				if (test_server)[m
 					ChatPacket(CHAT_TYPE_INFO, "PossibleDistant %f nNowDist %f", nDistant,nDist); [m
 				return false;[m
[36m@@ -5353,29 +5365,29 @@[m [mbool CHARACTER::UseItem(TItemPos Cell, TItemPos DestCell)[m
 		}[m
 [m
 		//PREVENT_PORTAL_AFTER_EXCHANGE[m
[31m-		//±³È¯ ÈÄ ½Ã°£Ã¼Å©[m
[32m+[m		[32m//ï¿½ï¿½È¯ ï¿½ï¿½ ï¿½Ã°ï¿½Ã¼Å©[m
 		if (iPulse - GetExchangeTime()  < PASSES_PER_SEC(g_nPortalLimitTime))[m
 		{[m
[31m-			ChatPacket(CHAT_TYPE_INFO, LC_TEXT("°Å·¡ ÈÄ %dÃÊ ÀÌ³»¿¡´Â ±ÍÈ¯ºÎ,±ÍÈ¯±â¾ïºÎµîÀ» »ç¿ëÇÒ ¼ö ¾ø½À´Ï´Ù."), g_nPortalLimitTime);[m
[32m+[m			[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½Å·ï¿½ ï¿½ï¿½ %dï¿½ï¿½ ï¿½Ì³ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½È¯ï¿½ï¿½,ï¿½ï¿½È¯ï¿½ï¿½ï¿½Îµï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."), g_nPortalLimitTime);[m
 			return false;[m
 		}[m
 		//END_PREVENT_PORTAL_AFTER_EXCHANGE[m
 [m
 	}[m
 [m
[31m-	//º¸µû¸® ºñ´Ü »ç¿ë½Ã °Å·¡Ã¢ Á¦ÇÑ Ã¼Å© [m
[32m+[m	[32m//ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½Å·ï¿½Ã¢ ï¿½ï¿½ï¿½ï¿½ Ã¼Å©[m[41m [m
 	if (item->GetVnum() == 50200 | item->GetVnum() == 71049)[m
 	{[m
 		if (GetExchange() || GetMyShop() || GetShopOwner() || IsOpenSafebox() || IsCubeOpen())[m
 		{[m
[31m-			ChatPacket(CHAT_TYPE_INFO, LC_TEXT("°Å·¡Ã¢,Ã¢°í µîÀ» ¿¬ »óÅÂ¿¡¼­´Â º¸µû¸®,ºñ´Üº¸µû¸®¸¦ »ç¿ëÇÒ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m			[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½Å·ï¿½Ã¢,Ã¢ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½Â¿ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½,ï¿½ï¿½Üºï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½Ò¼ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 			return false;[m
 		}[m
 [m
 	}[m
 	//END_PREVENT_TRADE_WINDOW[m
 [m
[31m-	if (IS_SET(item->GetFlag(), ITEM_FLAG_LOG)) // »ç¿ë ·Î±×¸¦ ³²±â´Â ¾ÆÀÌÅÛ Ã³¸®[m
[32m+[m	[32mif (IS_SET(item->GetFlag(), ITEM_FLAG_LOG)) // ï¿½ï¿½ï¿½ ï¿½Î±×¸ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ Ã³ï¿½ï¿½[m
 	{[m
 		DWORD vid = item->GetVID();[m
 		DWORD oldCount = item->GetCount();[m
[36m@@ -5389,7 +5401,7 @@[m [mbool CHARACTER::UseItem(TItemPos Cell, TItemPos DestCell)[m
 [m
 		bool ret = UseItemEx(item, DestCell);[m
 [m
[31m-		if (NULL == ITEM_MANAGER::instance().FindByVID(vid)) // UseItemEx¿¡¼­ ¾ÆÀÌÅÛÀÌ »èÁ¦ µÇ¾ú´Ù. »èÁ¦ ·Î±×¸¦ ³²±è[m
[32m+[m		[32mif (NULL == ITEM_MANAGER::instance().FindByVID(vid)) // UseItemExï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½Ç¾ï¿½ï¿½ï¿½. ï¿½ï¿½ï¿½ï¿½ ï¿½Î±×¸ï¿½ ï¿½ï¿½ï¿½ï¿½[m
 		{[m
 			LogManager::instance().ItemLog(this, vid, vnum, "REMOVE", hint);[m
 		}[m
[36m@@ -5409,7 +5421,7 @@[m [mbool CHARACTER::DestroyItem(TItemPos Cell)[m
     if (!CanHandleItem())[m
     {[m
         if (NULL != DragonSoul_RefineWindow_GetOpener())[m
[31m-            ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¡Æ*E*A¡ËA¡í ¢¯¡þ ¡íoAA¢¯¢®¨ù*¢¥A ¨ú¨¡AIAUA¡í ¢¯A¡¾©¡ ¨ùo ¨ú©ª¨öA¢¥I¢¥U."));[m
[32m+[m[32m            ChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½*E*Aï¿½ï¿½Aï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½oAAï¿½ï¿½ï¿½ï¿½ï¿½ï¿½*ï¿½ï¿½A ï¿½ï¿½ï¿½ï¿½AIAUAï¿½ï¿½ ï¿½ï¿½Aï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½o ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½Aï¿½ï¿½Iï¿½ï¿½U."));[m
         return false;[m
     }[m
     if (IsDead())[m
[36m@@ -5437,7 +5449,7 @@[m [mbool CHARACTER::DropItem(TItemPos Cell, WORD bCount)[m
 	if (!CanHandleItem())[m
 	{[m
 		if (NULL != DragonSoul_RefineWindow_GetOpener())[m
[31m-			ChatPacket(CHAT_TYPE_INFO, LC_TEXT("°­È­Ã¢À» ¿¬ »óÅÂ¿¡¼­´Â ¾ÆÀÌÅÛÀ» ¿Å±æ ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m			[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½È­Ã¢ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½Â¿ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Å±ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 		return false;[m
 	}[m
 [m
[36m@@ -5458,14 +5470,14 @@[m [mbool CHARACTER::DropItem(TItemPos Cell, WORD bCount)[m
 [m
 	if (IS_SET(item->GetAntiFlag(), ITEM_ANTIFLAG_DROP | ITEM_ANTIFLAG_GIVE))[m
 	{[m
[31m-		ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¹ö¸± ¼ö ¾ø´Â ¾ÆÀÌÅÛÀÔ´Ï´Ù."));[m
[32m+[m		[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½Ô´Ï´ï¿½."));[m
 		return false;[m
 	}[m
 [m
 	if (bCount == 0 || bCount > item->GetCount())[m
 		bCount = item->GetCount();[m
 [m
[31m-	SyncQuickslot(QUICKSLOT_TYPE_ITEM, Cell.cell, 255);	// Quickslot ¿¡¼­ Áö¿ò[m
[32m+[m	[32mSyncQuickslot(QUICKSLOT_TYPE_ITEM, Cell.cell, 255);	// Quickslot ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½[m
 [m
 	LPITEM pkItemToDrop;[m
 [m
[36m@@ -5520,12 +5532,12 @@[m [mbool CHARACTER::DropItem(TItemPos Cell, WORD bCount)[m
 [m
 	if (pkItemToDrop->AddToGround(GetMapIndex(), pxPos))[m
 	{[m
[31m-		// ÇÑ±¹¿¡´Â ¾ÆÀÌÅÛÀ» ¹ö¸®°í º¹±¸ÇØ´Þ¶ó´Â Áø»óÀ¯ÀúµéÀÌ ¸¹¾Æ¼­[m
[31m-		// ¾ÆÀÌÅÛÀ» ¹Ù´Ú¿¡ ¹ö¸± ½Ã ¼Ó¼º·Î±×¸¦ ³²±ä´Ù.[m
[32m+[m		[32m// ï¿½Ñ±ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ø´Þ¶ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Æ¼ï¿½[m
[32m+[m		[32m// ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ù´Ú¿ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½Ó¼ï¿½ï¿½Î±×¸ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½.[m
 		if (LC_IsYMIR())[m
 			item->AttrLog();[m
 [m
[31m-		ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¶³¾îÁø ¾ÆÀÌÅÛÀº 3ºÐ ÈÄ »ç¶óÁý´Ï´Ù."));[m
[32m+[m		[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ 3ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 		pkItemToDrop->StartDestroyEvent();[m
 [m
 		ITEM_MANAGER::instance().FlushDelayedSave(pkItemToDrop);[m
[36m@@ -5555,7 +5567,7 @@[m [mbool CHARACTER::DropGold(int gold)[m
 	{[m
 		if (get_dword_time() < m_dwLastGoldDropTime+g_GoldDropTimeLimitValue)[m
 		{[m
[31m-			ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¾ÆÁ÷ °ñµå¸¦ ¹ö¸± ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m			[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½å¸¦ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 			return false;[m
 		}[m
 	}[m
[36m@@ -5573,11 +5585,11 @@[m [mbool CHARACTER::DropGold(int gold)[m
 			//Motion(MOTION_PICKUP);[m
 			PointChange(POINT_GOLD, -gold, true);[m
 [m
[31m-			// ºê¶óÁú¿¡ µ·ÀÌ ¾ø¾îÁø´Ù´Â ¹ö±×°¡ ÀÖ´Âµ¥,[m
[31m-			// °¡´ÉÇÑ ½Ã³ª¸®¿À Áß¿¡ ÇÏ³ª´Â,[m
[31m-			// ¸ÞÅ©·Î³ª, ÇÙÀ» ½á¼­ 1000¿ø ÀÌÇÏÀÇ µ·À» °è¼Ó ¹ö·Á °ñµå¸¦ 0À¸·Î ¸¸µé°í, [m
[31m-			// µ·ÀÌ ¾ø¾îÁ³´Ù°í º¹±¸ ½ÅÃ»ÇÏ´Â °ÍÀÏ ¼öµµ ÀÖ´Ù.[m
[31m-			// µû¶ó¼­ ±×·± °æ¿ì¸¦ Àâ±â À§ÇØ ³·Àº ¼öÄ¡ÀÇ °ñµå¿¡ ´ëÇØ¼­µµ ·Î±×¸¦ ³²±è.[m
[32m+[m			[32m// ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½Ù´ï¿½ ï¿½ï¿½ï¿½×°ï¿½ ï¿½Ö´Âµï¿½,[m
[32m+[m			[32m// ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ã³ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ß¿ï¿½ ï¿½Ï³ï¿½ï¿½ï¿½,[m
[32m+[m			[32m// ï¿½ï¿½Å©ï¿½Î³ï¿½, ï¿½ï¿½ï¿½ï¿½ ï¿½á¼­ 1000ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½å¸¦ 0ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½,[m[41m [m
[32m+[m			[32m// ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½Ù°ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½Ã»ï¿½Ï´ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½Ö´ï¿½.[m
[32m+[m			[32m// ï¿½ï¿½ï¿½ï¿½ ï¿½×·ï¿½ ï¿½ï¿½ì¸¦ ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½Ä¡ï¿½ï¿½ ï¿½ï¿½å¿¡ ï¿½ï¿½ï¿½Ø¼ï¿½ï¿½ï¿½ ï¿½Î±×¸ï¿½ ï¿½ï¿½ï¿½ï¿½.[m
 			if (LC_IsBrazil() == true)[m
 			{[m
 				if (gold >= 213)[m
[36m@@ -5585,19 +5597,19 @@[m [mbool CHARACTER::DropGold(int gold)[m
 			}[m
 			else[m
 			{[m
[31m-				if (gold > 1000) // Ãµ¿ø ÀÌ»ó¸¸ ±â·ÏÇÑ´Ù.[m
[32m+[m				[32mif (gold > 1000) // Ãµï¿½ï¿½ ï¿½Ì»ï¿½ ï¿½ï¿½ï¿½ï¿½Ñ´ï¿½.[m
 					LogManager::instance().CharLog(this, gold, "DROP_GOLD", "");[m
 			}[m
 [m
 			if (false == LC_IsBrazil())[m
 			{[m
 				item->StartDestroyEvent(150);[m
[31m-				ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¶³¾îÁø ¾ÆÀÌÅÛÀº %dºÐ ÈÄ »ç¶óÁý´Ï´Ù."), 150/60);[m
[32m+[m				[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ %dï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."), 150/60);[m
 			}[m
 			else[m
 			{[m
 				item->StartDestroyEvent(60);[m
[31m-				ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¶³¾îÁø ¾ÆÀÌÅÛÀº %dºÐ ÈÄ »ç¶óÁý´Ï´Ù."), 1);[m
[32m+[m				[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ %dï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."), 1);[m
 			}[m
 		}[m
 [m
[36m@@ -5641,7 +5653,7 @@[m [mbool CHARACTER::MoveItem(TItemPos Cell, TItemPos DestCell, WORD count)[m
 	if (!CanHandleItem())[m
 	{[m
 		if (NULL != DragonSoul_RefineWindow_GetOpener())[m
[31m-			ChatPacket(CHAT_TYPE_INFO, LC_TEXT("°­È­Ã¢À» ¿¬ »óÅÂ¿¡¼­´Â ¾ÆÀÌÅÛÀ» ¿Å±æ ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m			[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½È­Ã¢ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½Â¿ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Å±ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 		return false;[m
 	}[m
 [m
[36m@@ -5654,7 +5666,7 @@[m [mbool CHARACTER::MoveItem(TItemPos Cell, TItemPos DestCell, WORD count)[m
 [m
 	if (DestCell.IsBeltInventoryPosition() && false == CBeltInventoryHelper::CanMoveIntoBeltInventory(item))[m
 	{[m
[31m-		ChatPacket(CHAT_TYPE_INFO, LC_TEXT("ÀÌ ¾ÆÀÌÅÛÀº º§Æ® ÀÎº¥Åä¸®·Î ¿Å±æ ¼ö ¾ø½À´Ï´Ù."));			[m
[32m+[m		[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½Æ® ï¿½Îºï¿½ï¿½ä¸®ï¿½ï¿½ ï¿½Å±ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m[41m			[m
 		return false;[m
 	}[m
 [m
[36m@@ -5679,9 +5691,9 @@[m [mbool CHARACTER::MoveItem(TItemPos Cell, TItemPos DestCell, WORD count)[m
 [m
 	if (DestCell.IsEquipPosition())[m
 	{[m
[31m-		if (GetItem(DestCell))	// ÀåºñÀÏ °æ¿ì ÇÑ °÷¸¸ °Ë»çÇØµµ µÈ´Ù.[m
[32m+[m		[32mif (GetItem(DestCell))	// ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½Ë»ï¿½ï¿½Øµï¿½ ï¿½È´ï¿½.[m
 		{[m
[31m-			ChatPacket(CHAT_TYPE_INFO, LC_TEXT("ÀÌ¹Ì Àåºñ¸¦ Âø¿ëÇÏ°í ÀÖ½À´Ï´Ù."));[m
[32m+[m			[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½Ì¹ï¿½ ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï°ï¿½ ï¿½Ö½ï¿½ï¿½Ï´ï¿½."));[m
 			[m
 			return false;[m
 		}[m
[36m@@ -5707,7 +5719,7 @@[m [mbool CHARACTER::MoveItem(TItemPos Cell, TItemPos DestCell, WORD count)[m
 					return false;[m
 			}[m
 		}[m
[31m-		// ¿ëÈ¥¼®ÀÌ ¾Æ´Ñ ¾ÆÀÌÅÛÀº ¿ëÈ¥¼® ÀÎº¥¿¡ µé¾î°¥ ¼ö ¾ø´Ù.[m
[32m+[m		[32m// ï¿½ï¿½È¥ï¿½ï¿½ï¿½ï¿½ ï¿½Æ´ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½È¥ï¿½ï¿½ ï¿½Îºï¿½ï¿½ï¿½ ï¿½ï¿½î°¥ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½.[m
 		else if (DRAGON_SOUL_INVENTORY == DestCell.window_type)[m
 			return false;[m
 [m
[36m@@ -5715,7 +5727,7 @@[m [mbool CHARACTER::MoveItem(TItemPos Cell, TItemPos DestCell, WORD count)[m
 [m
 		if ((item2 = GetItem(DestCell)) && item != item2 && item2->IsStackable() &&[m
 				!IS_SET(item2->GetAntiFlag(), ITEM_ANTIFLAG_STACK) &&[m
[31m-				item2->GetVnum() == item->GetVnum()) // ÇÕÄ¥ ¼ö ÀÖ´Â ¾ÆÀÌÅÛÀÇ °æ¿ì[m
[32m+[m				[32mitem2->GetVnum() == item->GetVnum()) // ï¿½ï¿½Ä¥ ï¿½ï¿½ ï¿½Ö´ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½[m
 		{[m
 			for (int i = 0; i < ITEM_SOCKET_MAX_NUM; ++i)[m
 				if (item2->GetSocket(i) != item->GetSocket(i))[m
[36m@@ -5743,7 +5755,11 @@[m [mbool CHARACTER::MoveItem(TItemPos Cell, TItemPos DestCell, WORD count)[m
 				DestCell.window_type, DestCell.cell, count);[m
 			[m
 			item->RemoveFromCharacter();[m
[32m+[m[32m#if defined(__BL_ENABLE_PICKUP_ITEM_EFFECT__)[m
[32m+[m			[32mSetItem(DestCell, item, false);[m
[32m+[m[32m#else[m
 			SetItem(DestCell, item);[m
[32m+[m[32m#endif[m
 [m
 			if (INVENTORY == Cell.window_type && INVENTORY == DestCell.window_type)[m
 				SyncQuickslot(QUICKSLOT_TYPE_ITEM, Cell.cell, DestCell.cell);[m
[36m@@ -5768,7 +5784,11 @@[m [mbool CHARACTER::MoveItem(TItemPos Cell, TItemPos DestCell, WORD count)[m
 			// copy socket -- by mhh[m
 			FN_copy_item_socket(item2, item);[m
 [m
[32m+[m[32m#if defined(__BL_ENABLE_PICKUP_ITEM_EFFECT__)[m
[32m+[m			[32mitem2->AddToCharacter(this, DestCell, false);[m
[32m+[m[32m#else[m
 			item2->AddToCharacter(this, DestCell);[m
[32m+[m[32m#endif[m
 [m
 			char szBuf[51+1];[m
 			snprintf(szBuf, sizeof(szBuf), "%u %u %u %u ", item2->GetID(), item2->GetCount(), item->GetCount(), item->GetCount() + item2->GetCount());[m
[36m@@ -5834,7 +5854,7 @@[m [mnamespace NPartyPickupDistribute[m
 				{[m
 					ch->PointChange(POINT_GOLD, iMoney, true);[m
 [m
[31m-					if (iMoney > 1000) // Ãµ¿ø ÀÌ»ó¸¸ ±â·ÏÇÑ´Ù.[m
[32m+[m					[32mif (iMoney > 1000) // Ãµï¿½ï¿½ ï¿½Ì»ï¿½ ï¿½ï¿½ï¿½ï¿½Ñ´ï¿½.[m
 						LogManager::instance().CharLog(ch, iMoney, "GET_GOLD", "");[m
 				}[m
 		}[m
[36m@@ -5852,7 +5872,7 @@[m [mvoid CHARACTER::GiveGold(int iAmount)[m
 	{[m
 		LPPARTY pParty = GetParty();[m
 [m
[31m-		// ÆÄÆ¼°¡ ÀÖ´Â °æ¿ì ³ª´©¾î °¡Áø´Ù.[m
[32m+[m		[32m// ï¿½ï¿½Æ¼ï¿½ï¿½ ï¿½Ö´ï¿½ ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½.[m
 		DWORD dwTotal = iAmount;[m
 		DWORD dwMyAmount = dwTotal;[m
 [m
[36m@@ -5871,18 +5891,18 @@[m [mvoid CHARACTER::GiveGold(int iAmount)[m
 [m
 		PointChange(POINT_GOLD, dwMyAmount, true);[m
 [m
[31m-		if (dwMyAmount > 1000) // Ãµ¿ø ÀÌ»ó¸¸ ±â·ÏÇÑ´Ù.[m
[32m+[m		[32mif (dwMyAmount > 1000) // Ãµï¿½ï¿½ ï¿½Ì»ï¿½ ï¿½ï¿½ï¿½ï¿½Ñ´ï¿½.[m
 			LogManager::instance().CharLog(this, dwMyAmount, "GET_GOLD", "");[m
 	}[m
 	else[m
 	{[m
 		PointChange(POINT_GOLD, iAmount, true);[m
 [m
[31m-		// ºê¶óÁú¿¡ µ·ÀÌ ¾ø¾îÁø´Ù´Â ¹ö±×°¡ ÀÖ´Âµ¥,[m
[31m-		// °¡´ÉÇÑ ½Ã³ª¸®¿À Áß¿¡ ÇÏ³ª´Â,[m
[31m-		// ¸ÞÅ©·Î³ª, ÇÙÀ» ½á¼­ 1000¿ø ÀÌÇÏÀÇ µ·À» °è¼Ó ¹ö·Á °ñµå¸¦ 0À¸·Î ¸¸µé°í, [m
[31m-		// µ·ÀÌ ¾ø¾îÁ³´Ù°í º¹±¸ ½ÅÃ»ÇÏ´Â °ÍÀÏ ¼öµµ ÀÖ´Ù.[m
[31m-		// µû¶ó¼­ ±×·± °æ¿ì¸¦ Àâ±â À§ÇØ ³·Àº ¼öÄ¡ÀÇ °ñµå¿¡ ´ëÇØ¼­µµ ·Î±×¸¦ ³²±è.[m
[32m+[m		[32m// ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½Ù´ï¿½ ï¿½ï¿½ï¿½×°ï¿½ ï¿½Ö´Âµï¿½,[m
[32m+[m		[32m// ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ã³ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ß¿ï¿½ ï¿½Ï³ï¿½ï¿½ï¿½,[m
[32m+[m		[32m// ï¿½ï¿½Å©ï¿½Î³ï¿½, ï¿½ï¿½ï¿½ï¿½ ï¿½á¼­ 1000ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½å¸¦ 0ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½,[m[41m [m
[32m+[m		[32m// ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½Ù°ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½Ã»ï¿½Ï´ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½Ö´ï¿½.[m
[32m+[m		[32m// ï¿½ï¿½ï¿½ï¿½ ï¿½×·ï¿½ ï¿½ï¿½ì¸¦ ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½Ä¡ï¿½ï¿½ ï¿½ï¿½å¿¡ ï¿½ï¿½ï¿½Ø¼ï¿½ï¿½ï¿½ ï¿½Î±×¸ï¿½ ï¿½ï¿½ï¿½ï¿½.[m
 		if (LC_IsBrazil() == true)[m
 		{[m
 			if (iAmount >= 213)[m
[36m@@ -5890,7 +5910,7 @@[m [mvoid CHARACTER::GiveGold(int iAmount)[m
 		}[m
 		else[m
 		{[m
[31m-			if (iAmount > 1000) // Ãµ¿ø ÀÌ»ó¸¸ ±â·ÏÇÑ´Ù.[m
[32m+[m			[32mif (iAmount > 1000) // Ãµï¿½ï¿½ ï¿½Ì»ï¿½ ï¿½ï¿½ï¿½ï¿½Ñ´ï¿½.[m
 				LogManager::instance().CharLog(this, iAmount, "GET_GOLD", "");[m
 		}[m
 	}[m
[36m@@ -5910,7 +5930,7 @@[m [mbool CHARACTER::PickupItem(DWORD dwVID)[m
 	{[m
 		if (item->IsOwnership(this))[m
 		{[m
[31m-			// ¸¸¾à ÁÖÀ¸·Á ÇÏ´Â ¾ÆÀÌÅÛÀÌ ¿¤Å©¶ó¸é[m
[32m+[m			[32m// ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ï´ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½Å©ï¿½ï¿½ï¿½[m
 			if (item->GetType() == ITEM_ELK)[m
 			{[m
 				GiveGold(item->GetCount());[m
[36m@@ -5920,7 +5940,7 @@[m [mbool CHARACTER::PickupItem(DWORD dwVID)[m
 [m
 				Save();[m
 			}[m
[31m-			// Æò¹üÇÑ ¾ÆÀÌÅÛÀÌ¶ó¸é[m
[32m+[m			[32m// ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½Ì¶ï¿½ï¿½[m
 			else[m
 			{[m
 				if (item->IsStackable() && !IS_SET(item->GetAntiFlag(), ITEM_ANTIFLAG_STACK))[m
[36m@@ -5956,7 +5976,7 @@[m [mbool CHARACTER::PickupItem(DWORD dwVID)[m
 [m
 							if (bCount == 0)[m
 							{[m
[31m-								ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¾ÆÀÌÅÛ È¹µæ: %s"), item2->GetName());[m
[32m+[m								[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ È¹ï¿½ï¿½: %s"), item2->GetName());[m
 								M2_DESTROY_ITEM(item);[m
 								if (item2->GetType() == ITEM_QUEST)[m
 									quest::CQuestManager::instance().PickupItem (GetPlayerID(), item2);[m
[36m@@ -5977,7 +5997,7 @@[m [mbool CHARACTER::PickupItem(DWORD dwVID)[m
 					if ((iEmptyCell = GetEmptyDragonSoulInventory(item)) == -1)[m
 					{[m
 						sys_log(0, "No empty ds inventory pid %u size %ud itemid %u", GetPlayerID(), item->GetSize(), item->GetID());[m
[31m-						ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¼ÒÁöÇÏ°í ÀÖ´Â ¾ÆÀÌÅÛÀÌ ³Ê¹« ¸¹½À´Ï´Ù."));[m
[32m+[m						[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½Ï°ï¿½ ï¿½Ö´ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ê¹ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 						return false;[m
 					}[m
 				}[m
[36m@@ -5986,7 +6006,7 @@[m [mbool CHARACTER::PickupItem(DWORD dwVID)[m
 					if ((iEmptyCell = GetEmptyInventory(item->GetSize())) == -1)[m
 					{[m
 						sys_log(0, "No empty inventory pid %u size %ud itemid %u", GetPlayerID(), item->GetSize(), item->GetID());[m
[31m-						ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¼ÒÁöÇÏ°í ÀÖ´Â ¾ÆÀÌÅÛÀÌ ³Ê¹« ¸¹½À´Ï´Ù."));[m
[32m+[m						[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½Ï°ï¿½ ï¿½Ö´ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ê¹ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 						return false;[m
 					}[m
 				}[m
[36m@@ -6004,7 +6024,7 @@[m [mbool CHARACTER::PickupItem(DWORD dwVID)[m
 #ifdef __FARM_SESSION_SYSTEM__[m
 			CFarmSessionManager::instance().OnItemReceived(this, item->GetOriginalVnum(), item->GetCount());[m
 #endif[m
[31m-				ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¾ÆÀÌÅÛ È¹µæ: %s"), item->GetName());[m
[32m+[m				[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ È¹ï¿½ï¿½: %s"), item->GetName());[m
 [m
 				if (item->GetType() == ITEM_QUEST)[m
 					quest::CQuestManager::instance().PickupItem (GetPlayerID(), item);[m
[36m@@ -6015,7 +6035,7 @@[m [mbool CHARACTER::PickupItem(DWORD dwVID)[m
 		}[m
 		else if (!IS_SET(item->GetAntiFlag(), ITEM_ANTIFLAG_GIVE | ITEM_ANTIFLAG_DROP) && GetParty())[m
 		{[m
[31m-			// ´Ù¸¥ ÆÄÆ¼¿ø ¼ÒÀ¯±Ç ¾ÆÀÌÅÛÀ» ÁÖÀ¸·Á°í ÇÑ´Ù¸é[m
[32m+[m			[32m// ï¿½Ù¸ï¿½ ï¿½ï¿½Æ¼ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ñ´Ù¸ï¿½[m
 			NPartyPickupDistribute::FFindOwnership funcFindOwnership(item);[m
 [m
 			GetParty()->ForEachOnlineMember(funcFindOwnership);[m
[36m@@ -6032,7 +6052,7 @@[m [mbool CHARACTER::PickupItem(DWORD dwVID)[m
 [m
 					if ((iEmptyCell = GetEmptyDragonSoulInventory(item)) == -1)[m
 					{[m
[31m-						owner->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¼ÒÁöÇÏ°í ÀÖ´Â ¾ÆÀÌÅÛÀÌ ³Ê¹« ¸¹½À´Ï´Ù."));[m
[32m+[m						[32mowner->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½Ï°ï¿½ ï¿½Ö´ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ê¹ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 						return false;[m
 					}[m
 				}[m
[36m@@ -6045,7 +6065,7 @@[m [mbool CHARACTER::PickupItem(DWORD dwVID)[m
 [m
 					if ((iEmptyCell = GetEmptyInventory(item->GetSize())) == -1)[m
 					{[m
[31m-						owner->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¼ÒÁöÇÏ°í ÀÖ´Â ¾ÆÀÌÅÛÀÌ ³Ê¹« ¸¹½À´Ï´Ù."));[m
[32m+[m						[32mowner->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½Ï°ï¿½ ï¿½Ö´ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ê¹ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 						return false;[m
 					}[m
 				}[m
[36m@@ -6066,11 +6086,11 @@[m [mbool CHARACTER::PickupItem(DWORD dwVID)[m
 #endif[m
 [m
 			if (owner == this)[m
[31m-				ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¾ÆÀÌÅÛ È¹µæ: %s"), item->GetName());[m
[32m+[m				[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ È¹ï¿½ï¿½: %s"), item->GetName());[m
 			else[m
 			{[m
[31m-				owner->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¾ÆÀÌÅÛ È¹µæ: %s ´ÔÀ¸·ÎºÎÅÍ %s"), GetName(), item->GetName());[m
[31m-				ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¾ÆÀÌÅÛ Àü´Þ: %s ´Ô¿¡°Ô %s"), owner->GetName(), item->GetName());[m
[32m+[m				[32mowner->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ È¹ï¿½ï¿½: %s ï¿½ï¿½ï¿½ï¿½ï¿½Îºï¿½ï¿½ï¿½ %s"), GetName(), item->GetName());[m
[32m+[m				[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½: %s ï¿½Ô¿ï¿½ï¿½ï¿½ %s"), owner->GetName(), item->GetName());[m
 			}[m
 [m
 			if (item->GetType() == ITEM_QUEST)[m
[36m@@ -6090,23 +6110,23 @@[m [mbool CHARACTER::SwapItem(BYTE bCell, BYTE bDestCell)[m
 [m
 	TItemPos srcCell(INVENTORY, bCell), destCell(INVENTORY, bDestCell);[m
 [m
[31m-	// ¿Ã¹Ù¸¥ Cell ÀÎÁö °Ë»ç[m
[31m-	// ¿ëÈ¥¼®Àº SwapÇÒ ¼ö ¾øÀ¸¹Ç·Î, ¿©±â¼­ °É¸².[m
[32m+[m	[32m// ï¿½Ã¹Ù¸ï¿½ Cell ï¿½ï¿½ï¿½ï¿½ ï¿½Ë»ï¿½[m
[32m+[m	[32m// ï¿½ï¿½È¥ï¿½ï¿½ï¿½ï¿½ Swapï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ç·ï¿½, ï¿½ï¿½ï¿½â¼­ ï¿½É¸ï¿½.[m
 	//if (bCell >= INVENTORY_MAX_NUM + WEAR_MAX_NUM || bDestCell >= INVENTORY_MAX_NUM + WEAR_MAX_NUM)[m
 	if (srcCell.IsDragonSoulEquipPosition() || destCell.IsDragonSoulEquipPosition())[m
 		return false;[m
 [m
[31m-	// °°Àº CELL ÀÎÁö °Ë»ç[m
[32m+[m	[32m// ï¿½ï¿½ï¿½ï¿½ CELL ï¿½ï¿½ï¿½ï¿½ ï¿½Ë»ï¿½[m
 	if (bCell == bDestCell)[m
 		return false;[m
 [m
[31m-	// µÑ ´Ù ÀåºñÃ¢ À§Ä¡¸é Swap ÇÒ ¼ö ¾ø´Ù.[m
[32m+[m	[32m// ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½Ã¢ ï¿½ï¿½Ä¡ï¿½ï¿½ Swap ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½.[m
 	if (srcCell.IsEquipPosition() && destCell.IsEquipPosition())[m
 		return false;[m
 [m
 	LPITEM item1, item2;[m
 [m
[31m-	// item2°¡ ÀåºñÃ¢¿¡ ÀÖ´Â °ÍÀÌ µÇµµ·Ï.[m
[32m+[m	[32m// item2ï¿½ï¿½ ï¿½ï¿½ï¿½Ã¢ï¿½ï¿½ ï¿½Ö´ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½Çµï¿½ï¿½ï¿½.[m
 	if (srcCell.IsEquipPosition())[m
 	{[m
 		item1 = GetInventoryItem(bDestCell);[m
[36m@@ -6127,27 +6147,31 @@[m [mbool CHARACTER::SwapItem(BYTE bCell, BYTE bDestCell)[m
 	    return false;[m
 	}[m
 [m
[31m-	// item2°¡ bCellÀ§Ä¡¿¡ µé¾î°¥ ¼ö ÀÖ´ÂÁö È®ÀÎÇÑ´Ù.[m
[32m+[m	[32m// item2ï¿½ï¿½ bCellï¿½ï¿½Ä¡ï¿½ï¿½ ï¿½ï¿½î°¥ ï¿½ï¿½ ï¿½Ö´ï¿½ï¿½ï¿½ È®ï¿½ï¿½ï¿½Ñ´ï¿½.[m
 	if (!IsEmptyItemGrid(TItemPos (INVENTORY, item1->GetCell()), item2->GetSize(), item1->GetCell()))[m
 		return false;[m
 [m
[31m-	// ¹Ù²Ü ¾ÆÀÌÅÛÀÌ ÀåºñÃ¢¿¡ ÀÖÀ¸¸é[m
[32m+[m	[32m// ï¿½Ù²ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Ã¢ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½[m
 	if (TItemPos(EQUIPMENT, item2->GetCell()).IsEquipPosition())[m
 	{[m
 		BYTE bEquipCell = item2->GetCell() - INVENTORY_MAX_NUM;[m
 		BYTE bInvenCell = item1->GetCell();[m
 [m
[31m-		// Âø¿ëÁßÀÎ ¾ÆÀÌÅÛÀ» ¹þÀ» ¼ö ÀÖ°í, Âø¿ë ¿¹Á¤ ¾ÆÀÌÅÛÀÌ Âø¿ë °¡´ÉÇÑ »óÅÂ¿©¾ß¸¸ ÁøÇà[m
[32m+[m		[32m// ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½Ö°ï¿½, ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Â¿ï¿½ï¿½ß¸ï¿½ ï¿½ï¿½ï¿½ï¿½[m
 		if (false == CanUnequipNow(item2) || false == CanEquipNow(item1))[m
 			return false;[m
 [m
[31m-		if (bEquipCell != item1->FindEquipCell(this)) // °°Àº À§Ä¡ÀÏ¶§¸¸ Çã¿ë[m
[32m+[m		[32mif (bEquipCell != item1->FindEquipCell(this)) // ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½Ä¡ï¿½Ï¶ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½[m
 			return false;[m
 [m
 		item2->RemoveFromCharacter();[m
 [m
 		if (item1->EquipTo(this, bEquipCell))[m
[32m+[m[32m#if defined(__BL_ENABLE_PICKUP_ITEM_EFFECT__)[m
[32m+[m			[32mitem2->AddToCharacter(this, TItemPos(INVENTORY, bInvenCell), false);[m
[32m+[m[32m#else[m
 			item2->AddToCharacter(this, TItemPos(INVENTORY, bInvenCell));[m
[32m+[m[32m#endif[m
 		else[m
 			sys_err("SwapItem cannot equip %s! item1 %s", item2->GetName(), item1->GetName());[m
 	}[m
[36m@@ -6159,8 +6183,13 @@[m [mbool CHARACTER::SwapItem(BYTE bCell, BYTE bDestCell)[m
 		item1->RemoveFromCharacter();[m
 		item2->RemoveFromCharacter();[m
 [m
[32m+[m[32m#if defined(__BL_ENABLE_PICKUP_ITEM_EFFECT__)[m
[32m+[m		[32mitem1->AddToCharacter(this, TItemPos(INVENTORY, bCell2), false);[m
[32m+[m		[32mitem2->AddToCharacter(this, TItemPos(INVENTORY, bCell1), false);[m
[32m+[m[32m#else[m
 		item1->AddToCharacter(this, TItemPos(INVENTORY, bCell2));[m
 		item2->AddToCharacter(this, TItemPos(INVENTORY, bCell1));[m
[32m+[m[32m#endif[m
 	}[m
 	[m
 #ifdef ENABLE_MOUNT_LIKE_HORSE[m
[36m@@ -6211,7 +6240,11 @@[m [mbool CHARACTER::UnequipItem(LPITEM item)[m
 		item->AddToCharacter(this, TItemPos(DRAGON_SOUL_INVENTORY, pos));[m
 	}[m
 	else[m
[32m+[m[32m#if defined(__BL_ENABLE_PICKUP_ITEM_EFFECT__)[m
[32m+[m		[32mitem->AddToCharacter(this, TItemPos(INVENTORY, pos), false);[m
[32m+[m[32m#else[m
 		item->AddToCharacter(this, TItemPos(INVENTORY, pos));[m
[32m+[m[32m#endif[m
 [m
 	CheckMaximumPoints();[m
 [m
[36m@@ -6219,7 +6252,7 @@[m [mbool CHARACTER::UnequipItem(LPITEM item)[m
 }[m
 [m
 //[m
[31m-// @version	05/07/05 Bang2ni - Skill »ç¿ëÈÄ 1.5 ÃÊ ÀÌ³»¿¡ Àåºñ Âø¿ë ±ÝÁö[m
[32m+[m[32m// @version	05/07/05 Bang2ni - Skill ï¿½ï¿½ï¿½ï¿½ï¿½ 1.5 ï¿½ï¿½ ï¿½Ì³ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½[m
 //[m
 bool CHARACTER::EquipItem(LPITEM item, int iCandidateCell)[m
 {[m
[36m@@ -6237,39 +6270,39 @@[m [mbool CHARACTER::EquipItem(LPITEM item, int iCandidateCell)[m
 	if (iWearCell < 0)[m
 		return false;[m
 [m
[31m-	// ¹«¾ð°¡¸¦ Åº »óÅÂ¿¡¼­ ÅÎ½Ãµµ ÀÔ±â ±ÝÁö[m
[32m+[m	[32m// ï¿½ï¿½ï¿½ð°¡¸ï¿½ Åº ï¿½ï¿½ï¿½Â¿ï¿½ï¿½ï¿½ ï¿½Î½Ãµï¿½ ï¿½Ô±ï¿½ ï¿½ï¿½ï¿½ï¿½[m
 	if (iWearCell == WEAR_BODY && IsRiding() && (item->GetVnum() >= 11901 && item->GetVnum() <= 11904))[m
 	{[m
[31m-		ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¸»À» Åº »óÅÂ¿¡¼­ ¿¹º¹À» ÀÔÀ» ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m		[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ Åº ï¿½ï¿½ï¿½Â¿ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 		return false;[m
 	}[m
 [m
 	if (iWearCell != WEAR_ARROW && IsPolymorphed())[m
 	{[m
[31m-		ChatPacket(CHAT_TYPE_INFO, LC_TEXT("µÐ°© Áß¿¡´Â Âø¿ëÁßÀÎ Àåºñ¸¦ º¯°æÇÒ ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m		[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½Ð°ï¿½ ï¿½ß¿ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 		return false;[m
 	}[m
 [m
 	if (FN_check_item_sex(this, item) == false)[m
 	{[m
[31m-		ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¼ºº°ÀÌ ¸ÂÁö¾Ê¾Æ ÀÌ ¾ÆÀÌÅÛÀ» »ç¿ëÇÒ ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m		[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ê¾ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 		return false;[m
 	}[m
 [m
[31m-	//½Å±Ô Å»°Í »ç¿ë½Ã ±âÁ¸ ¸» »ç¿ë¿©ºÎ Ã¼Å©[m
[32m+[m	[32m//ï¿½Å±ï¿½ Å»ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ë¿©ï¿½ï¿½ Ã¼Å©[m
 	if(item->IsRideItem() && IsRiding())[m
 	{[m
[31m-		ChatPacket(CHAT_TYPE_INFO, LC_TEXT("ÀÌ¹Ì Å»°ÍÀ» ÀÌ¿ëÁßÀÔ´Ï´Ù."));[m
[32m+[m		[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½Ì¹ï¿½ Å»ï¿½ï¿½ï¿½ï¿½ ï¿½Ì¿ï¿½ï¿½ï¿½ï¿½Ô´Ï´ï¿½."));[m
 		return false;[m
 	}[m
 [m
[31m-	// È­»ì ÀÌ¿Ü¿¡´Â ¸¶Áö¸· °ø°Ý ½Ã°£ ¶Ç´Â ½ºÅ³ »ç¿ë 1.5 ÈÄ¿¡ Àåºñ ±³Ã¼°¡ °¡´É[m
[32m+[m	[32m// È­ï¿½ï¿½ ï¿½Ì¿Ü¿ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½Ã°ï¿½ ï¿½Ç´ï¿½ ï¿½ï¿½Å³ ï¿½ï¿½ï¿½ 1.5 ï¿½Ä¿ï¿½ ï¿½ï¿½ï¿½ ï¿½ï¿½Ã¼ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½[m
 	DWORD dwCurTime = get_dword_time();[m
 [m
 	if (iWearCell != WEAR_ARROW [m
 		&& (dwCurTime - GetLastAttackTime() <= 1500 || dwCurTime - m_dwLastSkillTime <= 1500))[m
 	{[m
[31m-		ChatPacket(CHAT_TYPE_INFO, LC_TEXT("°¡¸¸È÷ ÀÖÀ» ¶§¸¸ Âø¿ëÇÒ ¼ö ÀÖ½À´Ï´Ù."));[m
[32m+[m		[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½Ö½ï¿½ï¿½Ï´ï¿½."));[m
 		return false;[m
 	}[m
 [m
[36m@@ -6314,14 +6347,14 @@[m [mbool CHARACTER::EquipItem(LPITEM item, int iCandidateCell)[m
 	}[m
 #endif[m
 [m
[31m-	// ¿ëÈ¥¼® Æ¯¼ö Ã³¸®[m
[32m+[m	[32m// ï¿½ï¿½È¥ï¿½ï¿½ Æ¯ï¿½ï¿½ Ã³ï¿½ï¿½[m
 	if (item->IsDragonSoul())[m
 	{[m
[31m-		// °°Àº Å¸ÀÔÀÇ ¿ëÈ¥¼®ÀÌ ÀÌ¹Ì µé¾î°¡ ÀÖ´Ù¸é Âø¿ëÇÒ ¼ö ¾ø´Ù.[m
[31m-		// ¿ëÈ¥¼®Àº swapÀ» Áö¿øÇÏ¸é ¾ÈµÊ.[m
[32m+[m		[32m// ï¿½ï¿½ï¿½ï¿½ Å¸ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½È¥ï¿½ï¿½ï¿½ï¿½ ï¿½Ì¹ï¿½ ï¿½ï¿½î°¡ ï¿½Ö´Ù¸ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½.[m
[32m+[m		[32m// ï¿½ï¿½È¥ï¿½ï¿½ï¿½ï¿½ swapï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï¸ï¿½ ï¿½Èµï¿½.[m
 		if(GetInventoryItem(INVENTORY_MAX_NUM + iWearCell))[m
 		{[m
[31m-			ChatPacket(CHAT_TYPE_INFO, "ÀÌ¹Ì °°Àº Á¾·ùÀÇ ¿ëÈ¥¼®À» Âø¿ëÇÏ°í ÀÖ½À´Ï´Ù.");[m
[32m+[m			[32mChatPacket(CHAT_TYPE_INFO, "ï¿½Ì¹ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½È¥ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï°ï¿½ ï¿½Ö½ï¿½ï¿½Ï´ï¿½.");[m
 			return false;[m
 		}[m
 		[m
[36m@@ -6330,13 +6363,13 @@[m [mbool CHARACTER::EquipItem(LPITEM item, int iCandidateCell)[m
 			return false;[m
 		}[m
 	}[m
[31m-	// ¿ëÈ¥¼®ÀÌ ¾Æ´Ô.[m
[32m+[m	[32m// ï¿½ï¿½È¥ï¿½ï¿½ï¿½ï¿½ ï¿½Æ´ï¿½.[m
 	else[m
 	{[m
[31m-		// Âø¿ëÇÒ °÷¿¡ ¾ÆÀÌÅÛÀÌ ÀÖ´Ù¸é,[m
[32m+[m		[32m// ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ö´Ù¸ï¿½,[m
 		if (GetWear(iWearCell) && !IS_SET(GetWear(iWearCell)->GetFlag(), ITEM_FLAG_IRREMOVABLE))[m
 		{[m
[31m-			// ÀÌ ¾ÆÀÌÅÛÀº ÇÑ¹ø ¹ÚÈ÷¸é º¯°æ ºÒ°¡. swap ¿ª½Ã ¿ÏÀü ºÒ°¡[m
[32m+[m			[32m// ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ñ¹ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½Ò°ï¿½. swap ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½Ò°ï¿½[m
 			if (item->GetWearFlag() == WEARABLE_ABILITY) [m
 				return false;[m
 [m
[36m@@ -6358,13 +6391,13 @@[m [mbool CHARACTER::EquipItem(LPITEM item, int iCandidateCell)[m
 [m
 	if (true == item->IsEquipped())[m
 	{[m
[31m-		// ¾ÆÀÌÅÛ ÃÖÃÊ »ç¿ë ÀÌÈÄºÎÅÍ´Â »ç¿ëÇÏÁö ¾Ê¾Æµµ ½Ã°£ÀÌ Â÷°¨µÇ´Â ¹æ½Ä Ã³¸®. [m
[32m+[m		[32m// ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Äºï¿½ï¿½Í´ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ê¾Æµï¿½ ï¿½Ã°ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ç´ï¿½ ï¿½ï¿½ï¿½ Ã³ï¿½ï¿½.[m[41m [m
 		if (-1 != item->GetProto()->cLimitRealTimeFirstUseIndex)[m
 		{[m
[31m-			// ÇÑ ¹øÀÌ¶óµµ »ç¿ëÇÑ ¾ÆÀÌÅÛÀÎÁö ¿©ºÎ´Â Socket1À» º¸°í ÆÇ´ÜÇÑ´Ù. (Socket1¿¡ »ç¿ëÈ½¼ö ±â·Ï)[m
[32m+[m			[32m// ï¿½ï¿½ ï¿½ï¿½ï¿½Ì¶ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Î´ï¿½ Socket1ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½Ç´ï¿½ï¿½Ñ´ï¿½. (Socket1ï¿½ï¿½ ï¿½ï¿½ï¿½È½ï¿½ï¿½ ï¿½ï¿½ï¿½)[m
 			if (0 == item->GetSocket(1))[m
 			{[m
[31m-				// »ç¿ë°¡´É½Ã°£Àº Default °ªÀ¸·Î Limit Value °ªÀ» »ç¿ëÇÏµÇ, Socket0¿¡ °ªÀÌ ÀÖÀ¸¸é ±× °ªÀ» »ç¿ëÇÏµµ·Ï ÇÑ´Ù. (´ÜÀ§´Â ÃÊ)[m
[32m+[m				[32m// ï¿½ï¿½ë°¡ï¿½É½Ã°ï¿½ï¿½ï¿½ Default ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ Limit Value ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½Ïµï¿½, Socket0ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½Ïµï¿½ï¿½ï¿½ ï¿½Ñ´ï¿½. (ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½)[m
 				long duration = (0 != item->GetSocket(0)) ? item->GetSocket(0) : item->GetProto()->aLimits[item->GetProto()->cLimitRealTimeFirstUseIndex].lValue;[m
 [m
 				if (0 == duration)[m
[36m@@ -6382,27 +6415,27 @@[m [mbool CHARACTER::EquipItem(LPITEM item, int iCandidateCell)[m
 [m
 		const DWORD& dwVnum = item->GetVnum();[m
 [m
[31m-		// ¶ó¸¶´Ü ÀÌº¥Æ® ÃÊ½Â´ÞÀÇ ¹ÝÁö(71135) Âø¿ë½Ã ÀÌÆåÆ® ¹ßµ¿[m
[32m+[m		[32m// ï¿½ó¸¶´ï¿½ ï¿½Ìºï¿½Æ® ï¿½Ê½Â´ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½(71135) ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½Æ® ï¿½ßµï¿½[m
 		if (true == CItemVnumHelper::IsRamadanMoonRing(dwVnum))[m
 		{[m
 			this->EffectPacket(SE_EQUIP_RAMADAN_RING);[m
 		}[m
[31m-		// ÇÒ·ÎÀ© »çÅÁ(71136) Âø¿ë½Ã ÀÌÆåÆ® ¹ßµ¿[m
[32m+[m		[32m// ï¿½Ò·ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½(71136) ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½Æ® ï¿½ßµï¿½[m
 		else if (true == CItemVnumHelper::IsHalloweenCandy(dwVnum))[m
 		{[m
 			this->EffectPacket(SE_EQUIP_HALLOWEEN_CANDY);[m
 		}[m
[31m-		// Çàº¹ÀÇ ¹ÝÁö(71143) Âø¿ë½Ã ÀÌÆåÆ® ¹ßµ¿[m
[32m+[m		[32m// ï¿½àº¹ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½(71143) ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½Æ® ï¿½ßµï¿½[m
 		else if (true == CItemVnumHelper::IsHappinessRing(dwVnum))[m
 		{[m
 			this->EffectPacket(SE_EQUIP_HAPPINESS_RING);[m
 		}[m
[31m-		// »ç¶ûÀÇ ÆÒ´øÆ®(71145) Âø¿ë½Ã ÀÌÆåÆ® ¹ßµ¿[m
[32m+[m		[32m// ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ò´ï¿½Æ®(71145) ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½Æ® ï¿½ßµï¿½[m
 		else if (true == CItemVnumHelper::IsLovePendant(dwVnum))[m
 		{[m
 			this->EffectPacket(SE_EQUIP_LOVE_PENDANT);[m
 		}[m
[31m-		// ITEM_UNIQUEÀÇ °æ¿ì, SpecialItemGroup¿¡ Á¤ÀÇµÇ¾î ÀÖ°í, (item->GetSIGVnum() != NULL)[m
[32m+[m		[32m// ITEM_UNIQUEï¿½ï¿½ ï¿½ï¿½ï¿½, SpecialItemGroupï¿½ï¿½ ï¿½ï¿½ï¿½ÇµÇ¾ï¿½ ï¿½Ö°ï¿½, (item->GetSIGVnum() != NULL)[m
 		// [m
 		else if (ITEM_UNIQUE == item->GetType() && 0 != item->GetSIGVnum())[m
 		{[m
[36m@@ -6568,7 +6601,7 @@[m [mint CHARACTER::CountSpecifyItem(DWORD vnum) const[m
 		item = GetInventoryItem(i);[m
 		if (NULL != item && item->GetVnum() == vnum)[m
 		{[m
[31m-			// °³ÀÎ »óÁ¡¿¡ µî·ÏµÈ ¹°°ÇÀÌ¸é ³Ñ¾î°£´Ù.[m
[32m+[m			[32m// ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½Ïµï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ì¸ï¿½ ï¿½Ñ¾î°£ï¿½ï¿½.[m
 			if (m_pkMyShop && m_pkMyShop->IsSellingItem(item->GetID()))[m
 			{[m
 				continue;[m
[36m@@ -6596,7 +6629,7 @@[m [mvoid CHARACTER::RemoveSpecifyItem(DWORD vnum, DWORD count)[m
 		if (GetInventoryItem(i)->GetVnum() != vnum)[m
 			continue;[m
 [m
[31m-		//°³ÀÎ »óÁ¡¿¡ µî·ÏµÈ ¹°°ÇÀÌ¸é ³Ñ¾î°£´Ù. (°³ÀÎ »óÁ¡¿¡¼­ ÆÇ¸ÅµÉ¶§ ÀÌ ºÎºÐÀ¸·Î µé¾î¿Ã °æ¿ì ¹®Á¦!)[m
[32m+[m		[32m//ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½Ïµï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ì¸ï¿½ ï¿½Ñ¾î°£ï¿½ï¿½. (ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ç¸ÅµÉ¶ï¿½ ï¿½ï¿½ ï¿½Îºï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½!)[m
 		if(m_pkMyShop)[m
 		{[m
 			bool isItemSelling = m_pkMyShop->IsSellingItem(GetInventoryItem(i)->GetID());[m
[36m@@ -6622,7 +6655,7 @@[m [mvoid CHARACTER::RemoveSpecifyItem(DWORD vnum, DWORD count)[m
 		}[m
 	}[m
 [m
[31m-	// ¿¹¿ÜÃ³¸®°¡ ¾àÇÏ´Ù.[m
[32m+[m	[32m// ï¿½ï¿½ï¿½ï¿½Ã³ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Ï´ï¿½.[m
 	if (count)[m
 		sys_log(0, "CHARACTER::RemoveSpecifyItem cannot remove enough item vnum %u, still remain %d", vnum, count);[m
 }[m
[36m@@ -6656,7 +6689,7 @@[m [mvoid CHARACTER::RemoveSpecifyTypeItem(BYTE type, DWORD count)[m
 		if (GetInventoryItem(i)->GetType() != type)[m
 			continue;[m
 [m
[31m-		//°³ÀÎ »óÁ¡¿¡ µî·ÏµÈ ¹°°ÇÀÌ¸é ³Ñ¾î°£´Ù. (°³ÀÎ »óÁ¡¿¡¼­ ÆÇ¸ÅµÉ¶§ ÀÌ ºÎºÐÀ¸·Î µé¾î¿Ã °æ¿ì ¹®Á¦!)[m
[32m+[m		[32m//ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½Ïµï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ì¸ï¿½ ï¿½Ñ¾î°£ï¿½ï¿½. (ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ç¸ÅµÉ¶ï¿½ ï¿½ï¿½ ï¿½Îºï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½!)[m
 		if(m_pkMyShop)[m
 		{[m
 			bool isItemSelling = m_pkMyShop->IsSellingItem(GetInventoryItem(i)->GetID());[m
[36m@@ -6772,7 +6805,7 @@[m [mLPITEM CHARACTER::AutoGiveItem(DWORD dwItemVnum, WORD bCount, int iRarePct, bool[m
 				if (bCount == 0)[m
 				{[m
 					if (bMsg)[m
[31m-						ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¾ÆÀÌÅÛ È¹µæ: %s"), item->GetName());[m
[32m+[m						[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ È¹ï¿½ï¿½: %s"), item->GetName());[m
 [m
 					return item;[m
 				}[m
[36m@@ -6824,7 +6857,7 @@[m [mLPITEM CHARACTER::AutoGiveItem(DWORD dwItemVnum, WORD bCount, int iRarePct, bool[m
 	if (iEmptyCell != -1)[m
 	{[m
 		if (bMsg)[m
[31m-			ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¾ÆÀÌÅÛ È¹µæ: %s"), item->GetName());[m
[32m+[m			[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ È¹ï¿½ï¿½: %s"), item->GetName());[m
 [m
 		if (item->IsDragonSoul())[m
 			item->AddToCharacter(this, TItemPos(DRAGON_SOUL_INVENTORY, iEmptyCell));[m
[36m@@ -6849,9 +6882,9 @@[m [mLPITEM CHARACTER::AutoGiveItem(DWORD dwItemVnum, WORD bCount, int iRarePct, bool[m
 	{[m
 		item->AddToGround(GetMapIndex(), GetXYZ());[m
 		item->StartDestroyEvent();[m
[31m-		// ¾ÈÆ¼ µå¶ø flag°¡ °É·ÁÀÖ´Â ¾ÆÀÌÅÛÀÇ °æ¿ì, [m
[31m-		// ÀÎº¥¿¡ ºó °ø°£ÀÌ ¾ø¾î¼­ ¾îÂ¿ ¼ö ¾øÀÌ ¶³¾îÆ®¸®°Ô µÇ¸é,[m
[31m-		// ownershipÀ» ¾ÆÀÌÅÛÀÌ »ç¶óÁú ¶§±îÁö(300ÃÊ) À¯ÁöÇÑ´Ù.[m
[32m+[m		[32m// ï¿½ï¿½Æ¼ ï¿½ï¿½ï¿½ flagï¿½ï¿½ ï¿½É·ï¿½ï¿½Ö´ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½,[m[41m [m
[32m+[m		[32m// ï¿½Îºï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½î¼­ ï¿½ï¿½Â¿ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½Æ®ï¿½ï¿½ï¿½ï¿½ ï¿½Ç¸ï¿½,[m
[32m+[m		[32m// ownershipï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½(300ï¿½ï¿½) ï¿½ï¿½ï¿½ï¿½ï¿½Ñ´ï¿½.[m
 		if (IS_SET(item->GetAntiFlag(), ITEM_ANTIFLAG_DROP))[m
 			item->SetOwnership(this, 300);[m
 		else[m
[36m@@ -6965,12 +6998,12 @@[m [mbool CHARACTER::CanReceiveItem(LPCHARACTER from, LPITEM item) const[m
 		case 20101:[m
 		case 20102:[m
 		case 20103:[m
[31m-			// ÃÊ±Þ ¸»[m
[32m+[m			[32m// ï¿½Ê±ï¿½ ï¿½ï¿½[m
 			if (item->GetVnum() == ITEM_REVIVE_HORSE_1)[m
 			{[m
 				if (!IsDead())[m
 				{[m
[31m-					from->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("Á×Áö ¾ÊÀº ¸»¿¡°Ô ¼±ÃÊ¸¦ ¸ÔÀÏ ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m					[32mfrom->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Ê¸ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 					return false;[m
 				}[m
 				return true;[m
[36m@@ -6979,7 +7012,7 @@[m [mbool CHARACTER::CanReceiveItem(LPCHARACTER from, LPITEM item) const[m
 			{[m
 				if (IsDead())[m
 				{[m
[31m-					from->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("Á×Àº ¸»¿¡°Ô »ç·á¸¦ ¸ÔÀÏ ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m					[32mfrom->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½á¸¦ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 					return false;[m
 				}[m
 				return true;[m
[36m@@ -6992,12 +7025,12 @@[m [mbool CHARACTER::CanReceiveItem(LPCHARACTER from, LPITEM item) const[m
 		case 20104:[m
 		case 20105:[m
 		case 20106:[m
[31m-			// Áß±Þ ¸»[m
[32m+[m			[32m// ï¿½ß±ï¿½ ï¿½ï¿½[m
 			if (item->GetVnum() == ITEM_REVIVE_HORSE_2)[m
 			{[m
 				if (!IsDead())[m
 				{[m
[31m-					from->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("Á×Áö ¾ÊÀº ¸»¿¡°Ô ¼±ÃÊ¸¦ ¸ÔÀÏ ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m					[32mfrom->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Ê¸ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 					return false;[m
 				}[m
 				return true;[m
[36m@@ -7006,7 +7039,7 @@[m [mbool CHARACTER::CanReceiveItem(LPCHARACTER from, LPITEM item) const[m
 			{[m
 				if (IsDead())[m
 				{[m
[31m-					from->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("Á×Àº ¸»¿¡°Ô »ç·á¸¦ ¸ÔÀÏ ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m					[32mfrom->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½á¸¦ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 					return false;[m
 				}[m
 				return true;[m
[36m@@ -7019,12 +7052,12 @@[m [mbool CHARACTER::CanReceiveItem(LPCHARACTER from, LPITEM item) const[m
 		case 20107:[m
 		case 20108:[m
 		case 20109:[m
[31m-			// °í±Þ ¸»[m
[32m+[m			[32m// ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½[m
 			if (item->GetVnum() == ITEM_REVIVE_HORSE_3)[m
 			{[m
 				if (!IsDead())[m
 				{[m
[31m-					from->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("Á×Áö ¾ÊÀº ¸»¿¡°Ô ¼±ÃÊ¸¦ ¸ÔÀÏ ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m					[32mfrom->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Ê¸ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 					return false;[m
 				}[m
 				return true;[m
[36m@@ -7033,7 +7066,7 @@[m [mbool CHARACTER::CanReceiveItem(LPCHARACTER from, LPITEM item) const[m
 			{[m
 				if (IsDead())[m
 				{[m
[31m-					from->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("Á×Àº ¸»¿¡°Ô »ç·á¸¦ ¸ÔÀÏ ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m					[32mfrom->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½á¸¦ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 					return false;[m
 				}[m
 				return true;[m
[36m@@ -7083,7 +7116,7 @@[m [mvoid CHARACTER::ReceiveItem(LPCHARACTER from, LPITEM item)[m
 			}[m
 			else[m
 			{[m
[31m-				from->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("ÀÌ ¾ÆÀÌÅÛÀº °³·®ÇÒ ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m				[32mfrom->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 			}[m
 			break;[m
 			// END_OF_DEVILTOWER_NPC[m
[36m@@ -7100,7 +7133,7 @@[m [mvoid CHARACTER::ReceiveItem(LPCHARACTER from, LPITEM item)[m
 			}[m
 			else[m
 			{[m
[31m-				from->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("ÀÌ ¾ÆÀÌÅÛÀº °³·®ÇÒ ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m				[32mfrom->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 			}[m
 			break;[m
 [m
[36m@@ -7119,14 +7152,14 @@[m [mvoid CHARACTER::ReceiveItem(LPCHARACTER from, LPITEM item)[m
 			{[m
 				from->ReviveHorse();[m
 				item->SetCount(item->GetCount()-1);[m
[31m-				from->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¸»¿¡°Ô ¼±ÃÊ¸¦ ÁÖ¾ú½À´Ï´Ù."));[m
[32m+[m				[32mfrom->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Ê¸ï¿½ ï¿½Ö¾ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 			}[m
 			else if (item->GetVnum() == ITEM_HORSE_FOOD_1 ||[m
 					item->GetVnum() == ITEM_HORSE_FOOD_2 ||[m
 					item->GetVnum() == ITEM_HORSE_FOOD_3)[m
 			{[m
 				from->FeedHorse();[m
[31m-				from->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¸»¿¡°Ô »ç·á¸¦ ÁÖ¾ú½À´Ï´Ù."));[m
[32m+[m				[32mfrom->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½á¸¦ ï¿½Ö¾ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 				item->SetCount(item->GetCount()-1);[m
 				EffectPacket(SE_HPUP_RED);[m
 			}[m
[36m@@ -7329,8 +7362,8 @@[m [mbool CHARACTER::ItemProcess_Hair(LPITEM item, int iDestCell)[m
 {[m
 	if (item->CheckItemUseLevel(GetLevel()) == false)[m
 	{[m
[31m-		// ·¹º§ Á¦ÇÑ¿¡ °É¸²[m
[31m-		ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¾ÆÁ÷ ÀÌ ¸Ó¸®¸¦ »ç¿ëÇÒ ¼ö ¾ø´Â ·¹º§ÀÔ´Ï´Ù."));[m
[32m+[m		[32m// ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Ñ¿ï¿½ ï¿½É¸ï¿½[m
[32m+[m		[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½Ó¸ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ô´Ï´ï¿½."));[m
 		return false;[m
 	}[m
 [m
[36m@@ -7339,7 +7372,7 @@[m [mbool CHARACTER::ItemProcess_Hair(LPITEM item, int iDestCell)[m
 	switch (GetJob())[m
 	{[m
 		case JOB_WARRIOR :[m
[31m-			hair -= 72000; // 73001 - 72000 = 1001 ºÎÅÍ Çì¾î ¹øÈ£ ½ÃÀÛ[m
[32m+[m			[32mhair -= 72000; // 73001 - 72000 = 1001 ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ ï¿½ï¿½È£ ï¿½ï¿½ï¿½ï¿½[m
 			break;[m
 [m
 		case JOB_ASSASSIN :[m
[36m@@ -7361,7 +7394,7 @@[m [mbool CHARACTER::ItemProcess_Hair(LPITEM item, int iDestCell)[m
 [m
 	if (hair == GetPart(PART_HAIR))[m
 	{[m
[31m-		ChatPacket(CHAT_TYPE_INFO, LC_TEXT("µ¿ÀÏÇÑ ¸Ó¸® ½ºÅ¸ÀÏ·Î´Â ±³Ã¼ÇÒ ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m		[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ó¸ï¿½ ï¿½ï¿½Å¸ï¿½Ï·Î´ï¿½ ï¿½ï¿½Ã¼ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 		return true;[m
 	}[m
 [m
[36m@@ -7378,13 +7411,13 @@[m [mbool CHARACTER::ItemProcess_Polymorph(LPITEM item)[m
 {[m
 	if (IsPolymorphed())[m
 	{[m
[31m-		ChatPacket(CHAT_TYPE_INFO, LC_TEXT("ÀÌ¹Ì µÐ°©ÁßÀÎ »óÅÂÀÔ´Ï´Ù."));[m
[32m+[m		[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½Ì¹ï¿½ ï¿½Ð°ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ô´Ï´ï¿½."));[m
 		return false;[m
 	}[m
 [m
 	if (true == IsRiding())[m
 	{[m
[31m-		ChatPacket(CHAT_TYPE_INFO, LC_TEXT("µÐ°©ÇÒ ¼ö ¾ø´Â »óÅÂÀÔ´Ï´Ù."));[m
[32m+[m		[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½Ð°ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ô´Ï´ï¿½."));[m
 		return false;[m
 	}[m
 [m
[36m@@ -7392,7 +7425,7 @@[m [mbool CHARACTER::ItemProcess_Polymorph(LPITEM item)[m
 [m
 	if (dwVnum == 0)[m
 	{[m
[31m-		ChatPacket(CHAT_TYPE_INFO, LC_TEXT("Àß¸øµÈ µÐ°© ¾ÆÀÌÅÛÀÔ´Ï´Ù."));[m
[32m+[m		[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ß¸ï¿½ï¿½ï¿½ ï¿½Ð°ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½Ô´Ï´ï¿½."));[m
 		item->SetCount(item->GetCount()-1);[m
 		return false;[m
 	}[m
[36m@@ -7401,7 +7434,7 @@[m [mbool CHARACTER::ItemProcess_Polymorph(LPITEM item)[m
 [m
 	if (pMob == NULL)[m
 	{[m
[31m-		ChatPacket(CHAT_TYPE_INFO, LC_TEXT("Àß¸øµÈ µÐ°© ¾ÆÀÌÅÛÀÔ´Ï´Ù."));[m
[32m+[m		[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ß¸ï¿½ï¿½ï¿½ ï¿½Ð°ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½Ô´Ï´ï¿½."));[m
 		item->SetCount(item->GetCount()-1);[m
 		return false;[m
 	}[m
[36m@@ -7414,14 +7447,14 @@[m [mbool CHARACTER::ItemProcess_Polymorph(LPITEM item)[m
 		case 70107 :[m
 		case 71093 :[m
 			{[m
[31m-				// µÐ°©±¸ Ã³¸®[m
[32m+[m				[32m// ï¿½Ð°ï¿½ï¿½ï¿½ Ã³ï¿½ï¿½[m
 				sys_log(0, "USE_POLYMORPH_BALL PID(%d) vnum(%d)", GetPlayerID(), dwVnum);[m
 [m
[31m-				// ·¹º§ Á¦ÇÑ Ã¼Å©[m
[32m+[m				[32m// ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ Ã¼Å©[m
 				int iPolymorphLevelLimit = MAX(0, 20 - GetLevel() * 3 / 10);[m
 				if (pMob->m_table.bLevel >= GetLevel() + iPolymorphLevelLimit)[m
 				{[m
[31m-					ChatPacket(CHAT_TYPE_INFO, LC_TEXT("³ªº¸´Ù ³Ê¹« ³ôÀº ·¹º§ÀÇ ¸ó½ºÅÍ·Î´Â º¯½Å ÇÒ ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m					[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ê¹ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Í·Î´ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 					return false;[m
 				}[m
 [m
[36m@@ -7448,11 +7481,11 @@[m [mbool CHARACTER::ItemProcess_Polymorph(LPITEM item)[m
 [m
 		case 50322:[m
 			{[m
[31m-				// º¸·ù[m
[32m+[m				[32m// ï¿½ï¿½ï¿½ï¿½[m
 [m
[31m-				// µÐ°©¼­ Ã³¸®[m
[31m-				// ¼ÒÄÏ0                ¼ÒÄÏ1           ¼ÒÄÏ2   [m
[31m-				// µÐ°©ÇÒ ¸ó½ºÅÍ ¹øÈ£   ¼ö·ÃÁ¤µµ        µÐ°©¼­ ·¹º§[m
[32m+[m				[32m// ï¿½Ð°ï¿½ï¿½ï¿½ Ã³ï¿½ï¿½[m
[32m+[m				[32m// ï¿½ï¿½ï¿½ï¿½0                ï¿½ï¿½ï¿½ï¿½1           ï¿½ï¿½ï¿½ï¿½2[m[41m   [m
[32m+[m				[32m// ï¿½Ð°ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½È£   ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½        ï¿½Ð°ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½[m
 				sys_log(0, "USE_POLYMORPH_BOOK: %s(%u) vnum(%u)", GetName(), GetPlayerID(), dwVnum);[m
 [m
 				if (CPolymorphUtils::instance().PolymorphCharacter(this, item, pMob) == true)[m
[36m@@ -7579,8 +7612,8 @@[m [mvoid CHARACTER::AutoRecoveryItemProcess(const EAffectTypes type)[m
 						const int pct_of_will_used = (amount_of_used + amount) * 100 / amount_of_full;[m
 [m
 						bool bLog = false;[m
[31m-						// »ç¿ë·®ÀÇ 10% ´ÜÀ§·Î ·Î±×¸¦ ³²±è[m
[31m-						// (»ç¿ë·®ÀÇ %¿¡¼­, ½ÊÀÇ ÀÚ¸®°¡ ¹Ù²ð ¶§¸¶´Ù ·Î±×¸¦ ³²±è.)[m
[32m+[m						[32m// ï¿½ï¿½ë·®ï¿½ï¿½ 10% ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Î±×¸ï¿½ ï¿½ï¿½ï¿½ï¿½[m
[32m+[m						[32m// (ï¿½ï¿½ë·®ï¿½ï¿½ %ï¿½ï¿½ï¿½ï¿½, ï¿½ï¿½ï¿½ï¿½ ï¿½Ú¸ï¿½ï¿½ï¿½ ï¿½Ù²ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Î±×¸ï¿½ ï¿½ï¿½ï¿½ï¿½.)[m
 						if ((pct_of_will_used / 10) - (pct_of_used / 10) >= 1)[m
 							bLog = true;[m
 						pItem->SetSocket(idx_of_amount_of_used, amount_of_used + amount, bLog);[m
[36m@@ -7652,7 +7685,7 @@[m [mbool CHARACTER::IsValidItemPosition(TItemPos Pos) const[m
 }[m
 [m
 [m
[31m-// ±ÍÂú¾Æ¼­ ¸¸µç ¸ÅÅ©·Î.. exp°¡ true¸é msg¸¦ Ãâ·ÂÇÏ°í return false ÇÏ´Â ¸ÅÅ©·Î (ÀÏ¹ÝÀûÀÎ verify ¿ëµµ¶ûÀº return ¶§¹®¿¡ ¾à°£ ¹Ý´ë¶ó ÀÌ¸§¶§¹®¿¡ Çò°¥¸± ¼öµµ ÀÖ°Ú´Ù..)[m
[32m+[m[32m// ï¿½ï¿½ï¿½ï¿½ï¿½Æ¼ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½Å©ï¿½ï¿½.. expï¿½ï¿½ trueï¿½ï¿½ msgï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½Ï°ï¿½ return false ï¿½Ï´ï¿½ ï¿½ï¿½Å©ï¿½ï¿½ (ï¿½Ï¹ï¿½ï¿½ï¿½ï¿½ï¿½ verify ï¿½ëµµï¿½ï¿½ï¿½ï¿½ return ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½à°£ ï¿½Ý´ï¿½ï¿½ ï¿½Ì¸ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ò°¥¸ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½Ö°Ú´ï¿½..)[m
 #define VERIFY_MSG(exp, msg)  \[m
 	if (true == (exp)) { \[m
 			ChatPacket(CHAT_TYPE_INFO, LC_TEXT(msg)); \[m
[36m@@ -7660,7 +7693,7 @@[m [mbool CHARACTER::IsValidItemPosition(TItemPos Pos) const[m
 	}[m
 [m
 		[m
[31m-/// ÇöÀç Ä³¸¯ÅÍÀÇ »óÅÂ¸¦ ¹ÙÅÁÀ¸·Î ÁÖ¾îÁø itemÀ» Âø¿ëÇÒ ¼ö ÀÖ´Â Áö È®ÀÎÇÏ°í, ºÒ°¡´É ÇÏ´Ù¸é Ä³¸¯ÅÍ¿¡°Ô ÀÌÀ¯¸¦ ¾Ë·ÁÁÖ´Â ÇÔ¼ö[m
[32m+[m[32m/// ï¿½ï¿½ï¿½ï¿½ Ä³ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Â¸ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ö¾ï¿½ï¿½ï¿½ itemï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½Ö´ï¿½ ï¿½ï¿½ È®ï¿½ï¿½ï¿½Ï°ï¿½, ï¿½Ò°ï¿½ï¿½ï¿½ ï¿½Ï´Ù¸ï¿½ Ä³ï¿½ï¿½ï¿½Í¿ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ë·ï¿½ï¿½Ö´ï¿½ ï¿½Ô¼ï¿½[m
 bool CHARACTER::CanEquipNow(const LPITEM item, const TItemPos& srcCell, const TItemPos& destCell) /*const*/[m
 {[m
 	const TItemTable* itemTable = item->GetProto();[m
[36m@@ -7698,7 +7731,7 @@[m [mbool CHARACTER::CanEquipNow(const LPITEM item, const TItemPos& srcCell, const TI[m
 			case LIMIT_LEVEL:[m
 				if (GetLevel() < limit)[m
 				{[m
[31m-					ChatPacket(CHAT_TYPE_INFO, LC_TEXT("·¹º§ÀÌ ³·¾Æ Âø¿ëÇÒ ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m					[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 					return false;[m
 				}[m
 				break;[m
[36m@@ -7706,7 +7739,7 @@[m [mbool CHARACTER::CanEquipNow(const LPITEM item, const TItemPos& srcCell, const TI[m
 			case LIMIT_STR:[m
 				if (GetPoint(POINT_ST) < limit)[m
 				{[m
[31m-					ChatPacket(CHAT_TYPE_INFO, LC_TEXT("±Ù·ÂÀÌ ³·¾Æ Âø¿ëÇÒ ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m					[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½Ù·ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 					return false;[m
 				}[m
 				break;[m
[36m@@ -7714,7 +7747,7 @@[m [mbool CHARACTER::CanEquipNow(const LPITEM item, const TItemPos& srcCell, const TI[m
 			case LIMIT_INT:[m
 				if (GetPoint(POINT_IQ) < limit)[m
 				{[m
[31m-					ChatPacket(CHAT_TYPE_INFO, LC_TEXT("Áö´ÉÀÌ ³·¾Æ Âø¿ëÇÒ ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m					[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 					return false;[m
 				}[m
 				break;[m
[36m@@ -7722,7 +7755,7 @@[m [mbool CHARACTER::CanEquipNow(const LPITEM item, const TItemPos& srcCell, const TI[m
 			case LIMIT_DEX:[m
 				if (GetPoint(POINT_DX) < limit)[m
 				{[m
[31m-					ChatPacket(CHAT_TYPE_INFO, LC_TEXT("¹ÎÃ¸ÀÌ ³·¾Æ Âø¿ëÇÒ ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m					[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½Ã¸ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 					return false;[m
 				}[m
 				break;[m
[36m@@ -7730,7 +7763,7 @@[m [mbool CHARACTER::CanEquipNow(const LPITEM item, const TItemPos& srcCell, const TI[m
 			case LIMIT_CON:[m
 				if (GetPoint(POINT_HT) < limit)[m
 				{[m
[31m-					ChatPacket(CHAT_TYPE_INFO, LC_TEXT("Ã¼·ÂÀÌ ³·¾Æ Âø¿ëÇÒ ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m					[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("Ã¼ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 					return false;[m
 				}[m
 				break;[m
[36m@@ -7744,14 +7777,14 @@[m [mbool CHARACTER::CanEquipNow(const LPITEM item, const TItemPos& srcCell, const TI[m
 			(GetWear(WEAR_COSTUME_MOUNT) && GetWear(WEAR_COSTUME_MOUNT)->IsSameSpecialGroup(item))[m
 			)[m
 		{[m
[31m-			ChatPacket(CHAT_TYPE_INFO, LC_TEXT("°°Àº Á¾·ùÀÇ À¯´ÏÅ© ¾ÆÀÌÅÛ µÎ °³¸¦ µ¿½Ã¿¡ ÀåÂøÇÒ ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m			[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½Å© ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Ã¿ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 			return false;[m
 		}[m
 [m
 		if (marriage::CManager::instance().IsMarriageUniqueItem(item->GetVnum()) && [m
 			!marriage::CManager::instance().IsMarried(GetPlayerID()))[m
 		{[m
[31m-			ChatPacket(CHAT_TYPE_INFO, LC_TEXT("°áÈ¥ÇÏÁö ¾ÊÀº »óÅÂ¿¡¼­ ¿¹¹°À» Âø¿ëÇÒ ¼ö ¾ø½À´Ï´Ù."));[m
[32m+[m			[32mChatPacket(CHAT_TYPE_INFO, LC_TEXT("ï¿½ï¿½È¥ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Â¿ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."));[m
 			return false;[m
 		}[m
 [m
[36m@@ -7760,18 +7793,18 @@[m [mbool CHARACTER::CanEquipNow(const LPITEM item, const TItemPos& srcCell, const TI[m
 	return true;[m
 }[m
 [m
[31m-/// ÇöÀç Ä³¸¯ÅÍÀÇ »óÅÂ¸¦ ¹ÙÅÁÀ¸·Î Âø¿ë ÁßÀÎ itemÀ» ¹þÀ» ¼ö ÀÖ´Â Áö È®ÀÎÇÏ°í, ºÒ°¡´É ÇÏ´Ù¸é Ä³¸¯ÅÍ¿¡°Ô ÀÌÀ¯¸¦ ¾Ë·ÁÁÖ´Â ÇÔ¼ö[m
[32m+[m[32m/// ï¿½ï¿½ï¿½ï¿½ Ä³ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Â¸ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ itemï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½Ö´ï¿½ ï¿½ï¿½ È®ï¿½ï¿½ï¿½Ï°ï¿½, ï¿½Ò°ï¿½ï¿½ï¿½ ï¿½Ï´Ù¸ï¿½ Ä³ï¿½ï¿½ï¿½Í¿ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ë·ï¿½ï¿½Ö´ï¿½ ï¿½Ô¼ï¿½[m
 bool CHARACTER::CanUnequipNow(const LPITEM item, const TItemPos& srcCell, const TItemPos& destCell) /*const*/[m
 {	[m
 [m
 	if (ITEM_BELT == item->GetType())[m
[31m-		VERIFY_MSG(CBeltInventoryHelper::IsExistItemInBeltInventory(this), "º§Æ® ÀÎº¥Åä¸®¿¡ ¾ÆÀÌÅÛÀÌ Á¸ÀçÇÏ¸é ÇØÁ¦ÇÒ ¼ö ¾ø½À´Ï´Ù.");[m
[32m+[m		[32mVERIFY_MSG(CBeltInventoryHelper::IsExistItemInBeltInventory(this), "ï¿½ï¿½Æ® ï¿½Îºï¿½ï¿½ä¸®ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï¸ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½.");[m
 [m
[31m-	// ¿µ¿øÈ÷ ÇØÁ¦ÇÒ ¼ö ¾ø´Â ¾ÆÀÌÅÛ[m
[32m+[m	[32m// ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½[m
 	if (IS_SET(item->GetFlag(), ITEM_FLAG_IRREMOVABLE))[m
 		return false;[m
 [m
[31m-	// ¾ÆÀÌÅÛ unequip½Ã ÀÎº¥Åä¸®·Î ¿Å±æ ¶§ ºó ÀÚ¸®°¡ ÀÖ´Â Áö È®ÀÎ[m
[32m+[m	[32m// ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ unequipï¿½ï¿½ ï¿½Îºï¿½ï¿½ä¸®ï¿½ï¿½ ï¿½Å±ï¿½ ï¿½ï¿½ ï¿½ï¿½ ï¿½Ú¸ï¿½ï¿½ï¿½ ï¿½Ö´ï¿½ ï¿½ï¿½ È®ï¿½ï¿½[m
 	{[m
 		int pos = -1;[m
 [m
[36m@@ -7780,7 +7813,7 @@[m [mbool CHARACTER::CanUnequipNow(const LPITEM item, const TItemPos& srcCell, const[m
 		else[m
 			pos = GetEmptyInventory(item->GetSize());[m
 [m
[31m-		VERIFY_MSG( -1 == pos, "¼ÒÁöÇ°¿¡ ºó °ø°£ÀÌ ¾ø½À´Ï´Ù." );[m
[32m+[m		[32mVERIFY_MSG( -1 == pos, "ï¿½ï¿½ï¿½ï¿½Ç°ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½." );[m
 	}[m
 [m
 [m
[1mdiff --git a/game/src/item.cpp b/game/src/item.cpp[m
[1mold mode 100644[m
[1mnew mode 100755[m
[1mindex 6f1946c..c9f3e80[m
[1m--- a/game/src/item.cpp[m
[1m+++ b/game/src/item.cpp[m
[36m@@ -295,7 +295,7 @@[m [mLPITEM CItem::RemoveFromCharacter()[m
 [m
 	LPCHARACTER pOwner = m_pOwner;[m
 [m
[31m-	if (m_bEquipped)	// ÀåÂøµÇ¾ú´Â°¡?[m
[32m+[m	[32mif (m_bEquipped)	// ï¿½ï¿½ï¿½ï¿½ï¿½Ç¾ï¿½ï¿½Â°ï¿½?[m
 	{[m
 		Unequip();[m
 		//pOwner->UpdatePacket();[m
[36m@@ -319,7 +319,7 @@[m [mLPITEM CItem::RemoveFromCharacter()[m
 			{[m
 				TItemPos cell(INVENTORY, m_wCell);[m
 [m
[31m-				if (false == cell.IsDefaultInventoryPosition() && false == cell.IsBeltInventoryPosition()) // ¾Æ´Ï¸é ¼ÒÁöÇ°¿¡?[m
[32m+[m				[32mif (false == cell.IsDefaultInventoryPosition() && false == cell.IsBeltInventoryPosition()) // ï¿½Æ´Ï¸ï¿½ ï¿½ï¿½ï¿½ï¿½Ç°ï¿½ï¿½?[m
 					sys_err("CItem::RemoveFromCharacter: Invalid Item Position");[m
 				else[m
 				{[m
[36m@@ -337,7 +337,11 @@[m [mLPITEM CItem::RemoveFromCharacter()[m
 	}[m
 }[m
 [m
[32m+[m[32m#if defined(__BL_ENABLE_PICKUP_ITEM_EFFECT__)[m
[32m+[m[32mbool CItem::AddToCharacter(LPCHARACTER ch, TItemPos Cell, bool bHighlight)[m
[32m+[m[32m#else[m
 bool CItem::AddToCharacter(LPCHARACTER ch, TItemPos Cell)[m
[32m+[m[32m#endif[m
 {[m
 	assert(GetSectree() == NULL);[m
 	assert(m_pOwner == NULL);[m
[36m@@ -366,7 +370,11 @@[m [mbool CItem::AddToCharacter(LPCHARACTER ch, TItemPos Cell)[m
 [m
 	event_cancel(&m_pkDestroyEvent);[m
 [m
[32m+[m[32m#if defined(__BL_ENABLE_PICKUP_ITEM_EFFECT__)[m
[32m+[m	[32mch->SetItem(TItemPos(window_type, pos), this, bHighlight);[m
[32m+[m[32m#else[m
 	ch->SetItem(TItemPos(window_type, pos), this);[m
[32m+[m[32m#endif[m
 	m_pOwner = ch;[m
 [m
 	Save();[m
[36m@@ -471,16 +479,16 @@[m [mbool CItem::CanUsedBy(LPCHARACTER ch)[m
 [m
 int CItem::FindEquipCell(LPCHARACTER ch, int iCandidateCell)[m
 {[m
[31m-	// ÄÚ½ºÃõ ¾ÆÀÌÅÛ(ITEM_COSTUME)Àº WearFlag ¾ø¾îµµ µÊ. (sub typeÀ¸·Î Âø¿ëÀ§Ä¡ ±¸ºÐ. ±ÍÂú°Ô ¶Ç wear flag ÁÙ ÇÊ¿ä°¡ ÀÖ³ª..)[m
[31m-	// ¿ëÈ¥¼®(ITEM_DS, ITEM_SPECIAL_DS)µµ  SUB_TYPEÀ¸·Î ±¸ºÐ. ½Å±Ô ¹ÝÁö, º§Æ®´Â ITEM_TYPEÀ¸·Î ±¸ºÐ -_-[m
[32m+[m	[32m// ï¿½Ú½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½(ITEM_COSTUME)ï¿½ï¿½ WearFlag ï¿½ï¿½ï¿½îµµ ï¿½ï¿½. (sub typeï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½Ä¡ ï¿½ï¿½ï¿½ï¿½. ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ wear flag ï¿½ï¿½ ï¿½Ê¿ä°¡ ï¿½Ö³ï¿½..)[m
[32m+[m	[32m// ï¿½ï¿½È¥ï¿½ï¿½(ITEM_DS, ITEM_SPECIAL_DS)ï¿½ï¿½  SUB_TYPEï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½. ï¿½Å±ï¿½ ï¿½ï¿½ï¿½ï¿½, ï¿½ï¿½Æ®ï¿½ï¿½ ITEM_TYPEï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ -_-[m
 	if ((0 == GetWearFlag() || ITEM_TOTEM == GetType()) && ITEM_COSTUME != GetType() && ITEM_DS != GetType() && ITEM_SPECIAL_DS != GetType() && ITEM_RING != GetType() && ITEM_BELT != GetType())[m
 		return -1;[m
 [m
[31m-	// ¿ëÈ¥¼® ½½·ÔÀ» WEAR·Î Ã³¸®ÇÒ ¼ö°¡ ¾ø¾î¼­(WEAR´Â ÃÖ´ë 32°³±îÁö °¡´ÉÇÑµ¥ ¿ëÈ¥¼®À» Ãß°¡ÇÏ¸é 32°¡ ³Ñ´Â´Ù.)[m
[31m-	// ÀÎº¥Åä¸®ÀÇ Æ¯Á¤ À§Ä¡((INVENTORY_MAX_NUM + WEAR_MAX_NUM)ºÎÅÍ (INVENTORY_MAX_NUM + WEAR_MAX_NUM + DRAGON_SOUL_DECK_MAX_NUM * DS_SLOT_MAX - 1)±îÁö)¸¦[m
[31m-	// ¿ëÈ¥¼® ½½·ÔÀ¸·Î Á¤ÇÔ.[m
[31m-	// return ÇÒ ¶§¿¡, INVENTORY_MAX_NUMÀ» »« ÀÌÀ¯´Â,[m
[31m-	// º»·¡ WearCellÀÌ INVENTORY_MAX_NUM¸¦ »©°í return ÇÏ±â ¶§¹®.[m
[32m+[m	[32m// ï¿½ï¿½È¥ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ WEARï¿½ï¿½ Ã³ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½î¼­(WEARï¿½ï¿½ ï¿½Ö´ï¿½ 32ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ñµï¿½ ï¿½ï¿½È¥ï¿½ï¿½ï¿½ï¿½ ï¿½ß°ï¿½ï¿½Ï¸ï¿½ 32ï¿½ï¿½ ï¿½Ñ´Â´ï¿½.)[m
[32m+[m	[32m// ï¿½Îºï¿½ï¿½ä¸®ï¿½ï¿½ Æ¯ï¿½ï¿½ ï¿½ï¿½Ä¡((INVENTORY_MAX_NUM + WEAR_MAX_NUM)ï¿½ï¿½ï¿½ï¿½ (INVENTORY_MAX_NUM + WEAR_MAX_NUM + DRAGON_SOUL_DECK_MAX_NUM * DS_SLOT_MAX - 1)ï¿½ï¿½ï¿½ï¿½)ï¿½ï¿½[m
[32m+[m	[32m// ï¿½ï¿½È¥ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½.[m
[32m+[m	[32m// return ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½, INVENTORY_MAX_NUMï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½,[m
[32m+[m	[32m// ï¿½ï¿½ï¿½ï¿½ WearCellï¿½ï¿½ INVENTORY_MAX_NUMï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ return ï¿½Ï±ï¿½ ï¿½ï¿½ï¿½ï¿½.[m
 	if (GetType() == ITEM_DS || GetType() == ITEM_SPECIAL_DS)[m
 	{[m
 		if (iCandidateCell < 0)[m
[36m@@ -551,7 +559,7 @@[m [mint CItem::FindEquipCell(LPCHARACTER ch, int iCandidateCell)[m
 			return WEAR_UNIQUE1;		[m
 	}[m
 [m
[31m-	// ¼öÁý Äù½ºÆ®¸¦ À§ÇÑ ¾ÆÀÌÅÛÀÌ ¹ÚÈ÷´Â°÷À¸·Î ÇÑ¹ø ¹ÚÈ÷¸é Àý´ë –E¼ö ¾ø´Ù.[m
[32m+[m	[32m// ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½Æ®ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Â°ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ñ¹ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½Eï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½.[m
 	else if (GetWearFlag() & WEARABLE_ABILITY)[m
 	{[m
 		if (!ch->GetWear(WEAR_ABILITY1))[m
[36m@@ -598,12 +606,12 @@[m [mvoid CItem::ModifyPoints(bool bAdd)[m
 {[m
 	int accessoryGrade;[m
 [m
[31m-	// ¹«±â¿Í °©¿Ê¸¸ ¼ÒÄÏÀ» Àû¿ë½ÃÅ²´Ù.[m
[32m+[m	[32m// ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Ê¸ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Å²ï¿½ï¿½.[m
 	if (false == IsAccessoryForSocket())[m
 	{[m
 		if (m_pProto->bType == ITEM_WEAPON || m_pProto->bType == ITEM_ARMOR)[m
 		{[m
[31m-			// ¼ÒÄÏÀÌ ¼Ó¼º°­È­¿¡ »ç¿ëµÇ´Â °æ¿ì Àû¿ëÇÏÁö ¾Ê´Â´Ù (ARMOR_WRIST ARMOR_NECK ARMOR_EAR)[m
[32m+[m			[32m// ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ó¼ï¿½ï¿½ï¿½È­ï¿½ï¿½ ï¿½ï¿½ï¿½Ç´ï¿½ ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ê´Â´ï¿½ (ARMOR_WRIST ARMOR_NECK ARMOR_EAR)[m
 			for (int i = 0; i < ITEM_SOCKET_MAX_NUM; ++i)[m
 			{[m
 				DWORD dwVnum;[m
[36m@@ -662,12 +670,12 @@[m [mvoid CItem::ModifyPoints(bool bAdd)[m
 			m_pOwner->ApplyPoint(m_pProto->aApplies[i].bType, bAdd ? value : -value);[m
 		}[m
 	}[m
[31m-	// ÃÊ½Â´ÞÀÇ ¹ÝÁö, ÇÒ·ÎÀ© »çÅÁ, Çàº¹ÀÇ ¹ÝÁö, ¿µ¿øÇÑ »ç¶ûÀÇ Ææ´øÆ®ÀÇ °æ¿ì[m
[31m-	// ±âÁ¸ÀÇ ÇÏµå ÄÚµùÀ¸·Î °­Á¦·Î ¼Ó¼ºÀ» ºÎ¿©ÇßÁö¸¸,[m
[31m-	// ±× ºÎºÐÀ» Á¦°ÅÇÏ°í special item group Å×ÀÌºí¿¡¼­ ¼Ó¼ºÀ» ºÎ¿©ÇÏµµ·Ï º¯°æÇÏ¿´´Ù.[m
[31m-	// ÇÏÁö¸¸ ÇÏµå ÄÚµùµÇ¾îÀÖÀ» ¶§ »ý¼ºµÈ ¾ÆÀÌÅÛÀÌ ³²¾ÆÀÖÀ» ¼öµµ ÀÖ¾î¼­ Æ¯¼öÃ³¸® ÇØ³õ´Â´Ù.[m
[31m-	// ÀÌ ¾ÆÀÌÅÛµéÀÇ °æ¿ì, ¹Ø¿¡ ITEM_UNIQUEÀÏ ¶§ÀÇ Ã³¸®·Î ¼Ó¼ºÀÌ ºÎ¿©µÇ±â ¶§¹®¿¡,[m
[31m-	// ¾ÆÀÌÅÛ¿¡ ¹ÚÇôÀÖ´Â attribute´Â Àû¿ëÇÏÁö ¾Ê°í ³Ñ¾î°£´Ù.[m
[32m+[m	[32m// ï¿½Ê½Â´ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½, ï¿½Ò·ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½, ï¿½àº¹ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½, ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Æ®ï¿½ï¿½ ï¿½ï¿½ï¿½[m
[32m+[m	[32m// ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ïµï¿½ ï¿½Úµï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ó¼ï¿½ï¿½ï¿½ ï¿½Î¿ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½,[m
[32m+[m	[32m// ï¿½ï¿½ ï¿½Îºï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï°ï¿½ special item group ï¿½ï¿½ï¿½Ìºï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ó¼ï¿½ï¿½ï¿½ ï¿½Î¿ï¿½ï¿½Ïµï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï¿ï¿½ï¿½ï¿½.[m
[32m+[m	[32m// ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ïµï¿½ ï¿½Úµï¿½ï¿½Ç¾ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½Ö¾î¼­ Æ¯ï¿½ï¿½Ã³ï¿½ï¿½ ï¿½Ø³ï¿½ï¿½Â´ï¿½.[m
[32m+[m	[32m// ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ûµï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½, ï¿½Ø¿ï¿½ ITEM_UNIQUEï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ Ã³ï¿½ï¿½ï¿½ï¿½ ï¿½Ó¼ï¿½ï¿½ï¿½ ï¿½Î¿ï¿½ï¿½Ç±ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½,[m
[32m+[m	[32m// ï¿½ï¿½ï¿½ï¿½ï¿½Û¿ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ö´ï¿½ attributeï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ê°ï¿½ ï¿½Ñ¾î°£ï¿½ï¿½.[m
 	if (true == CItemVnumHelper::IsRamadanMoonRing(GetVnum()) || true == CItemVnumHelper::IsHalloweenCandy(GetVnum())[m
 		|| true == CItemVnumHelper::IsHappinessRing(GetVnum()) || true == CItemVnumHelper::IsLovePendant(GetVnum()))[m
 	{[m
[36m@@ -727,7 +735,7 @@[m [mvoid CItem::ModifyPoints(bool bAdd)[m
 [m
 		case ITEM_ARMOR:[m
 			{[m
[31m-				// ÄÚ½ºÃõ body¸¦ ÀÔ°íÀÖ´Ù¸é armor´Â ¹þ´ø ÀÔ´ø »ó°ü ¾øÀÌ ºñÁÖ¾ó¿¡ ¿µÇâÀ» ÁÖ¸é ¾È µÊ.[m
[32m+[m				[32m// ï¿½Ú½ï¿½ï¿½ï¿½ bodyï¿½ï¿½ ï¿½Ô°ï¿½ï¿½Ö´Ù¸ï¿½ armorï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½Ô´ï¿½ ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Ö¾ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ö¸ï¿½ ï¿½ï¿½ ï¿½ï¿½.[m
 				if (0 != m_pOwner->GetWear(WEAR_COSTUME_BODY))[m
 					break;[m
 [m
[36m@@ -747,7 +755,7 @@[m [mvoid CItem::ModifyPoints(bool bAdd)[m
 			}[m
 			break;[m
 [m
[31m-		// ÄÚ½ºÃõ ¾ÆÀÌÅÛ ÀÔ¾úÀ» ¶§ Ä³¸¯ÅÍ parts Á¤º¸ ¼¼ÆÃ. ±âÁ¸ ½ºÅ¸ÀÏ´ë·Î Ãß°¡ÇÔ..[m
[32m+[m		[32m// ï¿½Ú½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ô¾ï¿½ï¿½ï¿½ ï¿½ï¿½ Ä³ï¿½ï¿½ï¿½ï¿½ parts ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½. ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½Å¸ï¿½Ï´ï¿½ï¿½ ï¿½ß°ï¿½ï¿½ï¿½..[m
 		case ITEM_COSTUME:[m
 			{[m
 				DWORD toSetValue = this->GetVnum();[m
[36m@@ -846,7 +854,7 @@[m [mbool CItem::EquipTo(LPCHARACTER ch, BYTE bWearCell)[m
 		return false;[m
 	}[m
 [m
[31m-	// ¿ëÈ¥¼® ½½·Ô index´Â WEAR_MAX_NUM º¸´Ù Å­.[m
[32m+[m	[32m// ï¿½ï¿½È¥ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ indexï¿½ï¿½ WEAR_MAX_NUM ï¿½ï¿½ï¿½ï¿½ Å­.[m
 	if (IsDragonSoul())[m
 	{[m
 		if (bWearCell < WEAR_MAX_NUM || bWearCell >= WEAR_MAX_NUM + DRAGON_SOUL_DECK_MAX_NUM * DS_SLOT_MAX)[m
[36m@@ -873,7 +881,7 @@[m [mbool CItem::EquipTo(LPCHARACTER ch, BYTE bWearCell)[m
 	if (GetOwner())[m
 		RemoveFromCharacter();[m
 [m
[31m-	ch->SetWear(bWearCell, this); // ¿©±â¼­ ÆÐÅ¶ ³ª°¨[m
[32m+[m	[32mch->SetWear(bWearCell, this); // ï¿½ï¿½ï¿½â¼­ ï¿½ï¿½Å¶ ï¿½ï¿½ï¿½ï¿½[m
 [m
 	m_pOwner = ch;[m
 	m_bEquipped = true;[m
[36m@@ -957,7 +965,7 @@[m [mbool CItem::Unequip()[m
 		return false;[m
 	}[m
 [m
[31m-	//½Å±Ô ¸» ¾ÆÀÌÅÛ Á¦°Å½Ã Ã³¸®[m
[32m+[m	[32m//ï¿½Å±ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Å½ï¿½ Ã³ï¿½ï¿½[m
 	if (IsRideItem())[m
 		ClearMountAttributeAndAffect();[m
 [m
[36m@@ -1317,7 +1325,7 @@[m [mvoid CItem::AlterToMagicItem()[m
 		}[m
 	}[m
 [m
[31m-	// 100% È®·ü·Î ÁÁÀº ¼Ó¼º ÇÏ³ª[m
[32m+[m	[32m// 100% È®ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½Ó¼ï¿½ ï¿½Ï³ï¿½[m
 	PutAttribute(aiItemMagicAttributePercentHigh);[m
 [m
 	if (number(1, 100) <= iSecondPct)[m
[36m@@ -1403,8 +1411,8 @@[m [mEVENTFUNC(unique_expire_event)[m
 		}[m
 		else[m
 		{[m
[31m-			// °ÔÀÓ ³»¿¡ ½Ã°£Á¦ ¾ÆÀÌÅÛµéÀÌ ºü¸´ºü¸´ÇÏ°Ô »ç¶óÁöÁö ¾Ê´Â ¹ö±×°¡ ÀÖ¾î[m
[31m-			// ¼öÁ¤[m
[32m+[m			[32m// ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½Ã°ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ûµï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½Ï°ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ê´ï¿½ ï¿½ï¿½ï¿½×°ï¿½ ï¿½Ö¾ï¿½[m
[32m+[m			[32m// ï¿½ï¿½ï¿½ï¿½[m
 			// by rtsummit[m
 			if (pkItem->GetSocket(ITEM_SOCKET_UNIQUE_REMAIN_TIME) - cur < 600)[m
 				return PASSES_PER_SEC(pkItem->GetSocket(ITEM_SOCKET_UNIQUE_REMAIN_TIME) - cur);[m
[36m@@ -1414,9 +1422,9 @@[m [mEVENTFUNC(unique_expire_event)[m
 	}[m
 }[m
 [m
[31m-// ½Ã°£ ÈÄºÒÁ¦[m
[31m-// timer¸¦ ½ÃÀÛÇÒ ¶§¿¡ ½Ã°£ Â÷°¨ÇÏ´Â °ÍÀÌ ¾Æ´Ï¶ó, [m
[31m-// timer°¡ ¹ßÈ­ÇÒ ¶§¿¡ timer°¡ µ¿ÀÛÇÑ ½Ã°£ ¸¸Å­ ½Ã°£ Â÷°¨À» ÇÑ´Ù.[m
[32m+[m[32m// ï¿½Ã°ï¿½ ï¿½Äºï¿½ï¿½ï¿½[m
[32m+[m[32m// timerï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½Ã°ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½Æ´Ï¶ï¿½,[m[41m [m
[32m+[m[32m// timerï¿½ï¿½ ï¿½ï¿½È­ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ timerï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ã°ï¿½ ï¿½ï¿½Å­ ï¿½Ã°ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ñ´ï¿½.[m
 EVENTFUNC(timer_based_on_wear_expire_event)[m
 {[m
 	item_event_info* info = dynamic_cast<item_event_info*>( event->info );[m
[36m@@ -1435,7 +1443,7 @@[m [mEVENTFUNC(timer_based_on_wear_expire_event)[m
 		pkItem->SetTimerBasedOnWearExpireEvent(NULL);[m
 		pkItem->SetSocket(ITEM_SOCKET_REMAIN_SEC, 0);[m
 	[m
[31m-		// ÀÏ´Ü timer based on wear ¿ëÈ¥¼®Àº ½Ã°£ ´Ù µÇ¾ú´Ù°í ¾ø¾ÖÁö ¾Ê´Â´Ù.[m
[32m+[m		[32m// ï¿½Ï´ï¿½ timer based on wear ï¿½ï¿½È¥ï¿½ï¿½ï¿½ï¿½ ï¿½Ã°ï¿½ ï¿½ï¿½ ï¿½Ç¾ï¿½ï¿½Ù°ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ê´Â´ï¿½.[m
 		if (pkItem->IsDragonSoul())[m
 		{[m
 			DSManager::instance().DeactivateDragonSoul(pkItem);[m
[36m@@ -1534,7 +1542,7 @@[m [mvoid CItem::StartUniqueExpireEvent()[m
 	if (m_pkUniqueExpireEvent)[m
 		return;[m
 [m
[31m-	//±â°£Á¦ ¾ÆÀÌÅÛÀÏ °æ¿ì ½Ã°£Á¦ ¾ÆÀÌÅÛÀº µ¿ÀÛÇÏÁö ¾Ê´Â´Ù[m
[32m+[m	[32m//ï¿½â°£ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ ï¿½Ã°ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ê´Â´ï¿½[m
 	if (IsRealTimeItem())[m
 		return;[m
 [m
[36m@@ -1557,14 +1565,14 @@[m [mvoid CItem::StartUniqueExpireEvent()[m
 	SetUniqueExpireEvent(event_create(unique_expire_event, info, PASSES_PER_SEC(iSec)));[m
 }[m
 [m
[31m-// ½Ã°£ ÈÄºÒÁ¦[m
[31m-// timer_based_on_wear_expire_event ¼³¸í ÂüÁ¶[m
[32m+[m[32m// ï¿½Ã°ï¿½ ï¿½Äºï¿½ï¿½ï¿½[m
[32m+[m[32m// timer_based_on_wear_expire_event ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½[m
 void CItem::StartTimerBasedOnWearExpireEvent()[m
 {[m
 	if (m_pkTimerBasedOnWearExpireEvent)[m
 		return;[m
 [m
[31m-	//±â°£Á¦ ¾ÆÀÌÅÛÀÏ °æ¿ì ½Ã°£Á¦ ¾ÆÀÌÅÛÀº µ¿ÀÛÇÏÁö ¾Ê´Â´Ù[m
[32m+[m	[32m//ï¿½â°£ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ ï¿½Ã°ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ê´Â´ï¿½[m
 	if (IsRealTimeItem())[m
 		return;[m
 [m
[36m@@ -1573,7 +1581,7 @@[m [mvoid CItem::StartTimerBasedOnWearExpireEvent()[m
 [m
 	int iSec = GetSocket(0);[m
 	[m
[31m-	// ³²Àº ½Ã°£À» ºÐ´ÜÀ§·Î ²÷±â À§ÇØ...[m
[32m+[m	[32m// ï¿½ï¿½ï¿½ï¿½ ï¿½Ã°ï¿½ï¿½ï¿½ ï¿½Ð´ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½...[m
 	if (0 != iSec)[m
 	{[m
 		iSec %= 60;[m
[36m@@ -1592,7 +1600,7 @@[m [mvoid CItem::StopUniqueExpireEvent()[m
 	if (!m_pkUniqueExpireEvent)[m
 		return;[m
 [m
[31m-	if (GetValue(2) != 0) // °ÔÀÓ½Ã°£Á¦ ÀÌ¿ÜÀÇ ¾ÆÀÌÅÛÀº UniqueExpireEvent¸¦ Áß´ÜÇÒ ¼ö ¾ø´Ù.[m
[32m+[m	[32mif (GetValue(2) != 0) // ï¿½ï¿½ï¿½Ó½Ã°ï¿½ï¿½ï¿½ ï¿½Ì¿ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ UniqueExpireEventï¿½ï¿½ ï¿½ß´ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½.[m
 		return;[m
 [m
 	// HARD CODING[m
[36m@@ -1629,12 +1637,12 @@[m [mint CItem::GetSpecialGroup() const[m
 }[m
 [m
 //[m
[31m-// ¾Ç¼¼¼­¸® ¼ÒÄÏ Ã³¸®.[m
[32m+[m[32m// ï¿½Ç¼ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ Ã³ï¿½ï¿½.[m
 //[m
 bool CItem::IsAccessoryForSocket()[m
 {[m
 	return (m_pProto->bType == ITEM_ARMOR && (m_pProto->bSubType == ARMOR_WRIST || m_pProto->bSubType == ARMOR_NECK || m_pProto->bSubType == ARMOR_EAR)) ||[m
[31m-		(m_pProto->bType == ITEM_BELT);				// 2013³â 2¿ù »õ·Î Ãß°¡µÈ 'º§Æ®' ¾ÆÀÌÅÛÀÇ °æ¿ì ±âÈ¹ÆÀ¿¡¼­ ¾Ç¼¼¼­¸® ¼ÒÄÏ ½Ã½ºÅÛÀ» ±×´ë·Î ÀÌ¿ëÇÏÀÚ°í ÇÔ.[m
[32m+[m		[32m(m_pProto->bType == ITEM_BELT);				// 2013ï¿½ï¿½ 2ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ß°ï¿½ï¿½ï¿½ 'ï¿½ï¿½Æ®' ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ ï¿½ï¿½È¹ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ç¼ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½Ã½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½×´ï¿½ï¿½ ï¿½Ì¿ï¿½ï¿½ï¿½ï¿½Ú°ï¿½ ï¿½ï¿½.[m
 }[m
 [m
 void CItem::SetAccessorySocketGrade(int iGrade) [m
[36m@@ -1659,7 +1667,7 @@[m [mvoid CItem::SetAccessorySocketDownGradeTime(DWORD time)[m
 	SetSocket(2, time); [m
 [m
 	if (test_server && GetOwner())[m
[31m-		GetOwner()->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("%s¿¡¼­ ¼ÒÄÏ ºüÁú¶§±îÁö ³²Àº ½Ã°£ %d"), GetName(), time);[m
[32m+[m		[32mGetOwner()->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("%sï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½Ã°ï¿½ %d"), GetName(), time);[m
 }[m
 [m
 EVENTFUNC(accessory_socket_expire_event)[m
[36m@@ -1781,7 +1789,7 @@[m [mvoid CItem::ClearMountAttributeAndAffect()[m
 }[m
 [m
 // fixme[m
[31m-// ÀÌ°Å Áö±ÝÀº ¾È¾´µ¥... ±Ùµ¥ È¤½Ã³ª ½Í¾î¼­ ³²°ÜµÒ.[m
[32m+[m[32m// ï¿½Ì°ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½È¾ï¿½ï¿½ï¿½... ï¿½Ùµï¿½ È¤ï¿½Ã³ï¿½ ï¿½Í¾î¼­ ï¿½ï¿½ï¿½Üµï¿½.[m
 // by rtsummit[m
 bool CItem::IsNewMountItem()[m
 {[m
[36m@@ -1809,7 +1817,7 @@[m [mvoid CItem::AccessorySocketDegrade()[m
 [m
 		if (ch)[m
 		{[m
[31m-			ch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("%s¿¡ ¹ÚÇôÀÖ´ø º¸¼®ÀÌ »ç¶óÁý´Ï´Ù."), GetName());[m
[32m+[m			[32mch->ChatPacket(CHAT_TYPE_INFO, LC_TEXT("%sï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ö´ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½Ï´ï¿½."), GetName());[m
 		}[m
 [m
 		ModifyPoints(false);[m
[36m@@ -1828,7 +1836,7 @@[m [mvoid CItem::AccessorySocketDegrade()[m
 	}[m
 }[m
 [m
[31m-// ring¿¡ itemÀ» ¹ÚÀ» ¼ö ÀÖ´ÂÁö ¿©ºÎ¸¦ Ã¼Å©ÇØ¼­ ¸®ÅÏ[m
[32m+[m[32m// ringï¿½ï¿½ itemï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½Ö´ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Î¸ï¿½ Ã¼Å©ï¿½Ø¼ï¿½ ï¿½ï¿½ï¿½ï¿½[m
 static const bool CanPutIntoRing(LPITEM ring, LPITEM item)[m
 {[m
 	const DWORD vnum = item->GetVnum();[m
[36m@@ -2037,10 +2045,10 @@[m [mint CItem::GetLevelLimit()[m
 [m
 bool CItem::OnAfterCreatedItem()[m
 {[m
[31m-	// ¾ÆÀÌÅÛÀ» ÇÑ ¹øÀÌ¶óµµ »ç¿ëÇß´Ù¸é, ±× ÀÌÈÄ¿£ »ç¿ë ÁßÀÌÁö ¾Ê¾Æµµ ½Ã°£ÀÌ Â÷°¨µÇ´Â ¹æ½Ä[m
[32m+[m	[32m// ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½ï¿½ï¿½Ì¶ï¿½ ï¿½ï¿½ï¿½ï¿½ß´Ù¸ï¿½, ï¿½ï¿½ ï¿½ï¿½ï¿½Ä¿ï¿½ ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ê¾Æµï¿½ ï¿½Ã°ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ç´ï¿½ ï¿½ï¿½ï¿½[m
 	if (-1 != this->GetProto()->cLimitRealTimeFirstUseIndex)[m
 	{[m
[31m-		// Socket1¿¡ ¾ÆÀÌÅÛÀÇ »ç¿ë È½¼ö°¡ ±â·ÏµÇ¾î ÀÖÀ¸´Ï, ÇÑ ¹øÀÌ¶óµµ »ç¿ëÇÑ ¾ÆÀÌÅÛÀº Å¸ÀÌ¸Ó¸¦ ½ÃÀÛÇÑ´Ù.[m
[32m+[m		[32m// Socket1ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ È½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ÏµÇ¾ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½, ï¿½ï¿½ ï¿½ï¿½ï¿½Ì¶ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ Å¸ï¿½Ì¸Ó¸ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ñ´ï¿½.[m
 		if (0 != GetSocket(1))[m
 		{[m
 			StartRealTimeExpireEvent();[m
[36m@@ -2076,7 +2084,7 @@[m [mint CItem::GiveMoreTime_Per(float fPercent)[m
 			return given_time;[m
 		}[m
 	}[m
[31m-	// ¿ì¼± ¿ëÈ¥¼®¿¡ °üÇØ¼­¸¸ ÇÏµµ·Ï ÇÑ´Ù.[m
[32m+[m	[32m// ï¿½ì¼± ï¿½ï¿½È¥ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Ø¼ï¿½ï¿½ï¿½ ï¿½Ïµï¿½ï¿½ï¿½ ï¿½Ñ´ï¿½.[m
 	else[m
 		return 0;[m
 }[m
[36m@@ -2100,7 +2108,7 @@[m [mint CItem::GiveMoreTime_Fix(DWORD dwTime)[m
 			return dwTime;[m
 		}[m
 	}[m
[31m-	// ¿ì¼± ¿ëÈ¥¼®¿¡ °üÇØ¼­¸¸ ÇÏµµ·Ï ÇÑ´Ù.[m
[32m+[m	[32m// ï¿½ì¼± ï¿½ï¿½È¥ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Ø¼ï¿½ï¿½ï¿½ ï¿½Ïµï¿½ï¿½ï¿½ ï¿½Ñ´ï¿½.[m
 	else[m
 		return 0;[m
 }[m
[36m@@ -2125,7 +2133,7 @@[m [mint	CItem::GetDuration()[m
 [m
 bool CItem::IsSameSpecialGroup(const LPITEM item) const[m
 {[m
[31m-	// ¼­·Î VNUMÀÌ °°´Ù¸é °°Àº ±×·ìÀÎ °ÍÀ¸·Î °£ÁÖ[m
[32m+[m	[32m// ï¿½ï¿½ï¿½ï¿½ VNUMï¿½ï¿½ ï¿½ï¿½ï¿½Ù¸ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½×·ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½[m
 	if (this->GetVnum() == item->GetVnum())[m
 		return true;[m
 [m
[1mdiff --git a/game/src/item.h b/game/src/item.h[m
[1mold mode 100644[m
[1mnew mode 100755[m
[1mindex 3dce2fe..0451198[m
[1m--- a/game/src/item.h[m
[1m+++ b/game/src/item.h[m
[36m@@ -58,10 +58,10 @@[m [mclass CItem : public CEntity[m
 		bool		SetCount(DWORD count);[m
 		DWORD		GetCount();[m
 [m
[31m-		// GetVnum°ú GetOriginalVnum¿¡ ´ëÇÑ comment[m
[31m-		// GetVnumÀº Masking µÈ VnumÀÌ´Ù. ÀÌ¸¦ »ç¿ëÇÔÀ¸·Î½á, ¾ÆÀÌÅÛÀÇ ½ÇÁ¦ VnumÀº 10ÀÌÁö¸¸, VnumÀÌ 20ÀÎ °ÍÃ³·³ µ¿ÀÛÇÒ ¼ö ÀÖ´Â °ÍÀÌ´Ù.[m
[31m-		// Masking °ªÀº ori_to_new.txt¿¡¼­ Á¤ÀÇµÈ °ªÀÌ´Ù.[m
[31m-		// GetOriginalVnumÀº ¾ÆÀÌÅÛ °íÀ¯ÀÇ VnumÀ¸·Î, ·Î±× ³²±æ ¶§, Å¬¶óÀÌ¾ðÆ®¿¡ ¾ÆÀÌÅÛ Á¤º¸ º¸³¾ ¶§, ÀúÀåÇÒ ¶§´Â ÀÌ VnumÀ» »ç¿ëÇÏ¿©¾ß ÇÑ´Ù.[m
[32m+[m		[32m// GetVnumï¿½ï¿½ GetOriginalVnumï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ comment[m
[32m+[m		[32m// GetVnumï¿½ï¿½ Masking ï¿½ï¿½ Vnumï¿½Ì´ï¿½. ï¿½Ì¸ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½Î½ï¿½, ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ Vnumï¿½ï¿½ 10ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½, Vnumï¿½ï¿½ 20ï¿½ï¿½ ï¿½ï¿½Ã³ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½Ö´ï¿½ ï¿½ï¿½ï¿½Ì´ï¿½.[m
[32m+[m		[32m// Masking ï¿½ï¿½ï¿½ï¿½ ori_to_new.txtï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Çµï¿½ ï¿½ï¿½ï¿½Ì´ï¿½.[m
[32m+[m		[32m// GetOriginalVnumï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ Vnumï¿½ï¿½ï¿½ï¿½, ï¿½Î±ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½, Å¬ï¿½ï¿½ï¿½Ì¾ï¿½Æ®ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½, ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ Vnumï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½Ï¿ï¿½ï¿½ï¿½ ï¿½Ñ´ï¿½.[m
 		// [m
 		DWORD		GetVnum() const		{ return m_dwMaskVnum ? m_dwMaskVnum : m_dwVnum;	}[m
 		DWORD		GetOriginalVnum() const		{ return m_dwVnum;	}[m
[36m@@ -80,7 +80,11 @@[m [mclass CItem : public CEntity[m
 		WORD		GetCell()				{ return m_wCell;	}[m
 [m
 		LPITEM		RemoveFromCharacter();[m
[32m+[m[32m#if defined(__BL_ENABLE_PICKUP_ITEM_EFFECT__)[m
[32m+[m		[32mbool		AddToCharacter(LPCHARACTER ch, TItemPos Cell, bool bHighlight = true);[m
[32m+[m[32m#else[m
 		bool		AddToCharacter(LPCHARACTER ch, TItemPos Cell);[m
[32m+[m[32m#endif[m
 		LPCHARACTER	GetOwner()		{ return m_pOwner; }[m
 [m
 		LPITEM		RemoveFromGround();[m
[36m@@ -105,7 +109,7 @@[m [mclass CItem : public CEntity[m
 [m
 		bool		IsPolymorphItem();[m
 [m
[31m-		void		ModifyPoints(bool bAdd);	// ¾ÆÀÌÅÛÀÇ È¿°ú¸¦ Ä³¸¯ÅÍ¿¡ ºÎ¿© ÇÑ´Ù. bAdd°¡ falseÀÌ¸é Á¦°ÅÇÔ[m
[32m+[m		[32mvoid		ModifyPoints(bool bAdd);	// ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ È¿ï¿½ï¿½ï¿½ï¿½ Ä³ï¿½ï¿½ï¿½Í¿ï¿½ ï¿½Î¿ï¿½ ï¿½Ñ´ï¿½. bAddï¿½ï¿½ falseï¿½Ì¸ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½[m
 [m
 		bool		CreateSocket(BYTE bSlot, BYTE bGold);[m
 		const long *	GetSockets()		{ return &m_alSockets[0];	}[m
[36m@@ -163,7 +167,7 @@[m [mclass CItem : public CEntity[m
 [m
 		DWORD		GetLastOwnerPID()	{ return m_dwLastOwnerPID; }[m
 [m
[31m-		int		GetAttributeSetIndex(); // ¼Ó¼º ºÙ´Â°ÍÀ» ÁöÁ¤ÇÑ ¹è¿­ÀÇ ¾î´À ÀÎµ¦½º¸¦ »ç¿ëÇÏ´ÂÁö µ¹·ÁÁØ´Ù.[m
[32m+[m		[32mint		GetAttributeSetIndex(); // ï¿½Ó¼ï¿½ ï¿½Ù´Â°ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½è¿­ï¿½ï¿½ ï¿½ï¿½ï¿½ ï¿½Îµï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½Ï´ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ø´ï¿½.[m
 		void		AlterToMagicItem();[m
 		void		AlterToSocketItem(int iSocketCount);[m
 [m
[36m@@ -182,7 +186,7 @@[m [mclass CItem : public CEntity[m
 		void		StopTimerBasedOnWearExpireEvent();[m
 		void		StopAccessorySocketExpireEvent();[m
 [m
[31m-		//			ÀÏ´Ü REAL_TIME°ú TIMER_BASED_ON_WEAR ¾ÆÀÌÅÛ¿¡ ´ëÇØ¼­¸¸ Á¦´ë·Î µ¿ÀÛÇÔ.[m
[32m+[m		[32m//			ï¿½Ï´ï¿½ REAL_TIMEï¿½ï¿½ TIMER_BASED_ON_WEAR ï¿½ï¿½ï¿½ï¿½ï¿½Û¿ï¿½ ï¿½ï¿½ï¿½Ø¼ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½.[m
 		int			GetDuration();[m
 [m
 		int		GetAttributeCount();[m
[36m@@ -197,7 +201,7 @@[m [mclass CItem : public CEntity[m
 		bool	IsSameSpecialGroup(const LPITEM item) const;[m
 [m
 		// ACCESSORY_REFINE[m
[31m-		// ¾×¼¼¼­¸®¿¡ ±¤»êÀ» ÅëÇØ ¼ÒÄÏÀ» Ãß°¡[m
[32m+[m		[32m// ï¿½×¼ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ß°ï¿½[m
 		bool		IsAccessoryForSocket();[m
 [m
 		int		GetAccessorySocketGrade();[m
[36m@@ -210,7 +214,7 @@[m [mclass CItem : public CEntity[m
 [m
 		void		AccessorySocketDegrade();[m
 [m
[31m-		// ¾Ç¼¼»ç¸® ¸¦ ¾ÆÀÌÅÛ¿¡ ¹Û¾ÒÀ»¶§ Å¸ÀÌ¸Ó µ¹¾Æ°¡´Â°Í( ±¸¸®, µî )[m
[32m+[m		[32m// ï¿½Ç¼ï¿½ï¿½ç¸® ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Û¿ï¿½ ï¿½Û¾ï¿½ï¿½ï¿½ï¿½ï¿½ Å¸ï¿½Ì¸ï¿½ ï¿½ï¿½ï¿½Æ°ï¿½ï¿½Â°ï¿½( ï¿½ï¿½ï¿½ï¿½, ï¿½ï¿½ )[m
 		void		StartAccessorySocketExpireEvent();[m
 		void		SetAccessorySocketExpireEvent(LPEVENT pkEvent);[m
 [m
[36m@@ -244,7 +248,7 @@[m [mclass CItem : public CEntity[m
 [m
 	protected:[m
 		friend class CInputDB;[m
[31m-		bool		OnAfterCreatedItem();			// ¼­¹ö»ó¿¡ ¾ÆÀÌÅÛÀÌ ¸ðµç Á¤º¸¿Í ÇÔ²² ¿ÏÀüÈ÷ »ý¼º(·Îµå)µÈ ÈÄ ºÒ¸®¿ì´Â ÇÔ¼ö.[m
[32m+[m		[32mbool		OnAfterCreatedItem();			// ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ô²ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½(ï¿½Îµï¿½)ï¿½ï¿½ ï¿½ï¿½ ï¿½Ò¸ï¿½ï¿½ï¿½ï¿½ ï¿½Ô¼ï¿½.[m
 [m
 	public:[m
 		bool		IsRideItem();[m
[36m@@ -254,42 +258,42 @@[m [mclass CItem : public CEntity[m
 		bool		IsNewMountItem();[m
 [m
 [m
[31m-		// µ¶ÀÏ¿¡¼­ ±âÁ¸ Ä³½Ã ¾ÆÀÌÅÛ°ú °°Áö¸¸, ±³È¯ °¡´ÉÇÑ Ä³½Ã ¾ÆÀÌÅÛÀ» ¸¸µç´Ù°í ÇÏ¿©,[m
[31m-		// ¿À¸®Áö³Î ¾ÆÀÌÅÛ¿¡, ±³È¯ ±ÝÁö ÇÃ·¡±×¸¸ »èÁ¦ÇÑ »õ·Î¿î ¾ÆÀÌÅÛµéÀ» »õ·Î¿î ¾ÆÀÌÅÛ ´ë¿ª¿¡ ÇÒ´çÇÏ¿´´Ù.[m
[31m-		// ¹®Á¦´Â »õ·Î¿î ¾ÆÀÌÅÛµµ ¿À¸®Áö³Î ¾ÆÀÌÅÛ°ú °°Àº È¿°ú¸¦ ³»¾ßÇÏ´Âµ¥,[m
[31m-		// ¼­¹ö°Ç, Å¬¶ó°Ç, vnum ±â¹ÝÀ¸·Î µÇ¾îÀÖ¾î[m
[31m-		// »õ·Î¿î vnumÀ» ÁË´Ù ¼­¹ö¿¡ »õ·Î ´Ù ¹Ú¾Æ¾ßÇÏ´Â ¾ÈÅ¸±î¿î »óÈ²¿¡ ¸Â´ê¾Ò´Ù.[m
[31m-		// ±×·¡¼­ »õ vnumÀÇ ¾ÆÀÌÅÛÀÌ¸é, ¼­¹ö¿¡¼­ µ¹¾Æ°¥ ¶§´Â ¿À¸®Áö³Î ¾ÆÀÌÅÛ vnumÀ¸·Î ¹Ù²ã¼­ µ¹°í ÇÏ°í,[m
[31m-		// ÀúÀåÇÒ ¶§¿¡ º»·¡ vnumÀ¸·Î ¹Ù²ãÁÖµµ·Ï ÇÑ´Ù.[m
[32m+[m		[32m// ï¿½ï¿½ï¿½Ï¿ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ Ä³ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Û°ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½, ï¿½ï¿½È¯ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ Ä³ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½Ù°ï¿½ ï¿½Ï¿ï¿½,[m
[32m+[m		[32m// ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Û¿ï¿½, ï¿½ï¿½È¯ ï¿½ï¿½ï¿½ï¿½ ï¿½Ã·ï¿½ï¿½×¸ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Î¿ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ûµï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Î¿ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ë¿ªï¿½ï¿½ ï¿½Ò´ï¿½ï¿½Ï¿ï¿½ï¿½ï¿½.[m
[32m+[m		[32m// ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Î¿ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ûµï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Û°ï¿½ ï¿½ï¿½ï¿½ï¿½ È¿ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½Ï´Âµï¿½,[m
[32m+[m		[32m// ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½, Å¬ï¿½ï¿½ï¿½, vnum ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ç¾ï¿½ï¿½Ö¾ï¿½[m
[32m+[m		[32m// ï¿½ï¿½ï¿½Î¿ï¿½ vnumï¿½ï¿½ ï¿½Ë´ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ ï¿½Ú¾Æ¾ï¿½ï¿½Ï´ï¿½ ï¿½ï¿½Å¸ï¿½ï¿½ï¿½ ï¿½ï¿½È²ï¿½ï¿½ ï¿½Â´ï¿½Ò´ï¿½.[m
[32m+[m		[32m// ï¿½×·ï¿½ï¿½ï¿½ ï¿½ï¿½ vnumï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½Ì¸ï¿½, ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½Æ°ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ vnumï¿½ï¿½ï¿½ï¿½ ï¿½Ù²ã¼­ ï¿½ï¿½ï¿½ï¿½ ï¿½Ï°ï¿½,[m
[32m+[m		[32m// ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ vnumï¿½ï¿½ï¿½ï¿½ ï¿½Ù²ï¿½ï¿½Öµï¿½ï¿½ï¿½ ï¿½Ñ´ï¿½.[m
 [m
[31m-		// Mask vnumÀº ¾î¶² ÀÌÀ¯(ex. À§ÀÇ »óÈ²)·Î ÀÎÇØ vnumÀÌ ¹Ù²î¾î µ¹¾Æ°¡´Â ¾ÆÀÌÅÛÀ» À§ÇØ ÀÖ´Ù.[m
[32m+[m		[32m// Mask vnumï¿½ï¿½ ï¿½î¶² ï¿½ï¿½ï¿½ï¿½(ex. ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½È²)ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ vnumï¿½ï¿½ ï¿½Ù²ï¿½ï¿½ ï¿½ï¿½ï¿½Æ°ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ ï¿½Ö´ï¿½.[m
 		void		SetMaskVnum(DWORD vnum)	{	m_dwMaskVnum = vnum; }[m
 		DWORD		GetMaskVnum()			{	return m_dwMaskVnum; }[m
 		bool		IsMaskedItem()	{	return m_dwMaskVnum != 0;	}[m
 [m
[31m-		// ¿ëÈ¥¼®[m
[32m+[m		[32m// ï¿½ï¿½È¥ï¿½ï¿½[m
 		bool		IsDragonSoul();[m
 		int		GiveMoreTime_Per(float fPercent);[m
 		int		GiveMoreTime_Fix(DWORD dwTime);[m
 [m
 	private:[m
[31m-		TItemTable const * m_pProto;		// ÇÁ·ÎÅä Å¸ÀÙ[m
[32m+[m		[32mTItemTable const * m_pProto;		// ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ Å¸ï¿½ï¿½[m
 [m
 		DWORD		m_dwVnum;[m
 		LPCHARACTER	m_pOwner;[m
 [m
[31m-		BYTE		m_bWindow;		// ÇöÀç ¾ÆÀÌÅÛÀÌ À§Ä¡ÇÑ À©µµ¿ì [m
[31m-		DWORD		m_dwID;			// °íÀ¯¹øÈ£[m
[31m-		bool		m_bEquipped;	// ÀåÂø µÇ¾ú´Â°¡?[m
[32m+[m		[32mBYTE		m_bWindow;		// ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½Ä¡ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½[m[41m [m
[32m+[m		[32mDWORD		m_dwID;			// ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½È£[m
[32m+[m		[32mbool		m_bEquipped;	// ï¿½ï¿½ï¿½ï¿½ ï¿½Ç¾ï¿½ï¿½Â°ï¿½?[m
 		DWORD		m_dwVID;		// VID[m
[31m-		WORD		m_wCell;		// À§Ä¡[m
[31m-		DWORD		m_dwCount;		// °³¼ö[m
[31m-		long		m_lFlag;		// Ãß°¡ flag[m
[31m-		DWORD		m_dwLastOwnerPID;	// ¸¶Áö¸· °¡Áö°í ÀÖ¾ú´ø »ç¶÷ÀÇ PID[m
[32m+[m		[32mWORD		m_wCell;		// ï¿½ï¿½Ä¡[m
[32m+[m		[32mDWORD		m_dwCount;		// ï¿½ï¿½ï¿½ï¿½[m
[32m+[m		[32mlong		m_lFlag;		// ï¿½ß°ï¿½ flag[m
[32m+[m		[32mDWORD		m_dwLastOwnerPID;	// ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½Ö¾ï¿½ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½ï¿½ PID[m
 [m
[31m-		bool		m_bExchanging;	///< ÇöÀç ±³È¯Áß »óÅÂ [m
[32m+[m		[32mbool		m_bExchanging;	///< ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½È¯ï¿½ï¿½ ï¿½ï¿½ï¿½ï¿½[m[41m [m
 [m
[31m-		long		m_alSockets[ITEM_SOCKET_MAX_NUM];	// ¾ÆÀÌÅÛ ¼ÒÄ¹[m
[32m+[m		[32mlong		m_alSockets[ITEM_SOCKET_MAX_NUM];	// ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ ï¿½ï¿½Ä¹[m
 		TPlayerItemAttribute	m_aAttr[ITEM_ATTRIBUTE_MAX_NUM];[m
 [m
 		LPEVENT		m_pkDestroyEvent;[m
