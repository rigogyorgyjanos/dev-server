#ifndef __INC_AFFECT_H
#define __INC_AFFECT_H

class CAffect
{
	public:
		DWORD	dwType;
		BYTE    bApplyOn;
		long    lApplyValue;
		DWORD   dwFlag;
		long	lDuration;
		long	lSPCost;

		static CAffect* Acquire();
		static void Release(CAffect* p);
};

enum EAffectTypes
{
	AFFECT_NONE,

	AFFECT_MOV_SPEED		= 200,
	AFFECT_ATT_SPEED,
	AFFECT_ATT_GRADE,
	AFFECT_INVISIBILITY,
	AFFECT_STR,
	AFFECT_DEX,			// 205
	AFFECT_CON,	
	AFFECT_INT,	
	AFFECT_FISH_MIND_PILL,

	AFFECT_POISON,
	AFFECT_STUN,		// 210
	AFFECT_SLOW,
	AFFECT_DUNGEON_READY,
	AFFECT_DUNGEON_UNIQUE,

	AFFECT_BUILDING,
	AFFECT_REVIVE_INVISIBLE,	// 215
	AFFECT_FIRE,
	AFFECT_CAST_SPEED,
	AFFECT_HP_RECOVER_CONTINUE,
	AFFECT_SP_RECOVER_CONTINUE,

	AFFECT_POLYMORPH,		// 220
	AFFECT_MOUNT,

	AFFECT_WAR_FLAG,		// 222

	AFFECT_BLOCK_CHAT,		// 223
	AFFECT_CHINA_FIREWORK,

	AFFECT_BOW_DISTANCE,	// 225
	AFFECT_DEF_GRADE,		// 226

	AFFECT_PREMIUM_START	= 500,
	AFFECT_EXP_BONUS		= 500,	// ������ ����
	AFFECT_ITEM_BONUS		= 501,	// ������ �尩
	AFFECT_SAFEBOX		= 502,  // PREMIUM_SAFEBOX,
	AFFECT_AUTOLOOT		= 503,	// PREMIUM_AUTOLOOT,
	AFFECT_FISH_MIND		= 504,	// PREMIUM_FISH_MIND,
	AFFECT_MARRIAGE_FAST	= 505,	// ������ ����
	AFFECT_GOLD_BONUS		= 506,	// �� ���Ȯ�� 50%����
	AFFECT_PREMIUM_END		= 509,

	AFFECT_MALL			= 510,	// �� ������ ����Ʈ
	AFFECT_NO_DEATH_PENALTY	= 511,	// ����� ��ȣ (����ġ�� �г�Ƽ�� �ѹ� �����ش�)
	AFFECT_SKILL_BOOK_BONUS	= 512,	// ������ ���� (å ���� ���� Ȯ���� 50% ����)
	AFFECT_SKILL_NO_BOOK_DELAY	= 513,	// �־ȼ���

	AFFECT_HAIR	= 514,	// ��� ȿ��
	AFFECT_COLLECT = 515, //��������Ʈ 
	AFFECT_EXP_BONUS_EURO_FREE = 516, // ������ ���� (���� ���� 14 ���� ���� �⺻ ȿ��)
	AFFECT_EXP_BONUS_EURO_FREE_UNDER_15 = 517,
	AFFECT_UNIQUE_ABILITY = 518,

	AFFECT_CUBE_1,
	AFFECT_CUBE_2,
	AFFECT_CUBE_3,
	AFFECT_CUBE_4,
	AFFECT_CUBE_5,
	AFFECT_CUBE_6,
	AFFECT_CUBE_7,
	AFFECT_CUBE_8,
	AFFECT_CUBE_9,
	AFFECT_CUBE_10,
	AFFECT_CUBE_11,
	AFFECT_CUBE_12,

	AFFECT_BLEND,

	AFFECT_HORSE_NAME,
	AFFECT_MOUNT_BONUS,

	AFFECT_AUTO_HP_RECOVERY = 534,
	AFFECT_AUTO_SP_RECOVERY = 535,

	AFFECT_DRAGON_SOUL_QUALIFIED = 540,
	AFFECT_DRAGON_SOUL_DECK_0 = 541,
	AFFECT_DRAGON_SOUL_DECK_1 = 542,


	AFFECT_RAMADAN_ABILITY = 300,
	AFFECT_RAMADAN_RING	   = 301,

	AFFECT_NOG_ABILITY = 302,
	AFFECT_HOLLY_STONE_POWER = 303,

#ifdef __AUTO_QUQUE_ATTACK__
	AFFECT_AUTO_METIN_FARM = 706,
#endif
#ifdef ENABLE_OFFLINESHOP_SYSTEM
	AFFECT_DECORATION = 707,	// premium offline-shop status (granted by Shop Decoration item, vnum 71221)
#endif
	AFFECT_QUEST_START_IDX = 1000
};

enum EAffectBits
{   
	AFF_NONE,

	AFF_YMIR,
	AFF_INVISIBILITY,
	AFF_SPAWN,

	AFF_POISON,
	AFF_SLOW,
	AFF_STUN,

	AFF_DUNGEON_READY,		// �������� �غ� ����
	AFF_DUNGEON_UNIQUE,		// ���� ����ũ (Ŭ���̾�Ʈ���� �ø���������)

	AFF_BUILDING_CONSTRUCTION_SMALL,
	AFF_BUILDING_CONSTRUCTION_LARGE,
	AFF_BUILDING_UPGRADE,

	AFF_MOV_SPEED_POTION,
	AFF_ATT_SPEED_POTION,

	AFF_FISH_MIND,

	AFF_JEONGWIHON,		// ����ȥ
	AFF_GEOMGYEONG,		// �˰�
	AFF_CHEONGEUN,		// õ����
	AFF_GYEONGGONG,		// �����
	AFF_EUNHYUNG,		// ������
	AFF_GWIGUM,			// �Ͱ�
	AFF_TERROR,			// ����
	AFF_JUMAGAP,		// �ָ���
	AFF_HOSIN,			// ȣ��
	AFF_BOHO,			// ��ȣ
	AFF_KWAESOK,		// ���
	AFF_MANASHIELD,		// ��������
	AFF_MUYEONG,		// ������ affect
	AFF_REVIVE_INVISIBLE,	// ��Ȱ�� ��õ��� ����
	AFF_FIRE,			// ���� �� ������
	AFF_GICHEON,		// ��õ���
	AFF_JEUNGRYEOK,		// ���¼�
	AFF_TANHWAN_DASH,		// źȯ�ݿ� �޸������Ʈ
	AFF_PABEOP,			// �Ĺ���
	AFF_CHEONGEUN_WITH_FALL,	// õ����
	AFF_POLYMORPH,
	AFF_WAR_FLAG1,
	AFF_WAR_FLAG2,
	AFF_WAR_FLAG3,

	AFF_CHINA_FIREWORK,
	AFF_HAIR,	// ���
	AFF_GERMANY, // ���� 

	AFF_BITS_MAX
};

extern void SendAffectAddPacket(LPDESC d, CAffect * pkAff);

// AFFECT_DURATION_BUG_FIX
enum AffectVariable
{
	// Affect�� ���Ѵ�� �� �־�� �� ��� ���.
	// �ð��� ��� ���̱� ������ �ſ� ū������ ���Ѵ븦 ���ķ��̼���.
	//// 24��Ʈ�� �����Ƿ� 25��Ʈ�� ���.
	// ... 25��Ʈ ����Ѵٰ� �س����� 29bit ����ϰ� �ִ� ��û�� �ּ��̶�...
	// collect quest���� ���� �ð��� 60������ ����ϰ� �����Ƿ�, ���⵵ 60������ ����.

	INFINITE_AFFECT_DURATION = 60 * 365 * 24 * 60 * 60
};
// END_AFFECT_DURATION_BUG_FIX

#endif
