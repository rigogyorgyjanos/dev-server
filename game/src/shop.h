#ifndef __INC_METIN_II_GAME_SHOP_H__
#define __INC_METIN_II_GAME_SHOP_H__

enum
{
	SHOP_MAX_DISTANCE = 1000
};

class CGrid;

/* ---------------------------------------------------------------------------------- */
class CShop
{
	public:
		typedef struct shop_item
		{
			DWORD	vnum;		// ������ ��ȣ
			long	price;		// ����
			WORD	count;		// ������ ����

			LPITEM	pkItem;
			int		itemid;		// ������ �������̵�

			shop_item()
			{
				vnum = 0;
				price = 0;
				count = 0;
				itemid = 0;
				pkItem = NULL;
			}
		} SHOP_ITEM;

		CShop();
		virtual ~CShop();

		bool	Create(DWORD dwVnum, DWORD dwNPCVnum, TShopItemTable * pItemTable);
		void	SetShopItems(TShopItemTable * pItemTable, BYTE bItemCount);

		virtual void	SetPCShop(LPCHARACTER ch);
		virtual bool	IsPCShop()	{ return m_pkPC ? true : false; }

		// �Խ�Ʈ �߰�/����
		virtual bool	AddGuest(LPCHARACTER ch,DWORD owner_vid, bool bOtherEmpire);
		void	RemoveGuest(LPCHARACTER ch);

		// ���� ����
		virtual int	Buy(LPCHARACTER ch, BYTE pos);

		// �Խ�Ʈ���� ��Ŷ�� ����
		void	BroadcastUpdateItem(BYTE pos);
#ifdef ENABLE_12ZI
		void	BroadcastUpdateItemCh(BYTE pos, LPCHARACTER ch);
#endif

		// �Ǹ����� �������� ������ �˷��ش�.
		int		GetNumberByVnum(DWORD dwVnum);

		// �������� ������ ��ϵǾ� �ִ��� �˷��ش�.
		virtual bool	IsSellingItem(DWORD itemID);

		DWORD	GetVnum() { return m_dwVnum; }
		DWORD	GetNPCVnum() { return m_dwNPCVnum; }

	protected:
		void	Broadcast(const void * data, int bytes);

	protected:
		DWORD				m_dwVnum;
		DWORD				m_dwNPCVnum;
#ifdef ENABLE_12ZI
		bool				m_IsLimitedItemShop;
#endif

		CGrid *				m_pGrid;

		typedef std::unordered_map<LPCHARACTER, bool> GuestMapType;
		GuestMapType m_map_guest;
		std::vector<SHOP_ITEM>		m_itemVector;	// �� �������� ����ϴ� ���ǵ�

		LPCHARACTER			m_pkPC;
};

#endif 
