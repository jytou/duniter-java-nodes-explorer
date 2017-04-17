package duniter.java.nodes.explorer;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class World
{
	private Map<String, EP> mEPs = new HashMap<>();// All endpoints
//	private Map<Node, Set<String>> mNode2EPs = new HashMap<>();// Node to its currently known endpoints
	private Map<String, Member> mId2Member = new HashMap<>();
	private Map<String, Member> mPK2Member = new HashMap<>();
	private Map<String, Block> mHash2Block = new HashMap<>();
	private Map<String, Block> mPreviousHash2Block = new HashMap<>();

	public Set<EP> getAllEndPoints()
	{
		synchronized (mEPs)
		{
			return new HashSet<EP>(mEPs.values());
		}
	}

	public Block getBlockFromHash(String pHash)
	{
		synchronized (mHash2Block)
		{
			return mHash2Block.get(pHash);
		}
	}

	public Block getBlockFromPreviousHash(String pHash)
	{
		synchronized (mHash2Block)
		{
			return mPreviousHash2Block.get(pHash);
		}
	}

	public Block offerBlock(Block pBlock)
	{
		synchronized (mHash2Block)
		{
			if (mHash2Block.get(pBlock.getHash()) != null)
				return mHash2Block.get(pBlock.getHash());
			mHash2Block.put(pBlock.getHash(), pBlock);
			if (pBlock.getPreviousHash() != null)
				mPreviousHash2Block.put(pBlock.getPreviousHash(), pBlock);
		}
		return pBlock;
	}

	public Member getMember(String pPK)
	{
		synchronized (mPK2Member)
		{
			return mPK2Member.get(pPK);
		}
	}

	public void addMember(Member pMember)
	{
		synchronized (mPK2Member)
		{
			mPK2Member.put(pMember.getPK(), pMember);
			mId2Member.put(pMember.getName(), pMember);
		}
	}

	public Map<String, Member> getAllMembers()
	{
		synchronized (mPK2Member)
		{
			return new HashMap<>(mPK2Member);
		}
	}

	public EP offerEndPoint(String pEP)
	{
		synchronized (mEPs)
		{
			if (mEPs.containsKey(pEP))
				return mEPs.get(pEP);
			else
			{
				final EP ep = new EP(pEP);
				mEPs.put(pEP, ep);
				return ep;
			}
		}
	}

	public EP getEndPoint(String pEP)
	{
		synchronized (mEPs)
		{
			return mEPs.get(pEP);
		}
	}

	public void removeEndPoint(String pEP)
	{
		synchronized (mEPs)
		{
			mEPs.remove(pEP);
		}
	}
}
