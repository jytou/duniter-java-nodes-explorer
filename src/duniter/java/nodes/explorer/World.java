package duniter.java.nodes.explorer;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class World
{
	private Map<String, Node> mEP2Node = new HashMap<>();// One endpoint to its node
//	private Map<Node, Set<String>> mNode2EPs = new HashMap<>();// Node to its currently known endpoints
	private Map<String, Member> mId2Member = new HashMap<>();
	private Map<String, Member> mPK2Member = new HashMap<>();
	private Map<String, Block> mHash2Block = new HashMap<>();
	private Map<String, Block> mPreviousHash2Block = new HashMap<>();

	public Set<Node> getAllNodes()
	{
		synchronized (mEP2Node)
		{
			return new HashSet<Node>(mEP2Node.values());
		}
	}

	public Node getNodeForEP(String pEp)
	{
		synchronized (mEP2Node)
		{
			return mEP2Node.get(pEp);
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

	public void addEndPoint(String pEpString, Node pNode)
	{
		synchronized (mEP2Node)
		{
			mEP2Node.put(pEpString, pNode);
		}
		pNode.addEndPoint(pEpString);
	}

	public void removeEndPoint(String pEpString, Node pNode)
	{
		synchronized (mEP2Node)
		{
			mEP2Node.remove(pEpString, pNode);
		}
		pNode.removeEndPoint(pEpString);
	}
}
