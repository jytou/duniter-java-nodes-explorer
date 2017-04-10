package duniter.java.nodes.explorer;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class World
{
	private Map<String, Node> mEP2Node = new HashMap<>();// One endpoint to its node
	private Map<Node, Set<String>> mNode2EPs = new HashMap<>();// Node to its currently known endpoints
	private Map<String, Member> mId2Member = new HashMap<>();
	private Map<String, Member> mPK2Member = new HashMap<>();
	private Map<String, Block> mHash2Block = new HashMap<>();

	public void setNode(Node pNode)
	{
		synchronized (mNode2EPs)
		{
			if (mNode2EPs.containsKey(pNode))
				for (String ep : mNode2EPs.get(pNode))
					mEP2Node.remove(ep);
			mNode2EPs.put(pNode, new HashSet<>(pNode.getEndPoints()));
			for (String ep : pNode.getEndPoints())
				mEP2Node.put(ep, pNode);
		}
	}

	public Set<Node> getAllNodes()
	{
		synchronized (mNode2EPs)
		{
			return new HashSet<Node>(mNode2EPs.keySet());
		}
	}

	public Node getNodeForEP(String pEp)
	{
		synchronized (mNode2EPs)
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

	public void addBlock(Block pBlock)
	{
		synchronized (mHash2Block)
		{
			mHash2Block.put(pBlock.getHash(), pBlock);
		}
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
}
