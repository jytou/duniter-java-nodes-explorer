package duniter.java.nodes.explorer;

import java.util.ArrayList;
import java.util.List;

public class Node implements Comparable<Node>
{
	private List<EP> mEPs = new ArrayList<>();

	public Node(EP pEP)
	{
		super();
		mEPs.add(pEP);
	}

	@Override
	public int compareTo(Node node)
	{
		return compare(mEPs.get(0), node.mEPs.get(0));
	}

	@Override
	public boolean equals(Object pObj)
	{
		if (pObj instanceof Node)
		{
			Node node = (Node)pObj;
			return compareTo(node) == 0;
		}
		return false;
	}

	private int compare(EP ep1, EP ep2)
	{
		// First members, then non members
		if (ep1.getMember() != ep2.getMember())
			if (ep1.getMember() == null)
				return 1;
			else if (ep2.getMember() == null)
				return -1;
//		if (Math.abs(1.0 * (ep1.getAvgResponseTime() - ep2.getAvgResponseTime()) / Math.max(1, Math.min(ep1.getAvgResponseTime(), ep2.getAvgResponseTime()))) > 0.15)
//			return Long.valueOf(ep1.getAvgResponseTime()).compareTo(ep2.getAvgResponseTime());
		if (!ep1.getPubKey().equals(ep2.getPubKey()))
			return ep1.getPubKey().compareTo(ep2.getPubKey());
		if (!ep1.getVersion().equals(ep2.getVersion()))
			return ep1.getVersion().compareTo(ep2.getVersion());
		if (ep1.getFreeIdentities() != ep2.getFreeIdentities())
			return Integer.valueOf(ep1.getFreeIdentities()).compareTo(ep2.getFreeIdentities());
		if (ep1.getFreeMemberships() != ep2.getFreeMemberships())
			return Integer.valueOf(ep1.getFreeMemberships()).compareTo(ep2.getFreeMemberships());
		if (ep1.getFreeTransactions() != ep2.getFreeTransactions())
			return Integer.valueOf(ep1.getFreeTransactions()).compareTo(ep2.getFreeTransactions());
		if (ep1.getCurrentBlock() != ep2.getCurrentBlock())
		{
			if (ep1.getCurrentBlock() == null)
				return -1;
			else if (ep2.getCurrentBlock() == null)
				return 1;
			else
			{
				final long n1 = ep1.getCurrentBlock().getNumber();
				final long n2 = ep2.getCurrentBlock().getNumber();
				if (n1 != n2)
					return Long.valueOf(n1).compareTo(n2);
				else
					return ep1.getCurrentBlock().getHash().compareTo(ep2.getCurrentBlock().getHash());
			}
		}
		return 0;
	}

	public EP getEP()
	{
		return mEPs.get(0);
	}

	public void addEP(EP pEP)
	{
		mEPs.add(pEP);
	}

	public List<EP> getEPs()
	{
		return new ArrayList<EP>(mEPs);
	}

	public List<EP> rejectIncompatibleEPs()
	{
		List<EP> rejected = new ArrayList<>();
		EP ep = mEPs.get(0);
		for (int i = mEPs.size(); i > 1 ; i--)
			if (compare(ep, mEPs.get(i)) != 0)
				rejected.add(mEPs.remove(i));
		return rejected;
	}
}
