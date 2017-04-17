package duniter.java.nodes.explorer;

import java.util.HashSet;
import java.util.LinkedList;
import java.util.Queue;
import java.util.Set;

public class EP
{
	private static final int NB_TICKS_WINDOW = 30;
	private String mError = null;// Current error on EP. If no error, then it is null
	private boolean mCertificateError = false;
	private String mURL;
	private String mVersion;
	private String mCurrency;
	private String mPubKey;
	private Member mMember;
	private Block mCurrentBlock;
	private int mFreeIdentities = 0;
	private int mFreeMemberships = 0;
	private int mFreeTransactions = 0;
	private Queue<Boolean> mUp = new LinkedList<>();
	private Queue<Long> mResponseTime = new LinkedList<>();
	private Set<String> mSiblings = new HashSet<>();
	private Set<String> mKnownPeers = new HashSet<>();

	public EP(String pURL)
	{
		super();
		mURL = pURL;
	}

	public String getError()
	{
		return mError;
	}

	public void setError(String pError)
	{
		mError = pError;
	}

	public boolean isCertificateError()
	{
		return mCertificateError;
	}

	public void setCertificateError(boolean pCertificateError)
	{
		mCertificateError = pCertificateError;
	}

	public String getVersion()
	{
		return mVersion;
	}

	public void setVersion(String pVersion)
	{
		mVersion = pVersion;
	}

	public String getCurrency()
	{
		return mCurrency;
	}

	public void setCurrency(String pCurrency)
	{
		mCurrency = pCurrency;
	}

	public String getPubKey()
	{
		return mPubKey;
	}

	public void setPubKey(String pPubKey)
	{
		mPubKey = pPubKey;
	}

	public Member getMember()
	{
		return mMember;
	}

	public void setMember(Member pMember)
	{
		mMember = pMember;
	}

	public Block getCurrentBlock()
	{
		return mCurrentBlock;
	}

	public void setCurrentBlock(Block pCurrentBlock)
	{
		mCurrentBlock = pCurrentBlock;
	}

	public void addKnownPeer(String pPeer)
	{
		synchronized (mKnownPeers)
		{
			mKnownPeers.add(pPeer);
		}
	}

	public Set<String> getKnownPeers()
	{
		synchronized (mKnownPeers)
		{
			return new HashSet<>(mKnownPeers);
		}
	}

	public void removeKnownPeer(String pPeer)
	{
		synchronized (mKnownPeers)
		{
			mKnownPeers.remove(pPeer);
		}
	}

	public void addResponseTime(long pResponseTime)
	{
		synchronized (mResponseTime)
		{
			while (mResponseTime.size() > NB_TICKS_WINDOW)
				mResponseTime.poll();
			mResponseTime.offer(pResponseTime);
		}
	}

	public long getAvgResponseTime()
	{
		synchronized (mResponseTime)
		{
			if (!mResponseTime.isEmpty())
			{
				long total = 0;
				for (Long rt : mResponseTime)
					total += rt;
				return total / mResponseTime.size();
			}
			else
				return -1;
		}
	}

	public void clearResponseTime()
	{
		synchronized (mResponseTime)
		{
			mResponseTime.clear();
		}
	}

	public void addSibling(String pPeer)
	{
		synchronized (mSiblings)
		{
			mSiblings.add(pPeer);
		}
	}

	public void removeSibling(String pPeer)
	{
		synchronized (mSiblings)
		{
			mSiblings.remove(pPeer);
		}
	}

	public Set<String> getSiblings()
	{
		synchronized (mSiblings)
		{
			return new HashSet<>(mSiblings);
		}
	}

	public void setUp(boolean pUp)
	{
		synchronized (mUp)
		{
			while (mUp.size() > NB_TICKS_WINDOW)
				mUp.poll();
			mUp.offer(pUp);
		}
	}

	public boolean isUp()
	{
		synchronized (mUp)
		{
			return mUp.peek().booleanValue();
		}
	}

	public int getUpPercent()
	{
		synchronized (mUp)
		{
			int total = 0;
			for (Boolean up : mUp)
				if (up)
					total++;
			if (mUp.isEmpty())
				return 0;
			else
				return (100 * total) / mUp.size();
		}
	}

	public String getURL()
	{
		return mURL;
	}

	public void setSiblings(Set<String> pSiblings)
	{
		synchronized (mSiblings)
		{
			mSiblings.clear();
			mSiblings.addAll(pSiblings);
		}
	}

	public void setKnownPeers(Set<String> pPeers)
	{
		synchronized (mKnownPeers)
		{
			mKnownPeers.clear();
			mKnownPeers.addAll(pPeers);
		}
	}

	public int getFreeIdentities()
	{
		return mFreeIdentities;
	}

	public void setFreeIdentities(int pFreeIdentities)
	{
		mFreeIdentities = pFreeIdentities;
	}

	public int getFreeMemberships()
	{
		return mFreeMemberships;
	}

	public void setFreeMemberships(int pFreeMemberships)
	{
		mFreeMemberships = pFreeMemberships;
	}

	public int getFreeTransactions()
	{
		return mFreeTransactions;
	}

	public void setFreeTransactions(int pFreeTransactions)
	{
		mFreeTransactions = pFreeTransactions;
	}
}
