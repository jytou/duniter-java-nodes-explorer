package duniter.java.nodes.explorer;

import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.Map;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

public class Node
{
	private Map<String, AtomicLong> mEndPoints = new HashMap<>();// Number of times each EP has been seen UP
	private Map<String, AtomicLong> mEPNbSeen = new HashMap<>();// Number of times each EP has been seen
	private Map<String, String> mEndPointErrors = new HashMap<>();// Current errors on EP. If no error, then there is no key for EP
	private Map<String, Boolean> mEndPointCertificateError = new HashMap<>();
	private String mPreferredBMAS = null;
	private String mPreferredBMA = null;
	private boolean mUp;
	private String mVersion;
	private String mCurrency;
	private String mPubKey;
	private Member mMember;
	private Block mCurrentBlock;
	private Queue<Long> mResponseTime = new LinkedList<>();
	private AtomicLong mUpTicks = new AtomicLong(0);
	private AtomicLong mTotalTicksKnown = new AtomicLong(0);
	private AtomicInteger mUpPerMillion = new AtomicInteger(1000000);

	public Node(Set<String> pEndPoints)
	{
		super();
		for (String string : pEndPoints)
		{
			mEndPoints.put(string, new AtomicLong(0));
			mEPNbSeen.put(string, new AtomicLong(0));
		}
	}

	public Set<String> getEndPoints()
	{
		synchronized (mEndPoints)
		{
			return new HashSet<>(mEndPoints.keySet());
		}
	}

	public void setEPUp(String pEP, boolean pUp)
	{
		if (pUp)
		{
			final AtomicLong ticksOk = mEndPoints.get(pEP);
			if (ticksOk != null)
				ticksOk.incrementAndGet();
		}

		final AtomicLong overallTicks = mEPNbSeen.get(pEP);
		if (overallTicks != null)
			overallTicks.incrementAndGet();
	}

	public double getEPStability(String pEP)
	{
		AtomicLong total = mEPNbSeen.get(pEP);
		if ((total != null) && (total.get() > 0))
			return 100.0 * mEndPoints.get(pEP).get() / total.get();
		else
			return 0;
	}

	public void setPreferredBMAS(String pPreferredBMAS)
	{
		mPreferredBMAS = pPreferredBMAS;
	}

	public void setPreferredBMA(String pPreferredBMA)
	{
		mPreferredBMA = pPreferredBMA;
	}

	public String getPreferredBMAS()
	{
		return mPreferredBMAS;
	}

	public String getPreferredBMA()
	{
		return mPreferredBMA;
	}

	public void setVersion(String pVersion)
	{
		mVersion = pVersion;
	}

	public String getVersion()
	{
		return mVersion;
	}

	public String getCurrency()
	{
		return mCurrency;
	}

	public void setCurrency(String pCurrency)
	{
		mCurrency = pCurrency;
	}

	public void setPubKey(String pPubKey)
	{
		mPubKey = pPubKey;
	}

	public String getPubKey()
	{
		return mPubKey;
	}

	public void setUp(boolean pUp)
	{
		mUp = pUp;
	}

	public boolean isUp()
	{
		return mUp;
	}

	public double getUpPercent()
	{
		return 0.0001 * mUpPerMillion.get();
	}

	public void incTicks()
	{
		mTotalTicksKnown.incrementAndGet();
		if (mUp)
			mUpTicks.incrementAndGet();
		mUpPerMillion.set((int)((1000000 * mUpTicks.get()) / mTotalTicksKnown.get()));
	}

	public void setCurrentBlock(Block pCurrentBlock)
	{
		mCurrentBlock = pCurrentBlock;
	}

	public Block getCurrentBlock()
	{
		return mCurrentBlock;
	}

	@Override
	public String toString()
	{
		return mEndPoints.toString();
	}

	public void addEndPointError(String pEndPoint, String pError)
	{
		synchronized (mEndPointErrors)
		{
			mEndPointErrors.put(pEndPoint, pError);
		}
	}

	public void removeEndPointError(String pEndPoint)
	{
		synchronized (mEndPointErrors)
		{
			mEndPointErrors.remove(pEndPoint);
		}
	}

	public Map<String, String> getEndPointErrors()
	{
		synchronized (mEndPointErrors)
		{
			return new HashMap<>(mEndPointErrors);
		}
	}

	public void setEndPointCertificateError(String pEndPoint, boolean pCertificateError)
	{
		synchronized (mEndPointCertificateError)
		{
			if (pCertificateError)
				mEndPointCertificateError.put(pEndPoint, pCertificateError);
			else
				mEndPointCertificateError.remove(pEndPoint);
		}
	}

	public boolean isEndPointCertificateError(String pEndPoint)
	{
		synchronized (mEndPointCertificateError)
		{
			return mEndPointCertificateError.containsKey(pEndPoint);
		}
	}

	public void addEndPoint(String pEndPoint)
	{
		synchronized (mEndPoints)
		{
			mEndPoints.put(pEndPoint, new AtomicLong(0));
			mEPNbSeen.put(pEndPoint, new AtomicLong(0));
		}
	}

	public void addResponseTime(long pResponseTime)
	{
		synchronized (mResponseTime)
		{
			if (mResponseTime.size() > 10)
				mResponseTime.remove();
			mResponseTime.add(pResponseTime);
		}
	}

	public long getResponseTime()
	{
		if (mResponseTime.isEmpty())
			return Long.MAX_VALUE;
		else
		{
			long totalRT = 0;
			for (Long rt : mResponseTime)
				totalRT += rt.longValue();
			return totalRT / mResponseTime.size();
		}
	}

	public Member getMember()
	{
		return mMember;
	}

	public void setMember(Member pMember)
	{
		mMember = pMember;
	}

	public void removeEndPoint(String pEpString)
	{
		synchronized (mEndPoints)
		{
			mEndPoints.remove(pEpString);
			mEPNbSeen.remove(pEpString);
		}
	}
}
