package duniter.java.nodes.explorer;

public class Block
{
	private long mNumber;
	private long mNonce;
	private long mTime;
	private long mMedianTime;
	private Member mIssuer;
	private String mHash;
	private String mPreviousHash;
	private Block mPrevious;

	public Block(long pNumber, long pNonce, long pTime, long pMedianTime, Member pIssuer, String pHash, String pPreviousHash)
	{
		super();
		mNumber = pNumber;
		mNonce = pNonce;
		mTime = pTime;
		mMedianTime = pMedianTime;
		mIssuer = pIssuer;
		mHash = pHash;
		mPreviousHash = pPreviousHash;
	}

	public String getHash()
	{
		return mHash;
	}

	public long getNumber()
	{
		return mNumber;
	}

	public long getTime()
	{
		return mTime;
	}

	public long getMedianTime()
	{
		return mMedianTime;
	}

	public Member getIssuer()
	{
		return mIssuer;
	}
}
