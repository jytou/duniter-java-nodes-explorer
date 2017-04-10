package duniter.java.nodes.explorer;

public class Member
{
	private String mName;
	private String mPK;
	private int mDifficulty;

	public Member(String pPK, String pName)
	{
		super();
		mPK = pPK;
		mName = pName;
	}

	public String getName()
	{
		return mName;
	}

	public String getPK()
	{
		return mPK;
	}

	public int getDifficulty()
	{
		return mDifficulty;
	}

	public void setDifficulty(int pDifficulty)
	{
		mDifficulty = pDifficulty;
	}

	public void setName(String pName)
	{
		mName = pName;
	}
}
