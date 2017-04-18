package duniter.java.nodes.explorer;

import org.json.simple.JSONObject;

public class PeerQueryResponse
{
	private JSONObject mJSonResult;
	private long mResponseTime;
	private String mError;

	public PeerQueryResponse(JSONObject pJSonResult, long pResponseTime)
	{
		super();
		mJSonResult = pJSonResult;
		mResponseTime = pResponseTime;
		mError = null;
	}

	public PeerQueryResponse(String pError)
	{
		super();
		mJSonResult = null;
		mResponseTime = -1;
		mError = pError;
	}

	public JSONObject getJSonResult()
	{
		return mJSonResult;
	}

	public long getResponseTime()
	{
		return mResponseTime;
	}

	public String getError()
	{
		return mError;
	}
}
