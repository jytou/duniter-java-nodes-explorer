package duniter.java.nodes.explorer;

import java.awt.Color;
import java.awt.Graphics;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.swing.JFrame;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

public class PeerQuery
{
	ConcurrentMap<String, MultiConnectThread> mBusyConnectThreads = new ConcurrentHashMap<>();
	BlockingQueue<String> mURLs = new LinkedBlockingQueue<>();
	ConcurrentSkipListSet<String> mPreIgnoreCertificateErrors = new ConcurrentSkipListSet<>();
	ConcurrentSkipListSet<String> mCertificatesInError = new ConcurrentSkipListSet<>();
	ConcurrentMap<String, Semaphore> mURLLocks = new ConcurrentHashMap<>();
	ConcurrentMap<String, JSONObject> mJSonResults = new ConcurrentHashMap<>();
	ConcurrentMap<String, String> mURLErrors = new ConcurrentHashMap<>();
	ConcurrentMap<String, Long> mResponseTimes = new ConcurrentHashMap<>();
	// The caller waits for a thread to pick up the URL and give its name, so that we can kill it if it doesn't respond
	ConcurrentMap<String, BlockingQueue<String>> mPickedURL = new ConcurrentHashMap<>();
	ConcurrentSkipListSet<String> mActiveThreads = new ConcurrentSkipListSet<>();
	AtomicInteger mNbRunningThreads = new AtomicInteger(0);
	private JFrame mFrame;

	private static AtomicInteger sThreadNum = new AtomicInteger(0);
	private class MultiConnectThread extends Thread
	{
		public MultiConnectThread(String pName)
		{
			super(pName);
		}

		@Override
		public void run()
		{
			super.run();
			mNbRunningThreads.incrementAndGet();
			try
			{
				while (true)
				{
					String url;
					try
					{
						url = mURLs.take();
					}
					catch (InterruptedException e1)
					{
						break;
					}
					if (!mActiveThreads.contains(getName()))
					{
						mURLs.offer(url);
						break;
					}
					mBusyConnectThreads.put(url, this);
					// Notify the caller we have taken the url now - and now the clock is ticking for this thread!
					mPickedURL.get(url).offer(getName());
					try
					{
						try
						{
							final JSONObject json = fetchInfo(url);
							mJSonResults.put(url, json);
						}
						catch (MalformedURLException e)
						{
							mURLErrors.put(url, "MalformedURLException: " + e.getMessage());
						}
						catch (IOException e)
						{
							mURLErrors.put(url, "IOException: " + e.getMessage());
						}
						catch (ParseException e)
						{
							mURLErrors.put(url, "ParseException: " + e.getMessage());
						}
						final Semaphore semaphore = mURLLocks.get(url);
						if (semaphore != null)
							semaphore.release();
					}
					finally
					{
						mBusyConnectThreads.remove(url);
					}
					if (!mActiveThreads.contains(getName()))
					// Exit if we have been ordered to
						break;
				}
			}
			finally
			{
				mNbRunningThreads.decrementAndGet();
			}
		}

		private JSONObject fetchInfo(String pURL) throws MalformedURLException, IOException, ParseException
		{
			long time = System.currentTimeMillis();
			URLConnection con = (URLConnection)new URL(pURL).openConnection();
			con.setReadTimeout(10000);
			InputStream ins = null;
			if (mPreIgnoreCertificateErrors.contains(pURL) && (mCertificatesInError.contains(pURL)))
				ignoreCertificateErrorsOnConnection(con);
			Object obj = null;
			try
			{
				try
				{
					ins = con.getInputStream();
					// If we were not pre-ignoring bad certificates and the certificate is marked in error, clear the error
					if (mCertificatesInError.contains(pURL) && (!mPreIgnoreCertificateErrors.contains(pURL)))
						mCertificatesInError.remove(pURL);
				}
				catch (Exception e)
				{
					// Could it be that it is a certificate error?
					if ((con instanceof HttpsURLConnection) && (!mPreIgnoreCertificateErrors.contains(pURL)))
					{
						con = (URLConnection)new URL(pURL).openConnection();
						con.setReadTimeout(10000);
						ignoreCertificateErrorsOnConnection(con);
						if (ins == null)
							ins = con.getInputStream();
						// Now that we are connected with the ignoring, flag it
						mCertificatesInError.add(pURL);
					}
					else
						throw e;
				}
				InputStreamReader isr = null;
				try
				{
					isr = new InputStreamReader(ins);
					mResponseTimes.put(pURL, System.currentTimeMillis() - time);
					final JSONParser parser = new JSONParser();
					obj = parser.parse(isr);
				}
				finally
				{
					if (isr != null)
						isr.close();
				}
			}
			finally
			{
				if (ins != null)
					ins.close();
			}
			return (JSONObject)obj;
		}

		private void ignoreCertificateErrorsOnConnection(final URLConnection pConn)
		{
			HttpsURLConnection httpsconn = (HttpsURLConnection)pConn;
			TrustManager[] trustAllCerts = new TrustManager[]{
				new X509TrustManager()
				{
					public X509Certificate[] getAcceptedIssuers(){ return null; }
					public void checkClientTrusted(X509Certificate[] certs, String authType) {}
					public void checkServerTrusted(X509Certificate[] certs, String authType) {}
				}
			};
			try
			{
				SSLContext sslContext = SSLContext.getInstance("SSL");
				sslContext.init(null, trustAllCerts, new SecureRandom());
				httpsconn.setSSLSocketFactory(sslContext.getSocketFactory());
			}
			catch (Exception e)
			{
				// could not switch the socket factory, ignore
			}
		}
	}

	private class BusyFrame extends JFrame
	{
		public BusyFrame()
		{
			super("avail");
			setSize(100, 100);
			setVisible(true);
			addWindowListener(new WindowAdapter()
			{
				@Override
				public void windowClosing(WindowEvent e)
				{
					super.windowClosing(e);
					System.exit(0);
				}
			});
		}

		@Override
		public void paint(Graphics g)
		{
			super.paint(g);
			g.setColor(Color.red);
			g.drawLine(0, 50, mBusyConnectThreads.size(), 50);
		}
	}

	public PeerQuery()
	{
		super();
		for (int i = 0; i < 100; i++)
			startNewThread();;
		mFrame = new BusyFrame();
		new Thread("FrameRefresher")
		{
			@Override
			public void run()
			{
				super.run();
				while (true)
				{
					try
					{
						Thread.sleep(500);
					}
					catch (InterruptedException e)
					{
						e.printStackTrace();
					}
					mFrame.repaint();
				}
			}
		}.start();;
	}

	public PeerQueryResponse fetchJSonResponses(final EP pEndPoint, final String pSuffix, final boolean pPreIgnoreCertificatesInError)
	{
		final Semaphore receivingSemaphore = new Semaphore(0);
		final String ep = pEndPoint.getURL();
		final String url = ep + pSuffix;

		mURLErrors.remove(url);
		mURLLocks.put(url, receivingSemaphore);
		if (pEndPoint.isCertificateError())
		{
			mCertificatesInError.add(url);
			if (pPreIgnoreCertificatesInError)
				mPreIgnoreCertificateErrors.add(url);
		}
		final BlockingQueue<String> pickedThreadName = new LinkedBlockingQueue<>();
		mPickedURL.put(url, pickedThreadName);
		mURLs.offer(url);

		// Now wait for a thread to pick it
		String threadName = null;
		try
		{
			threadName = pickedThreadName.take();
		}
		catch (InterruptedException e)
		{
			e.printStackTrace();// this should never happen
		}
		mPickedURL.remove(url);

		long responseTime = -1;
		boolean replied = false;
		try
		{
			replied = receivingSemaphore.tryAcquire(10, TimeUnit.SECONDS);
		}
		catch (InterruptedException e)
		{
			e.printStackTrace();// This should NOT happen
		}
		mPreIgnoreCertificateErrors.remove(url);
		final String error = mURLErrors.remove(url);
		PeerQueryResponse response;
		if (!replied)
		{
			// We have waited too long anyway, finish all
			mActiveThreads.remove(threadName);
			final MultiConnectThread connectThread = mBusyConnectThreads.remove(url);
			if (connectThread != null)
			{
				// The thread is still running on this URL, we have to try and kill it
				connectThread.interrupt();
				// And start a new one
				startNewThread();
			}
			pEndPoint.setUp(false);
			mJSonResults.remove(url);
			pEndPoint.setError(error);
			response =  new PeerQueryResponse(error);
		}
		else
		{
			final boolean isOK = mJSonResults.get(url) != null;
			if (isOK)
			{
				responseTime = mResponseTimes.remove(url);
				pEndPoint.setUp(true);
				pEndPoint.addResponseTime(responseTime);
				response = new PeerQueryResponse(mJSonResults.remove(url), responseTime);
			}
			else
			{
				pEndPoint.setError(error);
				pEndPoint.setUp(false);
				response = new PeerQueryResponse(error);
			}
		}
		pEndPoint.setCertificateError(mCertificatesInError.remove(url));// if remove() is not successful, it is because there was no such element
		mURLLocks.remove(url);
//		System.out.println("Still remaining: " + mURLLocks.keySet().toString());
		return response;
	}

	private void startNewThread()
	{
		String name = "MultiConnectThread" + sThreadNum.getAndIncrement();
		mActiveThreads.add(name);
		new MultiConnectThread(name).start();
	}


}
