package duniter.java.nodes.explorer;

import java.awt.AWTException;
import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.Image;
import java.awt.SystemTray;
import java.awt.Toolkit;
import java.awt.TrayIcon;
import java.awt.TrayIcon.MessageType;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
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

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

public class ExploreNodes
{
	private static final String DOWN_KEY = "DOWN";
	private static final String NO_BLOCK_KEY = "NO BLOCK";
	private World mWorld;
	private Set<Node> mNodesFound = new HashSet<>();
	private BlockingQueue<Node> mNodes2Explore = new LinkedBlockingQueue<>();
	private AtomicInteger mNbActive = new AtomicInteger(0);
	private Semaphore mFinished = new Semaphore(0);

	private BlockingQueue<String> mURLs = new LinkedBlockingQueue<>();
	private ConcurrentSkipListSet<String> mPreIgnoreCertificateErrors = new ConcurrentSkipListSet<>();
	private ConcurrentSkipListSet<String> mCertificatesInError = new ConcurrentSkipListSet<>();
	private ConcurrentMap<String, BlockingQueue<String>> mURLLocks = new ConcurrentHashMap<>();
	private ConcurrentMap<String, JSONObject> mJSonResults = new ConcurrentHashMap<>();
	private ConcurrentMap<String, String> mURLErrors = new ConcurrentHashMap<>();
	private ConcurrentMap<String, MultiConnectThread> mBusyConnectThreads = new ConcurrentHashMap<>();

	private class MultiConnectThread extends Thread
	{
		@Override
		public void run()
		{
			super.run();
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
				mBusyConnectThreads.put(url, this);
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
					final BlockingQueue<String> blockingQueue = mURLLocks.get(url);
					if (blockingQueue != null)
						blockingQueue.offer(url);
				}
				finally
				{
					mBusyConnectThreads.remove(url);
				}
			}
		}

		private JSONObject fetchInfo(String pURL) throws MalformedURLException, IOException, ParseException
		{
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

	private class NodeAnalyzer extends Thread
	{
		@Override
		public void run()
		{
			super.run();
			while (true)
			{
				try
				{
					final Node node = mNodes2Explore.take();
					synchronized (mNodesFound)
					{
						mNodesFound.add(node);
					}
					final Set<String> endPoints = node.getEndPoints();
//					System.out.println("Exploring " + endPoints.toString() + "... (" + mNodes2Explore.size() + " to go)");

					Map<String, String> receivedURL2EP = fetchJSonResponses(node, "/network/peering", false);
					final Set<String> existingEndPoints = new HashSet<>(node.getEndPoints());
					final Set<String> foundEndPoints = new HashSet<>();
					for (String url : receivedURL2EP.keySet())
					{
						final JSONObject peeringInfo = mJSonResults.remove(url);
						if (peeringInfo != null)
						{
							final String pubkey = (String)peeringInfo.get("pubkey");
							node.setPubKey(pubkey);
							final JSONArray raweps = (JSONArray)peeringInfo.get("endpoints");
							for (Object epObject : raweps)
							{
								final String epString = (String)epObject;
								final Set<String> eps = getEPStringsFromRawString(epString);
								for (String ep : eps)
								{
									foundEndPoints.add(ep);
									if (!existingEndPoints.contains(ep))
										mWorld.addEndPoint(ep, node);
								}
							}
							node.setEPUp(receivedURL2EP.get(url), true);
						}
						else
						{
							node.addEndPointError(receivedURL2EP.get(url), mURLErrors.remove(url));
							node.setEPUp(receivedURL2EP.get(url), false);
						}
					}
					if (!receivedURL2EP.isEmpty())
					{
						existingEndPoints.removeAll(foundEndPoints);
						for (String goneEP : existingEndPoints)
							mWorld.removeEndPoint(goneEP, node);
					}
					node.setUp(!receivedURL2EP.isEmpty());

					if (!receivedURL2EP.isEmpty())
					{
						// for nodes that are UP, let's fetch some more info
						receivedURL2EP = fetchJSonResponses(node, "/network/peers", true);
						for (String url : receivedURL2EP.keySet())
						{
							final JSONObject peersResult = mJSonResults.remove(url);
							if (peersResult != null)
							{
								final JSONArray peersArray = (JSONArray)peersResult.get("peers");
								for (Object peerObject : peersArray)
								{
									final JSONObject jsonPeer = (JSONObject)peerObject;
									final JSONArray enpointsArray = (JSONArray)jsonPeer.get("endpoints");
									final Set<String> peers = new HashSet<>();
									Node otherNode = null;
									for (Object endpointObject : enpointsArray)
									{
										final String endpointString = (String)endpointObject;
										final Set<String> peersfound = getEPStringsFromRawString(endpointString);
										peers.addAll(peersfound);
										if (otherNode == null)
											for (String peerep : peersfound)
												if (otherNode == null)
													otherNode = mWorld.getNodeForEP(peerep);
									}
									if (otherNode == null)
									{
										otherNode = new Node(peers);
										for (String peer : peers)
											mWorld.addEndPoint(peer, otherNode);
									}
									else
									{
										Set<String> oldPeers = otherNode.getEndPoints();
										Set<String> newPeers = new HashSet<>(peers);
										newPeers.removeAll(oldPeers);
										for (String peer : newPeers)
											mWorld.addEndPoint(peer, otherNode);
									}
									synchronized (mNodesFound)
									{
										if (!mNodesFound.contains(otherNode))
										{
											mNodes2Explore.offer(otherNode);
											mNodesFound.add(otherNode);
											mNbActive.incrementAndGet();
	//										System.out.println("Need to explore " + otherNode.getEndPoints().toString());
										}
									}
								}
								break;
							}
							else
							{
								// Can not reach that node, pick the error
								String error = mURLErrors.remove(url);
								node.addEndPointError(url, error);
							}
						}

						// Fetch the node's current block
						Block block = fetchBlockFromNode(-1, node);
						if (block != null)
							node.setCurrentBlock(block);

						receivedURL2EP = fetchJSonResponses(node, endPoints, "/node/summary", true);
						for (String url : receivedURL2EP.keySet())
						{
							final JSONObject info = mJSonResults.remove(url);
							if (info != null)
							{
								final JSONObject duniter = (JSONObject)info.get("duniter");
								if (node.getVersion() == null)
									node.setVersion((String)duniter.get("version"));
							}
							else
								node.addEndPointError(receivedURL2EP.get(url), mURLErrors.remove(url));
						}
					}

					node.incTicks();
					mNbActive.decrementAndGet();
					if ((mNbActive.get() == 0) && (mNodes2Explore.isEmpty()))
					// Nobody is active AND there is nothing left in all nodes to explore
						mFinished.release();
				}
				catch (InterruptedException e)
				{
					e.printStackTrace();// should never happen
				}
			}
		}

		private Set<String> getEPStringsFromRawString(final String endpointString)
		{
			final String[] endpointElements = endpointString.split(" ");
			final String header = endpointElements[0].equals("BMAS") ? "https://" : "http://";
			final String port = endpointElements[endpointElements.length - 1];
			final Set<String> peersfound = new HashSet<>();
			for (int i = 1; i < endpointElements.length - 1; i++)
				peersfound.add(header + endpointElements[i] + ":" + port);
			return peersfound;
		}
	}

	private Map<String, String> fetchJSonResponses(final Node pNode, final String pSuffix, final boolean pPreIgnoreCertificatesInError) throws InterruptedException
	{
		Map<String, String> receivedURL2EP = new HashMap<>();
		if (pNode.getPreferredBMAS() != null)
			receivedURL2EP = fetchJSonResponses(pNode, new HashSet<>(Arrays.asList(new String[] {pNode.getPreferredBMAS()})), pSuffix, pPreIgnoreCertificatesInError);
		if (receivedURL2EP.isEmpty() || (pNode.getPreferredBMA() != null))
			receivedURL2EP = fetchJSonResponses(pNode, new HashSet<>(Arrays.asList(new String[] {pNode.getPreferredBMA()})), pSuffix, pPreIgnoreCertificatesInError);
		if (receivedURL2EP.isEmpty())
			receivedURL2EP = fetchJSonResponses(pNode, pNode.getEndPoints(), pSuffix, pPreIgnoreCertificatesInError);
		return receivedURL2EP;
	}

	private Map<String, String> fetchJSonResponses(final Node pNode, final Set<String> pEndPoints, final String pSuffix, final boolean pPreIgnoreCertificatesInError) throws InterruptedException
	{
		final BlockingQueue<String> receivingQueue = new LinkedBlockingQueue<>();
		final Map<String, String> waitingURL2EP = new HashMap<>();
		for (String ep : pEndPoints)
		{
			final String url = ep + pSuffix;
			waitingURL2EP.put(url, ep);
			mURLErrors.remove(url);
			mURLLocks.put(url, receivingQueue);
			if (pNode.isEndPointCertificateError(ep))
			{
				mCertificatesInError.add(url);
				if (pPreIgnoreCertificatesInError)
					mPreIgnoreCertificateErrors.add(url);
			}
			mURLs.offer(url);
		}
		long time = System.currentTimeMillis();
		final Map<String, String> receivedURL2EP = new HashMap<>();
		final Set<String> okBMASs = new HashSet<>();
		String firstAnsweringBMAS = null;
		final Set<String> okBMAs = new HashSet<>();
		String firstAnsweringBMA = null;
		long responseTime = -1;
		for (int iEP = 0; iEP < pEndPoints.size(); iEP++)
		{
			final long time2wait = 10000 - (System.currentTimeMillis() - time);
			final String url = time2wait > 0 ? receivingQueue.poll(time2wait, TimeUnit.MILLISECONDS) : null;
			if (url == null)
			{
				// We have waited too long anyway, finish all
				while (!waitingURL2EP.isEmpty())
				{
					final String retrievedURL = waitingURL2EP.keySet().iterator().next();
//						synchronized (System.out)
//						{
//							System.out.println("TIMEOUT " + retrievedURL);
//						}
					final MultiConnectThread connectThread = mBusyConnectThreads.remove(retrievedURL);
					if (connectThread != null)
					{
						connectThread.interrupt();
						new MultiConnectThread().start();
					}
					String ep = waitingURL2EP.remove(retrievedURL);
					mPreIgnoreCertificateErrors.remove(retrievedURL);
					mCertificatesInError.remove(retrievedURL);
					pNode.setEPUp(ep, false);
					mJSonResults.remove(retrievedURL);
					pNode.addEndPointError(ep, mURLErrors.remove(retrievedURL));
				}
				break;
			}
			boolean isOK;
			synchronized (mJSonResults)
			{
				isOK = mJSonResults.get(url) != null;
			}
			final String endPoint = waitingURL2EP.remove(url);
			mPreIgnoreCertificateErrors.remove(url);
			if (isOK)
			{
				if (responseTime == -1)
					responseTime = System.currentTimeMillis() - time;
				pNode.setEPUp(endPoint, true);
				receivedURL2EP.put(url, endPoint);
				if (endPoint.startsWith("https"))
				{
					okBMASs.add(endPoint);
					if (firstAnsweringBMAS == null)
						firstAnsweringBMAS = endPoint;
				}
				else
				{
					okBMAs.add(endPoint);
					if (firstAnsweringBMA == null)
						firstAnsweringBMA = endPoint;
				}
			}
			else
			{
				pNode.addEndPointError(endPoint, mURLErrors.remove(url));
				pNode.setEPUp(endPoint, false);
			}
			pNode.setEndPointCertificateError(endPoint, mCertificatesInError.remove(url));// if remove() is not successful, it is because there was no such element
			mURLLocks.remove(url);
//				synchronized (System.out)
//				{
//					System.out.println((isOK ? "UP " : "DOWN ") + url);
//				}
		}
		if ((firstAnsweringBMAS != null) && ((pNode.getPreferredBMAS() == null) || (!okBMASs.contains(pNode.getPreferredBMAS()))))
			pNode.setPreferredBMAS(firstAnsweringBMAS);
		if ((firstAnsweringBMA != null) && ((pNode.getPreferredBMA() == null) || (!okBMAs.contains(pNode.getPreferredBMA()))))
			pNode.setPreferredBMA(firstAnsweringBMA);
		if (responseTime != -1)
			pNode.addResponseTime(responseTime);
		return receivedURL2EP;
	}

	public ExploreNodes()
	{
		super();
		mWorld = new World();
		for (int i = 0; i < 20; i++)
			new NodeAnalyzer().start();
		for (int i = 0; i < 60; i++)
			new MultiConnectThread().start();
	}

	private static BufferedImage scale(Image imageToScale, int dWidth, int dHeight, Color pBackground)
	{
        BufferedImage scaledImage = null;
        if (imageToScale != null)
        {
            scaledImage = new BufferedImage(dWidth, dHeight, BufferedImage.TYPE_INT_ARGB);
            Graphics2D graphics2D = scaledImage.createGraphics();
            graphics2D.setColor(pBackground);
            graphics2D.fillRect(0, 0, dWidth, dHeight);
            graphics2D.drawImage(imageToScale, 0, 0, dWidth, dHeight, null);
            graphics2D.dispose();
        }
        return scaledImage;
    }

	public void explore(String pRootNode) throws InterruptedException
	{
		TrayIcon trayIcon = null;
		if (new File("/usr/bin/notify-send").exists())
		{
			trayIcon = new TrayIcon(getTrayIconImage())
			{
				@Override
				public void displayMessage(String pCaption, String pText, MessageType pMessageType)
				{
					try
					{
						new ProcessBuilder(Arrays.asList(new String[] {"/usr/bin/notify-send", "-c", pCaption, pText})).start();
					}
					catch (IOException e1)
					{
						e1.printStackTrace();// should never happen
					}
				}
			};
			if (SystemTray.isSupported())
				try
				{
					SystemTray.getSystemTray().add(trayIcon);
				}
				catch (AWTException e)
				{
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
		}
		else if (SystemTray.isSupported())
			try
			{
				trayIcon = new TrayIcon(getTrayIconImage());
				SystemTray.getSystemTray().add(trayIcon);
			}
			catch (AWTException e1)
			{
				e1.printStackTrace();
			}
		final Node root = new Node(new HashSet<>(Arrays.asList(new String[] {pRootNode})));
		// In the meantime, get the members
		final Map<String, String> membersUrl = fetchJSonResponses(root, "/wot/members", false);
		for (String url : membersUrl.keySet())
		{
			final JSONObject jsonResult = mJSonResults.remove(url);
			if (jsonResult != null)
			{
				final JSONArray jsonMembers = (JSONArray)jsonResult.get("results");
				for (Object objectMember : jsonMembers)
				{
					final JSONObject jsonMember = (JSONObject)objectMember;
					final String name = (String)jsonMember.get("uid");
					final String pk = (String)jsonMember.get("pubkey");
					synchronized (mWorld)
					{
						Member member = mWorld.getMember(pk);
						if (member == null)
							mWorld.addMember(new Member(pk, name));
						else if (member.getName() == null)
							member.setName(name);
					}
				}
			}
			else
				System.err.println(mJSonResults.remove(url));
		}
		System.out.println("Number of members: " + mWorld.getAllMembers().size());
		int currentForks = -1;
		while (true)
		{
			System.out.println("Probing... (" + getReadableTime(System.currentTimeMillis()) + ")");
			mNodes2Explore.offer(root);
			mNbActive.set(1);
			mFinished.acquire();
			System.out.println("Status as of " + getReadableTime(System.currentTimeMillis()) + ":");
			final Map<String, List<Node>> hash2Nodes = new HashMap<>();
			for (Node node : mWorld.getAllNodes())
			{
				final String hash = node.isUp() ? (node.getCurrentBlock() == null ? NO_BLOCK_KEY : node.getCurrentBlock().getHash()) : DOWN_KEY;
				List<Node> list = hash2Nodes.get(hash);
				if (list == null)
					hash2Nodes.put(hash, list = new ArrayList<>());
				list.add(node);
			}
			final SortedSet<String> sortedHashes = new TreeSet<>(new Comparator<String>()
			{
				@Override
				public int compare(String pO1, String pO2)
				{
					final int s1 = hash2Nodes.containsKey(pO1) ? hash2Nodes.get(pO1).size() : 0;
					final int s2 = hash2Nodes.containsKey(pO2) ? hash2Nodes.get(pO2).size() : 0;
					if (s2 < s1)
						return -1;
					else if (s2 == s1)
						return 0;
					else
						return 1;
				}
			});
			sortedHashes.addAll(hash2Nodes.keySet());
			Map<String, List<Node>> hash2sortedNodes = new HashMap<>();
			for (String hash : sortedHashes)
			{
				final List<Node> sortedNodes = new ArrayList<>(hash2Nodes.get(hash));
				for (Node node : sortedNodes)
					node.setMember(mWorld.getMember(node.getPubKey()));

				sortedNodes.sort(new Comparator<Node>()
				{
					@Override
					public int compare(Node pO1, Node pO2)
					{
						if (pO1.getMember() == null)
							if (pO2.getMember() != null)
								return 1;
							else;
						else
							if (pO2.getMember() == null)
								return -1;
						final long r1 = pO1.getResponseTime();
						final long r2 = pO2.getResponseTime();
						if (r1 < r2)
							return -1;
						else if (r1 == r2)
							return 0;
						else
							return 1;
					}
				});
				hash2sortedNodes.put(hash, sortedNodes);
			}
			sortedHashes.addAll(hash2Nodes.keySet());
			sortedHashes.remove(NO_BLOCK_KEY);
			sortedHashes.remove(DOWN_KEY);
			for (String hash : sortedHashes)
			{
				final Block block = mWorld.getBlockFromHash(hash);
				System.out.println("Block " + block.getInnerHash() + " - " + block.getNumber() + " (" + getReadableTime(block.getTime() * 1000) + " - median " + getReadableTime(block.getMedianTime() * 1000) + "):");
				showNodesForHash(hash2sortedNodes, hash, true);
			}
			if (hash2Nodes.containsKey(NO_BLOCK_KEY) && (!hash2Nodes.get(NO_BLOCK_KEY).isEmpty()))
			{
				System.out.println("Nodes without blocks:");
				showNodesForHash(hash2sortedNodes, NO_BLOCK_KEY, true);
			}
			if (hash2Nodes.containsKey(DOWN_KEY) && (!hash2Nodes.get(DOWN_KEY).isEmpty()))
			{
				System.out.println("Nodes DOWN:");
				showNodesForHash(hash2sortedNodes, DOWN_KEY, false);
			}

			// Only the heads of all branches
			Set<String> headsFound = new HashSet<>();
			// associate all other hashes in this chain with the head
			Map<String, Set<String>> head2hashes = new HashMap<>();
			findHeads(sortedHashes, hash2sortedNodes, headsFound, head2hashes);

			List<String> hashesPerHeight = new ArrayList<>(headsFound);
			hashesPerHeight.sort(new Comparator<String>()
			{
				@Override
				public int compare(String pO1, String pO2)
				{
					final long n1 = mWorld.getBlockFromHash(pO1).getNumber();
					final long n2 = mWorld.getBlockFromHash(pO2).getNumber();
					if (n1 == n2)
					{
						// Compare with the number of members in each
						int mem1 = 0;
						for (Node node : hash2Nodes.get(pO1))
							if (node.getMember() != null)
								mem1++;
						int mem2 = 0;
						for (Node node : hash2Nodes.get(pO2))
								if (node.getMember() != null)
									mem2++;
						return -Integer.valueOf(mem1).compareTo(mem2);
					}
					return -Long.valueOf(n1).compareTo(n2);
				}
			});
			long highestBlockNumber = mWorld.getBlockFromHash(hashesPerHeight.get(0)).getNumber();
			String mainHash = hashesPerHeight.get(0);
			String extra = null;
			System.out.println("Found the following heads:");
			int totalMembers = 0;
			int allLateMembers = 0;
			int allForkedMembers = 0;
			int totalMirrors = 0;
			int allLateMirrors = 0;
			int allForkedMirrors = 0;
			int newNbForks = 0;
			for (String head : hashesPerHeight)
			{
				int nbMembers = 0;
				int nbMirrors = 0;
				int lateMembers = 0;
				int lateMirrors = 0;
				if (extra != null)
					newNbForks++;
				for (String associatedHash : head2hashes.get(head))
					for (Node node : hash2Nodes.get(associatedHash))
					{
						if (!associatedHash.equals(head))
							// This is a late node
							if (node.getMember() == null)
							{
								if (extra == null)
									allLateMirrors++;
								else
									allForkedMirrors++;
								lateMirrors++;
								totalMirrors++;
							}
							else
							{
								if (extra == null)
								// MAIN
									allLateMembers++;
								else
								// FORK
									allForkedMembers++;
								lateMembers++;
								totalMembers++;
							}
						else
							// This is a node on the head of this branch
							if (node.getMember() == null)
							{
								nbMirrors++;
								totalMirrors++;
								if (extra != null)
									allForkedMirrors++;
							}
							else
							{
								if (extra != null)
								// MAIN
									allForkedMembers++;
								totalMembers++;
								nbMembers++;
							}
					}
				String extra2 = "";
				if (extra == null)
					extra = "MAIN";
				else if (mWorld.getBlockFromHash(head).getNumber() < highestBlockNumber - 20)
					extra = "ASTRAY";
				else
				{
					// Find the fork point
					Block mainBlock = mWorld.getBlockFromHash(mainHash);
					Block overMainBlock = mainBlock;
					Block forkBlock = mWorld.getBlockFromHash(head);
					Block overForkBlock = forkBlock;
					do
					{
						if (forkBlock.getNumber() >= mainBlock.getNumber())
						{
							overForkBlock = forkBlock;
							// Try to get the block from memory
							forkBlock = fetchPreviousBlock(forkBlock, head, hash2sortedNodes);
							if (forkBlock == null)
								break;
						}
						if (forkBlock.getNumber() < mainBlock.getNumber())
						{
							// We also need to go to the previous block on main
							// Try to get the block from memory
							overMainBlock = mainBlock;
							mainBlock = fetchPreviousBlock(mainBlock, mainHash, hash2sortedNodes);
							if (mainBlock == null)
								break;
						}
//						System.out.println("Block main " + mainBlock.getNumber() + " - " + mainBlock.getInnerHash() + " fork " + forkBlock.getNumber() + " - " + forkBlock.getInnerHash());
					}
					while (mainBlock != forkBlock);
					extra = "FORK";
					if (mainBlock == forkBlock)
						extra2 = "\n\tforked at block " + mainBlock.getNumber() + " at " + getReadableTime(mainBlock.getTime() * 1000) + "\n\tinto block " + overMainBlock.getInnerHash() + " at " + getReadableTime(overMainBlock.getTime() * 1000) + " (MAIN)\n\t and block " + overForkBlock.getInnerHash() + " at " + getReadableTime(overForkBlock.getTime() * 1000) + " (FORK)";
					else
						extra2 = "\n\t(could not retrieve forking info)";
				}
				if (nbMembers > 0)
					extra += ", " + nbMembers + " members";
				if (nbMirrors > 0)
					extra += ", " + nbMirrors + " mirrors";
				if (lateMembers > 0)
					extra += ", " + lateMembers + " LATE members";
				if (lateMirrors > 0)
					extra += ", " + lateMirrors + " LATE mirrors";
				String message = "Hash " + mWorld.getBlockFromHash(head).getInnerHash() + " " + extra + extra2;
				System.out.println(message);
			}

			// Compute overall network stability
			Color trayColor = Color.DARK_GRAY;
			if (totalMembers > 0)
			{
				// Consider that a forked member is counting double
				double forkStability = Math.max(0.0, 100.0 - 100.0 * ((1.0 * (allForkedMembers * 2 + allForkedMirrors)) / (totalMembers + totalMirrors)));
				// Late nodes, a mirror node counts half
				double lateStability = (totalMembers + totalMirrors - allForkedMembers - allForkedMirrors == 0) ? 0 : 100.0 - (100.0 * (allLateMembers + allLateMirrors / 2)) / (totalMembers + totalMirrors - allForkedMembers - allForkedMirrors);
				double overallStability = forkStability * lateStability / 100;
				System.out.println("Stability of network: fork: " + forkStability + ", late: " + lateStability + ", overall: " + overallStability);
				double redComponent = Math.min(255, (100 - overallStability) * 4);
				double greenComponent = overallStability * 1.8;
				trayColor = new Color((int)redComponent, (int)greenComponent, 0);
			}
			else
			{
				System.out.println("No members???");
				trayColor = Color.red;
			}
			if (trayIcon != null)
			{
				trayIcon.setImage(scale(getTrayIconImage(), 24, 24, trayColor));
				if (currentForks == -1)
					currentForks = newNbForks;
				else if (newNbForks > currentForks)
					trayIcon.displayMessage("NEW FORK", "Duniter network FORKED!", MessageType.WARNING);
			}
			System.out.println("--------------------------------------------------------------------------------------------------------------------------------------------------------------------");
			Thread.sleep(30000);
			mNodesFound.clear();
		}
	}

	private void findHeads(final SortedSet<String> pSortedHashes, Map<String, List<Node>> pHash2sortedNodes, Set<String> pHeadsFound, Map<String, Set<String>> pHead2hashes)
	{
		for (String hash : pSortedHashes)
		{
			boolean foundOtherHead = false;
			Block searchingBlock = mWorld.getBlockFromHash(hash);
			for (String head : pHeadsFound)
			{
				Block existingBlock = mWorld.getBlockFromHash(head);
				Block highest;
				Block lowest;
				if (existingBlock.getNumber() > searchingBlock.getNumber())
				{
					highest = existingBlock;
					lowest = searchingBlock;
				}
				else if (existingBlock.getNumber() < searchingBlock.getNumber())
				{
					highest = searchingBlock;
					lowest = existingBlock;
				}
				else // 2 blocks with the same number and different hashes cannot be ok
					continue;
				if (highest.getNumber() > lowest.getNumber() + 50)
				// do not fetch info for blocks that are too far apart and consider them as 2 different branches
					continue;
				Block current = highest;
				do
				{
					// Try to get the block from memory
					current = fetchPreviousBlock(current, head, pHash2sortedNodes);
					if (current == null)
					// Yikes, we couldn't find that block, too bad, just let's ignore that info
						break;
				}
				while (current.getNumber() > lowest.getNumber());
				if (current == lowest)
				{
					// We have managed to find the exact lowest block from the highest, this is on the same branch, keep only the highest
					pHeadsFound.remove(lowest.getHash());
					pHeadsFound.add(highest.getHash());
					Set<String> associatedHashes = pHead2hashes.get(highest.getHash());
					if (associatedHashes == null)
						pHead2hashes.put(highest.getHash(), associatedHashes = new HashSet<>());
					associatedHashes.add(lowest.getHash());
					associatedHashes.add(highest.getHash());
					if (pHead2hashes.containsKey(lowest.getHash()))
					// We need to add all these to the new head
						associatedHashes.addAll(pHead2hashes.remove(lowest.getHash()));
					foundOtherHead = true;
					break;
				}
			}
			if (!foundOtherHead)
			{
				pHeadsFound.add(hash);
				Set<String> hashes = new HashSet<>();
				hashes.add(hash);
				pHead2hashes.put(hash, hashes);
			}
		}
	}

	private Block fetchPreviousBlock(Block pBlock, String pHeadHash, Map<String, List<Node>> pHash2Nodes)
	{
		Block previousMain = mWorld.getBlockFromHash(pBlock.getPreviousHash());
		if (previousMain == null)
		{
			// No block found, fetch from peers
			previousMain = fetchBlock(pBlock.getPreviousHash(), pBlock.getNumber() - 1, pHash2Nodes.get(pHeadHash));
			if (previousMain != null)
			// Add it in memory
				previousMain = mWorld.offerBlock(previousMain);
			else
			// Yikes, we couldn't find that block, too bad, just let's ignore that info
				return null;

		}
		return previousMain;
	}

	public Block fetchBlockFromNode(long pNumber, Node pNode)
	{
		Map<String, String> receivedURL2EP;
		try
		{
			receivedURL2EP = fetchJSonResponses(pNode, pNumber == -1 ? "/blockchain/current" : "/blockchain/block/" + pNumber, true);
		}
		catch (InterruptedException e)
		{
			return null;// should never happen
		}
		for (String url : receivedURL2EP.keySet())
		{
			final JSONObject curblock = mJSonResults.remove(url);
			if (curblock != null)
			{
				final String hash = (String)curblock.get("hash");
				Block block = mWorld.getBlockFromHash(hash);
				if (block != null)
					return block;
				final long blockNum = (long)curblock.get("number");
				final String innerhash = (String)curblock.get("inner_hash");
				final long nonce = (long)curblock.get("nonce");
				final long time = (long)curblock.get("time");
				final long medianTime = (long)curblock.get("medianTime");
				final String issuerPK = (String)curblock.get("issuer");
				Member issuer = mWorld.getMember(issuerPK);
				if (issuer == null)
					issuer = new Member(issuerPK, "");
				final String previousHash = (String)curblock.get("previousHash");
				block = mWorld.offerBlock(new Block(blockNum, nonce, time, medianTime, issuer, innerhash, hash, previousHash));
				return block;
			}
			else
				mURLErrors.remove(url);
		}
		return null;
	}

	private Block fetchBlock(String pHash, long pNumber, List<Node> pNodes)
	{
		for (Node node : pNodes)
		{
			Block found = fetchBlockFromNode(pNumber, node);
			if ((found != null) && found.getHash().equals(pHash))
			// Great, we found the node with the correct hash, return it
				return found;
			// else whoops, this is another hash, maybe that node is not on the same chain anymore, just go on with the search
		}
		return null;
	}

	private Image getTrayIconImage()
	{
		return Toolkit.getDefaultToolkit().getImage(getClass().getResource("duniter-logo24.png"));
	}

	public static void main(String[] args) throws IOException, ParseException, InterruptedException
	{
		final ExploreNodes exploreNodes = new ExploreNodes();
		if (args.length >= 1)
		{
			final String rootNode = args[0];
			System.out.println("Exploring from " + rootNode);
			exploreNodes.explore(rootNode);
		}
		else
			exploreNodes.explore("https://g1.duniter.org:443");
	}

	private static String getReadableTime(long pCurrentTimeMillis)
	{
		return new SimpleDateFormat("YYYY-MM-dd HH:mm:ss").format(new Date(pCurrentTimeMillis));
	}

	private void showNodesForHash(Map<String, List<Node>> pHash2Nodes, String pHash, final boolean pShowNodeInfos)
	{
		for (Node node : pHash2Nodes.get(pHash))
		{
			String nodeInfo = null;
			String extraInfo;
			Set<String> extraEndPoints = new HashSet<>(node.getEndPoints());
			if (node.getPreferredBMAS() != null)
			{
				nodeInfo = formatNodeInfo(node, node.getPreferredBMAS());
				extraEndPoints.remove(node.getPreferredBMAS());
			}
			if (node.getPreferredBMA() != null)
			{
				if (nodeInfo == null)
					nodeInfo = formatNodeInfo(node, node.getPreferredBMA());
				else
					nodeInfo += ", " + formatNodeInfo(node, node.getPreferredBMA());
				extraEndPoints.remove(node.getPreferredBMA());
			}
			if (nodeInfo == null)
			{
				nodeInfo = "";
				for (String ep : extraEndPoints)
				{
					if (!nodeInfo.isEmpty())
						nodeInfo += ", ";
					nodeInfo += formatNodeInfo(node, ep);
				}
				extraInfo = "";
			}
			else
			{
				extraInfo = "";
				for (String ep : extraEndPoints)
				{
					if (!extraInfo.isEmpty())
						extraInfo += ", ";
					extraInfo += formatNodeInfo(node, ep);
				}
			}

			if (!extraInfo.isEmpty())
				extraInfo = " (" + extraInfo + ")";
			if (pShowNodeInfos)
			{
				String memberInfo = node.getPubKey();
				if (node.getMember() != null)
					memberInfo = node.getMember().getName();
				System.out.println("\t" + normalize(memberInfo, 15, true) + " " + normalize(node.getVersion(), 6, true) + " " + normalize("" + node.getResponseTime() + "ms", 8, false) + " " + nodeInfo + extraInfo);
			}
			else
				System.out.println("\t" + nodeInfo + " " + extraInfo);
		}
	}

	private String formatNodeInfo(Node pNode, String pEndPoint)
	{
		String formatted = pEndPoint;
		if (pNode.isEndPointCertificateError(pEndPoint))
			formatted += "!";
		if (pNode.getEndPointErrors().containsKey(pEndPoint))
			formatted += " ERR";
		else
		{
			double stability = pNode.getEPStability(pEndPoint);
			formatted += stability > 90 ? "*" : stability > 50 ? "+" : "-";
		}
		return formatted;
	}

	private String normalize(String pMemberInfo, int pLength, boolean pRight)
	{
		if (pMemberInfo == null)
			pMemberInfo = "";
		if (pMemberInfo.length() > pLength)
			return pMemberInfo.substring(0, pLength);
		else
			return String.format("%" + (pRight ? "-" : "") + pLength + "s", pMemberInfo);
	}

}
