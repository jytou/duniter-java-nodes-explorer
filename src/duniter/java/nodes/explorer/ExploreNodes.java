package duniter.java.nodes.explorer;

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
	
						receivedURL2EP = fetchJSonResponses(node, "/blockchain/current", true);
						for (String url : receivedURL2EP.keySet())
						{
							final JSONObject curblock = mJSonResults.remove(url);
							if (curblock != null)
							{
								final long blockNum = (long)curblock.get("number");
								final String hash = (String)curblock.get("inner_hash");
								final long nonce = (long)curblock.get("nonce");
								final long time = (long)curblock.get("time");
								final long medianTime = (long)curblock.get("medianTime");
								final String issuerPK = (String)curblock.get("issuer");
								Member issuer = mWorld.getMember(issuerPK);
								if (issuer == null)
									issuer = new Member(issuerPK, "");
								final String previousHash = (String)curblock.get("previousHash");
								Block block = mWorld.getBlockFromHash(hash);
								if (block == null)
									mWorld.addBlock(block = new Block(blockNum, nonce, time, medianTime, issuer, hash, previousHash));
								node.setCurrentBlock(block);
							}
							else
								mURLErrors.remove(url);
						}

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

	public void explore(String pRootNode) throws InterruptedException
	{
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
			sortedHashes.remove(NO_BLOCK_KEY);
			sortedHashes.remove(DOWN_KEY);
			for (String hash : sortedHashes)
			{
				final Block block = mWorld.getBlockFromHash(hash);
				System.out.println("Block " + hash + " - " + block.getNumber() + " (" + getReadableTime(block.getTime() * 1000) + " - median " + getReadableTime(block.getMedianTime() * 1000) + "):");
				showNodesForHash(hash2Nodes, hash, true);
			}
			if (hash2Nodes.containsKey(NO_BLOCK_KEY) && (!hash2Nodes.get(NO_BLOCK_KEY).isEmpty()))
			{
				System.out.println("Nodes without blocks:");
				showNodesForHash(hash2Nodes, NO_BLOCK_KEY, true);
			}
			if (hash2Nodes.containsKey(DOWN_KEY) && (!hash2Nodes.get(DOWN_KEY).isEmpty()))
			{
				System.out.println("Nodes DOWN:");
				showNodesForHash(hash2Nodes, DOWN_KEY, false);
			}
//			for (Node node : mWorld.getAllNodes())
//				System.out.println(node.getVersion() + " " + (node.getCurrentBlock() == null ? "null" : node.getCurrentBlock().getHash()) + " " + (node.isUp() ? "UP in " + (node.getResponseTime()) + "ms" : "DOWN") + " " + (node.getPreferredBMAS() != null ? node.getPreferredBMAS() : node.getPreferredBMA() != null ? node.getPreferredBMA() : node.getEndPoints().toString()) + (node.getEndPointErrors().isEmpty() ? "" : " " + node.getEndPointErrors()));
			System.out.println("--------------------------------------------------------------------------------------------------------------------------------------------------------------------");
			Thread.sleep(60000);
			mNodesFound.clear();
		}
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
		final List<Node> sortedNodes = new ArrayList<>(pHash2Nodes.get(pHash));
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
		for (Node node : sortedNodes)
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
		formatted += (pNode.getEndPointErrors().containsKey(pEndPoint) ? " ERR" : "*");
		return formatted;
	}

	private String normalize(String pMemberInfo, int pLength, boolean pRight)
	{
		if (pMemberInfo.length() > pLength)
			return pMemberInfo.substring(0, pLength);
		else
			return String.format("%" + (pRight ? "-" : "") + pLength + "s", pMemberInfo);
	}

}
