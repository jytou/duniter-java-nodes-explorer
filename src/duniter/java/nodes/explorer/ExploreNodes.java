package duniter.java.nodes.explorer;

import java.awt.Color;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.management.ManagementFactory;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedMap;
import java.util.SortedSet;
import java.util.TreeMap;
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
	private Set<String> mEPsFound = new HashSet<>();
	private BlockingQueue<String> mEPs2Explore = new LinkedBlockingQueue<>();
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
					final EP ep = mWorld.getEndPoint(mEPs2Explore.take());

					Map<String, String> receivedURL2EP = fetchJSonResponses(ep, "/network/peering", false);
					final Set<String> foundEndPoints = new HashSet<>();
					for (String url : receivedURL2EP.keySet())
					{
						final JSONObject peeringInfo = mJSonResults.remove(url);
						if (peeringInfo != null)
						{
							final String pubkey = (String)peeringInfo.get("pubkey");
							ep.setPubKey(pubkey);
							final JSONArray raweps = (JSONArray)peeringInfo.get("endpoints");
							for (Object epObject : raweps)
							{
								final String epString = (String)epObject;
								final Set<String> epURLs = getEPStringsFromRawString(epString);
								for (String epURL : epURLs)
									foundEndPoints.add(epURL);
							}
							ep.setUp(true);
						}
						else
						{
							ep.setError(mURLErrors.remove(url));
							ep.setUp(false);
						}
					}
					if (!foundEndPoints.isEmpty())
						ep.setSiblings(foundEndPoints);

					if (ep.isUp())
					{
						// for EPs that are UP, let's fetch some more info
						receivedURL2EP = fetchJSonResponses(ep, "/network/peers", true);
						for (String url : receivedURL2EP.keySet())
						{
							final JSONObject peersResult = mJSonResults.remove(url);
							if (peersResult != null)
							{
								final JSONArray peersArray = (JSONArray)peersResult.get("peers");
								final Set<String> peers = new HashSet<>();
								for (Object peerObject : peersArray)
								{
									final JSONObject jsonPeer = (JSONObject)peerObject;
									final JSONArray enpointsArray = (JSONArray)jsonPeer.get("endpoints");
									for (Object endpointObject : enpointsArray)
									{
										final String endpointString = (String)endpointObject;
										final Set<String> peersfound = getEPStringsFromRawString(endpointString);
										peers.addAll(peersfound);
										for (String peer : peersfound)
											offerEP2Query(peer);
									}
								}
								ep.setKnownPeers(peers);
								break;
							}
							else
							// Can not reach that EP, pick the error
								ep.setError(mURLErrors.remove(url));
						}

						// Fetch the EP's current block
						Block block = fetchBlockFromEP(-1, ep);
						if (block != null)
							ep.setCurrentBlock(block);

						receivedURL2EP = fetchJSonResponses(ep, "/node/summary", true);
						for (String url : receivedURL2EP.keySet())
						{
							final JSONObject info = mJSonResults.remove(url);
							if (info != null)
							{
								final JSONObject duniter = (JSONObject)info.get("duniter");
								if (ep.getVersion() == null)
									ep.setVersion((String)duniter.get("version"));
							}
							else
								ep.setError(mURLErrors.remove(url));
						}
						receivedURL2EP = fetchJSonResponses(ep, "/node/sandboxes", true);
						for (String url : receivedURL2EP.keySet())
						{
							final JSONObject info = mJSonResults.remove(url);
							if (info != null)
							{
								final int id = ((Long)((JSONObject)info.get("identities")).get("free")).intValue();
								final int mem = ((Long)((JSONObject)info.get("memberships")).get("free")).intValue();
								final int trans = ((Long)((JSONObject)info.get("transactions")).get("free")).intValue();
								ep.setFreeIdentities(id);
								ep.setFreeMemberships(mem);
								ep.setFreeTransactions(trans);
							}
						}
					}

					mNbActive.decrementAndGet();
					if ((mNbActive.get() == 0) && (mEPs2Explore.isEmpty()))
					// Nobody is active AND there is nothing left in all EPs to explore
						mFinished.release();
				}
				catch (InterruptedException e)
				{
					e.printStackTrace();// should never happen
				}
			}
		}

	}

	private static Set<String> getEPStringsFromRawString(final String endpointString)
	{
		final String[] endpointElements = endpointString.split(" ");
		final String header = endpointElements[0].equals("BMAS") ? "https://" : "http://";
		final String port = endpointElements[endpointElements.length - 1];
		final Set<String> peersfound = new HashSet<>();
		for (int i = 1; i < endpointElements.length - 1; i++)
			peersfound.add(header + endpointElements[i] + ":" + port);
		return peersfound;
	}

	private Map<String, String> fetchJSonResponses(final EP pEndPoint, final String pSuffix, final boolean pPreIgnoreCertificatesInError) throws InterruptedException
	{
		final BlockingQueue<String> receivingQueue = new LinkedBlockingQueue<>();
		final Map<String, String> waitingURL2EP = new HashMap<>();
		String ep = pEndPoint.getURL();
		String url = ep + pSuffix;

		waitingURL2EP.put(url, ep);
		mURLErrors.remove(url);
		mURLLocks.put(url, receivingQueue);
		if (pEndPoint.isCertificateError())
		{
			mCertificatesInError.add(url);
			if (pPreIgnoreCertificatesInError)
				mPreIgnoreCertificateErrors.add(url);
		}
		mURLs.offer(url);

		long time = System.currentTimeMillis();
		final Map<String, String> receivedURL2EP = new HashMap<>();
		final Set<String> okBMASs = new HashSet<>();
		String firstAnsweringBMAS = null;
		final Set<String> okBMAs = new HashSet<>();
		String firstAnsweringBMA = null;
		long responseTime = -1;
//		for (int iEP = 0; iEP < pEndPoints.size(); iEP++)
//		{
			final long time2wait = 10000 - (System.currentTimeMillis() - time);
			url = time2wait > 0 ? receivingQueue.poll(time2wait, TimeUnit.MILLISECONDS) : null;
			if (url == null)
			{
				// We have waited too long anyway, finish all
				while (!waitingURL2EP.isEmpty())
				{
					final String retrievedURL = waitingURL2EP.keySet().iterator().next();
					final MultiConnectThread connectThread = mBusyConnectThreads.remove(retrievedURL);
					if (connectThread != null)
					{
						connectThread.interrupt();
						new MultiConnectThread().start();
					}
					waitingURL2EP.remove(retrievedURL);
					mPreIgnoreCertificateErrors.remove(retrievedURL);
					mCertificatesInError.remove(retrievedURL);
					pEndPoint.setUp(false);
					mJSonResults.remove(retrievedURL);
					pEndPoint.setError(mURLErrors.remove(retrievedURL));
				}
				return receivedURL2EP;
			}
			boolean isOK = mJSonResults.get(url) != null;
			final String endPoint = waitingURL2EP.remove(url);
			mPreIgnoreCertificateErrors.remove(url);
			if (isOK)
			{
				if (responseTime == -1)
					responseTime = System.currentTimeMillis() - time;
				pEndPoint.setUp(true);
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
				pEndPoint.setError(mURLErrors.remove(url));
				pEndPoint.setUp(false);
			}
			pEndPoint.setCertificateError(mCertificatesInError.remove(url));// if remove() is not successful, it is because there was no such element
			mURLLocks.remove(url);
//		}
		if (responseTime != -1)
			pEndPoint.addResponseTime(responseTime);
		return receivedURL2EP;
	}

	public ExploreNodes()
	{
		super();
		mWorld = new World();
		for (int i = 0; i < 50; i++)
		{
			System.out.print(".");
			new NodeAnalyzer().start();
		}
		System.out.println();
		for (int i = 0; i < 100; i++)
		{
			System.out.print(".");
			new MultiConnectThread().start();
		}
		System.out.println();
	}

	public void offerEP2Query(String pEP)
	{
		synchronized (mEPsFound)
		{
			if (mEPsFound.contains(pEP))
				return;
			mEPsFound.add(pEP);
			mNbActive.incrementAndGet();
			mWorld.offerEndPoint(pEP);
			mEPs2Explore.offer(pEP);
		}
	}

	public void explore(String pRootEP) throws InterruptedException
	{
		SystemSignal systemSignal = new SystemSignal();
		// In the meantime, get the members
		final EP root = mWorld.offerEndPoint(pRootEP);
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
		mEPsFound.add(pRootEP);
		while (true)
		{
			System.out.println("Probing... (" + getReadableTime(System.currentTimeMillis()) + ")");
			Set<String> toOffer = new HashSet<>(mEPsFound);
			mEPsFound.clear();
			for (String ep2offer : toOffer)
				offerEP2Query(ep2offer);
			mFinished.acquire();
			System.out.println("Status as of " + getReadableTime(System.currentTimeMillis()) + ":");
			final Map<String, List<EP>> hash2EPs = new HashMap<>();
			for (EP ep : mWorld.getAllEndPoints())
			{
				final String hash = ep.isUp() ? (ep.getCurrentBlock() == null ? NO_BLOCK_KEY : ep.getCurrentBlock().getHash()) : DOWN_KEY;
				List<EP> list = hash2EPs.get(hash);
				if (list == null)
					hash2EPs.put(hash, list = new ArrayList<>());
				list.add(ep);
			}
			final SortedSet<String> sortedHashes = new TreeSet<>(new Comparator<String>()
			{
				@Override
				public int compare(String pO1, String pO2)
				{
					final int s1 = hash2EPs.containsKey(pO1) ? hash2EPs.get(pO1).size() : 0;
					final int s2 = hash2EPs.containsKey(pO2) ? hash2EPs.get(pO2).size() : 0;
					if (s2 < s1)
						return -1;
					else if (s2 == s1)
						return 0;
					else
						return 1;
				}
			});
			sortedHashes.addAll(hash2EPs.keySet());
			Map<String, List<EP>> hash2sortedEPs = new HashMap<>();
			for (String hash : sortedHashes)
			{
				final List<EP> sortedEPs = new ArrayList<>(hash2EPs.get(hash));
				for (EP ep : sortedEPs)
					ep.setMember(mWorld.getMember(ep.getPubKey()));

				sortedEPs.sort(new Comparator<EP>()
				{
					@Override
					public int compare(EP pO1, EP pO2)
					{
						if (pO1.getMember() == null)
							if (pO2.getMember() != null)
								return 1;
							else;
						else
							if (pO2.getMember() == null)
								return -1;
						final long r1 = pO1.getAvgResponseTime();
						final long r2 = pO2.getAvgResponseTime();
						if (r1 < r2)
							return -1;
						else if (r1 == r2)
							return 0;
						else
							return 1;
					}
				});
				hash2sortedEPs.put(hash, sortedEPs);
			}
			sortedHashes.addAll(hash2EPs.keySet());
			sortedHashes.remove(DOWN_KEY);

			Map<String, SortedMap<Node, Node>> hash2Nodes = new HashMap<>();
			for (String hash : sortedHashes)
			{
				SortedMap<Node, Node> nodes = new TreeMap<>();
				hash2Nodes.put(hash, nodes);
				for (EP ep : hash2sortedEPs.get(hash))
				{
					Node node = new Node(ep);
					if (nodes.containsKey(node))
						nodes.get(node).addEP(ep);
					else
						nodes.put(node, node);
				}
			}
			for (String hash : sortedHashes)
			{
				final Block block = mWorld.getBlockFromHash(hash);
				System.out.println("Block " + block.getInnerHash() + " - Num " + block.getNumber() + " (" + getReadableTime(block.getTime() * 1000) + " - median " + getReadableTime(block.getMedianTime() * 1000) + "), " + hash2Nodes.get(hash).size() + " peers:");
				showEPsForHash(hash2Nodes, hash, true);
			}
			if (hash2EPs.containsKey(NO_BLOCK_KEY) && (!hash2EPs.get(NO_BLOCK_KEY).isEmpty()))
			{
				System.out.println("EPs without blocks:");
				showEPsForHash(hash2Nodes, NO_BLOCK_KEY, true);
			}

			System.out.println();
			if (hash2sortedEPs.containsKey(DOWN_KEY) && (!hash2sortedEPs.get(DOWN_KEY).isEmpty()))
			{
				StringBuilder sb = new StringBuilder("EPs DOWN: ").append(hash2sortedEPs.get(DOWN_KEY).size()).append(": ");
				boolean first = true;
				for (EP ep : hash2sortedEPs.get(DOWN_KEY))
				{
					if (first)
						first = false;
					else
						sb.append(", ");
					sb.append(ep.getURL()).append(" (").append(ep.getUpPercent()).append("%)");
				}
				System.out.println(sb.toString());
			}

			System.out.println();
			// Only the heads of all branches
			Set<String> headsFound = new HashSet<>();
			// associate all other hashes in this chain with the head
			Map<String, Set<String>> head2hashes = new HashMap<>();
			sortedHashes.remove(NO_BLOCK_KEY);// we don't want to fetch "NO_BLOCK_KEY" as a block, obviously
			findHeads(sortedHashes, hash2Nodes, headsFound, head2hashes);

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
						for (Node node : hash2Nodes.get(pO1).keySet())
							if (node.getEP().getMember() != null)
								mem1++;
						int mem2 = 0;
						for (Node node : hash2Nodes.get(pO2).keySet())
							if (node.getEP().getMember() != null)
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
				Set<String> membersOnBranch = new HashSet<>();
				if (extra != null)
					newNbForks++;
				for (String associatedHash : head2hashes.get(head))
					for (Node node : hash2Nodes.get(associatedHash).keySet())
					{
						EP ep = node.getEP();
						if (ep.getMember() != null)
							membersOnBranch.add(ep.getMember().getName());
						if (!associatedHash.equals(head))
							// This is a late EP
							if (ep.getMember() == null)
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
							// This is an EP on the head of this branch
							if (ep.getMember() == null)
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
							forkBlock = fetchPreviousBlock(forkBlock, head, hash2Nodes);
							if (forkBlock == null)
								break;
						}
						if (forkBlock.getNumber() < mainBlock.getNumber())
						{
							// We also need to go to the previous block on main
							// Try to get the block from memory
							overMainBlock = mainBlock;
							mainBlock = fetchPreviousBlock(mainBlock, mainHash, hash2Nodes);
							if (mainBlock == null)
								break;
						}
//						System.out.println("Block main " + mainBlock.getNumber() + " - " + mainBlock.getInnerHash() + " fork " + forkBlock.getNumber() + " - " + forkBlock.getInnerHash());
					}
					while (mainBlock != forkBlock);
					extra = "FORK";
					if (mainBlock == forkBlock)
					{
						extra2 = "\n\tforked at block " + mainBlock.getNumber() + " at " + getReadableTime(mainBlock.getTime() * 1000) + "\n";
						extra2 += "\tinto block " + overMainBlock.getInnerHash() + " at " + getReadableTime(overMainBlock.getTime() * 1000) + " generated by " + overMainBlock.getIssuer().getName() + " (MAIN)\n";
						extra2 += "\t and block " + overForkBlock.getInnerHash() + " at " + getReadableTime(overForkBlock.getTime() * 1000) + " generated by " + overForkBlock.getIssuer().getName() + " (FORK)";
					}
					else
						extra2 = "\n\t(could not retrieve forking info)";
				}
				extra += ", " + membersOnBranch.size() + " members (" + (int)((100.0 * membersOnBranch.size()) / mWorld.getAllMembers().size()) + "%)";
				if (nbMembers > 0)
					extra += ", " + nbMembers + " member peers";
				if (nbMirrors > 0)
					extra += ", " + nbMirrors + " mirror peers";
				if (lateMembers > 0)
					extra += ", " + lateMembers + " LATE member peers";
				if (lateMirrors > 0)
					extra += ", " + lateMirrors + " LATE mirror peers";
				String message = "Hash " + mWorld.getBlockFromHash(head).getInnerHash() + " " + extra + extra2;
				System.out.println(message);
			}

			// Compute overall network stability
			Color trayColor = Color.DARK_GRAY;
			if (totalMembers > 0)
			{
				// Consider that a forked member is counting double
				double forkStability = Math.max(0.0, 100.0 - 100.0 * ((1.0 * (allForkedMembers * 2 + allForkedMirrors)) / (totalMembers + totalMirrors)));
				// Late EPs, a mirror EP counts half
				double lateStability = (totalMembers + totalMirrors - allForkedMembers - allForkedMirrors == 0) ? 0 : 100.0 - (100.0 * (allLateMembers + 1.0 * allLateMirrors / 2)) / (totalMembers + totalMirrors - allForkedMembers - allForkedMirrors);
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
			systemSignal.health(trayColor);
			if ((currentForks >= 0) && (newNbForks > currentForks))
				systemSignal.displayWarning("NEW FORK", "Duniter network FORKED!");
			currentForks = newNbForks;
			System.out.println("Number of forks: " + currentForks);
			System.out.println("Current number of threads: " + ManagementFactory.getThreadMXBean().getThreadCount());
			System.out.println("--------------------------------------------------------------------------------------------------------------------------------------------------------------------");
			Thread.sleep(30000);
		}
	}

	private void findHeads(final SortedSet<String> pSortedHashes, Map<String, SortedMap<Node, Node>> pHash2Nodes, Set<String> pHeadsFound, Map<String, Set<String>> pHead2hashes)
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
					current = fetchPreviousBlock(current, head, pHash2Nodes);
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

	private Block fetchPreviousBlock(Block pBlock, String pHeadHash, Map<String, SortedMap<Node, Node>> pHash2Nodes)
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

	public Block fetchBlockFromEP(long pNumber, EP pEP)
	{
		Map<String, String> receivedURL2EP;
		try
		{
			receivedURL2EP = fetchJSonResponses(pEP, pNumber == -1 ? "/blockchain/current" : "/blockchain/block/" + pNumber, true);
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

	private Block fetchBlock(String pHash, long pNumber, SortedMap<Node,Node> pNodes)
	{
		for (Node node : pNodes.keySet())
		{
			EP ep = node.getEP();
			Block found = fetchBlockFromEP(pNumber, ep);
			if ((found != null) && found.getHash().equals(pHash))
			// Great, we found the EP with the correct hash, return it
				return found;
			// else whoops, this is another hash, maybe that EP is not on the same chain anymore, just go on with the search
		}
		return null;
	}

	public static void main(String[] args) throws IOException, ParseException, InterruptedException
	{
		final ExploreNodes exploreNodes = new ExploreNodes();
		if (args.length >= 1)
		{
			final String rootEP = args[0];
			System.out.println("Exploring from " + rootEP);
			exploreNodes.explore(rootEP);
		}
		else
			exploreNodes.explore("https://g1.duniter.org:443");
	}

	private static String getReadableTime(long pCurrentTimeMillis)
	{
		return new SimpleDateFormat("YYYY-MM-dd HH:mm:ss").format(new Date(pCurrentTimeMillis));
	}

	private void showEPsForHash(Map<String, SortedMap<Node, Node>> pHash2Nodes, String pHash, final boolean pShowEPInfos)
	{
		if (pHash2Nodes.containsKey(pHash))
		{
			System.out.println("\t" + normalize("Member/PK", 15, true) + " " + normalize("Vers.", 6, true) + " " + normalize("Latency", 8, true) + " " + normalize("Pool ID/Mem/Trans", 14, true));
			for (Node node : pHash2Nodes.get(pHash).keySet())
			{
				StringBuilder epInfo = new StringBuilder();
				for (EP ep : node.getEPs())
				{
					if (epInfo.length() > 0)
						epInfo.append(", ");
					epInfo.append(formatEPInfo(ep, ep.getURL())).append(" (").append(ep.getKnownPeers().size()).append(" peers, ").append(ep.getSiblings().size()).append(" siblings, " + ep.getUpPercent() + "% up)");
				}
				if (pShowEPInfos)
				{
					EP ep = node.getEP();
					String memberInfo = ep.getPubKey();
					if (ep.getMember() != null)
						memberInfo = ep.getMember().getName();
					System.out.println("\t" + normalize(memberInfo, 15, true) + " " + normalize(ep.getVersion(), 6, true) + " " + normalize("" + ep.getAvgResponseTime() + "ms", 8, false) + " " + normalize(String.valueOf(ep.getFreeIdentities()), 4, false) + " " + normalize(String.valueOf(ep.getFreeMemberships()), 4, false) + " " + normalize(String.valueOf(ep.getFreeTransactions()), 3, false) + " " + epInfo.toString());
				}
				else
					System.out.println("\t" + epInfo.toString());
			}
		}
	}

	private String formatEPInfo(EP pEP, String pEndPoint)
	{
		String formatted = pEndPoint;
		if (pEP.isCertificateError())
			formatted += "!";
		if (pEP.getError() != null)
			formatted += " ERR";
		else
		{
			double stability = pEP.getUpPercent();
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
