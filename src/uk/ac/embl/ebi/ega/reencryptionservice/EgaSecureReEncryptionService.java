/*
 * Copyright 2014 EMBL-EBI.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package uk.ac.embl.ebi.ega.reencryptionservice;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.Channel;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslProvider;
import io.netty.handler.ssl.util.SelfSignedCertificate;
import io.netty.handler.traffic.GlobalTrafficShapingHandler;
import io.netty.util.concurrent.DefaultEventExecutorGroup;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.management.ManagementFactory;
import java.net.URL;
import java.net.URLConnection;
import java.security.Security;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Set;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.management.Attribute;
import javax.management.AttributeList;
import javax.management.InstanceNotFoundException;
import javax.management.MBeanServer;
import javax.management.MalformedObjectNameException;
import javax.management.ObjectName;
import javax.management.ReflectionException;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.apache.commons.cli.BasicParser;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;
import uk.ac.embl.ebi.ega.reencryptionservice.endpoints.DownloadService;
import uk.ac.embl.ebi.ega.reencryptionservice.endpoints.FileService;
import uk.ac.embl.ebi.ega.reencryptionservice.endpoints.ResultService;
import uk.ac.embl.ebi.ega.reencryptionservice.endpoints.Service;
import uk.ac.embl.ebi.ega.reencryptionservice.endpoints.StatService;
import uk.ac.embl.ebi.ega.reencryptionservice.utils.Dailylog;
import uk.ac.embl.ebi.ega.reencryptionservice.utils.MyCacheEntry;
import uk.ac.embl.ebi.ega.reencryptionservice.utils.MyCompletedCacheEntry;
import uk.ac.embl.ebi.ega.reencryptionservice.utils.MyTimerTask;
import us.monoid.json.JSONArray;
import us.monoid.json.JSONException;
import us.monoid.json.JSONObject;
import us.monoid.web.BinaryResource;
import us.monoid.web.JSONResource;
import us.monoid.web.Resty;
import static us.monoid.web.Resty.content;
import static us.monoid.web.Resty.data;
import static us.monoid.web.Resty.form;

public class EgaSecureReEncryptionService {

    static boolean SSL = false;
    static int port = 9124;
    static int cpu_cores = 0;
    static int buffer = 16384;

    private static boolean testMode = false;
    public static boolean verbose = false;

    private static Dailylog dailylog;

    // Encryption/Decryption Keys
    private static HashMap<String, String[]> keys = new HashMap<>(); // Tag->Key Location
    private static HashMap<String, PGPPublicKey> gpgpublickeys = new HashMap<>(); // For mirroring
    
    // Runtime Cache - holds download resources (i.e. previously requested files)
    private static Cache<String,MyCacheEntry> theCache;
    private static Cache<String,MyCompletedCacheEntry> theCompletedCache;
    private static Timer theTimer;
    
    // Shutdown process: Wait until current operations complete
    public static volatile boolean keepRunning = true;
    
    // Shutdown hook
    static volatile int responseCount;
    
    // Executors
    private final DefaultEventExecutorGroup l, s;
    private final ScheduledExecutorService executor;
    private final GlobalTrafficShapingHandler globalTrafficShapingHandler;
    
    public EgaSecureReEncryptionService(int port, int cores) {
        EgaSecureReEncryptionService.port = port;
        EgaSecureReEncryptionService.cpu_cores = cores * 4; // Set 4 times as many connections as cores
        EgaSecureReEncryptionService.theCache = CacheBuilder.newBuilder()
                    .maximumSize(500)
                    .expireAfterWrite(25, TimeUnit.MINUTES)
                    .build();
        EgaSecureReEncryptionService.theCompletedCache = CacheBuilder.newBuilder()
                    .maximumSize(500)
                    .expireAfterWrite(25, TimeUnit.MINUTES)
                    .build();
        
        TimerTask timerTask = new MyTimerTask();
        theTimer = new Timer(true);
        theTimer.scheduleAtFixedRate(timerTask, 900000, 900000);
        
        // Executors
        // Executors
        this.l = new DefaultEventExecutorGroup(cores * 4);
        this.s = new DefaultEventExecutorGroup(cores);
        
        // Traffic Shaping Handler already created
        this.executor = Executors.newScheduledThreadPool(cores * 4);
        this.globalTrafficShapingHandler = new GlobalTrafficShapingHandler(executor, cores);
        //this.globalTrafficShapingHandler.trafficCounter().configure(15); // ??
    }
    
    public void run(HashMap<String, Service> mappings) throws Exception {
        // Configure SSL.
        final SslContext sslCtx;
        if (SSL) {
            SelfSignedCertificate ssc = new SelfSignedCertificate();
            sslCtx = SslContext.newServerContext(SslProvider.JDK, ssc.certificate(), ssc.privateKey());
        } else {
            sslCtx = null;
        }
        
        EventLoopGroup bossGroup = new NioEventLoopGroup();
        EventLoopGroup workerGroup = new NioEventLoopGroup(EgaSecureReEncryptionService.cpu_cores);
        try {
            ServerBootstrap b = new ServerBootstrap();
            b.group(bossGroup, workerGroup)
             .channel(NioServerSocketChannel.class)
             //.handler(new LoggingHandler(LogLevel.INFO))
             .childHandler(new EgaSecureReEncryptionServiceInitializer(sslCtx, mappings, this.l, this.s, this.globalTrafficShapingHandler, this));

            Channel ch = b.bind(port).sync().channel();

            System.err.println("Open your web browser and navigate to " +
                    (SSL? "https" : "http") + "://127.0.0.1:" + port + '/');

            if (testMode)
                testMe();
            
            ch.closeFuture().sync();
        } finally {
            bossGroup.shutdownGracefully();
            workerGroup.shutdownGracefully();
        }
        
    }

    // GET - Traffic Information
    public String getTransferString() {
        return this.globalTrafficShapingHandler.trafficCounter().toString();
    }
    public JSONObject getTransfer() {
        JSONObject traffic = new JSONObject();
        
        try {
            traffic.put("checkInterval", this.globalTrafficShapingHandler.trafficCounter().checkInterval());

            // Add more...
            
        } catch (JSONException ex) {;}
        
        return traffic;
    }
    
    /**
     * @param args the command line arguments
     * 
     * Parameters: port number (default 9124)
     *      -l path : location of the config file (default: "./../headers")
     *      -f file : config file name (default "DatabaseEcosystem.xml")
     *      -p port : server port (default 9124)
     */
    public static void main(String[] args) {
        String path = "./../headers/";
        String filename = "DecryptionEcosystem.xml";
        String p = "9124"; int pi = 9124;

        final Thread mainThread = Thread.currentThread();
        Runtime.getRuntime().addShutdownHook(new Thread() {
            @Override
            public void run() {
                System.out.println("Shutdown Initiated");
                
                keepRunning = false;
                long start = System.currentTimeMillis();
                try {
//                    mainThread.join();                    
                    long delta = System.currentTimeMillis();
                    while (EgaSecureReEncryptionService.responseCount > 0  && 
                            (delta-start < 82800000) ) {
                        Thread.sleep(1000);
                        delta = System.currentTimeMillis();
                    }
                } catch (InterruptedException ex) {;}

                System.out.println("Shutdown!!");
            }
        });

        int cores = Runtime.getRuntime().availableProcessors();
        
        Options options = new Options();

        options.addOption("l", true, "config file path");
        options.addOption("f", true, "config file filename");
        options.addOption("o", true, "gpg organization");
        options.addOption("p", true, "port");
        options.addOption("t", false, "testMe");
        options.addOption("c", true, "cpus");
        options.addOption("b", true, "buffer");
        options.addOption("v", false, "verbose");
        
        CommandLineParser parser = new BasicParser();
        try {        
            CommandLine cmd = parser.parse( options, args);
            
            if (cmd.hasOption("l"))
                path = cmd.getOptionValue("l");
            if (cmd.hasOption("f"))
                filename = cmd.getOptionValue("f");
            if (cmd.hasOption("p"))
                p = cmd.getOptionValue("p");
            if (cmd.hasOption("t")) 
                EgaSecureReEncryptionService.testMode = true;
            if (cmd.hasOption("c"))
                cores = Integer.parseInt(cmd.getOptionValue("c"));
            if (cmd.hasOption("b"))
                buffer = Integer.parseInt(cmd.getOptionValue("b"));
            if (cmd.hasOption("v"))
                verbose = true;
            
            pi = Integer.parseInt(p);
        } catch (ParseException ex) {
            System.out.println("Unrecognized Parameter. Use '-l'  '-f'  '-p'  '-t' '-c' '-v', '-b'.");
            Logger.getLogger(EgaSecureReEncryptionService.class.getName()).log(Level.SEVERE, null, ex);
        }
 
        // Set up Gpg Decryption information
        File gpgxml = new File(path + filename);
        setupKeys(gpgxml); // Cache paths, put some keys into server memory
        
        // Add Service Endpoints
        FileService fileService = new FileService();
        DownloadService downloadService = new DownloadService();
        ResultService resultService = new ResultService();
        StatService statService = new StatService();
        
        HashMap<String, Service> mappings = new HashMap<>();
        mappings.put("/files", fileService); // POST requests for re-encrypted streams (<-ID)
        mappings.put("/downloads", downloadService); // GET access requested sreams (by ID)
        mappings.put("/results", resultService); // GET stats of completed downloads
        mappings.put("/stats", statService);
        
        // Set up Log File
        EgaSecureReEncryptionService.dailylog = new Dailylog("reencryption");

        // Starting the Service (on 'port'!
        try {
            new EgaSecureReEncryptionService(pi, cores).run(mappings);
        } catch (Exception ex) {
            Logger.getLogger(EgaSecureReEncryptionService.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    // -------------------------------------------------------------------------
    // -------------------------------------------------------------------------
    private static void setupKeys(File gpgxml) {
        HashMap<String, ArrayList<String>> gpgconfig = readGpgXML(gpgxml);
        EgaSecureReEncryptionService.keys = new HashMap<>();

        Set<String> keySet = gpgconfig.keySet();
        Iterator<String> iter = keySet.iterator();
        while (iter.hasNext()) {
            String tag = iter.next(); // "AES" or "SymmetricGPG" or "PrivateGPG_{org}" or "PublicGPG_{org}"
            String[] vals = gpgconfig.get(tag).toArray(new String[gpgconfig.get(tag).size()]);
            EgaSecureReEncryptionService.keys.put(tag, vals);
            
            if (tag.toLowerCase().startsWith("publicgpg_")) {
                String organization = tag.substring(tag.indexOf('_')+1).trim();
                
                try { // Attempt to read the key, and put it in hash table
                    PGPPublicKey key = getKey(organization, vals); // vals[0] = path, [1][2] n/a
                    EgaSecureReEncryptionService.gpgpublickeys.put(organization, key);
                    EgaSecureReEncryptionService.gpgpublickeys.put(tag, key); // "backup"
                } catch (IOException ex) {
                    Logger.getLogger(EgaSecureReEncryptionService.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        }        
    }
    
    public static HashMap<String, ArrayList<String>> readGpgXML(File xmlFile) {
        HashMap<String, ArrayList<String>> resources_temp = new HashMap<>();
        
        DocumentBuilderFactory docBuilderFactory = DocumentBuilderFactory.newInstance();
        try {
            DocumentBuilder docBuilder = docBuilderFactory.newDocumentBuilder();            
            Document doc = docBuilder.parse (xmlFile);
            doc.getDocumentElement ().normalize ();
            
            // All servers in the XML file
            NodeList listOfKeys = doc.getElementsByTagName("Key");
            
            for(int s=0; s<listOfKeys.getLength() ; s++){
                Node nNode = listOfKeys.item(s);
                
                if (nNode.getNodeType() == Node.ELEMENT_NODE) {
                    Element eElement = (Element) nNode;
                    
                    String type = eElement.getElementsByTagName("Type").item(0).getTextContent();
                    
                    // Add server type to local HashMap, if not already present
                    if (!resources_temp.containsKey(type))
                        resources_temp.put(type, new ArrayList<>());
                    
                    // Add server to list for that type
                    String keyPath = eElement.getElementsByTagName("KeyPath").item(0).getTextContent();
                    String keyFile = eElement.getElementsByTagName("KeyFile").item(0).getTextContent();
                    String keyKey = eElement.getElementsByTagName("KeyKey").item(0).getTextContent();
                    
                    resources_temp.get(type).add(keyPath);
                    resources_temp.get(type).add(keyFile);
                    resources_temp.get(type).add(keyKey);
                }
            }
        } catch (ParserConfigurationException | SAXException | IOException ex) {
            Logger.getLogger(EgaSecureReEncryptionService.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        return resources_temp;
    }
    
    // -------------------------------------------------------------------------
    // -------------------------------------------------------------------------
    public static void log(String text) {
        EgaSecureReEncryptionService.dailylog.log(text);
    }

    // -------------------------------------------------------------------------
    public static boolean isTest() {
        return testMode;
    }
    
    public static void incCount() { // Test: keep track of number of current requests in process
        EgaSecureReEncryptionService.responseCount++;
    }
    
    public static void decCount() {
        if (EgaSecureReEncryptionService.responseCount>0)
            EgaSecureReEncryptionService.responseCount--;
    }
    
    /*
     * *************************************************************************
     * Helper Functions to perform Database Queries and set up Cache Structures
     * *************************************************************************
     */
    
    public static MyCacheEntry getEntry(String key) {
        return EgaSecureReEncryptionService.theCache.getIfPresent(key);
    }
    
    public static boolean hasEntry(String key) {
        return (EgaSecureReEncryptionService.theCache.getIfPresent(key) != null);
    }
    
    public static void putEntry(String key, MyCacheEntry mce) {
        EgaSecureReEncryptionService.theCache.put(key, mce);
    }
    
    public static void removeEntry(String key) {
        EgaSecureReEncryptionService.theCache.invalidate(key);
        EgaSecureReEncryptionService.theCache.cleanUp();
    }

    public static MyCompletedCacheEntry getCompletedEntry(String key) {
        return EgaSecureReEncryptionService.theCompletedCache.getIfPresent(key);
    }
    
    public static boolean hasCompletedEntry(String key) {
        return (EgaSecureReEncryptionService.theCompletedCache.getIfPresent(key) != null);
    }
    
    public static void putCompletedEntry(String key, MyCompletedCacheEntry mce) {
        EgaSecureReEncryptionService.theCompletedCache.put(key, mce);
    }

    public static void removeCompletedEntry(String key) {
        EgaSecureReEncryptionService.theCompletedCache.invalidate(key);
        EgaSecureReEncryptionService.theCompletedCache.cleanUp();
    }
    
    public static void cleanCache() {
        EgaSecureReEncryptionService.theCompletedCache.cleanUp();
        EgaSecureReEncryptionService.theCache.cleanUp();
    }
    // -------------------------------------------------------------------------

    public static String[] getKeyPath(String tag) {
        return EgaSecureReEncryptionService.keys.get(tag);
    }
    
    // -------------------------------------------------------------------------

    public static PGPPublicKey getKey(String organization, String[] vals) throws IOException {
        PGPPublicKey pgKey = null;
        Security.addProvider(new BouncyCastleProvider());
        
        // Paths (file containing the key - no paswords for public GPG Keys)
        String path = vals[0];
        InputStream in = new FileInputStream(path);
        
        if (organization.toLowerCase().contains("ebi")) { // "pubring.gpg"
            try {
                pgKey = readPublicKey(in);
            } catch (IOException | PGPException ex) {;}
        } else if (organization.toLowerCase().contains("crg")) { // "/exported.gpg"
            try {
                pgKey = getEncryptionKey(getKeyring(in));
            } catch (IOException ex) {;}
        }
        in.close();

        return pgKey;
    }
    private static PGPPublicKey readPublicKey(InputStream in)
            throws IOException, PGPException {
        in = PGPUtil.getDecoderStream(in);

        PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(in);

        //
        // we just loop through the collection till we find a key suitable for encryption, in the real
        // world you would probably want to be a bit smarter about this.
        //
        PGPPublicKey key = null;

        //
        // iterate through the key rings.
        //
        Iterator rIt = pgpPub.getKeyRings();

        while (key == null && rIt.hasNext()) {
            PGPPublicKeyRing kRing = (PGPPublicKeyRing) rIt.next();
            Iterator kIt = kRing.getPublicKeys();
            boolean encryptionKeyFound = false;

            while (key == null && kIt.hasNext()) {
                PGPPublicKey k = (PGPPublicKey) kIt.next();

                if (k.isEncryptionKey()) {
                    key = k;
                }
            }
        }

        if (key == null) {
            throw new IllegalArgumentException("Can't find encryption key in key ring.");
        }

        return key;
    }
    
    // -------------------------------------------------------------------------
    // -------------------------------------------------------------------------
    public static double getSystemCpuLoad() throws MalformedObjectNameException, ReflectionException, InstanceNotFoundException {

        MBeanServer mbs    = ManagementFactory.getPlatformMBeanServer();
        ObjectName name    = ObjectName.getInstance("java.lang:type=OperatingSystem");
        AttributeList list = mbs.getAttributes(name, new String[]{ "SystemCpuLoad" });

        if (list.isEmpty())     return Double.NaN;

        Attribute att = (Attribute)list.get(0);
        Double value  = (Double)att.getValue();

        if (value == -1.0)      return Double.NaN;  // usually takes a couple of seconds before we get real values

        return ((int)(value * 1000) / 10.0);        // returns a percentage value with 1 decimal point precision
    }    
    
    
    // -------------------------------------------------------------------------
    // -------------------------------------------------------------------------
    private static PGPPublicKeyRing getKeyring(InputStream keyBlockStream) throws IOException {
        // PGPUtil.getDecoderStream() will detect ASCII-armor automatically and decode it,
        // the PGPObject factory then knows how to read all the data in the encoded stream
        PGPObjectFactory factory = new PGPObjectFactory(PGPUtil.getDecoderStream(keyBlockStream));

        // these files should really just have one object in them,
        // and that object should be a PGPPublicKeyRing.
        Object o = factory.nextObject();
        if (o instanceof PGPPublicKeyRing) {
            return (PGPPublicKeyRing)o;
        }
        throw new IllegalArgumentException("Input text does not contain a PGP Public Key");
    }
    private static PGPPublicKey getEncryptionKey(PGPPublicKeyRing keyRing) {
        if (keyRing == null)
            return null;

        // iterate over the keys on the ring, look for one
        // which is suitable for encryption.
        Iterator keys = keyRing.getPublicKeys();
        PGPPublicKey key = null;
        while (keys.hasNext()) {
            key = (PGPPublicKey)keys.next();
            if (key.isEncryptionKey()) {
                return key;
            }
        }
        return null;
    }    
    
    // -------------------------------------------------------------------------
    // -------------------------------------------------------------------------
    // -------------------------------------------------------------------------
    // -------------------------------------------------------------------------
    // -------------------------------------------------------------------------
    // -------------------------------------------------------------------------
    // Self-Test of functionality provided in this server
    private void testMe() throws Exception {
        // Wait until server has started up
        Thread.sleep(2000);

        Resty r = new Resty();
        
        // Test POST: Post a resource for a real file, and for a 1GB test stream
        String file_resource, test_resource;

        {
            System.out.println("POST Test File");
            JSONObject json = new JSONObject();
            
            // Not populated - in its current state not to be used for tests!
            
            json.put("filepath", ".."); // File - full path or relative path for Cleversafe 
            json.put("pathtype", ".."); // Type of Path: "Cleversafe" or "Absolute" or "Virtual"
            json.put("originformat", ".."); // Origin format: "AES256", "AES128", "SymmetricGPG", "PublicGPG", "Plain"
            json.put("destinationformat", ".."); // Destination format: "AES256", "AES128", "SymmetricGPG", "PublicGPG", "Plain"
            json.put("originkey", ""); // Decryption Key - blank in most cases; determined by format
            json.put("destinationkey", ".."); // (Re)Encryption Key (user supplied, or blank if PublicGPG/Plain is chosen)

System.out.println("URL " + "http://localhost:"+EgaSecureReEncryptionService.port+"/ega/rest/res/v1/files");
            JSONResource json1 = r.json("http://localhost:"+EgaSecureReEncryptionService.port+"/ega/rest/res/v1/files", 
                    form( data("filerequest", content(json)) ));

            // This should have placed a request in the in-memory cache
            JSONObject jobj = (JSONObject) json1.get("response");
            JSONArray jsonarr = (JSONArray)jobj.get("result");
            for (int i=0; i<jsonarr.length(); i++) {
                System.out.println("  " + i + " : " + jsonarr.getString(i));
            }

            file_resource = jsonarr.getString(0); // File Resource
            MyCacheEntry mce = theCache.getIfPresent(file_resource);
            System.out.println("File Cache Resource Entry: ");
            System.out.println(" --> " + mce.getFileUrl());
            System.out.println(" --> " + mce.getPathtype());
            System.out.println(" --> " + mce.getOrigin());
            System.out.println(" --> " + mce.getDestination());
            System.out.println(" --> " + mce.getOriginKey());
            System.out.println(" --> " + mce.getDestinationKey());
            System.out.println();
        }

        {
            // Not Implemented
            
            System.out.println("POST Test StreamTest");
            JSONObject json = new JSONObject();
            json.put("filepath", "EGATEST_1073725440"); // File - full path or relative path for Cleversafe 
            json.put("pathtype", "Virtual"); // Type of Path: "Cleversafe" or "Absolute" or "Virtual"
            json.put("originformat", "Plain"); // Origin format: "AES256", "AES128", "SymmetricGPG", "PublicGPG", "Plain"
            json.put("destinationformat", "Plain"); // Destination format: "AES256", "AES128", "SymmetricGPG", "PublicGPG", "Plain"
            json.put("originkey", ""); // Decryption Key - blank in most cases; determined by format
            json.put("destinationkey", ""); // (Re)Encryption Key (user supplied, or blank if PublicGPG/Plain is chosen)

            JSONResource json1 = r.json("http://localhost:"+EgaSecureReEncryptionService.port+"/ega/rest/res/v1/files", 
                    form( data("filerequest", content(json)) ));

            // This should have placed a request in the in-memory cache
            JSONObject jobj = (JSONObject) json1.get("response");
            JSONArray jsonarr = (JSONArray)jobj.get("result");
            for (int i=0; i<jsonarr.length(); i++) {
                System.out.println("  " + i + " : " + jsonarr.getString(i));
            }

            test_resource = jsonarr.getString(0); // File Resource
            //MyCacheEntry mce = theCache.get(test_resource);
            MyCacheEntry mce = theCache.getIfPresent(test_resource);
            System.out.println("TestStream Cache Resource Entry: ");
            System.out.println(" --> " + mce.getFileUrl());
            System.out.println(" --> " + mce.getPathtype());
            System.out.println(" --> " + mce.getOrigin());
            System.out.println(" --> " + mce.getDestination());
            System.out.println(" --> " + mce.getOriginKey());
            System.out.println(" --> " + mce.getDestinationKey());
        }
        System.out.println();
        
      
        // Now try to access these resources for download!
        {
            System.out.println("Download Test FileTest");
            String url = "http://localhost:"+EgaSecureReEncryptionService.port+"/ega/rest/res/v1/downloads/" + file_resource;
            System.out.println("File URL = " + url);

            // Download the resource (to Null)
            long time = System.currentTimeMillis();
            BinaryResource bytes = r.bytes(url);
            InputStream in = bytes.stream();
            long cnt = 0, tot = 0;
            byte[] buffer = new byte[64000];
            cnt = in.read(buffer);
            while (cnt > 0) {
                tot += cnt;
                cnt = in.read(buffer);
            }
            time = System.currentTimeMillis() - time;
            System.out.println("tot="+tot);
            double rate = (tot * 1.0 / 1024.0 / 1024.0) / (time * 1.0 / 1000.0);
            System.out.println("tot="+tot+" /  Rate Resty (MB/s): "+rate);

            System.out.println("---------------------");
            Thread.sleep(5000);
            System.out.println("---------------------");
            
            // Finished download stats
            r = new Resty();
            System.out.println("Testing result of download");
            String url_ = "http://localhost:"+EgaSecureReEncryptionService.port+"/ega/rest/res/v1/results/" + file_resource;
            System.out.println("url = " + url_);
            JSONResource json3 = r.json(url_);
            JSONObject jobj = (JSONObject) json3.get("response");
            JSONArray jsonarr = (JSONArray)jobj.get("result");
            System.out.println("Size: " + jsonarr.length());
            for (int i=0; i<jsonarr.length(); i++) {
                System.out.println("  " + i + " : " + jsonarr.getString(i));
            }
            System.out.println();
        }

        {
            System.out.println("Download Test StreamTest");
            String url = "http://localhost:"+EgaSecureReEncryptionService.port+"/ega/rest/res/v1/downloads/" + test_resource;
            System.out.println("Test URL = " + url);

            // Download the resource (to Null)
            long time = System.currentTimeMillis();
            //HttpURLConnection urlConn = (HttpURLConnection) (new URL(url)).openConnection();//connect
            //InputStream in = urlConn.getInputStream();
            BinaryResource bytes = r.bytes(url);
            InputStream in = bytes.stream();
            
            long cnt = 0, tot = 0;
            byte[] buffer = new byte[65536];
            cnt = in.read(buffer);
            try {
                while (cnt > -1) {
                    tot += cnt;
                    cnt = in.read(buffer);
                }
            } catch (Throwable t) {
                System.out.println(t.getLocalizedMessage());
            }
            time = System.currentTimeMillis() - time;
            System.out.println("tot="+tot);
            double rate = (tot * 1.0 / 1024.0 / 1024.0) / (time * 1.0 / 1000.0);
            System.out.println("tot="+tot+" /  Rate Resty (MB/s): "+rate);

            // Finished download stats
            System.out.println("Testing result of download");
            url = "http://localhost:"+EgaSecureReEncryptionService.port+"/ega/rest/res/v1/results/" + test_resource;
            JSONResource json3 = r.json(url);
            JSONObject jobj = (JSONObject) json3.get("response");
            JSONArray jsonarr = (JSONArray)jobj.get("result");
            for (int i=0; i<jsonarr.length(); i++) {
                System.out.println("  " + i + " : " + jsonarr.getString(i));
            }
            System.out.println();
        }
      
        //System.out.println("Java HTTP Stream Test");
        //time = System.currentTimeMillis();
        //downloadFromUrl(new URL(url), "test1.cip");
        //time = System.currentTimeMillis()-time;
        //File x = new File("test1.cip");
        //long sent = x.length();
        //rate = (sent * 1.0 / 1024.0 / 1024.0) / (time * 1.0 / 1000.0); // MB/s
        //System.out.println("Rate HTTP (MB/s: " + rate);
        
        
        System.out.println("---------------------");
        Thread.sleep(5000);
        System.out.println("---------------------");
        
        // Test 4: Query the server load
        String query = "http://localhost:" + EgaSecureReEncryptionService.port + "/ega/rest/res/v1/Stats/load";
        JSONResource json2 = r.json(query);
        JSONObject jobj = (JSONObject) json2.get("response");
        JSONArray jsonarr = (JSONArray)jobj.get("result");
        System.out.println("Loads (should be 1): " + jsonarr.length());
        for (int i=0; i<jsonarr.length(); i++) {
            String request = jsonarr.getString(i);
            System.out.println("Load "+i+": " + request);
        }
        
        System.out.println();
        
        System.exit(100);
    }
    void downloadFromUrl(URL url, String localFilename) throws IOException {
        InputStream is = null;
        FileOutputStream fos = null;

        try {
            URLConnection urlConn = url.openConnection();//connect

            is = urlConn.getInputStream();               //get connection inputstream
            fos = new FileOutputStream(localFilename);   //open outputstream to local file

            byte[] buffer = new byte[4096];              //declare 4KB buffer
            int len;

            //while we have availble data, continue downloading and storing to local file
            while ((len = is.read(buffer)) > 0) {  
                fos.write(buffer, 0, len);
            }
        } finally {
            try {
                if (is != null) {
                    is.close();
                }
            } finally {
                if (fos != null) {
                    fos.close();
                }
            }
        }
    }
}
