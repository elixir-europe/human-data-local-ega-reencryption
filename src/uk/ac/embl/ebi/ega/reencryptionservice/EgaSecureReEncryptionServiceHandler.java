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

/*
 * This class provides responses to REST URLs
 * This service will run ONLY inside the EGA Vault and is not available anywhere else
 * For this reason it uses plain http and no user account information
 *
 * URL Prefix for his server is: /ega/rest/reencryption/v1
 *
 * Resources are:
 *
 *      /downloads/{ticket} -- download a ticket (returns binary stream)
 *
 *      /results/{ticket} -- gets the MD5 and size of the data sent, after download
 *
 *      [POST] /files/ {"downloadrequest": user, file id, file path, reencryption key, format} 
 *      [POST] /files/ {"filerequest": file path, reencryption key, origin format, destination format} 
 * 
 *      /Stats/load                         Server Load (total server CPU 0-100)
 */

package uk.ac.embl.ebi.ega.reencryptionservice;

import uk.ac.embl.ebi.ega.reencryptionservice.utils.MyGPGInputStream;
import uk.ac.embl.ebi.ega.reencryptionservice.utils.MyInputStream;
import com.google.common.io.CountingInputStream;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelProgressiveFuture;
import io.netty.channel.ChannelProgressiveFutureListener;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.DefaultHttpResponse;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpChunkedInput;
import static io.netty.handler.codec.http.HttpHeaderNames.CACHE_CONTROL;
import static io.netty.handler.codec.http.HttpHeaderNames.CONNECTION;
import static io.netty.handler.codec.http.HttpHeaderNames.CONTENT_TYPE;
import static io.netty.handler.codec.http.HttpHeaderNames.DATE;
import static io.netty.handler.codec.http.HttpHeaderNames.EXPIRES;
import static io.netty.handler.codec.http.HttpHeaderNames.LAST_MODIFIED;
import io.netty.handler.codec.http.HttpHeaderUtil;
import io.netty.handler.codec.http.HttpHeaderValues;
import static io.netty.handler.codec.http.HttpMethod.GET;
import io.netty.handler.codec.http.HttpResponse;
import io.netty.handler.codec.http.HttpResponseStatus;
import static io.netty.handler.codec.http.HttpResponseStatus.BAD_REQUEST;
import static io.netty.handler.codec.http.HttpResponseStatus.INTERNAL_SERVER_ERROR;
import static io.netty.handler.codec.http.HttpResponseStatus.METHOD_NOT_ALLOWED;
import static io.netty.handler.codec.http.HttpResponseStatus.NOT_FOUND;
import static io.netty.handler.codec.http.HttpResponseStatus.OK;
import static io.netty.handler.codec.http.HttpResponseStatus.SEE_OTHER;
import static io.netty.handler.codec.http.HttpResponseStatus.SERVICE_UNAVAILABLE;
import static io.netty.handler.codec.http.HttpVersion.HTTP_1_1;
import io.netty.handler.codec.http.LastHttpContent;
import io.netty.handler.stream.ChunkedStream;
import io.netty.util.CharsetUtil;
import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.PushbackInputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.DigestInputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Locale;
import java.util.Map;
import java.util.Random;
import java.util.TimeZone;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import uk.ac.ebi.ega.cipher.GPGStream;
import uk.ac.embl.ebi.ega.reencryptionservice.endpoints.Service;
import uk.ac.embl.ebi.ega.reencryptionservice.utils.MyCacheEntry;
import uk.ac.embl.ebi.ega.reencryptionservice.utils.MyCompletedCacheEntry;
import uk.ac.embl.ebi.ega.reencryptionservice.utils.MyNewBackgroundInputStream;
import uk.ac.embl.ebi.ega.reencryptionservice.utils.MyPipelineUtils;
import uk.ac.embl.ebi.ega.reencryptionservice.utils.MyRandomInputStream;
import us.monoid.json.JSONException;
import us.monoid.json.JSONObject;
import us.monoid.json.XML;

/**
 *
 * This is unique/exclusive for each connection - place user interaction caches here
 */
public class EgaSecureReEncryptionServiceHandler extends SimpleChannelInboundHandler<FullHttpRequest> { // (1)

    public static final String HTTP_DATE_FORMAT = "EEE, dd MMM yyyy HH:mm:ss zzz";
    public static final String HTTP_DATE_GMT_TIMEZONE = "GMT";
    public static final int HTTP_CACHE_SECONDS = 60;
    
    public static final double load_ceiling = 100.0;

    // Handle session unique information
    private MessageDigest md, md_;
    private boolean SSL = false, active = true;
    private final HashMap<String, Service> endpointMappings;

    // Internally used variabled
    private InputStream ins = null, ins_re = null;
    private CountingInputStream c_in = null, c_out = null;
    private DigestInputStream dis_ins_re = null, dis_ins = null;
    private MyNewBackgroundInputStream in = null;
    private boolean inc = false;

    private String error_message = "";
    
    private String idk = "";
    
    private final EgaSecureReEncryptionService ref;

    // New Error Codes (TODO: Test)
    private static HttpResponseStatus REQUEST_ERROR = new HttpResponseStatus(580, "Error Getting Request Header");
    
    public EgaSecureReEncryptionServiceHandler(boolean SSL, HashMap<String, Service> mappings, EgaSecureReEncryptionService ref) throws NoSuchAlgorithmException {
        super();
        this.md = MessageDigest.getInstance("MD5");
        this.md_ = MessageDigest.getInstance("MD5");
        this.SSL = SSL;
        this.endpointMappings = mappings;
        
        this.ref = ref; // reference to server object - to have access to statistics
    }

    // *************************************************************************
    // *************************************************************************
    @Override
    public void messageReceived(ChannelHandlerContext ctx, FullHttpRequest request) throws Exception {
        if (ctx==null) return; if (request==null) return; // Don't even proceed in these cases!
        error_message = "";
        
        // Step 1: Get Header
        String get = request.headers().get("Accept").toString(); // Response Type

        // Step 2: Check Request
        HttpResponseStatus checkURL = MyPipelineUtils.checkURL(request);
        if (checkURL != OK) {
            error_message = "Request Verification Error.";
            sendError(ctx, checkURL, get);
            return;
        }
        
        // Step 3: Active for Binary Connections??
        if (!EgaSecureReEncryptionService.keepRunning && !get.contains("application/json")) {
            error_message = "Service shutting down.";
            sendError(ctx, SERVICE_UNAVAILABLE, get); // Service is shutting down
            return;
        }
        
        // Step 4: process the path (1) verify root and service (2) determine function & resource
        String path = MyPipelineUtils.sanitizedUserAction(request);
        ArrayList<String> id = new ArrayList<>();
        String function = MyPipelineUtils.processUserURL(path, id);
        
        // Step 5: Extract any parameters sent with request
        Map<String, String> parameters = MyPipelineUtils.getParameters(path);
        
        // Past "limiters" - increase count of active connections
        EgaSecureReEncryptionService.incCount(); inc = true;
        
        // Step 6: Split execution by function
        if (get.contains("application/json")) { // -----------------------------
            // Map function to endpoint, process request
            JSONObject json = null;
            if (this.endpointMappings.containsKey(function)) {
                json = this.endpointMappings.get(function).handle(id, parameters, request, this.ref); // parameters now contain form data
                if (json==null) {
                    error_message = "Processing the " + function + " function produced a null result!";
                    System.out.println(error_message);
                    sendError(ctx, INTERNAL_SERVER_ERROR, get); // If the URL Function is incorrect...
                    if (inc) {EgaSecureReEncryptionService.decCount(); inc = false;}
                    return;
                }
            } else {
                error_message = "Function " + function + " is not implemented!";
                System.out.println(error_message);
                sendError(ctx, NOT_FOUND, get); // If the URL Function is incorrect...
                if (inc) {EgaSecureReEncryptionService.decCount(); inc = false;}
                return;
            }
            
            // Step 4.1: Prepare a response - set content typt to the expected type
            FullHttpResponse response = new DefaultFullHttpResponse(HTTP_1_1, OK);
            StringBuilder buf = new StringBuilder();
            if (get.contains("application/json")) { // Format list of values as JSON
                response.headers().set(CONTENT_TYPE, "application/json");
                buf.append(json.toString());

            } else {
                error_message = "Header 'application/json' must be specified for text-based queries!";
                System.out.println(error_message);
                sendError(ctx, SEE_OTHER, get);
                if (inc) {EgaSecureReEncryptionService.decCount(); inc = false;}
                return;
            }

            // Step 4.2: Result has been obtained. Build response and send to requestor
            ByteBuf buffer = Unpooled.copiedBuffer(buf, CharsetUtil.UTF_8);
            response.content().writeBytes(buffer);
            ctx.writeAndFlush(response).addListener(ChannelFutureListener.CLOSE);

            // Cleanup
            buffer.release();
        
            if (inc) {EgaSecureReEncryptionService.decCount(); inc = false;}
            return;
        } // -------------------------------------------------------------------

        // ---------------------------------------------------------------------
        // ---------------------------------------------------------------------
        // ---------------------------------------------------------------------
        // ReEncryption / Binary Code Starts Here
        // ---------------------------------------------------------------------
        // ---------------------------------------------------------------------
        
        String id_ = (id.size()>0)?id.get(0):"";
        // If the code progresses here, it is a request for a data stream
        if (get.contains("application/octet-stream")) { // --------------
            if (request.method() != GET) { // Getting the download resource
                error_message = "Only the GET method is allowed!";
                System.out.println(error_message);
                sendError(ctx, METHOD_NOT_ALLOWED, get);
                if (inc) {EgaSecureReEncryptionService.decCount(); inc = false;}
                return;
            }
        } else { // If the request is not for a binary stream, exit
            error_message = "Header 'application/octet-stream' must be specified for binary queries!";
            System.out.println(error_message);
            sendError(ctx, SEE_OTHER, get);
            if (inc) {EgaSecureReEncryptionService.decCount(); inc = false;}
            return;
        }
        
        if (!function.equalsIgnoreCase("/downloads")) {
            error_message = "Only the '/downloads' function is allowed!";
            System.out.println(error_message);
            sendError(ctx, BAD_REQUEST, get);
            if (inc) {EgaSecureReEncryptionService.decCount(); inc = false;}
            return;
        }
        
        // Downloads only work if there is an entry in theCache (prior POST)
        // theCache access key is in 'id' -- check if it exists!
        MyCacheEntry downloadData = null;
        if (!EgaSecureReEncryptionService.hasEntry(id_)) {
            error_message = "The specified resource '" + id_ + "' can't be found. POST your request again before transferring!";
            System.out.println(error_message);
            sendError(ctx, NOT_FOUND, get); // resource not found
            if (inc) {EgaSecureReEncryptionService.decCount(); inc = false;}
            return;            
        } else  {
            downloadData = EgaSecureReEncryptionService.getEntry(id_);
        }
        String idKey = id_; // Key used to store completed file entry (it is the Resource ID)
        idk = idKey;

        // Get Input Stream based on POSTed data (origin: virtual, Cleversafe, path)
        this.c_in = getCountingInputStream(downloadData); // Unmodified source data stream, counting
        if (this.c_in==null) {
            error_message = "Error accessing the file '" + downloadData.getFileUrl() + "'!";
            System.out.println(error_message);
            sendError(ctx, NOT_FOUND, get); // file not found
            EgaSecureReEncryptionService.removeEntry(id_); // Resource no good - remove!
            EgaSecureReEncryptionService.log(error_message);
            if (inc) {EgaSecureReEncryptionService.decCount(); inc = false;}
            return;            
        }

        // Get Plain Input Stream, based on POSTed data (origin: AES256, AES128, SymmetricGPG , PublicGPG_EBI, PublicGPG_Sanger, Plain
        this.ins = getPlainInputStream(this.c_in, downloadData);
        if (downloadData.getOrigin().toLowerCase().startsWith("publicgpg")) {
            // Special case: data encrypted using the public key - get plain MD5 as well
            if (this.ins!=null) { 
                this.dis_ins = new DigestInputStream(this.ins, this.md_);
                this.ins = this.dis_ins; // TODO - TEST
            }
        }
        if (this.ins==null) {
            error_message = "File '" + downloadData.getFileUrl() + "' can be accessed, but there is an Error decrypting it. Using the correct mode or password?";
            System.out.println(error_message);
            sendError(ctx, INTERNAL_SERVER_ERROR); // file can't be decrypted
            EgaSecureReEncryptionService.removeEntry(id_); // Resource no good - remove!
            EgaSecureReEncryptionService.log(error_message);
            if (inc) {EgaSecureReEncryptionService.decCount(); inc = false;}
            return;            
        }
        
        // Get Re-Encrypting Output Stream, based on POSTed data (which is actually also an InputStream...)
        this.ins_re = getReEncryptingInputStream(this.ins, downloadData);
        if (this.ins_re==null) {
            error_message = "File '" + downloadData.getFileUrl() + "' can be accessed and decrypted, but there is an Error encrypting it!";
            System.out.println(error_message);
            sendError(ctx, INTERNAL_SERVER_ERROR); // file can't be re-encrypted
            EgaSecureReEncryptionService.removeEntry(id_); // Resource no good - remove!
            EgaSecureReEncryptionService.log(error_message);
            if (inc) {EgaSecureReEncryptionService.decCount(); inc = false;}
            return;            
        }
                 
        this.dis_ins_re = new DigestInputStream(this.ins_re, this.md); // MD5 of outgoing data stream
        if (this.dis_ins_re!=null) this.c_out = getCountingInputStream(this.dis_ins_re); // Counting outgoing data stream
        if (this.c_out!=null) this.in = new MyNewBackgroundInputStream(this.c_out); // Buffer/Read-Ahead on the Stream (separate thread)
        
        assert (this.in!=null);
        if (this.in==null) {
            error_message = "File '" + downloadData.getFileUrl() + "' can be accessed and re-encrypted. There is an Error producing the final data stream!";
            System.out.println(error_message);
            sendError(ctx, INTERNAL_SERVER_ERROR); // one of the remaining streams can't be created
            EgaSecureReEncryptionService.removeEntry(id_); // Resource no good - remove!
            EgaSecureReEncryptionService.log(error_message);
            if (inc) {EgaSecureReEncryptionService.decCount(); inc = false;}
            return;            
        }
        if (EgaSecureReEncryptionService.isTest()) System.out.println("Remaining Streams Created: " + (this.in != null));
        //ReadableByteChannel channel = Channels.newChannel(in); 
        
        // Step 7: Send stream in HTTP response
        long fileLength = downloadData.getSize();
        HttpResponse response = new DefaultHttpResponse(HTTP_1_1, OK);
        HttpHeaderUtil.setContentLength(response, fileLength);
        HttpHeaderUtil.setTransferEncodingChunked(response, true);
        setContentTypeHeaderBinary(response);
        //setDateAndCacheHeaders(response, testfile?downloadData.getFilePath()[0]:downloadData.getFilePath()[3]);
        setDateAndCacheHeaders(response, downloadData.getFileUrl());
        if (HttpHeaderUtil.isKeepAlive(request)) {
            response.headers().set(CONNECTION, HttpHeaderValues.KEEP_ALIVE);
        }

        // Write the initial line and the header. ------------------------------
        ctx.write(response);

        // Write the content. -------------------------------------------------- Writing the actual Data
        if (EgaSecureReEncryptionService.verbose)
            System.out.println("Send Started ----------------------");
        final long time = System.currentTimeMillis();
        ChannelFuture sendFileFuture;
        sendFileFuture =
                ctx.writeAndFlush(new HttpChunkedInput(new ChunkedStream(this.in, EgaSecureReEncryptionService.buffer)),
                        ctx.newProgressivePromise());       
        //        ctx.write(new HttpChunkedInput(new ChunkedStream(this.in, 16384)),
        //                ctx.newProgressivePromise());       
//        sendFileFuture =
//                ctx.write(new HttpChunkedInput(new ChunkedNioStream(channel, 16384)),
//                        ctx.newProgressivePromise());       

        sendFileFuture.addListener(new ChannelProgressiveFutureListener() {
            @Override
            public void operationProgressed(ChannelProgressiveFuture future, long progress, long total) {
                if (EgaSecureReEncryptionService.verbose && total < 0) { // total unknown
                    System.err.println(future.channel() + " Transfer progress: " + progress);
                    System.out.println("Read: " + c_in.getCount() + "\tSent: " + c_out.getCount());
                } else if (EgaSecureReEncryptionService.verbose) {
                    System.err.println(future.channel() + " Transfer progress: " + progress + " / " + total);
                    System.out.println("Read: " + c_in.getCount() + "\tSent: " + c_out.getCount());
                }
            }

            @Override
            public void operationComplete(ChannelProgressiveFuture future) {
                if (EgaSecureReEncryptionService.verbose)
                    System.out.println("COMPLETED --- (pre flush) ---- Read: " + c_in.getCount() + "\tSent: " + c_out.getCount());
                ctx.flush();
                if (EgaSecureReEncryptionService.verbose)
                    System.out.println("COMPLETED --- (post flush) ---- Read: " + c_in.getCount() + "\tSent: " + c_out.getCount());
                System.out.println(future.channel() + " Transfer complete.");
                long xfertime = System.currentTimeMillis()-time;

                long read = c_in==null?-1:c_in.getCount();
                assert (read==fileLength);
                long sent = c_out==null?-1:c_out.getCount();
                // Verify that 'read' bytes corresponds to size of file in storage
                EgaSecureReEncryptionService.log("Read: " + read + " Sent: " + sent);
                
                try { // Close streams in reverse order
                    if (in!=null) in.close();
                    if (c_out!=null) c_out.close();
                    if (dis_ins_re!=null) dis_ins_re.close();
                    if (ins_re!=null) ins_re.close();
                    if (dis_ins!=null) dis_ins.close();
                    if (ins!=null) ins.close();
                    if (c_in!=null) c_in.close();
                } catch (IOException ex) {
                    System.out.println("Stream close error: " + ex.getLocalizedMessage());
                }

                byte[] digest = md.digest();
                BigInteger bigInt = new BigInteger(1,digest);
                String hashtext = bigInt.toString(16), hashtext_ = "";
                while(hashtext.length() < 32 ){
                    hashtext = "0"+hashtext;
                }
                if (dis_ins!=null&&md_!=null) {
                    byte[] digest_ = md_.digest();
                    BigInteger bigInt_ = new BigInteger(1,digest_);
                    hashtext_ = bigInt_.toString(16);
                    while(hashtext_.length() < 32 ){
                        hashtext_ = "0"+hashtext_;
                    }
                }
                // Log file stuff...
                System.out.println("MD5 = " + hashtext);
                System.out.println(sent + "  " + read + "  " + fileLength);
                double rate = (sent * 1.0 / 1024.0 / 1024.0) / (xfertime * 1.0 / 1000.0); // MB/s
                System.out.println("Rate Server (MB/s:) " + rate);
                
                // Put data in completed-Cache (so that DS can verify download)
                String ip = "";
                try {
                    ip = parameters.get("ip");
                } catch (Throwable t) {;}
                MyCompletedCacheEntry mcce = new MyCompletedCacheEntry(hashtext, hashtext_, sent);
                EgaSecureReEncryptionService.putCompletedEntry(idKey, mcce);
                if (!EgaSecureReEncryptionService.hasEntry(idKey))
                    EgaSecureReEncryptionService.putCompletedEntry(idKey, mcce);
                if (!EgaSecureReEncryptionService.hasEntry(idKey))
                    System.out.println("Can't add completed cache entry for " + idKey);
                
                // Done!
                in = null;
                c_out = null;
                dis_ins_re = null;
                ins = null;
                dis_ins = null;
                c_in = null;
                //ctx.close();
                
                if (inc) {
                    EgaSecureReEncryptionService.decCount();
                    inc = false;
                }
            }
        });

        // Write the end marker
        ChannelFuture lastContentFuture = ctx.writeAndFlush(LastHttpContent.EMPTY_LAST_CONTENT);

        // Decide whether to close the connection or not.
        if (!HttpHeaderUtil.isKeepAlive(request)) {
            // Close the connection when the whole content is written out.
            lastContentFuture.addListener(ChannelFutureListener.CLOSE);
        }
        
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        cause.printStackTrace();

        // See if this helps with CLOSE_WAIT states.
        try { // Close streams in reverse order
            if (in!=null) in.close();
            if (c_out!=null) c_out.close();
            if (dis_ins_re!=null) dis_ins_re.close();
            if (ins_re!=null) ins_re.close();
            if (dis_ins!=null) dis_ins.close();
            if (ins!=null) ins.close();
            if (c_in!=null) c_in.close();
        } catch (IOException ex) {
            System.out.println("Stream close error: " + ex.getLocalizedMessage());
        }
        
        if (ctx.channel().isActive()) {
            // Just in case....
            long read = c_in==null?-1:c_in.getCount();
            long sent = c_out==null?-1:c_out.getCount();
            byte[] digest = md.digest();
            BigInteger bigInt = new BigInteger(1,digest);
            String hashtext = bigInt.toString(16), hashtext_ = "";
            while(hashtext.length() < 32 ){
                hashtext = "0"+hashtext;
            }
            if (dis_ins!=null&&md_!=null) {
                byte[] digest_ = md_.digest();
                BigInteger bigInt_ = new BigInteger(1,digest_);
                hashtext_ = bigInt_.toString(16);
                while(hashtext_.length() < 32 ){
                    hashtext_ = "0"+hashtext_;
                }
            }
            // Put data in completed-Cache (so that DS can verify download)
            String ip = "";
            MyCompletedCacheEntry mcce = new MyCompletedCacheEntry(hashtext, hashtext_, sent);
            EgaSecureReEncryptionService.putCompletedEntry(idk, mcce);
            if (!EgaSecureReEncryptionService.hasEntry(idk))
                EgaSecureReEncryptionService.putCompletedEntry(idk, mcce);
            
            //in = null;
            //c_out = null;
            //dis_ins_re = null;
            //ins = null;
            //c_in = null;
            EgaSecureReEncryptionService.log("Exception: " + cause.getLocalizedMessage());
            error_message = cause.getLocalizedMessage();
            System.out.println(error_message);
            sendError(ctx, INTERNAL_SERVER_ERROR);
        }
    }

    // JSON Version of error messages
    private void sendError(ChannelHandlerContext ctx, HttpResponseStatus status) {
        sendError(ctx, status, "application/json");
    }
    private void sendError(ChannelHandlerContext ctx, HttpResponseStatus status, String get) {
        EgaSecureReEncryptionService.log(status.toString());
        try {
            FullHttpResponse response = new DefaultFullHttpResponse(HTTP_1_1, status);
            JSONObject json = new JSONObject(); // Start out with common JSON Object
            json.put("header", responseHeader(status, error_message)); // Header Section of the response (error message by default!!)
            json.put("response", "null"); // ??
            
            StringBuilder buf = new StringBuilder();
            if (get.contains("application/json")) { // Format list of values as JSON
                response.headers().set(CONTENT_TYPE, "application/json");
                buf.append(json.toString());
            } else if (get.contains("xml")) { // Format list of values as XML
                response.headers().set(CONTENT_TYPE, "application/xml");
                String xml = XML.toString(json);
                buf.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
                buf.append("<Result>");
                buf.append(xml);
                buf.append("</Result>");
            }
            
            ByteBuf buffer = Unpooled.copiedBuffer(buf, CharsetUtil.UTF_8);
            response.content().writeBytes(buffer);
            
            // Close the connection as soon as the error message is sent.
            ctx.writeAndFlush(response).addListener(ChannelFutureListener.CLOSE);
        } catch (JSONException ex) {
            Logger.getLogger(EgaSecureReEncryptionServiceHandler.class.getName()).log(Level.SEVERE, null, ex);
        }
        if (inc) {
            EgaSecureReEncryptionService.decCount();
            inc = false;
        }
    }

    /**
     * Sets the Date and Cache headers for the HTTP Response
     *
     * @param response
     *            HTTP response
     * @param fileToCache
     *            file to extract content type
     */
    private static void setDateAndCacheHeaders(HttpResponse response, String fileToCache) {
        SimpleDateFormat dateFormatter = new SimpleDateFormat(HTTP_DATE_FORMAT, Locale.US);
        dateFormatter.setTimeZone(TimeZone.getTimeZone(HTTP_DATE_GMT_TIMEZONE));

        // Date header
        Calendar time = new GregorianCalendar();
        response.headers().set(DATE, dateFormatter.format(time.getTime()));

        // Add cache headers
        time.add(Calendar.SECOND, HTTP_CACHE_SECONDS);
        response.headers().set(EXPIRES, dateFormatter.format(time.getTime()));
        response.headers().set(CACHE_CONTROL, "private, max-age=" + HTTP_CACHE_SECONDS);
        Date x = new Date();
        x.setTime(System.currentTimeMillis()-1000000);
        response.headers().set(
                LAST_MODIFIED, dateFormatter.format(x));
        //response.headers().set(
        //        LAST_MODIFIED, dateFormatter.format(new Date(fileToCache.lastModified())));
    }

    /**
     * Sets the content type header for the HTTP Response
     *
     * @param response
     *            HTTP response
     * @param file
     *            file to extract content type
     */
    private static void setContentTypeHeaderBinary(HttpResponse response) {
        response.headers().set(CONTENT_TYPE, "application/octet-stream");
    }

    // -------------------------------------------------------------------------
    // -------------------------------------------------------------------------
    
    private CountingInputStream getCountingInputStream(InputStream in) {
        return new CountingInputStream(in);
    }
    // Access a file from a variety of sources
    private CountingInputStream getCountingInputStream(MyCacheEntry mce) {
        InputStream in = null;

        if (mce.getPathtype().equalsIgnoreCase("virtual")) {
            in = new MyRandomInputStream(mce.getSize());
        } else if (mce.getPathtype().equalsIgnoreCase("absolute")) {
            try {
                String path = mce.getFilePath();
                in = new FileInputStream(path);
                //in = new URL(mce.getFileUrl()).openStream(); // open InputStream from URL
            } catch (IOException ex) {
                System.out.println("FILE ERROR " + ex.getLocalizedMessage());
                Logger.getLogger(EgaSecureReEncryptionServiceHandler.class.getName()).log(Level.SEVERE, null, ex);
            }
        } else if (mce.getPathtype().equalsIgnoreCase("cleversafe")) {
            HttpURLConnection conn = null;
            int try_count = 0;
            boolean success = false;
            try {
                Random rand = new Random(System.currentTimeMillis());
                while (!success && (try_count++ < 8)) {
                    URL url = new URL(mce.getFileUrl());
                    conn = (HttpURLConnection)url.openConnection();
                    String userpass = mce.getUserpass();

                    // Java bug : http://bugs.sun.com/bugdatabase/view_bug.do?bug_id=6459815
                    String encoding = new sun.misc.BASE64Encoder().encode (userpass.getBytes());
                    encoding = encoding.replaceAll("\n", "");  

                    String basicAuth = "Basic " + encoding;
                    conn.setRequestProperty ("Authorization", basicAuth);
                    in = conn.getInputStream();
                    PushbackInputStream pbis = new PushbackInputStream(in);

                    int temp = pbis.read();
                    if (pbis.available()>0) {
                        //System.out.println("Success " + pbis.available());
                        pbis.unread(temp);
                        success = true;
                        in = pbis;
                    } else {
                        System.out.println("Failure accessing Cleversafe " + try_count);
                        Thread.sleep(rand.nextInt(10000));
                    }
                }
            } catch (IOException | InterruptedException t) {
                try_count++;
                System.out.println("Failure w/ Cleversafe " + try_count + " times!");
            }
        } else if (mce.getPathtype().equalsIgnoreCase("localproxy")) {
            HttpURLConnection conn = null;
            int try_count = 0;
            boolean success = false;
            try {
                Random rand = new Random(System.currentTimeMillis());
                while (!success && (try_count++ < 8)) {
                    URL url = new URL(mce.getFileUrl());
                    conn = (HttpURLConnection)url.openConnection();
                    in = conn.getInputStream();
                    PushbackInputStream pbis = new PushbackInputStream(in);

                    int temp = pbis.read();
                    if (pbis.available()>0) {
                        pbis.unread(temp);
                        success = true;
                        in = pbis;
                    } else {
                        System.out.println("Failure accessing Proxy URL " + try_count);
                        Thread.sleep(rand.nextInt(10000));
                    }
                }
            } catch (IOException | InterruptedException t) {
                try_count++;
                System.out.println("Failure w/ Proxy Server " + try_count + " times!");
            }
        }
        
        if (in!=null)
            return new CountingInputStream(in);
        else
            return null;
    }
    
    // -------------------------------------------------------------------------
    // -------------------------------------------------------------------------

    // Decrypt stream from a variety of formats
    private InputStream getPlainInputStream(InputStream c_in, MyCacheEntry mce) {
        InputStream in = null;

        if (mce.getOrigin().equalsIgnoreCase("plain") || mce.getPathtype().equalsIgnoreCase("virtual"))
            in = c_in; // No Decryption Necessary
        else if (mce.getOrigin().equalsIgnoreCase("aes128"))
            in = getAESDecryptingInputStream(c_in, 128, mce);
        else if (mce.getOrigin().equalsIgnoreCase("aes256"))
            in = getAESDecryptingInputStream(c_in, 256, mce);
        else if (mce.getOrigin().equalsIgnoreCase("symmetricgpg"))
            in = getSymmetricGPGDecryptingInputStream(c_in, mce);
        else if (mce.getOrigin().toLowerCase().startsWith("publicgpg"))
            in = getAsymmetricGPGDecryptingInputStream(c_in, mce);
        
        return in;
    }
    // -------------------------------------------------------------------------
    // -------------------------------------------------------------------------
    private InputStream getAESDecryptingInputStream(InputStream c_in, int bits, MyCacheEntry mce) {
        InputStream in = c_in;

        try {
            String key = mce.getOriginKey(); // Key provided directly
            if (key==null||key.length()==0) {
                String[] keyPath = EgaSecureReEncryptionService.getKeyPath("AES"); // Get key info from XML
                BufferedReader br = new BufferedReader(new FileReader(keyPath[0]));
                key = br.readLine();
                br.close();
            }
        
            byte[] salt = {(byte)-12, (byte)34, (byte)1, (byte)0, (byte)-98, (byte)223, (byte)78, (byte)21};                
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            // Key Generation - original decryption
            KeySpec spec = new PBEKeySpec(key.toCharArray(), salt, 1024, bits);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");

            byte[] random_iv = new byte[16];
            int read = in.read(random_iv, 0, 16);
            AlgorithmParameterSpec paramSpec = new IvParameterSpec(random_iv);

            Cipher cipher = null;
            cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, secret, paramSpec);                        
            in = new CipherInputStream(in, cipher);               
        } catch (IOException | InvalidKeySpecException | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchPaddingException ex) {
            Logger.getLogger(EgaSecureReEncryptionService.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        return in;
    }
    private InputStream getSymmetricGPGDecryptingInputStream(InputStream c_in, MyCacheEntry mce) {
        InputStream in = c_in;

        try {
            String key = mce.getOriginKey();
            if (key==null||key.length()==0) {
                String[] keyPath = EgaSecureReEncryptionService.getKeyPath("SymmetricGPG"); // Get key info from XML
                BufferedReader br = new BufferedReader(new FileReader(keyPath[0]));
                key = br.readLine();
                br.close();
            }
        
            Security.addProvider(new BouncyCastleProvider());
            in = GPGStream.getDecodingGPGInoutStream(in, key.toCharArray());
        } catch (IOException ex) {
            Logger.getLogger(EgaSecureReEncryptionService.class.getName()).log(Level.SEVERE, null, ex);
        } catch (PGPException ex) {
            Logger.getLogger(EgaSecureReEncryptionServiceHandler.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchProviderException ex) {
            Logger.getLogger(EgaSecureReEncryptionServiceHandler.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        return in;
    }
    private InputStream getAsymmetricGPGDecryptingInputStream(InputStream c_in, MyCacheEntry mce) {
        Security.addProvider(new BouncyCastleProvider());
        InputStream in = null;

        try {
            String okey = mce.getOrigin(); // Sanger has its own key, so must be handled differently
            String[] keyPath = okey.equalsIgnoreCase("publicgpg_sanger")?
                    EgaSecureReEncryptionService.getKeyPath("PrivateGPG_Sanger"):
                    EgaSecureReEncryptionService.getKeyPath("PrivateGPG");
            //String[] keyPath = EgaSecureReEncryptionService.getKeyPath("PrivateGPG"); // Get key info from XML
            //String[] keyPath = EgaSecureReEncryptionService.getKeyPath(okey); // Get key info from XML
            String key = keyPath[2]; // password for key file, not password itself
            if (key==null||key.length()==0) {
                BufferedReader br = new BufferedReader(new FileReader(keyPath[1]));
                key = br.readLine();
                br.close();
            }
        
            InputStream keyIn = new BufferedInputStream(new FileInputStream(keyPath[0]));

            PGPObjectFactory pgpF = new PGPObjectFactory(c_in);
            PGPEncryptedDataList    enc;
 
            Object                  o = pgpF.nextObject();
            //
            // the first object might be a PGP marker packet.
            //
            if (o instanceof PGPEncryptedDataList)
            {
                enc = (PGPEncryptedDataList)o;
            }
            else
            {
                enc = (PGPEncryptedDataList)pgpF.nextObject();
            }
             
            //
            // find the secret key
            //
            Iterator                    it = enc.getEncryptedDataObjects();
            PGPPrivateKey               sKey = null;
            PGPPublicKeyEncryptedData   pbe = null;
            PGPSecretKeyRingCollection  pgpSec = new PGPSecretKeyRingCollection(
                PGPUtil.getDecoderStream(keyIn));

            while (sKey == null && it.hasNext())
            {
                try {
                    pbe = (PGPPublicKeyEncryptedData)it.next();
                    
                    // New Code -- Start
//                    PGPSecretKey pgpSecKey = null;
//                    Iterator<PGPSecretKeyRing> keyRings = pgpSec.getKeyRings();
//                    while (keyRings.hasNext()) {
//                        PGPSecretKeyRing next = keyRings.next();
//                        pgpSecKey = next.getSecretKey(pbe.getKeyID());
//                        if (pgpSecKey!=null) break;
//                        Iterator<PGPSecretKey> t = next.getSecretKeys();
//                        while (t.hasNext()) {
//                            PGPSecretKey next1 = t.next();
//                            if (pbe.getKeyID() == next1.getKeyID())
//                                pgpSecKey = next1;
//                            if (pgpSecKey!=null) break;
//                        }
//                    }
    // New Code Above -- Cycles through all Keys, including all Subkeys, to find the Key
                    PGPSecretKey pgpSecKey = pgpSec.getSecretKey(pbe.getKeyID());
                    if (pgpSecKey == null)
                    {
                        sKey = null;
                    } else {
                        sKey = pgpSecKey.extractPrivateKey(key.toCharArray(), "BC");
                        //sKey = pgpSecKey.extractPrivateKey(null, "BC");
                    }
                } catch (Throwable t) {
                    System.out.println("Error -- " + t.getLocalizedMessage());
                }
            }
            
            if (sKey == null)
            {
                throw new IllegalArgumentException("secret key for message not found.");
            }
            
            InputStream         clear = pbe.getDataStream(sKey, "BC");
            
            PGPObjectFactory    plainFact = new PGPObjectFactory(clear);
            
            Object              message = plainFact.nextObject();
    
            if (message instanceof PGPCompressedData)
            {
                PGPCompressedData   cData = (PGPCompressedData)message;
                PGPObjectFactory    pgpFact = new PGPObjectFactory(cData.getDataStream());
                
                message = pgpFact.nextObject();
            }
            
            if (message instanceof PGPLiteralData)
            {
                PGPLiteralData ld = (PGPLiteralData)message;
                in = ld.getInputStream();
            }            
        } catch (IOException ex) {
            Logger.getLogger(EgaSecureReEncryptionService.class.getName()).log(Level.SEVERE, null, ex);
        } catch (PGPException ex) {
            Logger.getLogger(EgaSecureReEncryptionServiceHandler.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchProviderException ex) {
            Logger.getLogger(EgaSecureReEncryptionServiceHandler.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        return in;
    }
    
    // -------------------------------------------------------------------------
    // -------------------------------------------------------------------------
    
    private InputStream getReEncryptingInputStream(InputStream ins, MyCacheEntry mce) {
        InputStream in = null;

        if (mce.getDestination().equalsIgnoreCase("plain") || mce.getPathtype().equalsIgnoreCase("virtual"))
            in = ins; // No Decryption Necessary
        else if (mce.getDestination().equalsIgnoreCase("aes128"))
            in = getAESEncryptedInputStream(ins, mce.getDestinationKey().toCharArray(), 128);
        else if (mce.getDestination().equalsIgnoreCase("aes256"))
            in = getAESEncryptedInputStream(ins, mce.getDestinationKey().toCharArray(), 256);
        else if (mce.getDestination().equalsIgnoreCase("symmetricgpg"))
            System.out.println("Symmetric GPG Not Supported for Encryption"); // Not Supported!!!
        else if (mce.getDestination().toLowerCase().startsWith("publicgpg")) { //.equalsIgnoreCase("publicgpg")) {
            String[] paths = EgaSecureReEncryptionService.getKeyPath(mce.getDestination()); // -- org specific
            //String[] paths = EgaSecureReEncryptionService.getKeyPath("PublicGPG_CRG");
            PGPPublicKey gpgKey = null;
            try {
                gpgKey = EgaSecureReEncryptionService.getKey("CRG", paths);
            } catch (IOException ex) {;}
            in = getGPGEncryptedInputStream(ins, gpgKey);
        }
        
        return in;
    }
    
    private InputStream getAESEncryptedInputStream(InputStream in, char[] pw_re, int bits) {
        InputStream in_ = null;

        try {
            byte[] salt = {(byte)-12, (byte)34, (byte)1, (byte)0, (byte)-98, (byte)223, (byte)78, (byte)21};
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            KeySpec spec_re = new PBEKeySpec(pw_re, salt, 1024, bits); // used to be 256
            SecretKey tmp_re = factory.generateSecret(spec_re);
            SecretKey secret_re = new SecretKeySpec(tmp_re.getEncoded(), "AES");
            
            // Initialization Vector - new Random Value
            byte[] random_iv_re = new byte[16];
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            random.nextBytes(random_iv_re);
            AlgorithmParameterSpec paramSpec_re = new IvParameterSpec(random_iv_re);
            
            Cipher cipher_re = null;
            cipher_re = Cipher.getInstance("AES/CTR/NoPadding"); // load a cipher AES / Segmented Integer Counter
            cipher_re.init(Cipher.ENCRYPT_MODE, secret_re, paramSpec_re);
            //in_ = new CipherInputStream(in, cipher_re);
            in_ = new MyInputStream(new CipherInputStream(in, cipher_re), random_iv_re);
        
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException ex) {
            Logger.getLogger(EgaSecureReEncryptionService.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        return in_;
    }

    // Remains to be tested...
    private InputStream getGPGEncryptedInputStream(InputStream in, PGPPublicKey gpgKey) {
        InputStream in_ = null;
        
        try {
            in_ = new MyGPGInputStream(in, gpgKey);
        } catch (IOException ex) {
            Logger.getLogger(EgaSecureReEncryptionServiceHandler.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        return in_;
    }
    
    private String getEncryptionScheme(String path) {
        String scheme = "";
        
        if (path.trim().toLowerCase().endsWith("aes"))
            scheme = "aes";
        else if (path.trim().toLowerCase().endsWith("gpg"))
            scheme = "gpg";
        return scheme;
    }

    // Get the length of a file, from disk or Cleversafe server
    private long getLength(String[] path) {
        long result = -1;
        
        try {
            if (path[1] != null && path[1].length() == 0) { // Get size of file directly
                File f = new File(path[0]);
                result = f.length();
            } else { // Get file size from HTTP
                // Sending Request
                HttpURLConnection connection = null;
                connection = (HttpURLConnection)(new URL(path[0])).openConnection();
                connection.setRequestMethod("HEAD");

                String userpass = path[1];
                
                // Java bug : http://bugs.sun.com/bugdatabase/view_bug.do?bug_id=6459815
                String encoding = new sun.misc.BASE64Encoder().encode (userpass.getBytes());
                encoding = encoding.replaceAll("\n", "");  
                
                String basicAuth = "Basic " + encoding;
                connection.setRequestProperty ("Authorization", basicAuth);
                
                // Reading Response
                int responseCode = connection.getResponseCode();

                String headerField = connection.getHeaderField("content-length");
                String temp = headerField.trim();
                result = Long.parseLong(temp);

                connection.disconnect();
            }
        } catch (IOException | NumberFormatException e) {
            e.printStackTrace();
        }            
        
        return result;
    }
    
    // Generate JSON Header Section
    private JSONObject responseHeader(HttpResponseStatus status) throws JSONException {
        return responseHeader(status, "");
    }
    private JSONObject responseHeader(HttpResponseStatus status, String error) throws JSONException {
        JSONObject head = new JSONObject();
        
        head.put("apiVersion", "v1");
        head.put("code", String.valueOf(status.code()));
        head.put("service", "res");
        head.put("technicalMessage", "");                   // TODO (future)
        head.put("userMessage", status.reasonPhrase());
        head.put("errorCode", String.valueOf(status.code()));
        head.put("docLink", "http://www.ebi.ac.uk/ega");    // TODO (future)
        head.put("errorStack", error);                     // TODO ??
        
        return head;
    }
}
