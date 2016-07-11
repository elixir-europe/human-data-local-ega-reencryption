/*
 * Copyright 2015 EMBL-EBI.
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

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerAdapter;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPipeline;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import static io.netty.handler.codec.http.HttpHeaderNames.CONTENT_TYPE;
import io.netty.handler.codec.http.HttpResponseStatus;
import static io.netty.handler.codec.http.HttpResponseStatus.OK;
import static io.netty.handler.codec.http.HttpVersion.HTTP_1_1;
import io.netty.util.CharsetUtil;
import io.netty.util.concurrent.DefaultEventExecutorGroup;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import uk.ac.embl.ebi.ega.reencryptionservice.endpoints.Service;
import uk.ac.embl.ebi.ega.reencryptionservice.utils.MyPipelineUtils;
import us.monoid.json.JSONArray;
import us.monoid.json.JSONException;
import us.monoid.json.JSONObject;
import us.monoid.json.XML;

/**
 *
 * @author asenf
 */
public class EgaChannelSelector extends ChannelHandlerAdapter {
    private boolean SSL = false, active = true;
    private final HashMap<String, Service> endpointMappings;
    private final DefaultEventExecutorGroup l, s; // long, short request executors
    
    private final EgaSecureReEncryptionService ref;

    private static HttpResponseStatus REQUEST_ERROR = new HttpResponseStatus(580, "Error Getting Request Header");

    private String error_message = "";
    
    public EgaChannelSelector(boolean SSL, HashMap<String, Service> mappings, 
            DefaultEventExecutorGroup s, DefaultEventExecutorGroup l,
            EgaSecureReEncryptionService ref) {
        this.SSL = SSL;
        this.endpointMappings = mappings;
        this.s = s;
        this.l = l;        
        this.ref = ref;
    }
    
    //@Override
    //public void read(ChannelHandlerContext ctx) {
    //    ctx.read();
    //}
    
    @Override
    public void channelRead(ChannelHandlerContext ctx, Object i) {
        // Step 1: Verify that there is a channel and request
        if (ctx==null) return; if (i==null) return; // Don't even proceed in these cases!
        FullHttpRequest request = (FullHttpRequest)i;
        String get = request.headers().get("Accept").toString(); // Response Type

        // Step 2: Check Request
        HttpResponseStatus checkURL = MyPipelineUtils.checkURL(request);
        if (checkURL != OK) {
            error_message = "Request Verification Error.";
            sendError(ctx, checkURL, get);
            return;
        }
        
        // Step 3: Sanitize URL, and decide what to do based on this URL
        String unescapedSafeUri = MyPipelineUtils.sanitize(request);
        
        // *********************************************************************
        // * Two thread pools: l for long lasting, s for immediate
        // *********************************************************************        

        // Distribute request to different handlers and/or thread pools, based on URL
        try {
            if (unescapedSafeUri.contains("/stats") || unescapedSafeUri.contains("/results")) { // Requests that require immediate answer
                ChannelPipeline p = ctx.pipeline();
                
                p.addLast(this.s, new EgaSecureReEncryptionServiceHandler(SSL, 
                                                                this.endpointMappings, 
                                                                ref));
                p.remove(this);        
                
                ctx.fireChannelRead(i);
            } else { // Long Requests - Downloads (also all other 404 requests...)
                ChannelPipeline p = ctx.pipeline();
                
                p.addLast(this.l, new EgaSecureReEncryptionServiceHandler(SSL, 
                                                                this.endpointMappings, 
                                                                ref));
                p.remove(this);        
                
                ctx.fireChannelRead(i);
            }
        } catch (NoSuchAlgorithmException ex) {;}
    }

    private void sendError(ChannelHandlerContext ctx, HttpResponseStatus status) {
        sendError(ctx, status, "application/json");
    }
    private void sendError(ChannelHandlerContext ctx, HttpResponseStatus status, String get) {
        EgaSecureReEncryptionService.log(status.toString());
        try {
            FullHttpResponse response = new DefaultFullHttpResponse(HTTP_1_1, status);
            JSONObject json = new JSONObject(); // Start out with common JSON Object
            json.put("header", responseHeader(status)); // Header Section of the response
            json.put("response", "null"); // ??
            
            StringBuilder buf = new StringBuilder();
            if (get.contains("application/json") || get.contains("application/octet-stream")) { // Format list of values as JSON
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
            Logger.getLogger(EgaChannelSelector.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    // Generate JSON Header Section
    private JSONObject responseHeader(HttpResponseStatus status) throws JSONException {
        return responseHeader(status, error_message);
    }
    private JSONObject responseHeader(HttpResponseStatus status, String error) throws JSONException {
        JSONObject head = new JSONObject();
        
        head.put("apiVersion", "v1");
        head.put("code", String.valueOf(status.code()));
        head.put("service", "res");
        head.put("technicalMessage", "ChannelSelector");                   // TODO (future)
        head.put("userMessage", status.reasonPhrase());
        head.put("errorCode", String.valueOf(status.code()));
        head.put("docLink", "http://www.ebi.ac.uk/ega");    // TODO (future)
        head.put("errorStack", error);                     // TODO ??
        
        return head;
    }

    // Generate JSON Response Section
    private JSONObject responseSection(String[] arr) throws JSONException {
        JSONObject response = new JSONObject();

        response.put("numTotalResults", 1); // -- Result = 1 Array -- (?)
        response.put("resultType", "us.monoid.json.JSONArray");
        
        JSONArray mJSONArray = new JSONArray(Arrays.asList(arr));        
        response.put("result", mJSONArray);
        
        return response;
    }
}
