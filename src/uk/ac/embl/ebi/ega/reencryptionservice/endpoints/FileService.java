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

package uk.ac.embl.ebi.ega.reencryptionservice.endpoints;

import io.netty.handler.codec.http.FullHttpRequest;
import static io.netty.handler.codec.http.HttpResponseStatus.OK;
import static io.netty.handler.codec.http.HttpResponseStatus.SEE_OTHER;
import io.netty.handler.codec.http.multipart.DefaultHttpDataFactory;
import io.netty.handler.codec.http.multipart.HttpPostRequestDecoder;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;
import uk.ac.embl.ebi.ega.reencryptionservice.EgaSecureReEncryptionService;
import uk.ac.embl.ebi.ega.reencryptionservice.utils.MyCacheEntry;
import us.monoid.json.JSONException;
import us.monoid.json.JSONObject;

public class FileService extends ServiceTemplate implements Service {

    @Override
    public JSONObject handle(ArrayList<String> id, Map<String, String> parameters, FullHttpRequest request, EgaSecureReEncryptionService ref) {
        JSONObject json = new JSONObject(); // Start out with common JSON Object
        
        try {
            Map<String,String> body = new HashMap<>();

            HttpPostRequestDecoder decoder = new HttpPostRequestDecoder(new DefaultHttpDataFactory(false), request);

            body.put("filepath", ""); // File - full path or relative path for Cleversafe 
            body.put("pathtype", ""); // Type of Path: "Cleversafe" or "Absolute" or "Virtual" (New: "Localproxy")
            body.put("originformat", ""); // Origin format: "AES256", "AES128", "SymmetricGPG", "PublicGPG", "PublicGPG_Sanger", "Plain"
            body.put("destinationformat", ""); // Destination format: "AES256", "AES128", "SymmetricGPG", "PublicGPG_{org}", "Plain"
            body.put("originkey", ""); // Decryption Key - blank in most cases; determined by format
            body.put("destinationkey", ""); // (Re)Encryption Key (user supplied, or blank if PublicGPG/Plain is chosen)
            // Key from XML: "AES", "SymmetricGPG", "PrivateGPG", "PublicGPG_{organization}"
            
            int elements = decodeRequestBody(request, "filerequest", body);

            String filepath = body.get("filepath").trim();
            String pathtype = body.get("pathtype").trim();
            String origin = body.get("originformat").trim();
            String destination = body.get("destinationformat").trim();
            String originkey = body.get("originkey").trim();
            String destinationkey = body.get("destinationkey").trim();

            // Set up environment based on provided information
            String userpass = "", fileUrl=""; // Needed for Cleversafe
            long fileSize = 0; // Virtual (Test) Files: desired length encoded in filename
            if (pathtype.equalsIgnoreCase("cleversafe")) { // Cleversafe Path (=URL)
                String[] cleversafepath = getPath(filepath);
                fileUrl = cleversafepath[0];
                userpass = cleversafepath[1];
                fileSize = getLength(cleversafepath);
            } else if (pathtype.equalsIgnoreCase("localproxy")) { // Proxy/URL
                fileUrl = "http://" + parameters.get("ip") + ":8080?path=" + filepath;
                fileSize = (new File(filepath)).length();
            } else if (pathtype.equalsIgnoreCase("virtual")) { // Virtual File
                fileUrl = filepath; // Simply the file name, e.g. "EGA_1023494"
                fileSize = Long.parseLong( filepath.substring(filepath.indexOf("_")+1) );
            } else if (pathtype.equalsIgnoreCase("absolute")) { // Absolute File Path
                fileUrl = new File(filepath).toURI().toURL().toString();
                if ( !(new File(fileUrl)).exists() ) fileUrl = filepath;
                fileSize = (new File(filepath)).length();
            }
            
            // Key Environment? --> Set up upon streaming

            MyCacheEntry mce = new MyCacheEntry(pathtype, fileUrl, userpass, fileSize, origin, destination, originkey, destinationkey);

            UUID idOne = UUID.randomUUID();
            String theID = idOne.toString();

            EgaSecureReEncryptionService.putEntry(theID, mce);

            try { // Return cache entry key as result
                String[] result = new String[]{theID};

                json.put("header", responseHeader(OK)); // Header Section of the response
                json.put("response", responseSection(result));            
            } catch (JSONException ex) {
                Logger.getLogger(FileService.class.getName()).log(Level.SEVERE, null, ex);
                try {
                    json.put("header", responseHeader(SEE_OTHER, ex.getLocalizedMessage()));
                    json.put("response", responseSection(null));            
                } catch (JSONException ex1) {
                    Logger.getLogger(StatService.class.getName()).log(Level.SEVERE, null, ex1);
                }
            }
        } catch (Throwable t) {;}

        return json;
    }
    
    private String[] getPath(String path) {
        // EBI-Internal Only! Not implemented in Local EGA
        /*
        try {
            ArrayList<String> temp_path = new ArrayList<>();
            String[] result = new String[4]; // [0][1] path [2] size [3] rel path
            result[0] = "";
            result[1] = "";
            result[3] = path;
            String path_ = path;

            String[] server = new String[]{""};
            Random r = new Random();
            int idx = r.nextInt(1);
            
            // Sending Request
            HttpURLConnection connection = null;
            connection = (HttpURLConnection)(new URL("http://"+server[idx]+"/fire/direct")).openConnection();
            connection.setRequestMethod("GET");
            connection.setRequestProperty("..", "..");
            connection.setRequestProperty("..", "..");
            connection.setRequestProperty("..", "..");

            // Reading Response
            int responseCode = connection.getResponseCode();

            BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            String inputLine;
            StringBuilder response = new StringBuilder();

            // Multiple files are returned - pick the one that works for EGA
            ArrayList<String[]> paths = new ArrayList<>();
            
            String location_http = "", 
                   location_http_tag = "", 
                   location_md5 = "";
            while ((inputLine = in.readLine()) != null) {
                if (inputLine.startsWith("FILE_PATH"))
                    temp_path.add(inputLine.substring(inputLine.indexOf("/")).trim());
                if (inputLine.startsWith("HTTP_GET"))
                    location_http = inputLine.substring(inputLine.indexOf("http://")).trim();
                if (inputLine.startsWith("AUTH_BASIC"))
                    location_http_tag = inputLine.substring(inputLine.indexOf(" ")+1).trim();
                if (inputLine.startsWith("FILE_MD5")) {
                    location_md5 = inputLine.substring(inputLine.indexOf(" ")+1).trim();
                    paths.add(new String[]{location_http, location_http_tag, location_md5});
                }
            }
            in.close();

            if (paths.size() > 0) {
                for (int i=0; i<paths.size(); i++) {
                    String[] e = paths.get(i);
                    if (e[1].contains("egaread")) {
                        result[0] = e[0];
                        result[1] = e[1];
                        result[2] = String.valueOf(getLength(new String[]{location_http, location_http_tag}));
                    }
                }
            } else if (temp_path.size()>0 && result[1].length()==0) { // Determine proper path
                for (String temp_path1 : temp_path) {
                    if ((new File(temp_path1)).exists()) {
                        result[0] = temp_path1;
                        result[2] = String.valueOf((new File(temp_path1)).length());
                        break;
                    }
                }
                result[1] = "";
            }
            
            return result;
        } catch (Exception e) {
            System.out.println("Path = " + path);
            System.out.println(e.getMessage());
        }            
        */
        return null;
    }

    // Get the length of a file, from disk or Cleversafe server
    private long getLength(String[] path) {
        long result = -1;
        
        try {
            if ((path.length == 1) || (path[1] != null && path[1].length() == 0)) { // Get size of file directly
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

}
