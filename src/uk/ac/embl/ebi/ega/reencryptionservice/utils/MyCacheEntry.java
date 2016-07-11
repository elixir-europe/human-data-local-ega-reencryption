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

package uk.ac.embl.ebi.ega.reencryptionservice.utils;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.logging.Level;
import java.util.logging.Logger;

public class MyCacheEntry {
    private final String pathtype;
    private final String fileUrl;
    private final String userpass; // abs.path1/abs.path2/size/rel.path
    private final long size;
    private final String origin;
    private final String destination;
    private final String originkey;
    private final String destinationkey;
    
    public MyCacheEntry(String pathtype, String fileUrl, String userpass, long fileSize, String origin, String destination, String originkey, String destinationkey) {
        this.pathtype = pathtype;
        this.fileUrl = fileUrl;
        this.userpass = userpass;
        this.size = fileSize;
        this.origin = origin;
        this.destination = destination;
        this.originkey = originkey;
        this.destinationkey = destinationkey;
    }
    
    public String getPathtype() {
        return this.pathtype;
    }
    
    public String getFilePath() {
        String path = null;
        try {
            path = URLDecoder.decode(this.fileUrl, "UTF-8");
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(MyCacheEntry.class.getName()).log(Level.SEVERE, null, ex);
        }
        if (path!=null && path.toLowerCase().startsWith("file:")) path = path.substring(5);
        return path;
    }
    
    public String getFileUrl() {
        return this.fileUrl;
    }
    
    public String getUserpass() {
        return this.userpass;
    }
    
    public long getSize() {
        return this.size;
    }
    
    public String getOrigin() {
        return this.origin;
    }
    
    public String getDestination() {
        return this.destination;
    }
    
    public String getOriginKey() {
        return this.originkey;
    }
    
    public String getDestinationKey() {
        return this.destinationkey;
    }
}
