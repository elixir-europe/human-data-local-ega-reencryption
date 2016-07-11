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
import static io.netty.handler.codec.http.HttpMethod.POST;
import static io.netty.handler.codec.http.HttpResponseStatus.OK;
import static io.netty.handler.codec.http.HttpResponseStatus.SEE_OTHER;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import uk.ac.embl.ebi.ega.reencryptionservice.EgaSecureReEncryptionService;
import us.monoid.json.JSONException;
import us.monoid.json.JSONObject;

public class DownloadService extends ServiceTemplate implements Service {

    @Override
    public JSONObject handle(ArrayList<String> id, Map<String, String> parameters, FullHttpRequest request, EgaSecureReEncryptionService ref) {
        JSONObject json = new JSONObject(); // Start out with common JSON Object

        try {
            Map<String,String> body = new HashMap<>();
            if (request.method() == POST) {
                body.put("fileid", "");
                body.put("filepath0", "");
                body.put("key", "");
                body.put("format", "");
                body.put("user", "");
                int elements = decodeRequestBody(request, "downloadrequest", body);
            }
            
            String[] result = null; // Holds JDBC Database Query results
            
            // TODO
            
            
            json.put("header", responseHeader(OK)); // Header Section of the response
            json.put("response", responseSection(result));            
        } catch (JSONException | IOException ex) {
            Logger.getLogger(DownloadService.class.getName()).log(Level.SEVERE, null, ex);
            try {
                json.put("header", responseHeader(SEE_OTHER, ex.getLocalizedMessage()));
                json.put("response", responseSection(null));            
            } catch (JSONException ex1) {
                Logger.getLogger(StatService.class.getName()).log(Level.SEVERE, null, ex1);
            }
        }

        return json;
    }
    
}
