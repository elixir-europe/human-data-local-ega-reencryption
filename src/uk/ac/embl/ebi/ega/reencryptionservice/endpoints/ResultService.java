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
import static io.netty.handler.codec.http.HttpResponseStatus.NOT_FOUND;
import java.util.ArrayList;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import uk.ac.embl.ebi.ega.reencryptionservice.EgaSecureReEncryptionService;
import uk.ac.embl.ebi.ega.reencryptionservice.utils.MyCompletedCacheEntry;
import us.monoid.json.JSONException;
import us.monoid.json.JSONObject;

public class ResultService extends ServiceTemplate implements Service {

    @Override
    public JSONObject handle(ArrayList<String> id, Map<String, String> parameters, FullHttpRequest request, EgaSecureReEncryptionService ref) {
        JSONObject json = new JSONObject(); // Start out with common JSON Object

        try {
            String id_ = (id!=null && id.size()>0)?id.get(0):"";
            // id = key to results
            System.out.println("id = " + id_);
            MyCompletedCacheEntry mcce = EgaSecureReEncryptionService.getCompletedEntry(id_);
            
            if (mcce!=null) {
                String[] result = {mcce.getMD5(), String.valueOf(mcce.getSentSize()), mcce.getPlainMD5()};

                json.put("header", responseHeader(OK)); // Header Section of the response
                json.put("response", responseSection(result));            

                // OK. Now Remove from Cache (DS has all relevant information)
                //EgaSecureReEncryptionService.removeCompletedEntry(id_);
                //EgaSecureReEncryptionService.removeEntry(id_);
            } else {
                json.put("header", responseHeader(NOT_FOUND)); // Header Section of the response
                json.put("response", responseSection(null));            
            }
        } catch (Exception ex) {
            Logger.getLogger(ResultService.class.getName()).log(Level.SEVERE, null, ex);
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
