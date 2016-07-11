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
import java.util.ArrayList;
import java.util.Map;
import uk.ac.embl.ebi.ega.reencryptionservice.EgaSecureReEncryptionService;
import us.monoid.json.JSONObject;

public interface Service {
    
    public JSONObject handle(ArrayList<String> id, Map<String, String> parameters, FullHttpRequest request, EgaSecureReEncryptionService ref);
    
}
