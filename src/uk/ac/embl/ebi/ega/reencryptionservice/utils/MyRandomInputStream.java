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

import java.io.IOException;
import java.io.InputStream;
import java.util.Random;

/**
 *
 * @author asenf
 * 
 * This stream produces random data, it has a length that is given upon instantiation.
 * This is used for testing the system - streaming random data instead of an actual file
 * allows for testing the performance of the system apart from file access and encryption
 */
public class MyRandomInputStream extends InputStream {
    private final Random random;
    private final long size;
    private long sent;
    
    public MyRandomInputStream(long size) {
        this.size = size;
        this.sent = 0;
        this.random = new Random(System.currentTimeMillis());
    }
    
    @Override
    public int read() throws IOException {
        if (this.sent>=this.size) return -1;

        int r = this.random.nextInt(128);
        this.sent++;
        return r;
    }
    
    
    @Override
    public int read(byte b[]) throws IOException {
        if (this.sent>=this.size) return -1;

        int range = b.length;
        long available = this.size-this.sent;
        int using = (int) (range<=available?range:available);
        
        byte[] b_ = new byte[using];
        this.random.nextBytes(b_);
        System.arraycopy(b_, 0, b, 0, using);
        this.sent += using;
        
        return using;
    }

    @Override
    public int read(byte b[], int off, int len) throws IOException {
    
        if (b == null) {
            throw new NullPointerException();
        } else if (off < 0 || len < 0 || len > b.length - off) {
            throw new IndexOutOfBoundsException();
        } else if (len == 0) {
            return 0;
        }

        if (this.sent>=this.size) return -1;

        int range = len;
        long available = this.size-this.sent;
        int using = (int) (range<=available?range:available);
        
        byte[] b_ = new byte[using];
        this.random.nextBytes(b_);
        System.arraycopy(b_, 0, b, off, using);
        this.sent += using;
        
        return using;
    }

    @Override
    public long skip(long n) throws IOException {
        long skipped = 0;
        
        long available = this.size-this.sent;
        skipped = skipped<=available?skipped:available;
        this.sent += skipped;
        
        return skipped;
    }
    
    @Override
    public int available() throws IOException {
        long available = this.size-this.sent;
        int iAvailable = available>Integer.MAX_VALUE?Integer.MAX_VALUE:(int)available;
        return iAvailable;
    }

    @Override
    public boolean markSupported() {
        return false;
    }
}
