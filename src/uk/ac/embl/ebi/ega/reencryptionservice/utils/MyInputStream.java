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

/**
 *
 * @author asenf
 */
public class MyInputStream extends InputStream {
    private final InputStream in;
    private final byte[] buf;
    private int pos;
    private boolean startmode;
    
    public MyInputStream(InputStream in, byte[] iv) {
        this.in = in;
        this.buf = new byte[iv.length];
        System.arraycopy(iv, 0, this.buf, 0, iv.length);
        this.pos = 0;
        this.startmode = true;
    }

    @Override
    public int read() throws IOException {
        int r = -1;
        if (this.startmode) {
            r = (int)this.buf[this.pos++];
            if (this.pos>=this.buf.length) startmode = false;
        } else {
            r = in.read();
        }
        return r;
    }
    
    
    @Override
    public int read(byte b[]) throws IOException {
//System.out.println("read(b[]) " + b.length);
        return in.read(b, 0, b.length);
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

//System.out.println("read(b[],off,len) " + b.length + " " + off + " " + len + "  " + startmode);

        if (startmode) {
            int readlength = len;
            int bufferavailable = this.buf.length - this.pos;
            int initialcopy = bufferavailable<=readlength?bufferavailable:readlength;
            System.arraycopy(this.buf, this.pos, b, off, initialcopy);
            this.pos += initialcopy;
            if (this.pos>=this.buf.length)
                startmode = false;
            return initialcopy;
        } else {
            return in.read(b, off, len);
        }
    }

    @Override
    public long skip(long n) throws IOException {
//System.out.println("skip(n) " + n);
        return in.skip(n);
    }

    @Override
    public int available() throws IOException {
//System.out.println("available() " + startmode);
        if (startmode) {
//System.out.println(" --> " + (this.buf.length-this.pos));
            return (this.buf.length-this.pos);
        } else {
//System.out.println(" --> " + in.available());
            return in.available();
        }
    }

    @Override
    public void close() throws IOException {
//System.out.println("close()");
        in.close();
    }

    @Override
    public synchronized void mark(int readlimit) {
//System.out.println("mark(readLimit) " + readlimit);
        in.mark(readlimit);
    }

    @Override
    public synchronized void reset() throws IOException {
        throw new IOException("mark/reset not supported");
    }

    @Override
    public boolean markSupported() {
        return false;
    }
}
