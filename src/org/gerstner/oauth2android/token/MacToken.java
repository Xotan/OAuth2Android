/*
 * The MIT License (MIT)
 * Copyright (c) 2011 Christoph Gerstner <development@christoph-gerstner.de>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * Note: For questions or suggestions don't hesitate to contact me under the
 * above email address.
 */
package org.gerstner.oauth2android.token;

import java.io.Serializable;

/**
 * The <code>MacToken</code> is an extension of the standard access token used in OAuth 2.0.<br>
 * It provides cryptographic verification of portions of the HTTP requests by calculating
 * a message authentication code (MAC). In addition to the access standard token the
 * <code>MacToken</code>
 * can contain an <code>ext</code> parameter wich is an optional extension parameter
 * that should be included in the requests mac
 * @author Christoph Gerstner <development@christoph-gerstner.de>
 */
public class MacToken
        extends Token
        implements Serializable{

    String ext;

    /**
     * Creates an empty instance of a <code>MacToken</code>. This standard constructor
     * should not be used. Use {@link #MacToken(java.lang.String, java.lang.String, long)} instead.
     */
    public MacToken(){
    }

    /**
     * Creates an instance of a <code>MacToken</code> containing the tokens identifier
     * (also called Mac Key Identifier), the scope for wich the token is valid and
     * the tokens lifetime in seconds. The tokens type will be set to "mac".
     * @param token <code>String</code> the token identifier (or Mac Key Identifier)
     * @param scope <code>String</code> the scope for the token
     * @param secondsValid <code>long</code> seconds the token will be valid
     */
    public MacToken(String token, String scope, long secondsValid){
        super(token, scope, secondsValid);
        this.setType("mac");
        this.ext ="";
    }

    /**
     * Returns the ext parameter
     * @return <code>string</code> ext parameter
     */
    public String getExt() {
        return ext;
    }

    /**
     * Sets the ext parameters
     * @param ext <code>string</code> ext parameter
     */
    public void setExt(String ext) {
        this.ext = ext;
    }

    

   
}
