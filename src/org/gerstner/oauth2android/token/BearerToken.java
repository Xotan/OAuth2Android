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
 * The <code>BearerToken</code> is the standard token class for OAuth 2.0.
 * It is also the simpliest token.
 * @author Christoph Gerstner <development@christoph-gerstner.de>
 */
public class BearerToken
    extends Token
    implements Serializable {

    /**
     * Creates an empty instance of a <code>BearerToken</code>. This standard constructor
     * should not be used. Use {@link #BearerToken(java.lang.String, java.lang.String, long)} instead.
     */
    public BearerToken() {
    }

    /**
     * Creates an instance of a <code>BearerToken</code> containing the tokens identifier,
     * the scope for wich the token is valid and
     * the tokens lifetime in seconds. The tokens type will be set to "bearer".
     * @param token <code>String</code> the token identifier
     * @param scope <code>String</code> the scope for the token
     * @param secondsValid <code>long</code> seconds the token will be valid
     */
    public BearerToken(String token, String scope, long secondsValid) {
        super(token, scope, secondsValid);
        this.setType("bearer");
    }
}
