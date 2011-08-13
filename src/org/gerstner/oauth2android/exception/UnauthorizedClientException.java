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
package org.gerstner.oauth2android.exception;

/**
 * This Exception is thrown either, when the client fails to present a valid
 * authorization to the server or if the server expects another type of authorization.
 * For example the client send an authorization containing a Bearer-Token in the
 * Http "Authorization"-Header, but the server expects a MAC-Token. So the server
 * sends the 401 (unauthorized) status code back to the client and includes the
 * "WWW-Authenticate" - Header with continuative informations on the expected token
 * type.
 * <br><br>
 * <strong>Example header:</strong>
 * <br>
 * <pre>
 *   <code>HTTP/1.1    401  Unauthorized
 *   WWW-Authentcate: MAC</code>
 * </pre>
 *
 * @see org.gerstner.oauth2android.token.Token
 * @see org.gerstner.oauth2android.token.TokenTypeDefinition
 * @author Christoph Gerstner <development@christoph-gerstner.de>
 */
public class UnauthorizedClientException extends OAuthException{

    /**
     * Creates a new instance of <code>UnauthorizedClientException</code> with predefined detail message.
     */
    public UnauthorizedClientException(){
        super("The client is not authorized");
    }

    /**
     * Constructs an instance of <code>UnauthorizedClientException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public UnauthorizedClientException(String msg){
        super(msg);
    }
}
