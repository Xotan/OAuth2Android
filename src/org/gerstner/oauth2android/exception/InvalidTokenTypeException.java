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

import org.gerstner.oauth2android.token.Token;

/**
 * Thrown when either the issued token from the server does not match the
 * predefined or any known token type.
 * <br><br>
 * OAuth 2.0 exception - see the OAuth 2.0 specification for more details.
 * 
 * @see org.gerstner.oauth2android.token.Token#setType(java.lang.String)
 * @see org.gerstner.oauth2android.token.TokenTypeDefinition#getName()  
 * @author Christoph Gerstner <development@christoph-gerstner.de>
 *
 */
public class InvalidTokenTypeException extends OAuthException{

    /**
     * Creates a new instance of <code>InvalidTokenTypeException</code> without detail message.
     */
    public InvalidTokenTypeException(){
    }

    /**
     * Constructs an instance of <code>InvalidTokenTypeException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public InvalidTokenTypeException(String msg){
        super(msg);
    }
}
