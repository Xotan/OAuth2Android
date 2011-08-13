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
package org.gerstner.oauth2android.response;

import org.gerstner.oauth2android.exception.InvalidClientException;
import org.gerstner.oauth2android.exception.InvalidGrantException;
import org.gerstner.oauth2android.exception.InvalidRequestException;
import org.gerstner.oauth2android.exception.InvalidScopeException;
import org.gerstner.oauth2android.exception.OAuthException;
import org.gerstner.oauth2android.exception.UnauthorizedClientException;
import org.gerstner.oauth2android.exception.UnsupportedGrantTypeException;

/**
 * Static class containing methods that are capable of recognizing specific errors
 * by their names and return the appropriate Exception. This is especially usefull
 * to recognize OAuth 2.0 errors that are returned without the use of a http error code.
 * @see #getException(java.lang.String) 
 * @author Christoph Gerstner <development@christoph-gerstner.de>
 */
public class ErrorParser{

    /**
     * If a requst is invalid or contains errors that are OAuth 2.0 specific, the server
     * may return an error code as for example <b>401 Unautorized</b>. In most cases however
     * the server will return a 302 or similar http status code and add a error indication
     * as a parameter to the request. The server may also provide a detaild error description
     * or an url leading to a website comtaining more information.
     * The server MUST however return <code>error</code> - parameter wich can have
     * the following meanings:
     * <ul>
     * <li><code>invalid_request</code> - the request is missing a parameter or is otherwise invalid. See: {@link org.gerstner.oauth2android.exception.InvalidRequestException} </li>
     * <li><code>invalid_client</code> - the client could not be identified. See {@link org.gerstner.oauth2android.exception.InvalidClientException}</li>
     * <li><code>invalid_grant</code> - the authorization grant is not valid. See {@link org.gerstner.oauth2android.exception.InvalidGrantException}</li>
     * <li><code>unauthorized_client</code> - the token is not valid or is of the wrong type. See: {@link org.gerstner.oauth2android.exception.UnauthorizedClientException}</li>
     * <li><code>unsupported_grant_type</code> - the client used an unsupported method for the authorization grant. See: {@link org.gerstner.oauth2android.exception.UnsupportedGrantTypeException}</li>
     * <li><code>invalid_scope</code> - the scope is incomplete or invalid. See: {@link org.gerstner.oauth2android.exception.InvalidScopeException}</li>
     * </ul>
     * The method determins wich <code>OAuthException</code> has to be used and returns an instance of this exception for the calling method 
     * to throw it.
     *
     * @param error <code>string</code> indicating the error
     * @return the appropriate <code>OAuthException</code> for the error
     */
    public static OAuthException getException(String error){
        OAuthException exception = new OAuthException("Request failed.");

        if(error.equalsIgnoreCase("invalid_request")){
            exception = new InvalidRequestException();
        }
        if(error.equalsIgnoreCase("invalid_client")){
            exception = new InvalidClientException();
        }
        if(error.equalsIgnoreCase("invalid_grant")){
            exception = new InvalidGrantException();
        }
        if(error.equalsIgnoreCase("unauthorized_client")){
            exception = new UnauthorizedClientException();
        }
        if(error.equalsIgnoreCase("unsupported_grant_type")){
            exception = new UnsupportedGrantTypeException();
        }
        if(error.equalsIgnoreCase("invalid_scope")){
            exception = new InvalidScopeException();
        }
        return exception;
    }
}
