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
 * Parent class for all OAuth 2.0 specific exceptions. <br>
 * OAuth 2.0 exceptions have three additional parameters for error handling:
 * <ul>
 * <li> <code>error</code> - name of the error that occured, e.g. invalid_client</li>
 * <li> <code>error description</code> - an human readable description of the error, given by the server </li>
 * <li> <code>error uri</code> - uri directing to a human readable webpage for futher description of the error</li>
 * </ul>
 * In case of the {@link org.gerstner.oauth2android.exception.UnauthorizedClientException} the  <code>error decription</code>
 * should contain the servers "WWW-Authorization"-Header, if one was issued. This header gives specfic information
 * on which authorization the server expects.
 * @see InvalidClientException
 * @see InvalidGrantException
 * @see InvalidRequestException
 * @see InvalidScopeException
 * @see UnauthorizedClientException
 * @see UnsupportedGrantTypeException
 *
 * @author Christoph Gerstner <development@christoph-gerstner.de>
 */
public class OAuthException
        extends Exception{

    /**
     * Short description or name of the occured error. (REQUIRED)
     * @see #errorDescription
     * @see #errorUri
     */
    private String error;
    /**
     * Human readable description returned by the server to be shown to the user. (OPTIONAL)
     * @see #error
     * @see #errorUri
     */
    private String errorDescription;
    /**
     * Uri leading to a human readable webpage with further information to the occured error.
     * The client may choose to redirect the user to this page. (OPTIONAL)
     * @see #error
     * @see #errorDescription
     */
    private String errorUri;

    /**
     * Returns the errors designation as a string. The value must be given by the server
     * when the error occures.
     * @return <code>String</code> value of the errors designation / name
     * @see #error
     */
    public String getError(){
        return error;
    }

    /**
     * Sets the name or designation of the occured error. The designation is given by the server
     * and can be passed to the exception by this method.
     * @param error <code>String</code> value of the errors designation / name
     * @see #error
     */
    public void setError(String error){
        this.error = error;
    }

    /**
     * Returns the description to this error, if one was given by the server.
     *
     * @return <code>string</code> containing the description of the error
     * @see #errorDescription
     */
    public String getErrorDescription(){
        return errorDescription;
    }

    /**
     * Sets the description for this error, if one was given by the server.
     *
     * @param errorDescription <code>string</code> containing the description of the error
     * @see #errorDescription
     */
    public void setErrorDescription(String errorDescription){
        this.errorDescription = errorDescription;
    }

    /**
     * Returns a uri leading to a detailed description to this error, if one was
     * given by the server.
     * @return <code>string</code> containing the uri to a webpage for this error
     */
    public String getErrorUri(){
        return errorUri;
    }

    /**
     * Sets the uri leading to a detailed description to this error, if one was
     * given by the server.
     *
     * @param errorUri <code>string</code> containing the uri to a webpage for this error
     */
    public void setErrorUri(String errorUri){
        this.errorUri = errorUri;
    }

    /**
     * Creates a new instance of <code>OAuthException</code> without detail message.
     */
    public OAuthException(){
    }

    /**
     * Constructs an instance of <code>OAuthException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public OAuthException(String msg){
        super(msg);
    }
}
