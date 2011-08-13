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
package org.gerstner.oauth2android;

/**
 * The <code>Server</code> class contains all necessary information on the
 * service providers urls and a few preferences regarding the behavior of the
 * server.<br>
 * All urls and other informations for this class can be found in the service
 * providers documentation. Essential to the OAuth flow are the three urls
 * leading to the service providers endpoints. As there are:
 * <ul>
 * <li> authorization endpoint - Url to the {@link #authorizationServer} where the
 * client requests authorization from the resource owner</li>
 * <li> token endpoint - Url to the {@link #accessTokenServer} where the client
 * presents his authorization and changes it for an access token</li>
 * <li>resource endpoint - Url leading to the {@link #resourceServer} where the client
 * presents his access token to gain access to the protected resources he requested</li>
 * </ul>
 * All these urls should be definite and complete but without any optional parameters
 * for they will be included in the request in another manner.<br>
 * <pre>
 * <b>Example urls:</b><br>
 * authorization endpoint =  "https://login.example.com"
 * token endpoint = "https://www.example.com/token"
 * resourece endpoint = "https://www.example.com/resource"
 * </pre>
 * @see #accessTokenServer
 * @see #authorizationServer
 * @see #resourceServer
 * @see #preferredHttpMethod
 * @see #useAuthorizationHeader
 *
 * @author Christoph Gerstner <development@christoph-gerstner.de>
 */
public class Server{

    /**
     * The authorization endpoint is the server, that is capable of issuing the
     * authorization from the resource owner - it may be the same endpoint as the
     * access token server
     * @see #accessTokenServer
     * @see #resourceServer
     */
    private String authorizationServer;
    /**
     * The server issuing access tokens to the client after successfully authenticating
     * the resource owner and obtaining authorization. May be the same endpoint as
     * the authorization server.
     * @see #authorizationServer
     * @see #resourceServer
     */
    private String accessTokenServer;
    /**
     * The server hosting the protected resources, capable of accepting access tokens
     * and responding to protected resource requests.
     * @see #accessTokenServer
     * @see #authorizationServer
     */
    private String resourceServer;
    /**
     * Flag to indicate if the server preferres the use of the "Authorization" Http-Header.
     * Set to true by default - since the server MUST be capable of accepting authorization
     * through the header.
     */
    private boolean useAuthorizationHeader;
    /**
     * Flag indicating the preferred Http Method (GET, POST ...) for resource operation.
     * Standardized values are available in the {@link org.gerstner.oauth2android.common.Connection} class.
     */
    private String preferredHttpMethod;

    /**
     * Constructs a newly allocated <code>Server</code> object holding all neccessary endpoint urls.
     * @param authorizationServer <code>string</code> representation of the {@link #authorizationServer} url
     * @param accessTokenServer <code>string</code> representation of the {@link #accessTokenServer} url
     * @param resourceServer <code>string</code> representation of the {@link #resourceServer} url
     */
    public Server(String authorizationServer, String accessTokenServer, String resourceServer){
        setAuthorizationServer(authorizationServer);
        setAccessTokenServer(accessTokenServer);
        setResourceServer(resourceServer);
        this.useAuthorizationHeader = true;
    }

    /**
     * Returns the <code>string</code> representation of the access tokens endpoint.
     * @see #accessTokenServer
     * @return <code>string</code> of the access token server url
     */
    public String getAccessTokenServer(){
        return accessTokenServer;
    }

    /**
     * Sets the access tokens server url, given by the value of the input <code>string</code>.
     * @param accessTokenServer the access token endpoint
     */
    public void setAccessTokenServer(String accessTokenServer){
        this.accessTokenServer = accessTokenServer.endsWith("/") ? accessTokenServer.substring(0, accessTokenServer.length() - 1) : accessTokenServer;
    }

    /**
     * Returns the <code>string</code> representation of the authorization endpoint.
     * @see #authorizationServer
     * @return <code>string</code> of the authorization server url
     */
    public String getAuthorizationServer(){
        return authorizationServer;
    }

    /**
     * Sets the authorization server url, given by the value of the input <code>string</code>.
     * @param authorizationServer the authorization endpoint
     */
    public void setAuthorizationServer(String authorizationServer){
        this.authorizationServer = authorizationServer.endsWith("/") ? authorizationServer.substring(0, authorizationServer.length() - 1) : authorizationServer;
    }

    /**
     * Returns the <code>string</code> representation of the resource endpoint.
     * @see #resourceServer
     * @return <code>string</code> of the resourece server url
     */
    public String getResourceServer(){
        return resourceServer;
    }

    /**
     * Sets the resource server url, given by the value of the input <code>string</code>.
     * @param resourceServer the resource endpoint
     */
    public void setResourceServer(String resourceServer){
        this.resourceServer = resourceServer.endsWith("/") ? resourceServer.substring(0, resourceServer.length() - 1) : resourceServer;
    }

    /**
     * May be set to false to force the client to include the access token in the
     * requests url or request body instead of using the http "Authorization" request header.
     * This flag is set to true by default.
     * @see #useAuthorizationHeader
     * @param useHeader <code>true</code> to use the authorization header, <code>false</code> otherwise
     */
    public void useAuthorizationHeader(boolean useHeader){
        this.useAuthorizationHeader = useHeader;
    }

    /**
     * Returns the state of the authorization header flag {@link #useAuthorizationHeader}.
     * If not changed, this flag is set to <code>true</code> by  default.
     * @return <code>true</code> if the client can use the http "Authorization" request header, <code>false</code> otherwise
     */
    public boolean useAuthorizationHeader(){
        return this.useAuthorizationHeader;
    }

    /**
     * Returns the preferred Http Method (GET, POST, ... ) for the protected resource
     * request.
     * @see org.gerstner.oauth2android.common.Connection#HTTP_METHOD_DELETE
     * @see org.gerstner.oauth2android.common.Connection#HTTP_METHOD_GET
     * @see org.gerstner.oauth2android.common.Connection#HTTP_METHOD_POST
     * @see org.gerstner.oauth2android.common.Connection#HTTP_METHOD_PUT
     * @return <code>string</code> indicating the preferred http method
     */
    public String getPreferredHttpMethod(){
        return preferredHttpMethod;
    }

    /**
     * Sets the preferred Http Method (GET, POST, ... ) for the protected resource
     * request.
     * @see org.gerstner.oauth2android.common.Connection#HTTP_METHOD_DELETE
     * @see org.gerstner.oauth2android.common.Connection#HTTP_METHOD_GET
     * @see org.gerstner.oauth2android.common.Connection#HTTP_METHOD_POST
     * @see org.gerstner.oauth2android.common.Connection#HTTP_METHOD_PUT
     * @param preferredHttpMethod
     */
    public void setPreferredHttpMethod(String preferredHttpMethod){
        this.preferredHttpMethod = preferredHttpMethod;
    }
}
