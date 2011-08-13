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

import org.gerstner.oauth2android.token.Token;

/**
 * In OAuth 2.0 the client is the actual application requesting access to the
 * protected resources of the resource owner. Therefor the service provider
 * needs to assign a unique id to the client {@link #clientId} and if necessary
 * a secret {@link #clientSecret}, shared only
 * between client and server, to identify the client (client credentials).
 * After successful identification,
 * the client can request access to the resources, for wich he needs the
 * authorization from the resource owner in form of an access token.
 *
 * This class can contain all necessary parameters regarding the client and
 * its authentification towards the server.
 *
 * @see org.gerstner.oauth2android.Server
 * @see org.gerstner.oauth2android.token.Token
 * @see org.gerstner.oauth2android.token.TokenTypeDefinition
 *
 * @author Christoph Gerstner <development@christoph-gerstner.de>
 */
public class Client{

    /**
     * Access token the client can use to gain access to the protected resources.
     * @see org.gerstner.oauth2android.token.TokenTypeDefinition
     */
    private Token accessToken;
    /**
     * Refresh token the client may use to request a new access token, if the
     * previous access token is no longer valid and if the service provider issued
     * a refresh token together with the previous access token.
     */
    private Token refreshToken;
    /**
     * Unique id, identifying the client towards the service provider. It is usually
     * a large randomlike string issued by the service provider after the registration process.
     * The client id can not be used to gain access to the protected resources on its own.
     * Only in combination with an access token or under special circumstances with
     * a client secret<br>
     * The client id may be issued together with a secret.
     * @see #clientSecret
     */
    private String clientId;
    /**
     * The client secret is a shared symetric secret to authenticate the client
     * towards the server. Some service providers may issue a secret for the client
     * to request an access token for the clients own resources. See the OAuth 2.0
     * specification for more details.
     * @see #clientId
     */
    private String clientSecret;
    /**
     * The redirect uri ist an url the client gets redirected to after each request.
     * For installed applications (or mobile applications) the redirect uri is
     * mostly not a real url directing to a webpage, but a string signaling the
     * server that the client is not capable of redirecting to a webpage. This may
     * be singnaled through the string "oob" (out-of-band).
     * Therefor the client doesn't call the uri on its own but transmits it together
     * with its client credentials.
     * @see Server
     */
    private String redirectUri;

    /**
     * Constructs a newly allocated <code>Client</code> object including all
     * values a <code>Client</code> can hold.
     * @param accessToken <code>token</code> to access the protected resources
     * @param refreshToken <code>token</code> for requesting a new access token
     * @param clientId <code>string</code> identifying the client
     * @param clientSecret <code>string</code> verifying the clients id
     * @param redirectUri <code>string</code> containing the url the client will be redirected to
     */
    public Client(Token accessToken, Token refreshToken, String clientId, String clientSecret, String redirectUri){
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.redirectUri = redirectUri;
    }

    /**
     * Constructs a newly allocated <code>Client</code> object including all
     * values the <code>Client</code> got issued by the service provider.
     *
     * @param clientId <code>string</code> identifying the client
     * @param clientSecret <code>string</code> verifying the clients id
     * @param redirectUri <code>string</code> containing the url the client will be redirected to
     */
    public Client(String clientId, String clientSecret, String redirectUri){
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.redirectUri = redirectUri;
    }

    /**
     * Returns the {@link #redirectUri} the client needs to include in every request.
     * @return the redirect uri <code>string</code>
     */
    public String getRedirectUri(){
        return redirectUri;
    }

    /**
     * Sets the {@link #redirectUri} the client needs to include in every request.
     * @param redirectUri <code>string</code> specifying the redirect uri
     */
    public void setRedirectUri(String redirectUri){
        this.redirectUri = redirectUri;
    }

    /**
     * Returns the current access token for the client to make authorized requests
     * to the resource server ({@link Server#resourceServer}).
     *
     * @return the access token
     * @see org.gerstner.oauth2android.token.BearerToken 
     * @see org.gerstner.oauth2android.token.MacToken
     * @see org.gerstner.oauth2android.token.TokenTypeDefinition
     */
    public Token getAccessToken(){
        return accessToken;
    }

    /**
     * Sets the current access token for the client to make authorized requests
     * to the resource server ({@link Server#resourceServer}).
     *
     * @param accessToken current <code>token</code> used to gain access to the server
     * @see org.gerstner.oauth2android.token.BearerToken
     * @see org.gerstner.oauth2android.token.MacToken
     * @see org.gerstner.oauth2android.token.TokenTypeDefinition
     */
    public void setAccessToken(Token accessToken){
        this.accessToken = accessToken;
    }

    /**
     * Returns the {@link #clientId} of this client.
     * @return the clientId <code>string</code>
     * @see #clientSecret
     */
    public String getClientID(){
        return clientId;
    }

    /**
     * Sets the {@link #clientId} of this client.
     *
     * @param  clientID <code>string</code> representing the clients id
     * @see #clientSecret
     */
    public void setClientID(String clientID){
        this.clientId = clientID;
    }

    /**
     * Returns the {@link #clientSecret}
     *
     * @return <code>string</code> representation of the clients secret
     * @see #clientId
     */
    public String getClientSecret(){
        return clientSecret;
    }

    /**
     * Sets the {@link #clientSecret}
     * @param clientSecret <code>string</code> containing the clients secret
     * @see #clientId
     */
    public void setClientSecret(String clientSecret){
        this.clientSecret = clientSecret;
    }

    /**
     * Returns the {@link #refreshToken} for the current {@link #accessToken}
     *
     * @return <code>token</code> to refresh the access token
     * @see org.gerstner.oauth2android.token.BearerToken
     * @see org.gerstner.oauth2android.token.MacToken
     * @see org.gerstner.oauth2android.token.TokenTypeDefinition
     */
    public Token getRefreshToken(){
        return refreshToken;
    }

    /**
     * Sets the {@link #refreshToken} for the current {@link #accessToken}
     * @param refreshToken <code>token</code> to refresh the access token
     * @see org.gerstner.oauth2android.token.BearerToken
     * @see org.gerstner.oauth2android.token.MacToken
     * @see org.gerstner.oauth2android.token.TokenTypeDefinition
     */
    public void setRefreshToken(Token refreshToken){
        this.refreshToken = refreshToken;
    }
}
