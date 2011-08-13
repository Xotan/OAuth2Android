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

import java.io.EOFException;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.io.StreamCorruptedException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Christoph Gerstner <development@christoph-gerstner.de>
 */
public abstract class Token
    implements Serializable {

    public static final int VALID_INDEFINITELY = -1;
    public static final int VALID_NOT_SET = 0;
    private String token;
    private String scope;
    private long secondsValid;
    private long created;
    private String type;
    private Map<String, String> additionalParameters;

    /**
     * Creates a new -empty- Instance of a Token. This constructor should not be used.
     * @see #Token(java.lang.String)
     * @see #Token(java.lang.String, java.lang.String)
     * @see #Token(java.lang.String, java.lang.String, long)
     * @see #Token(java.lang.String, java.lang.String, long, java.lang.String) 
     * @see BearerToken
     * @see MacToken
     */
    public Token() {
    }

    /**
     * Creates a new Instance of a Token. <br>
     * Every token has a String representing the token itself. It can contain
     * letters, numbers or special characters.<br>
     * Some token may contain more information than the token key, for example
     * a secret to encrypt the token. Please see the service providers specifications
     * to find a more suitable constructor.
     *
     * @param token String of the token itself
     *
     * @see #Token(java.lang.String, java.lang.String)
     * @see #Token(java.lang.String, java.lang.String, long)
     * @see #Token(java.lang.String, java.lang.String, long, java.lang.String)
     * @see BearerToken
     * @see macToken
     */
    public Token(String token) {
        this.token = token;
        this.scope = "";
        this.secondsValid = -1;
        this.created = System.currentTimeMillis() / 1000;
    }

    /**
     * Creates a new Instance of a Token. <br>
     * Every token has a String representing the token itself. It can contain
     * letters, numbers or special characters.
     * Depending on the service providers specification, a token may have a special
     * scope of resources it can access. A scope is always
     * represented by a series of concatenated strings seperated by a whitespace.
     * There are no standards specified in the OAuth2.0 protocoll on how the scope
     * of a token should be defined. Definition and range of a scope should be explained
     * by the service provider.
     * @param token String of the token itself
     * @param scope String defining the scope of the token (optional - see service provider for details)
     *
     * @see #Token(java.lang.String)
     * @see #Token(java.lang.String, java.lang.String, long)
     * @see #Token(java.lang.String, java.lang.String, long, java.lang.String)
     * @see BearerToken
     * @see MacToken
     */
    public Token(String token, String scope) {
        this.token = token;
        this.scope = scope;
        this.secondsValid = -1;
        this.created = System.currentTimeMillis() / 1000;
    }

    /**
     * Creates a new Instance of a Token. <br>
     * Every token has a String representing the token itself. It can contain
     * letters, numbers or special characters.
     * Depending on the service providers specification, a token may have a special
     * scope of resources it can access. A scope is always
     * represented by a series of concatenated strings seperated by a whitespace.
     * There are no standards specified in the OAuth2.0 protocoll on how the scope
     * of a token should be defined. Definition and range of a scope should be explained
     * by the service provider.<br>
     * Most tokens have a predefined lifetime, so that they are not valid for ever
     * and the chances of abuse of the token can be limited.
     * @param token String of the token itself
     * @param scope String defining the scope of the token (optional - see service provider for details)
     * @param secondsValid number of seconds the token will be valid (optional)
     *
     * @see #Token(java.lang.String)
     * @see #Token(java.lang.String, java.lang.String)
     * @see #Token(java.lang.String, java.lang.String, long, java.lang.String)
     * @see BearerToken
     * @see MacToken
     */
    public Token(String token, String scope, long secondsValid) {
        this.token = token;
        this.scope = scope;
        this.secondsValid = secondsValid;
        this.created = System.currentTimeMillis() / 1000;
    }

    /**
     * Creates a new Instance of a Token. <br>
     * Every token has a String representing the token itself. It can contain
     * letters, numbers or special characters.
     * Depending on the service providers specification, a token may have a special
     * scope of resources it can access. A scope is always
     * represented by a series of concatenated strings seperated by a whitespace.
     * There are no standards specified in the OAuth2.0 protocoll on how the scope
     * of a token should be defined. Definition and range of a scope should be explained
     * by the service provider.<br>
     * Most tokens have a predefined lifetime, so that they are not valid for ever
     * and the chances of abuse of the token can be limited.<br>
     * It is possible to define, what kind of token is used. The standard type of a token is <italic>Bearer</italic>,
     * there are however more types as for example <italic> MAC-Tokens</italic> or <italic>SAML-Bearer-Tokens</italic>.
     * Defining the type of a token does not define the corresponding subclass of this token class. It is recommended to
     * use an appropriate subclass or, if not implemented yet, define a new class, depending on the type of token the provider expects.<br>
     * 
     * @param token String of the token itself
     * @param scope String defining the scope of the token (optional - see service provider for details)
     * @param secondsValid number of seconds the token will be valid (optional)
     * @see #Token(java.lang.String)
     * @see #Token(java.lang.String, java.lang.String)
     * @see #Token(java.lang.String, java.lang.String, long)
     * @see BearerToken
     * @see MacToken
     */
    public Token(String token, String scope, long secondsValid, String type) {
        this.token = token;
        this.type = type;
        this.scope = scope;
        this.secondsValid = secondsValid;
        this.created = System.currentTimeMillis() / 1000;
    }

    // TODO: load and save token funktioniert nich mit parentClass!!!
    /**
     * Creates a new Token by reading a FileInputStream. If a token was searialized
     * and saved into a file by using the Token classes method <code>writeToFileOutputStream()</code>
     * or by using a similar method as for example serializing the Token object
     * with ObjectOutputStream, this method can read the Token back from a FileInputStream.<br>
     * <code>
     * <p>
     * <b>Example:</b><br>
     * <i>saving a token:</i><br>
     * FileOutputStream outputStream = new FileOutputStream("path/to/myFile");<br>
     * myToken.writeToFileOutputStream(outputStream);<br>
     * <br>
     * <i>reading a token:</i><br>
     * FileInputStream inputStream = new FileInputStream("path/to/myFile");<br>
     * Token myToken = new Token(inputStream);<br>
     * </p>
     * </code>
     *
     * @param fileInputStream inputStream from the file containing the token
     * @throws IOException if an error occures while reading the inputStream
     * @throws ClassNotFoundException if the stream does not contain a proper token
     */
    public Token(FileInputStream fileInputStream)
        throws IOException, ClassNotFoundException {
        ObjectInputStream objectInputStream = null;
        try {
            try {
                //Construct the ObjectInputStream object
                objectInputStream = new ObjectInputStream(fileInputStream);
            } catch (StreamCorruptedException ex) {
                Logger.getLogger(Token.class.getName()).log(Level.SEVERE, null, ex);
            } catch (IOException ex) {
                Logger.getLogger(Token.class.getName()).log(Level.SEVERE, null, ex);
            }

            Object object = null;
            while ((object = objectInputStream.readObject()) != null) {

                if (object instanceof Token) {
                    Token readToken = (Token) object;
                    this.created = readToken.getCreated();
                    this.token = readToken.getToken();
                    this.scope = readToken.getScope();
                    this.secondsValid = readToken.getSecondsValid();
                    this.type = readToken.getType();
                    this.additionalParameters = readToken.getAdditionalParameters();
                }
            }
        } catch (EOFException ex) {
            //This exception will be caught when EOF is reached
        } finally {
            //Close the ObjectInputStream
            try {
                if (objectInputStream != null) {
                    objectInputStream.close();
                }
            } catch (IOException ignored) {
            }
        }
    }

    /**
     * Returns the token string itself. This is only the key value of the token
     * and is not related to the toString() method. Every token must have a key value
     * otherwise the token is empty.
     * @return key value of the token as a String
     */
    public String getToken() {
        if (this.token == null) {
            this.token = "";
        }
        return token;
    }

    /**
     * Sets the key of a token. Every token MUST have a key, it is the tokens value
     * itself. Without the key the token is empty.
     * @param token
     */
    public void setToken(String token) {
        this.token = token;
    }

    /**
     * Some tokens have a predefined lifetime, so that they are not valid for ever
     * and the chances of abuse of the token can be limited.
     * If the lifetime of the token was predefined this method returns the number
     * of seconds the token was supposed to be valid.
     * If the lifetime of the token is
     * unlimited or no predefined lifetime was set a <code>-1</code> is returned. <br>
     * This is not the actual number of seconds
     * the token is still valid. To determine if a token is still valid use the <code> isValid()</code>
     * method.
     * @return number of seconds this token was supposed to be valid.
     */
    public long getSecondsValid() {
        return secondsValid;
    }

    /**
     * Sets the number of seconds a token is supposed to be valid from the beginning
     * of its creation. If no lifetime for the token was set, the default is <code>0</code>.
     * For an unlimited lifetime set the number of seconds to -1 (default);
     * @param secondsValid number of seconds the token is valid
     */
    public void setSecondsValid(long secondsValid) {
        this.created = System.currentTimeMillis() / 1000;
        this.secondsValid = secondsValid;
    }

    /**
     * Returns the creation time (seconds passed since January 1, 1970)
     * This method is especially usefull when using the mac-token type and
     * calculating the age of the token
     * @return long time of creation in seconds
     */
    public long getCreated() {
        return this.created;
    }

    /**
     * Returns alle scopes concatenated into one single string, sepperated by a
     * whitespace character (according to the specifications)
     * @return string concatenated scopes
     */
    public String getScope() {
        if (this.scope == null) {
            this.scope = "";
        }
        return this.scope;
    }

    /**
     * To set the scope with one single string. Either it is only one scope or
     * it containes many scopes seperated by a whitespace character (according
     * to the specifications) [Facebook for example uses commas for seperating
     * scopes]
     * Any previously specified scope will be replaced by this string. To simply
     * add a scope to the existing one use {@link #addScope(java.lang.String)}
     * @param scope string containing the scope
     * @see #addScope(java.lang.String)
     */
    public void setScope(String scope) {
        this.scope = scope;
    }

    /**
     * Adds an additional scope at the end of the existing one. If no scope was
     * set before a new scope will be created. All scopes will be seperated
     * by a whitespace character (according to the specification).<br>
     * If you are using facebook you might need to seperate the scopes with a
     * comma and use {@link #setScope(java.lang.String)} insetead.
     * Please refere to your service providers api documentation.
     * @param scope string with additional scope
     */
    public void addScope(String scope) {
        if (this.scope == null || this.scope.isEmpty()) {
            this.scope = scope;
        } else {
            this.scope += " " + scope;
        }
    }

    /**
     * Returns the type of the <code>Token</code> as a String.
     * e.g. <code>bearer</code> or <code>mac</code>
     * @return string naming the tokens type
     */
    public String getType() {
        if (this.type == null) {
            this.type = "";
        }
        return type;
    }

    /**
     * Sets the type of the <code>Token</code>. Normaly it should not be
     * neccessary to call this method manualy, since the
     * {@link org.gerstner.oauth2android.response.Response} class detects wich
     * type is used and sets this parameter automatically. (currently the
     * bearer and the mac type are supported)
     * @param type string naming the tokens type
     */
    public void setType(String type) {
        this.type = type;
    }

    /**
     * returns a <code>Map</code> containing additional parameters or this token.
     * E.g. if it is a {@link org.gerstner.oauth2android.token.BearerToken}, this
     * method will return an empty map, since this token type does not need any
     * additional parameters. A {@link org.gerstner.oauth2android.token.MacToken}
     * on the other needs the parameters <it>secret</it> and <it>algorithm</it>
     * @return map<String, String> with additional token parameters
     */
    public Map<String, String> getAdditionalParameters() {
        return additionalParameters;
    }

    /**
     * Sets a map of additional parameters for the token. It is a HashMap containing
     * to Strings (name and value) for each parameter item.
     * @param additionalParameters map<string, string>
     * @see #addAdditionalParameter(java.lang.String, java.lang.String)
     */
    public void setAdditionalParameters(Map<String, String> additionalParameters) {
        this.additionalParameters = additionalParameters;
    }

    /**
     * Adds an additional parameter to the token. If the map is empty or does not
     * contain any parameters, a new map will be created with the given parameter
     * as its first value/name pair. To get a list of needed parameters for this
     * tokens type see the according {@link org.gerstner.oauth2android.token.TokenTypeDefinition}
     * @param name string containing the name of the parameter
     * @param value string with the parameters value
     */
    public void addAdditionalParameter(String name, String value) {
        if (this.additionalParameters == null || this.additionalParameters.isEmpty()) {
            this.additionalParameters = new HashMap<String, String>(1);
        }
        this.additionalParameters.put(name, value);
    }

    /**
     * Determines if the token is still valid of if the predefined lifetime of
     * the token since its creation has passed.
     * This method will return true under the following circumstances:<br>
     *  i) the number of seconds passed since the creation of the token is
     * smaller than or equal to the number of seconds the token was supposed to be valid.<br>
     *  ii) the number of seconds the token is supposed to be valid equals -1 (unlimited or undefined)<br>
     * @return true if token is still valid, if no lifetime was set or if lifetime is unlimited, false otherwise
     */
    public boolean isValid() {
        if (this.getSecondsValid() == -1) {
            return true;
        }
        return (System.currentTimeMillis() / 1000 - created) <= this.getSecondsValid();
    }

    /**
     * Returns a String containing informations about this token. Note that
     * the additional parameters (if any) won't be included. To get a Map
     * containing all additional parameters see {@link #getAdditionalParameters()}
     * <br>
     * This method cannot be used for authentification purposes.
     * @return String with informations about this token
     */
    @Override
    public String toString() {
        return "Token [key=" + this.getToken() + ", Type=" + this.getType() + ", secondsValid=" + this.getSecondsValid() + ", valid=" + this.isValid() + "] ";
    }

    /**
     * Writes the token to the given FileOutputStream. <br>
     * This method can be used in order to write Tokens into a file to store them
     * for further usage. Especialy if this Token is a RefreshToken it should be
     * saved until the current AccessToken is no longer valid.<br>
     * <code>
     * <p>
     * <b>Example:</b><br>
     * <i>saving a token:</i><br>
     * FileOutputStream outputStream = new FileOutputStream("path/to/myFile");<br>
     * myToken.writeToFileOutputStream(outputStream);<br>
     * <br>
     * <i>reading a token:</i><br>
     * FileInputStream inputStream = new FileInputStream("path/to/myFile");<br>
     * Token myToken = new Token(inputStream);<br>
     * </p>
     * </code>
     *
     * @param fileOutputStream the Stream this Token should be written into.
     * @throws IOException if an error occures while writing.
     */
    public void writeToFileOutputStream(FileOutputStream fileOutputStream)
        throws IOException {

        ObjectOutputStream objectOutputStream = null;
        try {
            objectOutputStream = new ObjectOutputStream(fileOutputStream);
            objectOutputStream.writeObject(this);
        } catch (IOException ioException) {
            throw ioException;
        } finally {
            if (fileOutputStream != null) {
                try {
                    fileOutputStream.flush();
                    fileOutputStream.close();
                } catch (IOException ex) {
                    Logger.getLogger(Token.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        }
    }

    /**
     * Compares this token with another token by comparing each parameter.
     * @param object
     * @return <code>boolean</code> true if the two are equal, false otherwise
     */
    @Override
    public boolean equals(Object object) {
        boolean equal = false;
        Token tokenObject = (Token) object;
        equal = this.token.compareTo(tokenObject.token) == 0
                && this.created == tokenObject.created
                && this.scope.compareTo(tokenObject.scope) == 0
                && this.type.equalsIgnoreCase(tokenObject.type);

        Set<String> keys = this.additionalParameters.keySet();
        Map<String, String> map = tokenObject.getAdditionalParameters();
        for(String key : keys){
            equal &= map.containsKey(key);
            equal &= map.get(key).equalsIgnoreCase(this.additionalParameters.get(key));
        }
        return equal;
    }
}
