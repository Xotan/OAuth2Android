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
package org.gerstner.oauth2android.common;

import java.util.ArrayList;
import java.util.Iterator;

import org.apache.http.NameValuePair;
import org.apache.http.message.BasicNameValuePair;

/**
 * The ParameterList class extends the <code>ArrayList<NameValuePair> </code> for the sole
 * purpose to make the handling of parameters easier.
 * <pre>
 * Instead of instantiating a List like this:
 *   <code>List&lt;NameValuePair&gt; myList = new ArrayList&lt;NameValuePair&gt;()</code>
 * and adding parameters like this:
 *   <code>myList.add( new BasicNameValuePair( "name", "value" ) );</code><br>
 * it is possible to do the following:
 *   <code>ParameterList myList = new ParameterList();
 *   myList.add("name", "value");</code>
 * </pre>
 * @author Christoph Gerstner <development@christoph-gerstner.de>
 */
public class ParameterList
    extends ArrayList<NameValuePair> {

    public ParameterList() {
        super();
    }

    /**
     * Adds a parameter (a <code>BasicNameValuePair</code>) by its name and value.
     * @param name <code>string</code> including the name
     * @param value <code>string</code> the value of the parameter
     * @return always true
     */
    public boolean add(String name, String value) {
        return super.add(new BasicNameValuePair(name, value));
    }

    /**
     * Adds a parameter (a <code>BasicNameValuePair</code>) by its name and value at the indicated position by moving
     * the original parameter to the next position.
     * @param name <code>string</code> including the name
     * @param value <code>string</code> the value of the parameter
     * @param index <code>int</code> value of the index, where the parameter is to be put
     */
    public void add(int index, String name, String value) {
        super.add(index, new BasicNameValuePair(name, value));
    }

    @Override
    public void clear() {
        super.clear();
    }

    /**
     * Returns the value of the parameter at the specified index.
     * @param index <code>int</code> value of the position
     * @return <code>string</code> value of the parameter
     */
    public String getValueAt(int index) {
        return super.get(index).getValue();
    }

    @Override
    public boolean isEmpty() {
        return super.isEmpty();
    }

    @Override
    public Iterator<NameValuePair> iterator() {
        return super.iterator();
    }

    @Override
    public NameValuePair remove(int index) {
        return super.remove(index);
    }

    /**
     * Sets a parameter (a <code>BasicNameValuePair</code>) by its name and value at the indicated position by replacing
     * the original parameter.
     * @param index <code>int</code> value of the position
     * @param name <code>string</code> name of the parameter
     * @param value <code>string</code> value of the parameter
     */
    public void set(int index, String name, String value) {
        super.set(index, new BasicNameValuePair(name, value));
    }

    @Override
    public int size() {
        return super.size();
    }
}
