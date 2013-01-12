/*
 * The MIT License
 *
 * Copyright (c) 2004-2009, Sun Microsystems, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.jenkinsci.plugins.url_auth;

import hudson.Extension;
import hudson.model.Descriptor;
import hudson.security.AbstractPasswordBasedSecurityRealm;
import hudson.security.GroupDetails;
import hudson.security.SecurityRealm;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.AuthenticationServiceException;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.userdetails.User;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.kohsuke.stapler.DataBoundConstructor;
import org.springframework.dao.DataAccessException;

/**
 *
 * @author Kelly Elton
 * @since 2013
 * @see http://www.kellyelton.com/
 */
public class UrlSecurityRealm extends AbstractPasswordBasedSecurityRealm {

    public final String loginUrl;
    public final String successString;
    public final int successResponse;
    public final Boolean useResponseCode;
    
    public HttpURLConnection testConnection;
    
    @DataBoundConstructor
    public UrlSecurityRealm(String loginUrl, Boolean useResponseCode, String successString, int successResponse) {
            this.loginUrl = loginUrl;
            this.successString = successString;
            this.successResponse = successResponse;
            this.useResponseCode = useResponseCode;
    }
    
    @Override
    protected UserDetails authenticate(String username, String password) throws AuthenticationException {
        try{
            if(username == null || password == null || username.trim().isEmpty() || password.trim().isEmpty())
            {
                throw new BadCredentialsException("Username or password can't be empty.");
            }
            String urlString = loginUrl.replace("[username]", username)
                    .replace("[password]", password);
            //System.out.println(urlString);
            URL iurl = new URL(urlString);
            HttpURLConnection uc;
            if(testConnection == null) {
                uc = (HttpURLConnection)iurl.openConnection();
            }
            else {
                uc = testConnection;
            }
            uc.connect();
            if(this.useResponseCode)
            {
                int response = uc.getResponseCode();
                uc.disconnect();
                if(response != successResponse) {
                    throw new BadCredentialsException(String.format("Response %d didn't match %d", response ,this.successResponse));
                }
            }
            else
            {
                BufferedReader in = new BufferedReader(
                                new InputStreamReader(uc.getInputStream()));
                
                String matchLine = in.readLine().toLowerCase();
                String inputLine;
                while ((inputLine = in.readLine()) != null) 
                {
                    System.out.println(inputLine);
                    matchLine = matchLine.concat(inputLine);
                }
                matchLine = matchLine.trim().toLowerCase();
                System.out.println(matchLine);
                in.close();
                uc.disconnect();
                if(matchLine == null ? this.successString.toLowerCase() != null : !matchLine.equals(this.successString.toLowerCase()))
                {
                    throw new BadCredentialsException(String.format("Response %s didn't match %s", matchLine ,this.successString));
                }
            }
            GrantedAuthority[] groups = new GrantedAuthority[0];
            UserDetails d = new User(username, password, true, true, true, true, groups);
            return d;
        }
        catch(Exception e){
            throw new AuthenticationServiceException("Failed",e);
        }
    }

    @Override
    public UserDetails loadUserByUsername(String string) throws UsernameNotFoundException, DataAccessException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public GroupDetails loadGroupByGroupname(final String groupname) throws UsernameNotFoundException, DataAccessException {
        return new GroupDetails() {
                public String getName() {
                        return groupname;
                }
        };
    }
    
	@Extension
	public static final class DescriptorImpl extends Descriptor<SecurityRealm> {
		public String getDisplayName() {
			return "Authenticate using a URL";
		}
	}
}
