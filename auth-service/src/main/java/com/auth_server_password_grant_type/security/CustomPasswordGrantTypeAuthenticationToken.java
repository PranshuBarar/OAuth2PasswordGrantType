package com.auth_server_password_grant_type.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;
import org.springframework.util.StringUtils;

import java.util.Map;
import java.util.Set;

public class CustomPasswordGrantTypeAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {

	private final String email;
	private final String password;
	private final String scope;

	protected CustomPasswordGrantTypeAuthenticationToken(
			String granttype,
			Authentication clientPrincipal, 
			Map<String, Object> additionalParameters) {
		super(new AuthorizationGrantType(granttype), clientPrincipal, additionalParameters);
		this.email = (String) additionalParameters.get(OAuth2ParameterNames.USERNAME);
		this.password = (String) additionalParameters.get(OAuth2ParameterNames.PASSWORD);
		this.scope = (String) additionalParameters.get(OAuth2ParameterNames.SCOPE);
		if (this.scope == null) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_SCOPE);
		}
	}

	public String getEmail() {
		return this.email;
	}

	public String getPassword() {
		return this.password;
	}
	
	public Set<String> getScope() {
		return StringUtils.commaDelimitedListToSet(scope.replace(" ", ""));
	}

}
