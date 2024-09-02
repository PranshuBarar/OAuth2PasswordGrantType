package com.auth_server_password_grant_type.security;

import com.repo_server_password_grant_type.services.CustomUserDetails;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.util.Assert;

import java.security.Principal;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class CustomPasswordGrantTypeAuthenticationProvider implements AuthenticationProvider {

	private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";
	private static final OAuth2TokenType ID_TOKEN_TOKEN_TYPE = new OAuth2TokenType(OidcParameterNames.ID_TOKEN);
	private final OAuth2AuthorizationService authorizationService;
	private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;

	private final UserDetailsService userDetailsService;
	private final PasswordEncoder passwordEncoder;

	private String email = new String();
	private String password = new String();
	private Set<String> authorizedScopes = new HashSet<>();

	private SessionRegistry sessionRegistry;

	public CustomPasswordGrantTypeAuthenticationProvider(OAuth2AuthorizationService authorizationService,
														 OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator, UserDetailsManager userDetailsService,
														 PasswordEncoder passwordEncoder) {
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		Assert.notNull(tokenGenerator, "tokenGenerator cannot be null");
		this.authorizationService = authorizationService;
		this.tokenGenerator = tokenGenerator;
		this.userDetailsService = userDetailsService;
		this.passwordEncoder = passwordEncoder;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {

		CustomPasswordGrantTypeAuthenticationToken customCodeGrantAuthentication = (CustomPasswordGrantTypeAuthenticationToken) authentication;
		OAuth2ClientAuthenticationToken clientPrincipal = getAuthenticatedClientElseThrowInvalidClient(
				customCodeGrantAuthentication);
		RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();
		email = customCodeGrantAuthentication.getEmail();
		password = customCodeGrantAuthentication.getPassword();
		authorizedScopes = customCodeGrantAuthentication.getScope();
		CustomUserDetails customUserDetails = null;
		try {
			customUserDetails = (CustomUserDetails) userDetailsService.loadUserByUsername(email);
		} catch (UsernameNotFoundException e) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.ACCESS_DENIED);
		}
		if (!passwordEncoder.matches(password, customUserDetails.getPassword()) || !customUserDetails.getUsername().equals(email)) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.ACCESS_DENIED);
		}
		if (!registeredClient.getAuthorizationGrantTypes().contains(customCodeGrantAuthentication.getGrantType())) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
		}
		authorizedScopes.forEach(scope -> {
			if (!registeredClient.getScopes().contains(scope)) {
				throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_SCOPE);
			}
		});
		Authentication usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(customUserDetails, null,
				customUserDetails.getAuthorities());

		DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
				.registeredClient(registeredClient)
				.principal(usernamePasswordAuthenticationToken)
				.authorizationServerContext(AuthorizationServerContextHolder.getContext())
				.authorizedScopes(authorizedScopes)
				.authorizationGrantType(customCodeGrantAuthentication.getGrantType())
				.authorizationGrant(customCodeGrantAuthentication);

		// ----- Now we will generate Access Token here -----
		OAuth2TokenContext tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.ACCESS_TOKEN).build();
		OAuth2Token generatedAccessToken = this.tokenGenerator.generate(tokenContext);
		if (generatedAccessToken == null) {
			OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
					"The token generator failed to generate the access token.", null);
			throw new OAuth2AuthenticationException(error);
		}
		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				generatedAccessToken.getTokenValue(), generatedAccessToken.getIssuedAt(),
				generatedAccessToken.getExpiresAt(), null);

		OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
				.principalName(clientPrincipal.getName())
				.authorizationGrantType(customCodeGrantAuthentication.getGrantType());
		if (generatedAccessToken instanceof ClaimAccessor) {
			authorizationBuilder.token(accessToken,
					(metadata) -> metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME,
							((ClaimAccessor) generatedAccessToken).getClaims()));
		} else {
			authorizationBuilder.accessToken(accessToken);
		}



		Map<String, Object> additionalParameters = Collections.emptyMap();


		OAuth2Authorization authorization = authorizationBuilder
				.accessToken(accessToken)
				.authorizedScopes(authorizedScopes)
				.attribute(Principal.class.getName(), usernamePasswordAuthenticationToken)
				.build();
		this.authorizationService.save(authorization);

		return new OAuth2AccessTokenAuthenticationToken(registeredClient, usernamePasswordAuthenticationToken, accessToken, null, additionalParameters);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return CustomPasswordGrantTypeAuthenticationToken.class.isAssignableFrom(authentication);
	}

	private static OAuth2ClientAuthenticationToken getAuthenticatedClientElseThrowInvalidClient(
			Authentication authentication) {
		OAuth2ClientAuthenticationToken clientPrincipal = null;
		if (OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication.getPrincipal().getClass())) {
			clientPrincipal = (OAuth2ClientAuthenticationToken) authentication.getPrincipal();
		}
		if (clientPrincipal != null && clientPrincipal.isAuthenticated()) {
			return clientPrincipal;
		}
		throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
	}


}
