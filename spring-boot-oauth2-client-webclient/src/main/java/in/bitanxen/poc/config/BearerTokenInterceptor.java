package in.bitanxen.poc.config;

import lombok.extern.log4j.Log4j2;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.http.HttpRequest;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpHeaders.CONTENT_TYPE;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED_VALUE;

@Log4j2
public class BearerTokenInterceptor implements ClientHttpRequestInterceptor {

    private final OAuth2AuthorizedClientService authorizedClientService;
    private final Duration accessTokenExpiresSkew = Duration.ofMinutes(1);

    public BearerTokenInterceptor(OAuth2AuthorizedClientService authorizedClientService) {
        this.authorizedClientService = authorizedClientService;
    }

    @Override
    public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution) throws IOException {

        OAuth2AuthenticationToken authentication = (OAuth2AuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
        OAuth2AuthorizedClient clientRegistration = authorizedClientService
                .loadAuthorizedClient(
                        authentication.getAuthorizedClientRegistrationId(),
                        authentication.getName());
        if (isExpired(clientRegistration.getAccessToken())) {
            log.info("AccessToken expired, refreshing automatically");
            refreshToken(clientRegistration, authentication);
        }
        request.getHeaders().add(AUTHORIZATION, "Bearer "+clientRegistration.getAccessToken().getTokenValue());

        return execution.execute(request, body);
    }

    private void refreshToken(OAuth2AuthorizedClient clientRegistration, OAuth2AuthenticationToken authentication) {
        OAuth2RefreshToken refreshToken = clientRegistration.getRefreshToken();
        if(refreshToken == null) {
            log.warn("Refresh token is null. Cannot get new access token");
            return;
        }

        OAuth2AccessTokenResponse accessTokenResponse = refreshTokenClient(clientRegistration);
        if (accessTokenResponse == null || accessTokenResponse.getAccessToken() == null) {
            log.info("Failed to refresh token for "+authentication.getName());
            return;
        }

        OAuth2RefreshToken oAuth2RefreshToken = accessTokenResponse.getRefreshToken() != null
                ? accessTokenResponse.getRefreshToken() : clientRegistration.getRefreshToken();
        OAuth2AuthorizedClient updatedClient = new OAuth2AuthorizedClient(
                clientRegistration.getClientRegistration(),
                authentication.getName(),
                accessTokenResponse.getAccessToken(),
                oAuth2RefreshToken
        );

        authorizedClientService.saveAuthorizedClient(updatedClient, authentication);
    }

    private OAuth2AccessTokenResponse refreshTokenClient(OAuth2AuthorizedClient clientRegistration) {
        LinkedMultiValueMap<String, String> formParameters = new LinkedMultiValueMap<>();
        formParameters.add(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.REFRESH_TOKEN.getValue());
        formParameters.add(OAuth2ParameterNames.REFRESH_TOKEN, Objects.requireNonNull(clientRegistration.getRefreshToken()).getTokenValue());
        formParameters.add(OAuth2ParameterNames.REDIRECT_URI, clientRegistration.getClientRegistration().getRedirectUriTemplate());

        RequestEntity<LinkedMultiValueMap<String, String>> requestEntity = RequestEntity
                .post(URI.create(clientRegistration.getClientRegistration().getProviderDetails().getTokenUri()))
                .header(CONTENT_TYPE, APPLICATION_FORM_URLENCODED_VALUE)
                .body(formParameters);

        try {
            RestTemplate restTemplate = restTemplate(clientRegistration.getClientRegistration().getClientId(),
                    clientRegistration.getClientRegistration().getClientSecret());
            ResponseEntity<OAuth2AccessTokenResponse> exchange = restTemplate.exchange(requestEntity, OAuth2AccessTokenResponse.class);
            return exchange.getBody();
        } catch (OAuth2AuthorizationException e) {
            log.error("Unable to refresh token "+e.getLocalizedMessage());
            throw e;
        }
    }

    private boolean isExpired(OAuth2AccessToken accessToken) {
        Instant expiresAt = accessToken.getExpiresAt();
        Instant currentInstant = Clock.systemUTC().instant();
        return expiresAt == null || currentInstant.isAfter(expiresAt.minus(this.accessTokenExpiresSkew));
    }

    private RestTemplate restTemplate(String clientId, String clientSecret) {
        return new RestTemplateBuilder()
                .additionalMessageConverters(
                        new FormHttpMessageConverter(),
                        new OAuth2AccessTokenResponseHttpMessageConverter())
                .errorHandler(new OAuth2ErrorResponseErrorHandler())
                .basicAuthentication(clientId, clientSecret)
                .build();
    }
}
