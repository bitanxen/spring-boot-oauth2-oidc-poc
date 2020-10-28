package in.bitanxen.poc.config.filter;

import com.google.common.base.Strings;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import in.bitanxen.poc.config.openid.JWTBearerAssertionAuthenticationToken;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.exceptions.BadClientCredentialsException;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.text.ParseException;

@Log4j2
public class JWTBearerClientAssertionTokenEndpointFilter extends AbstractAuthenticationProcessingFilter {

    private final AuthenticationEntryPoint authenticationEntryPoint = new OAuth2AuthenticationEntryPoint();

    public JWTBearerClientAssertionTokenEndpointFilter(RequestMatcher additionalMatcher) {
        super(new ClientAssertionRequestMatcher(additionalMatcher));
        ((OAuth2AuthenticationEntryPoint) authenticationEntryPoint).setTypeName("Form");
    }

    @Override
    public void afterPropertiesSet() {
        super.afterPropertiesSet();
        setAuthenticationFailureHandler(new AuthenticationFailureHandler() {
            @Override
            public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                                AuthenticationException exception) throws IOException, ServletException {
                if (exception instanceof BadCredentialsException) {
                    exception = new BadCredentialsException(exception.getMessage(), new BadClientCredentialsException());
                }
                authenticationEntryPoint.commence(request, response, exception);
            }
        });
        setAuthenticationSuccessHandler((request, response, authentication) -> {
            // no-op - just allow filter chain to continue to token endpoint
        });
    }


    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        String assertionType = request.getParameter("client_assertion_type");
        String assertion = request.getParameter("client_assertion");

        try {
            JWT jwt = JWTParser.parse(assertion);

            String clientId = jwt.getJWTClaimsSet().getSubject();

            log.info("Attempting Authentication for {}", clientId);

            Authentication authRequest = new JWTBearerAssertionAuthenticationToken(jwt);

            return this.getAuthenticationManager().authenticate(authRequest);
        } catch (ParseException e) {
            throw new BadCredentialsException("Invalid JWT credential: " + assertion);
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                            FilterChain chain, Authentication authResult) throws IOException, ServletException {
        super.successfulAuthentication(request, response, chain, authResult);
        chain.doFilter(request, response);
    }

    private static class ClientAssertionRequestMatcher implements RequestMatcher {

        private final RequestMatcher additionalMatcher;

        public ClientAssertionRequestMatcher(RequestMatcher additionalMatcher) {
            this.additionalMatcher = additionalMatcher;
        }

        @Override
        public boolean matches(HttpServletRequest request) {
            // check for appropriate parameters
            String assertionType = request.getParameter("client_assertion_type");
            String assertion = request.getParameter("client_assertion");

            if (Strings.isNullOrEmpty(assertionType) || Strings.isNullOrEmpty(assertion)) {
                return false;
            } else if (!assertionType.equals("urn:ietf:params:oauth:client-assertion-type:jwt-bearer")) {
                return false;
            }

            return additionalMatcher.matches(request);
        }

    }
}
