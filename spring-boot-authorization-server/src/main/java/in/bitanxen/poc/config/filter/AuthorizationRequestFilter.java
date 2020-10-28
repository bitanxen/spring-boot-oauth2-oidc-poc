package in.bitanxen.poc.config.filter;

import com.google.common.base.Splitter;
import com.google.common.base.Strings;
import in.bitanxen.poc.dto.client.ClientEntityDTO;
import in.bitanxen.poc.service.client.ClientEntityService;
import lombok.extern.log4j.Log4j2;
import org.apache.http.client.utils.URIBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.endpoint.RedirectResolver;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.net.URISyntaxException;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static in.bitanxen.poc.config.openid.ConnectRequestParameters.*;

@Component
@Log4j2
public class AuthorizationRequestFilter extends GenericFilterBean {

    public final static String PROMPTED = "PROMPT_FILTER_PROMPTED";
    public final static String PROMPT_REQUESTED = "PROMPT_FILTER_REQUESTED";
    private final RequestMatcher requestMatcher = new AntPathRequestMatcher("/authorize");

    private final OAuth2RequestFactory authRequestFactory;
    private final RedirectResolver redirectResolver;
    private final ClientEntityService clientEntityService;
    private final LoginHintExtractor loginHintExtractor;

    public AuthorizationRequestFilter(OAuth2RequestFactory authRequestFactory, RedirectResolver redirectResolver, ClientEntityService clientEntityService) {
        this.authRequestFactory = authRequestFactory;
        this.redirectResolver = redirectResolver;
        this.clientEntityService = clientEntityService;
        this.loginHintExtractor = new RemoveLoginHintsWithHTTP();
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {

        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;
        HttpSession session = request.getSession();

        // skip everything that's not an authorize URL
        if (!requestMatcher.matches(request)) {
            chain.doFilter(req, res);
            return;
        }

        Map<String, String> parameterMap = createRequestMap(request.getParameterMap());
        AuthorizationRequest authRequest = authRequestFactory.createAuthorizationRequest(parameterMap);
        ClientEntityDTO clientEntity = null;

        try {
            if (!Strings.isNullOrEmpty(authRequest.getClientId())) {
                clientEntity = clientEntityService.loadClientByClientId(authRequest.getClientId());
            }

            String loginHint = loginHintExtractor.extractHint((String) authRequest.getExtensions().get(LOGIN_HINT));
            if (!Strings.isNullOrEmpty(loginHint)) {
                session.setAttribute(LOGIN_HINT, loginHint);
            } else {
                session.removeAttribute(LOGIN_HINT);
            }

            if (authRequest.getExtensions().get(PROMPT) != null) {
                String prompt = (String)authRequest.getExtensions().get(PROMPT);
                List<String> prompts = Splitter.on(PROMPT_SEPARATOR).splitToList(Strings.nullToEmpty(prompt));

                if (prompts.contains(PROMPT_NONE)) {
                    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
                    if (auth != null) {
                        chain.doFilter(req, res);
                    } else {
                        log.info("Client requested no prompt");
                        if (clientEntity != null && authRequest.getRedirectUri() != null) {
                            String url = redirectResolver.resolveRedirect(authRequest.getRedirectUri(), clientEntity);

                            try {
                                URIBuilder uriBuilder = new URIBuilder(url);

                                uriBuilder.addParameter(ERROR, LOGIN_REQUIRED);
                                if (!Strings.isNullOrEmpty(authRequest.getState())) {
                                    uriBuilder.addParameter(STATE, authRequest.getState()); // copy the state parameter if one was given
                                }

                                response.sendRedirect(uriBuilder.toString());
                                return;

                            } catch (URISyntaxException e) {
                                logger.error("Can't build redirect URI for prompt=none, sending error instead", e);
                                response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access Denied");
                                return;
                            }
                        }
                        response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access Denied");
                        return;
                    }
                } else if(prompts.contains(PROMPT_LOGIN)) {
                    if (session.getAttribute(PROMPTED) == null) {

                        session.setAttribute(PROMPT_REQUESTED, Boolean.TRUE);

                        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
                        if (auth != null) {

                            SecurityContextHolder.getContext().setAuthentication(null);
                            chain.doFilter(req, res);
                        } else {
                            // user hasn't been logged in yet, we can keep going since we'll get there
                            chain.doFilter(req, res);
                        }
                    } else {
                        // user has been PROMPTED, we're fine

                        // but first, undo the prompt tag
                        session.removeAttribute(PROMPTED);
                        chain.doFilter(req, res);
                    }
                } else {
                    chain.doFilter(req, res);
                }

            } else if (authRequest.getExtensions().get(MAX_AGE) != null || (clientEntity != null && clientEntity.getDefaultMaxAge() > 0)) {

                // default to the client's stored value, check the string parameter
                Integer max = (clientEntity != null ? clientEntity.getDefaultMaxAge() : null);
                String maxAge = (String) authRequest.getExtensions().get(MAX_AGE);
                if (maxAge != null) {
                    max = Integer.parseInt(maxAge);
                }

                if (max != null) {

                    Date authTime = (Date) session.getAttribute(AUTH_TIMESTAMP);

                    Date now = new Date();
                    if (authTime != null) {
                        long seconds = (now.getTime() - authTime.getTime()) / 1000;
                        if (seconds > max) {
                            // session is too old, log the user out and continue
                            SecurityContextHolder.getContext().setAuthentication(null);
                        }
                    }
                }
                chain.doFilter(req, res);
            } else {
                // no prompt parameter, not our business
                chain.doFilter(req, res);
            }
        } catch (Exception e) {
            e.printStackTrace();
            // we couldn't find the client, move on and let the rest of the system catch the error
            chain.doFilter(req, res);
        }
    }

    private Map<String, String> createRequestMap(Map<String, String[]> parameterMap) {
        Map<String, String> requestMap = new HashMap<>();
        for (String key : parameterMap.keySet()) {
            String[] val = parameterMap.get(key);
            if (val != null && val.length > 0) {
                requestMap.put(key, val[0]);
            }
        }
        return requestMap;
    }
}
