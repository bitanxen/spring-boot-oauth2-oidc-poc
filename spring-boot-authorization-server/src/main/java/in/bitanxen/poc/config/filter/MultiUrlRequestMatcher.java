package in.bitanxen.poc.config.filter;

import org.springframework.security.web.util.UrlUtils;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import java.util.HashSet;
import java.util.Set;

public class MultiUrlRequestMatcher implements RequestMatcher {
    private final Set<RequestMatcher> matchers;

    public MultiUrlRequestMatcher(Set<String> filterProcessesUrls) {
        this.matchers = new HashSet<>(filterProcessesUrls.size());
        for (String filterProcessesUrl : filterProcessesUrls) {
            Assert.hasLength(filterProcessesUrl, "filterProcessesUrl must be specified");
            Assert.isTrue(UrlUtils.isValidRedirectUrl(filterProcessesUrl), filterProcessesUrl + " isn't a valid URL");
            matchers.add(new AntPathRequestMatcher(filterProcessesUrl));
        }

    }

    @Override
    public boolean matches(HttpServletRequest request) {
        for (RequestMatcher matcher : matchers) {
            if (matcher.matches(request)) {
                return true;
            }
        }

        return false;
    }
}

