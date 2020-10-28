package in.bitanxen.poc.config.handler;

import com.google.common.base.Strings;
import in.bitanxen.poc.config.bean.ConfigurationProperty;
import in.bitanxen.poc.service.watchlist.BlackListService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.endpoint.DefaultRedirectResolver;
import org.springframework.stereotype.Component;

@Component
public class BlacklistAwareRedirectResolver extends DefaultRedirectResolver {

    private final ConfigurationProperty configurationProperty;
    private final BlackListService blackListService;

    @Value("${sysbean.oauth2.server.config.blacklist.strict-match}")
    private boolean strictMatch;

    public BlacklistAwareRedirectResolver(ConfigurationProperty configurationProperty, BlackListService blackListService) {
        this.configurationProperty = configurationProperty;
        this.blackListService = blackListService;
    }

    @Override
    public String resolveRedirect(String requestedRedirect, ClientDetails client) throws OAuth2Exception {
        String redirect = super.resolveRedirect(requestedRedirect, client);
        if (blackListService.isSiteBlacklisted(redirect)) {
            throw new InvalidRequestException("The supplied redirect_uri is not allowed on this server.");
        } else {
            return redirect;
        }
    }

    @Override
    protected boolean redirectMatches(String requestedRedirect, String redirectUri) {
        if (isStrictMatch()) {
            return Strings.nullToEmpty(requestedRedirect).equals(redirectUri);
        } else {
            return super.redirectMatches(requestedRedirect, redirectUri);
        }
    }

    public boolean isStrictMatch() {
        if (configurationProperty.isHeartMode()) {
            return true;
        } else {
            return strictMatch;
        }
    }
}
