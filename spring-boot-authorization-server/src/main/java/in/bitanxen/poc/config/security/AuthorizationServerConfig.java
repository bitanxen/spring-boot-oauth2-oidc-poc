package in.bitanxen.poc.config.security;

import in.bitanxen.poc.config.oauth2.ChainedTokenGranter;
import in.bitanxen.poc.config.oauth2.DeviceTokenGranter;
import in.bitanxen.poc.config.oauth2.JWTAssertionTokenGranter;
import in.bitanxen.poc.config.openid.ConnectOAuth2RequestFactory;
import in.bitanxen.poc.service.client.ClientEntityService;
import in.bitanxen.poc.service.oauth2.OAuth2AuthorizationCodeService;
import in.bitanxen.poc.service.oauth2.OAuth2TokenEntityService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.OAuth2RequestValidator;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.approval.UserApprovalHandler;
import org.springframework.security.oauth2.provider.endpoint.DefaultRedirectResolver;

import java.util.ArrayList;
import java.util.List;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    @Value("${sysbean.oauth2.server.config.realm-name}")
    private String realmName;

    private final ClientEntityService clientEntityService;
    private final ConnectOAuth2RequestFactory connectOAuth2RequestFactory;
    private final OAuth2TokenEntityService oAuth2TokenEntityService;
    private final OAuth2AuthorizationCodeService oAuth2AuthorizationCodeService;
    private final UserApprovalHandler userApprovalHandler;
    private final OAuth2RequestValidator oAuth2RequestValidator;
    private final DefaultRedirectResolver defaultRedirectResolver;

    private final ChainedTokenGranter chainedTokenGranter;
    private final JWTAssertionTokenGranter jwtAssertionTokenGranter;
    private final DeviceTokenGranter deviceTokenGranter;

    public AuthorizationServerConfig(ClientEntityService clientEntityService, ConnectOAuth2RequestFactory connectOAuth2RequestFactory,
                                     OAuth2TokenEntityService oAuth2TokenEntityService, OAuth2AuthorizationCodeService oAuth2AuthorizationCodeService,
                                     UserApprovalHandler userApprovalHandler, OAuth2RequestValidator oAuth2RequestValidator,
                                     DefaultRedirectResolver defaultRedirectResolver, ChainedTokenGranter chainedTokenGranter,
                                     JWTAssertionTokenGranter jwtAssertionTokenGranter, DeviceTokenGranter deviceTokenGranter) {
        this.clientEntityService = clientEntityService;
        this.connectOAuth2RequestFactory = connectOAuth2RequestFactory;
        this.oAuth2TokenEntityService = oAuth2TokenEntityService;
        this.oAuth2AuthorizationCodeService = oAuth2AuthorizationCodeService;
        this.userApprovalHandler = userApprovalHandler;
        this.oAuth2RequestValidator = oAuth2RequestValidator;
        this.defaultRedirectResolver = defaultRedirectResolver;
        this.chainedTokenGranter = chainedTokenGranter;
        this.jwtAssertionTokenGranter = jwtAssertionTokenGranter;
        this.deviceTokenGranter = deviceTokenGranter;
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) {
        security
                .realm(realmName)
                .tokenKeyAccess("permitAll()")
                .checkTokenAccess("isAuthenticated()");
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.withClientDetails(clientEntityService);
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {

        List<TokenGranter> tokenGranters = new ArrayList<>();
        tokenGranters.add(endpoints.getTokenGranter());
        tokenGranters.add(chainedTokenGranter);
        tokenGranters.add(jwtAssertionTokenGranter);
        tokenGranters.add(deviceTokenGranter);

        endpoints
                .pathMapping("/oauth/authorize", "/authorize")
                .pathMapping("/oauth/check_token", "/check_token")
                .pathMapping("/oauth/confirm_access", "/confirm_access")
                .pathMapping("/oauth/error", "/error")
                .pathMapping("/oauth/token", "/token")
                .authorizationCodeServices(oAuth2AuthorizationCodeService) // authorization-code-services-ref
                .tokenServices(oAuth2TokenEntityService) // token-services-ref
                .userApprovalHandler(userApprovalHandler) // user-approval-handler-ref
                .requestValidator(oAuth2RequestValidator) //request-validator-ref
                .redirectResolver(defaultRedirectResolver) // redirect-resolver-ref
                .requestFactory(connectOAuth2RequestFactory) // authorization-request-manager-ref
        .tokenGranter(new CompositeTokenGranter(tokenGranters));
    }

}
