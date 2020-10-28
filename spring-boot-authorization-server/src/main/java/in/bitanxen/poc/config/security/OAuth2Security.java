package in.bitanxen.poc.config.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration;
import org.springframework.security.oauth2.provider.error.OAuth2AccessDeniedHandler;
import org.springframework.security.oauth2.provider.expression.OAuth2MethodSecurityExpressionHandler;
import org.springframework.security.oauth2.provider.expression.OAuth2WebSecurityExpressionHandler;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true, proxyTargetClass = true)
public class OAuth2Security extends GlobalMethodSecurityConfiguration {

    @Override
    @Bean(name = "oauthExpressionHandler")
    public MethodSecurityExpressionHandler createExpressionHandler() {
        return new OAuth2MethodSecurityExpressionHandler();
    }

    @Bean(name = "oauthWebExpressionHandler")
    public OAuth2WebSecurityExpressionHandler webSecurityExpressionHandler() {
        return new OAuth2WebSecurityExpressionHandler();
    }

    @Bean(name = "oauthAccessDeniedHandler")
    public OAuth2AccessDeniedHandler accessDeniedHandler() {
        return new OAuth2AccessDeniedHandler();
    }

}
