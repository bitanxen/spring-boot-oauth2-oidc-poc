package in.bitanxen.poc.config.security;

import in.bitanxen.poc.service.oauth2.OAuth2TokenEntityServiceImpl;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfiguration;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.annotation.PostConstruct;

@Configuration
@EnableResourceServer
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {

    private final OAuth2TokenEntityServiceImpl oAuth2TokenEntityServiceImpl;
    private final OAuth2AuthenticationEntryPoint oAuth2AuthenticationEntryPoint;
    private final ResourceServerConfiguration configuration;

    public ResourceServerConfig(OAuth2TokenEntityServiceImpl oAuth2TokenEntityServiceImpl,
                                OAuth2AuthenticationEntryPoint oAuth2AuthenticationEntryPoint, @Lazy ResourceServerConfiguration configuration) {
        this.oAuth2TokenEntityServiceImpl = oAuth2TokenEntityServiceImpl;
        this.oAuth2AuthenticationEntryPoint = oAuth2AuthenticationEntryPoint;
        this.configuration = configuration;
    }

    @PostConstruct
    public void setSecurityConfigurerOrder() {
        configuration.setOrder(99);
    }

    @Override
    public void configure(ResourceServerSecurityConfigurer resources) {
        resources.tokenServices(oAuth2TokenEntityServiceImpl).stateless(false);
    }

    public RequestMatcher resources() {
        return new AntPathRequestMatcher("/userinfo");
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http
                .httpBasic().disable()
                .requestMatcher(resources())
                .authorizeRequests()
                .anyRequest().hasRole("USER")
                .and();
    }
}
