package in.bitanxen.poc.config.security;

import in.bitanxen.poc.config.filter.CorsFilter;
import in.bitanxen.poc.config.filter.JWTBearerClientAssertionTokenEndpointFilter;
import in.bitanxen.poc.config.filter.MultiUrlRequestMatcher;
import in.bitanxen.poc.config.provider.JWTBearerAuthenticationProvider;
import in.bitanxen.poc.service.client.ClientUserDetailsService;
import in.bitanxen.poc.service.client.UriEncodedClientUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.provider.client.ClientCredentialsTokenEndpointFilter;
import org.springframework.security.oauth2.provider.error.OAuth2AccessDeniedHandler;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.HashSet;
import java.util.Set;

@Configuration
@EnableWebSecurity
@Order(101)
public class ClientSecurityConfig extends WebSecurityConfigurerAdapter {

    private final OAuth2AuthenticationEntryPoint oAuth2AuthenticationEntryPoint;
    private final OAuth2AccessDeniedHandler oAuth2AccessDeniedHandler;

    private final ClientUserDetailsService clientUserDetailsService;
    private final UriEncodedClientUserDetailsService uriEncodedClientUserDetailsService;

    private final JWTBearerAuthenticationProvider jwtBearerAuthenticationProvider;

    private final CorsFilter corsFilter;

    public ClientSecurityConfig(OAuth2AuthenticationEntryPoint oAuth2AuthenticationEntryPoint, OAuth2AccessDeniedHandler oAuth2AccessDeniedHandler,
                                ClientUserDetailsService clientUserDetailsService, UriEncodedClientUserDetailsService uriEncodedClientUserDetailsService,
                                JWTBearerAuthenticationProvider jwtBearerAuthenticationProvider, CorsFilter corsFilter) {
        this.oAuth2AuthenticationEntryPoint = oAuth2AuthenticationEntryPoint;
        this.oAuth2AccessDeniedHandler = oAuth2AccessDeniedHandler;
        this.clientUserDetailsService = clientUserDetailsService;
        this.uriEncodedClientUserDetailsService = uriEncodedClientUserDetailsService;
        this.jwtBearerAuthenticationProvider = jwtBearerAuthenticationProvider;
        this.corsFilter = corsFilter;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
                .userDetailsService(clientUserDetailsService)
                .and()
                .userDetailsService(uriEncodedClientUserDetailsService)
                .and()
                .authenticationProvider(jwtBearerAuthenticationProvider);
    }

    @Bean
    public PasswordEncoder encoder() {
        return new BCryptPasswordEncoder();
    }



    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .authorizeRequests()
                .antMatchers(HttpMethod.OPTIONS,"/token").permitAll()
                .antMatchers(HttpMethod.GET,"/token").permitAll()
                .antMatchers("/token").authenticated()
                .and()
                .httpBasic()
                .authenticationEntryPoint(oAuth2AuthenticationEntryPoint)
                .and()
                .addFilterAfter(clientAssertionEndpointFilter(), AbstractPreAuthenticatedProcessingFilter.class)
                .addFilterAfter(clientCredentialsTokenEndpointFilter(), BasicAuthenticationFilter.class)
                .addFilterAfter(corsFilter, SecurityContextPersistenceFilter.class)
                .exceptionHandling().accessDeniedHandler(oAuth2AccessDeniedHandler);
    }

    @Bean
    public ClientCredentialsTokenEndpointFilter clientCredentialsTokenEndpointFilter() throws Exception {
        ClientCredentialsTokenEndpointFilter filter = new ClientCredentialsTokenEndpointFilter();
        filter.setAuthenticationManager(authenticationManagerBean());
        filter.setRequiresAuthenticationRequestMatcher(clientAuthMatcher());
        return filter;
    }

    @Bean
    public JWTBearerClientAssertionTokenEndpointFilter clientAssertionEndpointFilter() throws Exception {
        JWTBearerClientAssertionTokenEndpointFilter clientAssertionTokenEndpointFilter =
                new JWTBearerClientAssertionTokenEndpointFilter(clientAuthMatcher());
        clientAssertionTokenEndpointFilter.setAuthenticationManager(authenticationManagerBean());
        return clientAssertionTokenEndpointFilter;
    }

    @Bean
    public RequestMatcher clientAuthMatcher() {
        Set<String> filterProcessesUrls = new HashSet<>();
        filterProcessesUrls.add("/introspect");
        filterProcessesUrls.add("/revoke");
        filterProcessesUrls.add("/token");
        return new MultiUrlRequestMatcher(filterProcessesUrls);
    }
}
