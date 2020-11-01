package in.bitanxen.poc.config.security;

import in.bitanxen.poc.config.filter.AuthorizationRequestFilter;
import in.bitanxen.poc.config.filter.LoginPageFilter;
import in.bitanxen.poc.config.handler.AuthenticationSuccessHandler;
import in.bitanxen.poc.config.provider.UserAuthenticationProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.provider.expression.OAuth2WebSecurityExpressionHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;

@Configuration
@EnableWebSecurity
@Order(100)
public class ServerSecurityConfig extends WebSecurityConfigurerAdapter {

    private final AuthenticationSuccessHandler authenticationSuccessHandler;
    private final AuthorizationRequestFilter authorizationRequestFilter;
    private final UserAuthenticationProvider authenticationProvider;

    @Autowired
    private OAuth2WebSecurityExpressionHandler expressionHandler;

    public ServerSecurityConfig(AuthenticationSuccessHandler authenticationSuccessHandler, AuthorizationRequestFilter authorizationRequestFilter,
                                UserAuthenticationProvider authenticationProvider) {
        this.authenticationSuccessHandler = authenticationSuccessHandler;
        this.authorizationRequestFilter = authorizationRequestFilter;
        this.authenticationProvider = authenticationProvider;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(authenticationProvider);
    }

    @Override
    @Bean
    protected AuthenticationManager authenticationManager() throws Exception {
        return super.authenticationManager();
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/assets/**");
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http
                .csrf()
                .and()
                .formLogin()
                    .loginPage("/login")
                    .loginProcessingUrl("/loginAction")
                    .successHandler(authenticationSuccessHandler)
                    .failureUrl("/login?error=true")
                .and()
                .logout()
                    .logoutUrl("/logout")
                    .deleteCookies("JSESSIONID")
                    .logoutSuccessUrl("/")
                .and()
                .headers()
                    .frameOptions().deny()
                .and()
                .addFilterBefore(new LoginPageFilter(), UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(authorizationRequestFilter, SecurityContextPersistenceFilter.class)
                .authorizeRequests()
                    .antMatchers("/authorize").hasRole("USER")
                    .antMatchers("/login*").permitAll()
                    .antMatchers("/.well-known/**").permitAll()
                    .antMatchers("/", "/index**").permitAll()
                    .antMatchers("/jwk**").permitAll();
    }
}
