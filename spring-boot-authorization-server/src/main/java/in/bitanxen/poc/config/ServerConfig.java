package in.bitanxen.poc.config;

import in.bitanxen.poc.config.bean.ConfigurationProperty;
import in.bitanxen.poc.config.bean.JWKSetKeyStore;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ResourceLoader;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;

@Configuration
@Log4j2
public class ServerConfig {

    @Value("${sysbean.oauth2.server.config.issuer}")
    private String issuer;
    @Value("${sysbean.oauth2.server.config.realm-name}")
    private String realmName;
    @Value("${sysbean.oauth2.server.config.force-https}")
    private boolean forceHttps;
    @Value("${sysbean.oauth2.server.config.dual-client}")
    private boolean dualClient;
    @Value("${sysbean.oauth2.server.config.heart-mode}")
    private boolean heartMode;
    @Value("${sysbean.oauth2.server.config.complete-device-code-uri}")
    private boolean allowCompleteDeviceCodeUri;
    @Value("${sysbean.oauth2.server.config.jwk-uri}")
    private String jwkUri;
    @Value("${sysbean.oauth2.server.config.jwk-keystore}")
    private String jwkKeyStoreLocation;

    private final ResourceLoader resourceLoader;

    public ServerConfig(ResourceLoader resourceLoader) {
        this.resourceLoader = resourceLoader;
    }

    @Bean
    public ConfigurationProperty serverPropertyConfigure() {
        ConfigurationProperty configurationProperty = new ConfigurationProperty();
        configurationProperty.setIssuer(issuer);
        configurationProperty.setForceHttps(forceHttps);
        configurationProperty.setDualClient(dualClient);
        configurationProperty.setHeartMode(heartMode);
        configurationProperty.setAllowCompleteDeviceCodeUri(allowCompleteDeviceCodeUri);
        configurationProperty.setJwkUri(issuer+jwkUri);
        return configurationProperty;
    }

    @Bean
    public OAuth2AuthenticationEntryPoint oauth2AuthenticationEntryPoint() {
        OAuth2AuthenticationEntryPoint oAuth2AuthenticationEntryPoint = new OAuth2AuthenticationEntryPoint();
        oAuth2AuthenticationEntryPoint.setRealmName(realmName);
        return oAuth2AuthenticationEntryPoint;
    }

    @Bean
    public JWKSetKeyStore jwkSetKeyStore() {
        return new JWKSetKeyStore(resourceLoader.getResource(jwkKeyStoreLocation));
    }
}
