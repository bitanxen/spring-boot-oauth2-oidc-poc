package in.bitanxen.poc.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

@Configuration
public class WebClientConfig {

    @Value("${app.rapidapi.host}")
    private String rapidApiHost;
    @Value("${app.rapidapi.key}")
    private String rapidApiKey;

    @Bean
    public WebClient webClient() {
        return WebClient.builder()
                .baseUrl("https://amazon-product-reviews-keywords.p.rapidapi.com")
                .defaultHeader("x-rapidapi-host", rapidApiHost)
                .defaultHeader("x-rapidapi-key", rapidApiKey)
                .build();
    }
}
