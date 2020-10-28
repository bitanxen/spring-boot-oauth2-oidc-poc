package in.bitanxen.poc.controller;

import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.client.WebClient;

@Controller
@RequestMapping("/")
public class DashboardController {

    private final RestTemplate restTemplate;
    private final OAuth2AuthorizedClientService authorizedClientService;
    private final WebClient webClient;

    public DashboardController(RestTemplate restTemplate, OAuth2AuthorizedClientService authorizedClientService, WebClient webClient) {
        this.restTemplate = restTemplate;
        this.authorizedClientService = authorizedClientService;
        this.webClient = webClient;
    }

    @RequestMapping("/dashboard")
    public String getUserDashboard(OAuth2AuthenticationToken authentication, Model model) {
        OAuth2AuthorizedClient client = authorizedClientService
                .loadAuthorizedClient(
                        authentication.getAuthorizedClientRegistrationId(),
                        authentication.getName());
        System.out.println(authentication.getAuthorities());
        System.out.println(client.getAccessToken().getTokenValue());
        System.out.println(client.getRefreshToken().getTokenValue());

        String data = webClient.get()
                .uri("http://localhost:6591/api/categories")
                .retrieve()
                .bodyToMono(String.class)
                .block();

        model.addAttribute("webclientdata", data);


        String body = restTemplate.getForEntity("http://localhost:6591/api/categories", String.class).getBody();
        model.addAttribute("resttemplatedata", body);

        return "dashboard";
    }
}
