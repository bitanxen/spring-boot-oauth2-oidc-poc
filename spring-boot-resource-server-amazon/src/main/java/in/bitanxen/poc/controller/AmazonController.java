package in.bitanxen.poc.controller;

import in.bitanxen.poc.dto.CategoryTypeDTO;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.Collection;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class AmazonController {

    private final WebClient webClient;

    public AmazonController(WebClient webClient) {
        this.webClient = webClient;
    }

    @GetMapping(value = "/categories")
    public Flux<CategoryTypeDTO> getCategories(@RequestParam(name = "country", defaultValue = "US", required = false) String country) {
        Mono<Map<String, CategoryTypeDTO>> categoryData = webClient.get()
                .uri(uriBuilder -> uriBuilder
                        .path("/categories")
                        .queryParam("country", country)
                        .build())
                .retrieve()
                .bodyToMono(new ParameterizedTypeReference<Map<String, CategoryTypeDTO>>() {
                });
        return categoryData.map(Map::values).flatMapMany(Flux::fromIterable);
    }
}
