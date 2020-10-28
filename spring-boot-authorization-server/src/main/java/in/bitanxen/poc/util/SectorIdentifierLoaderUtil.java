package in.bitanxen.poc.util;

import com.google.common.cache.CacheLoader;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import lombok.extern.log4j.Log4j2;
import org.apache.http.client.HttpClient;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

@Log4j2
public class SectorIdentifierLoaderUtil extends CacheLoader<String, List<String>> {
    private HttpComponentsClientHttpRequestFactory httpFactory;
    private RestTemplate restTemplate;
    private boolean forceHttps;

    public SectorIdentifierLoaderUtil(HttpClient httpClient, boolean forceHttps) {
        this.httpFactory = new HttpComponentsClientHttpRequestFactory(httpClient);
        this.restTemplate = new RestTemplate(httpFactory);
        this.forceHttps = forceHttps;
    }

    @Override
    public List<String> load(String key) throws Exception {
        if (!key.startsWith("https")) {
            if (forceHttps) {
                throw new IllegalArgumentException("Sector identifier must start with https: " + key);
            }
            log.error("Sector identifier doesn't start with https, loading anyway...");
        }

        String jsonString = restTemplate.getForObject(key, String.class);
        JsonElement jsonElement = JsonParser.parseString(Objects.requireNonNull(jsonString));

        if (jsonElement.isJsonArray()) {
            List<String> redirectUris = new ArrayList<>();
            for (JsonElement el : jsonElement.getAsJsonArray()) {
                redirectUris.add(el.getAsString());
            }

            log.info("Found " + redirectUris + " for sector " + key);

            return redirectUris;
        } else {
            throw new IllegalArgumentException("JSON Format Error");
        }
    }
}
