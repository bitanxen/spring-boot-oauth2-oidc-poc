package in.bitanxen.poc.controller;

import com.nimbusds.jose.jwk.JWK;
import in.bitanxen.poc.dto.jwt.JWKDTO;
import in.bitanxen.poc.service.jwt.signer.JWTSignerVerifierService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.*;
import java.util.stream.Collectors;

@RestController
public class JWKSetPublishingEndpoint {

    public static final String URL = "jwk";
    private final JWTSignerVerifierService jwtSignerVerifierService;

    public JWKSetPublishingEndpoint(JWTSignerVerifierService jwtSignerVerifierService) {
        this.jwtSignerVerifierService = jwtSignerVerifierService;
    }

    @GetMapping("/"+URL)
    public Map<String, List<JWKDTO>> getJWK() {
        Collection<JWK> jwkList = jwtSignerVerifierService.getAllPublicKeys().values();
        List<JWKDTO> keys = jwkList.stream().map(jwk -> {
            LinkedHashMap<String, ?> requiredParams = jwk.getRequiredParams();
            String eValue = (String) requiredParams.get("e");
            String ktyValue = (String) requiredParams.get("kty");
            String nValue = (String) requiredParams.get("n");

            return JWKDTO.builder()
                    .kid(jwk.getKeyID())
                    .e(eValue)
                    .kty(ktyValue)
                    .n(nValue)
                    .alg(jwk.getAlgorithm().getName())
                    .use("sig")
                    .build();
        }).collect(Collectors.toList());


        Map<String, List<JWKDTO>> allKeys = new HashMap<>();
        allKeys.put("keys", keys);
        return allKeys;
    }
}
