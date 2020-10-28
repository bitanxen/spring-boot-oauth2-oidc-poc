package in.bitanxen.poc.controller;

import com.google.common.collect.Lists;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWSAlgorithm;
import in.bitanxen.poc.config.bean.ConfigurationProperty;
import in.bitanxen.poc.config.jose.PKCEAlgorithm;
import in.bitanxen.poc.service.jwt.encryption.JWTEncryptionDecryptionService;
import in.bitanxen.poc.service.jwt.signer.JWTSignerVerifierService;
import in.bitanxen.poc.service.scope.SystemScopeService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
public class DiscoveryEndpoint {

    public static final String WELL_KNOWN_URL = ".well-known";
    public static final String OPENID_CONFIGURATION_URL = WELL_KNOWN_URL + "/openid-configuration";
    public static final String WEB_FINGER_URL = WELL_KNOWN_URL + "/webfinger";

    private final ConfigurationProperty configurationProperty;
    private final SystemScopeService systemScopeService;
    private final JWTSignerVerifierService signService;
    private final JWTEncryptionDecryptionService encService;

    public DiscoveryEndpoint(ConfigurationProperty configurationProperty, SystemScopeService systemScopeService, JWTSignerVerifierService signService, JWTEncryptionDecryptionService encService) {
        this.configurationProperty = configurationProperty;
        this.systemScopeService = systemScopeService;
        this.signService = signService;
        this.encService = encService;
    }

    @GetMapping("/" + OPENID_CONFIGURATION_URL)
    public Map<String, Object> getWellKnownOpenIdConfiguration() {
        Map<String, Object> objectMap = new HashMap<>();

        String issuerUri = configurationProperty.getIssuer();
        List<String> grantTypes = Arrays.asList(
                "authorization_code",
                "implicit",
                "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "client_credentials",
                "urn:ietf:params:oauth:grant_type:redelegate",
                "urn:ietf:params:oauth:grant-type:device_code",
                "refresh_token");

        List<JWSAlgorithm> clientSymmetricAndAsymmetricSigningAlgorithm = Arrays.asList(
                JWSAlgorithm.HS256, JWSAlgorithm.HS384, JWSAlgorithm.HS512,
                JWSAlgorithm.RS256, JWSAlgorithm.RS384, JWSAlgorithm.RS512,
                JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512,
                JWSAlgorithm.PS256, JWSAlgorithm.PS384, JWSAlgorithm.PS512);

        List<Algorithm> clientSymmetricAndAsymmetricSigningAlgorithmWithNone = Arrays.asList(
                JWSAlgorithm.HS256, JWSAlgorithm.HS384, JWSAlgorithm.HS512,
                JWSAlgorithm.RS256, JWSAlgorithm.RS384, JWSAlgorithm.RS512,
                JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512,
                JWSAlgorithm.PS256, JWSAlgorithm.PS384, JWSAlgorithm.PS512,
                Algorithm.NONE);

        List<String> clientSymmetricAndAsymmetricSigningAlgorithmName =
                clientSymmetricAndAsymmetricSigningAlgorithm.stream().map(Algorithm::getName).collect(Collectors.toList());
        List<String> clientSymmetricAndAsymmetricSigningAlgorithmWithNoneName =
                clientSymmetricAndAsymmetricSigningAlgorithmWithNone.stream().map(Algorithm::getName).collect(Collectors.toList());
        List<String> allAlgoSupported = encService.getAllAlgorithmsSupported().stream().map(Algorithm::getName).collect(Collectors.toList());
        List<String> allEncSupported = encService.getAllEncryptionSupported().stream().map(Algorithm::getName).collect(Collectors.toList());

        objectMap.put("issuer", issuerUri);
        objectMap.put("authorization_endpoint", issuerUri + "authorize");
        objectMap.put("token_endpoint", issuerUri + "token");
        objectMap.put("userinfo_endpoint", issuerUri + UserInfoEndpoint.URL);
        //check_session_iframe
        objectMap.put("end_session_endpoint", issuerUri + EndSessionEndpoint.URL);
        objectMap.put("jwks_uri", issuerUri + JWKSetPublishingEndpoint.URL);
        objectMap.put("registration_endpoint", issuerUri + ClientController.URL);

        objectMap.put("scopes_supported", systemScopeService.toStrings(systemScopeService.getUnrestricted()));
        objectMap.put("response_types_supported", Lists.newArrayList("code", "token")); // we don't support these yet: , "id_token", "id_token token"));
        objectMap.put("grant_types_supported", grantTypes);
        //acr_values_supported
        objectMap.put("subject_types_supported", Lists.newArrayList("public", "pairwise"));

        objectMap.put("userinfo_signing_alg_values_supported", clientSymmetricAndAsymmetricSigningAlgorithmName);
        objectMap.put("userinfo_encryption_alg_values_supported", allAlgoSupported);
        objectMap.put("userinfo_encryption_enc_values_supported", allEncSupported);
        objectMap.put("id_token_signing_alg_values_supported", clientSymmetricAndAsymmetricSigningAlgorithmWithNoneName);
        objectMap.put("id_token_encryption_alg_values_supported", allAlgoSupported);
        objectMap.put("id_token_encryption_enc_values_supported", allEncSupported);
        objectMap.put("request_object_signing_alg_values_supported", clientSymmetricAndAsymmetricSigningAlgorithmName);
        objectMap.put("request_object_encryption_alg_values_supported", allAlgoSupported);
        objectMap.put("request_object_encryption_enc_values_supported", allEncSupported);
        objectMap.put("token_endpoint_auth_methods_supported", Arrays.asList("client_secret_post", "client_secret_basic", "client_secret_jwt", "private_key_jwt", "none"));
        objectMap.put("token_endpoint_auth_signing_alg_values_supported", clientSymmetricAndAsymmetricSigningAlgorithmName);
        objectMap.put("claim_types_supported", Arrays.asList("normal"));
        objectMap.put("claims_supported", Arrays.asList(
                "sub",
                "name",
                "preferred_username",
                "given_name",
                "family_name",
                "middle_name",
                "nickname",
                "profile",
                "picture",
                "website",
                "gender",
                "zoneinfo",
                "locale",
                "updated_at",
                "birthdate",
                "email",
                "email_verified",
                "phone_number",
                "phone_number_verified",
                "address"));
        objectMap.put("service_documentation", issuerUri + "about");
        //claims_locales_supported
        //ui_locales_supported
        objectMap.put("claims_parameter_supported", false);
        objectMap.put("request_parameter_supported", true);
        objectMap.put("request_uri_parameter_supported", false);
        objectMap.put("require_request_uri_registration", false);
        objectMap.put("op_policy_uri", issuerUri + "about");
        objectMap.put("op_tos_uri", issuerUri + "about");

        objectMap.put("introspection_endpoint", issuerUri + IntrospectionEndpoint.URL); // token introspection endpoint for verifying tokens
        objectMap.put("revocation_endpoint", issuerUri + RevocationEndpoint.URL); // token revocation endpoint

        objectMap.put("code_challenge_methods_supported", Lists.newArrayList(PKCEAlgorithm.plain.getName(), PKCEAlgorithm.S256.getName()));

        objectMap.put("device_authorization_endpoint", issuerUri + DeviceEndpoint.URL);


        return objectMap;
    }
}
