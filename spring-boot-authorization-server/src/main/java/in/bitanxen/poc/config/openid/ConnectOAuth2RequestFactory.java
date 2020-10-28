package in.bitanxen.poc.config.openid;

import com.google.gson.JsonObject;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.*;
import in.bitanxen.poc.config.jose.PKCEAlgorithm;
import in.bitanxen.poc.dto.client.ClientEntityDTO;
import in.bitanxen.poc.service.client.ClientEntityService;
import in.bitanxen.poc.service.jwt.ClientKeyCacheService;
import in.bitanxen.poc.service.jwt.encryption.JWTEncryptionDecryptionService;
import in.bitanxen.poc.service.jwt.signer.JWTSignerVerifierService;
import in.bitanxen.poc.util.CommonUtil;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory;
import org.springframework.stereotype.Component;

import java.io.Serializable;
import java.text.ParseException;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

import static in.bitanxen.poc.config.openid.ConnectRequestParameters.*;

@Component
@Log4j2
public class ConnectOAuth2RequestFactory extends DefaultOAuth2RequestFactory {

    private final ClientEntityService clientEntityService;
    private final ClientKeyCacheService clientKeyCacheService;
    private final JWTEncryptionDecryptionService encryptionDecryptionService;

    public ConnectOAuth2RequestFactory(ClientEntityService clientEntityService, ClientKeyCacheService clientKeyCacheService, JWTEncryptionDecryptionService encryptionDecryptionService) {
        super(clientEntityService);
        this.clientEntityService = clientEntityService;
        this.clientKeyCacheService = clientKeyCacheService;
        this.encryptionDecryptionService = encryptionDecryptionService;
    }

    @Override
    public AuthorizationRequest createAuthorizationRequest(Map<String, String> authorizationParameters) {

        AuthorizationRequest request = new AuthorizationRequest(authorizationParameters, Collections.<String, String> emptyMap(),
                authorizationParameters.get(OAuth2Utils.CLIENT_ID),
                OAuth2Utils.parseParameterList(authorizationParameters.get(OAuth2Utils.SCOPE)), null,
                null, false, authorizationParameters.get(OAuth2Utils.STATE),
                authorizationParameters.get(OAuth2Utils.REDIRECT_URI),
                OAuth2Utils.parseParameterList(authorizationParameters.get(OAuth2Utils.RESPONSE_TYPE)));

        if (authorizationParameters.containsKey(PROMPT)) {
            request.getExtensions().put(PROMPT, authorizationParameters.get(PROMPT));
        }
        if (authorizationParameters.containsKey(NONCE)) {
            request.getExtensions().put(NONCE, authorizationParameters.get(NONCE));
        }

        if (authorizationParameters.containsKey(CLAIMS)) {
            JsonObject claimsRequest = CommonUtil.getJSONObject(authorizationParameters.get(CLAIMS));
            if (claimsRequest != null) {
                request.getExtensions().put(CLAIMS, claimsRequest.toString());
            }
        }

        if (authorizationParameters.containsKey(MAX_AGE)) {
            request.getExtensions().put(MAX_AGE, authorizationParameters.get(MAX_AGE));
        }

        if (authorizationParameters.containsKey(LOGIN_HINT)) {
            request.getExtensions().put(LOGIN_HINT, authorizationParameters.get(LOGIN_HINT));
        }

        if (authorizationParameters.containsKey(AUD)) {
            request.getExtensions().put(AUD, authorizationParameters.get(AUD));
        }

        if (authorizationParameters.containsKey(CODE_CHALLENGE)) {
            request.getExtensions().put(CODE_CHALLENGE, authorizationParameters.get(CODE_CHALLENGE));
            if (authorizationParameters.containsKey(CODE_CHALLENGE_METHOD)) {
                request.getExtensions().put(CODE_CHALLENGE_METHOD, authorizationParameters.get(CODE_CHALLENGE_METHOD));
            } else {
                // if the client doesn't specify a code challenge transformation method, it's "plain"
                request.getExtensions().put(CODE_CHALLENGE_METHOD, PKCEAlgorithm.plain.getName());
            }

        }

        if (authorizationParameters.containsKey(REQUEST)) {
            request.getExtensions().put(REQUEST, authorizationParameters.get(REQUEST));
            processRequestObject(authorizationParameters.get(REQUEST), request);
        }

        if (request.getClientId() != null) {
            try {
                ClientEntityDTO client = clientEntityService.loadClientByClientId(request.getClientId());

                if ((request.getScope() == null || request.getScope().isEmpty())) {
                    Set<String> clientScopes = client.getScope();
                    request.setScope(clientScopes);
                }

                if (request.getExtensions().get(MAX_AGE) == null && client.getDefaultMaxAge() > 0) {
                    request.getExtensions().put(MAX_AGE, client.getDefaultMaxAge());
                }
            } catch (OAuth2Exception e) {
                log.error("Caught OAuth2 exception trying to test client scopes and max age:", e);
            }
        }
        return request;
    }

    private void processRequestObject(String jwtString, AuthorizationRequest request) {
        ClientEntityDTO client = clientEntityService.loadClientByClientId(request.getClientId());

        try{
            JWT jwt = JWTParser.parse(jwtString);

            if (jwt instanceof SignedJWT) {
                SignedJWT signedJwt = (SignedJWT)jwt;

                if (request.getClientId() == null) {
                    request.setClientId(signedJwt.getJWTClaimsSet().getStringClaim(CLIENT_ID));
                }


                if (client == null) {
                    throw new InvalidClientException("Client not found: " + request.getClientId());
                }

                JWSAlgorithm alg = signedJwt.getHeader().getAlgorithm();

                if (client.getRequestObjectSigningAlg() == null || !client.getRequestObjectSigningAlg().equals(alg)) {
                    throw new InvalidClientException("Client's registered request object signing algorithm (" + client.getRequestObjectSigningAlg() + ") does not match request object's actual algorithm (" + alg.getName() + ")");
                }

                JWTSignerVerifierService validator = clientKeyCacheService.getValidator(client, alg);

                if (validator == null) {
                    throw new InvalidClientException("Unable to create signature validator for client " + client + " and algorithm " + alg);
                }

                if (!validator.validateSignature(signedJwt)) {
                    throw new InvalidClientException("Signature did not validate for presented JWT request object.");
                }
            } else if(jwt instanceof PlainJWT) {
                PlainJWT plainJwt = (PlainJWT)jwt;

                // need to check clientId first so that we can load the client to check other fields
                if (request.getClientId() == null) {
                    request.setClientId(plainJwt.getJWTClaimsSet().getStringClaim(CLIENT_ID));
                }

                if (client == null) {
                    throw new InvalidClientException("Client not found: " + request.getClientId());
                }

                if (client.getRequestObjectSigningAlg() == null) {
                    throw new InvalidClientException("Client is not registered for unsigned request objects (no request_object_signing_alg registered)");
                } else if (!client.getRequestObjectSigningAlg().equals(Algorithm.NONE)) {
                    throw new InvalidClientException("Client is not registered for unsigned request objects (request_object_signing_alg is " + client.getRequestObjectSigningAlg() +")");
                }
            } else if (jwt instanceof EncryptedJWT) {
                EncryptedJWT encryptedJWT = (EncryptedJWT)jwt;
                encryptionDecryptionService.decryptJwt(encryptedJWT);

                if (!encryptedJWT.getState().equals(JWEObject.State.DECRYPTED)) {
                    throw new InvalidClientException("Unable to decrypt the request object");
                }

                if (request.getClientId() == null) {
                    request.setClientId(encryptedJWT.getJWTClaimsSet().getStringClaim(CLIENT_ID));
                }
            }

            JWTClaimsSet claims = jwt.getJWTClaimsSet();

            Set<String> responseTypes = OAuth2Utils.parseParameterList(claims.getStringClaim(RESPONSE_TYPE));
            if (!responseTypes.isEmpty()) {
                if (!responseTypes.equals(request.getResponseTypes())) {
                    log.info("Mismatch between request object and regular parameter for response_type, using request object");
                }
                request.setResponseTypes(responseTypes);
            }

            String redirectUri = claims.getStringClaim(REDIRECT_URI);
            if (redirectUri != null) {
                if (!redirectUri.equals(request.getRedirectUri())) {
                    log.info("Mismatch between request object and regular parameter for redirect_uri, using request object");
                }
                request.setRedirectUri(redirectUri);
            }

            String state = claims.getStringClaim(STATE);
            if(state != null) {
                if (!state.equals(request.getState())) {
                    log.info("Mismatch between request object and regular parameter for state, using request object");
                }
                request.setState(state);
            }

            String nonce = claims.getStringClaim(NONCE);
            if(nonce != null) {
                if (!nonce.equals(request.getExtensions().get(NONCE))) {
                    log.info("Mismatch between request object and regular parameter for nonce, using request object");
                }
                request.getExtensions().put(NONCE, nonce);
            }

            String display = claims.getStringClaim(DISPLAY);
            if (display != null) {
                if (!display.equals(request.getExtensions().get(DISPLAY))) {
                    log.info("Mismatch between request object and regular parameter for display, using request object");
                }
                request.getExtensions().put(DISPLAY, display);
            }

            String prompt = claims.getStringClaim(PROMPT);
            if (prompt != null) {
                if (!prompt.equals(request.getExtensions().get(PROMPT))) {
                    log.info("Mismatch between request object and regular parameter for prompt, using request object");
                }
                request.getExtensions().put(PROMPT, prompt);
            }

            Set<String> scope = OAuth2Utils.parseParameterList(claims.getStringClaim(SCOPE));
            if (!scope.isEmpty()) {
                if (!scope.equals(request.getScope())) {
                    log.info("Mismatch between request object and regular parameter for scope, using request object");
                }
                request.setScope(scope);
            }

            JsonObject claimRequest = CommonUtil.getJSONObject(claims.getStringClaim(CLAIMS));
            if (claimRequest != null) {
                Serializable claimExtension = request.getExtensions().get(CLAIMS);
                if (claimExtension == null || !claimRequest.equals(CommonUtil.getJSONObject(claimExtension.toString()))) {
                    log.info("Mismatch between request object and regular parameter for claims, using request object");
                }
                // we save the string because the object might not be a Java Serializable, and we can parse it easily enough anyway
                request.getExtensions().put(CLAIMS, claimRequest.toString());
            }

            String loginHint = claims.getStringClaim(LOGIN_HINT);
            if (loginHint != null) {
                if (!loginHint.equals(request.getExtensions().get(LOGIN_HINT))) {
                    log.info("Mistmatch between request object and regular parameter for login_hint, using requst object");
                }
                request.getExtensions().put(LOGIN_HINT, loginHint);
            }

        } catch (ParseException e) {
            e.printStackTrace();
        }
    }
}
