package in.bitanxen.poc.service.oidc;

import com.google.common.base.Strings;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
import com.nimbusds.jose.*;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.*;
import in.bitanxen.poc.config.bean.ConfigurationProperty;
import in.bitanxen.poc.dto.client.ClientEntityDTO;
import in.bitanxen.poc.model.authholder.AuthenticationHolderEntity;
import in.bitanxen.poc.model.client.ClientEntity;
import in.bitanxen.poc.model.statics.SystemScopeType;
import in.bitanxen.poc.model.token.AccessTokenEntity;
import in.bitanxen.poc.model.token.AccessTokenScope;
import in.bitanxen.poc.repository.AuthenticationHolderRepository;
import in.bitanxen.poc.service.jwt.ClientKeyCacheService;
import in.bitanxen.poc.service.jwt.SymmetricKeyJWTValidatorCacheService;
import in.bitanxen.poc.service.jwt.encryption.JWTEncryptionDecryptionService;
import in.bitanxen.poc.service.jwt.signer.JWTSignerVerifierService;
import in.bitanxen.poc.service.oauth2.OAuth2TokenEntityService;
import in.bitanxen.poc.util.CommonUtil;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import static in.bitanxen.poc.config.openid.ConnectRequestParameters.*;

@Service
@Log4j2
public class OIDCTokenServiceImpl implements OIDCTokenService {

    private final ConfigurationProperty configurationProperty;
    private final JWTSignerVerifierService jwtService;
    private final AuthenticationHolderRepository authenticationHolderRepository;
    private final ClientKeyCacheService encrypters;
    private final SymmetricKeyJWTValidatorCacheService symmetricCacheService;
    private final OAuth2TokenEntityService tokenService;

    public OIDCTokenServiceImpl(ConfigurationProperty configurationProperty, JWTSignerVerifierService jwtService, AuthenticationHolderRepository authenticationHolderRepository,
                                ClientKeyCacheService encrypters, SymmetricKeyJWTValidatorCacheService symmetricCacheService, OAuth2TokenEntityService tokenService) {
        this.configurationProperty = configurationProperty;
        this.jwtService = jwtService;
        this.authenticationHolderRepository = authenticationHolderRepository;
        this.encrypters = encrypters;
        this.symmetricCacheService = symmetricCacheService;
        this.tokenService = tokenService;
    }

    @Override
    public JWT createIdToken(ClientEntityDTO client, OAuth2Request request, LocalDateTime issueTime, String sub, AccessTokenEntity accessToken) {
        JWSAlgorithm signingAlg = jwtService.getDefaultSigningAlgorithm();

        if (client.getIdTokenSignedResponseAlg() != null) {
            signingAlg = client.getIdTokenSignedResponseAlg();
        }

        JWT idToken = null;
        JWTClaimsSet.Builder idClaims = new JWTClaimsSet.Builder();

        if (request.getExtensions().containsKey(MAX_AGE) || (request.getExtensions().containsKey("idtoken")) || client.isRequireAuthTime()) {

            if (request.getExtensions().get(AUTH_TIMESTAMP) != null) {

                long authTimestamp = Long.parseLong((String) request.getExtensions().get(AUTH_TIMESTAMP));
                idClaims.claim("auth_time", authTimestamp / 1000L);
            } else {
                log.warn("Unable to find authentication timestamp! There is likely something wrong with the configuration.");
            }
        }

        idClaims.issueTime(Date.from(issueTime.atZone(ZoneId.systemDefault()).toInstant()));

        if (client.getIdTokenValiditySeconds() > 0) {
            Date expiration = new Date(System.currentTimeMillis() + (client.getIdTokenValiditySeconds() * 1000L));
            idClaims.expirationTime(expiration);
        }

        idClaims.issuer(configurationProperty.getIssuer());
        idClaims.subject(sub);
        idClaims.audience(Lists.newArrayList(client.getClientId()));
        idClaims.jwtID(UUID.randomUUID().toString());

        String nonce = (String)request.getExtensions().get(NONCE);
        if (!Strings.isNullOrEmpty(nonce)) {
            idClaims.claim("nonce", nonce);
        }

        Set<String> responseTypes = request.getResponseTypes();

        if (responseTypes.contains("token")) {
            Base64URL at_hash = CommonUtil.getAccessTokenHash(signingAlg, accessToken.getJwtValue());
            idClaims.claim("at_hash", at_hash);
        }

        //addCustomIdTokenClaims

        if (client.getIdTokenEncryptedResponseAlg() != null && !client.getIdTokenEncryptedResponseAlg().equals(Algorithm.NONE)
                && client.getIdTokenEncryptedResponseEnc() != null && !client.getIdTokenEncryptedResponseEnc().equals(Algorithm.NONE)
                && (!Strings.isNullOrEmpty(client.getJwksUri()) || client.getJwks() != null)) {

            JWTEncryptionDecryptionService encrypter = encrypters.getEncrypter(client);

            if (encrypter != null) {
                idToken = new EncryptedJWT(new JWEHeader(client.getIdTokenEncryptedResponseAlg(), client.getIdTokenEncryptedResponseEnc()), idClaims.build());
                encrypter.encryptJwt((JWEObject) idToken);
            } else {
                log.error("Couldn't find encrypter for client: " + client.getClientId());
            }
        } else {
            if (signingAlg.equals(Algorithm.NONE)) {
                // unsigned ID token
                idToken = new PlainJWT(idClaims.build());
            } else {
                if (signingAlg.equals(JWSAlgorithm.HS256)
                        || signingAlg.equals(JWSAlgorithm.HS384)
                        || signingAlg.equals(JWSAlgorithm.HS512)) {

                    JWSHeader header = new JWSHeader.Builder(signingAlg)
                            .keyID(jwtService.getDefaultSignerKeyId())
                            .build();
                    idToken = new SignedJWT(header, idClaims.build());

                    JWTSignerVerifierService signer = symmetricCacheService.getSymmetricValidtor(client);

                    // sign it with the client's secret
                    signer.signJwt((SignedJWT) idToken);
                } else {
                    idClaims.claim("kid", jwtService.getDefaultSignerKeyId());
                    JWSHeader header = new JWSHeader.Builder(signingAlg)
                            .keyID(jwtService.getDefaultSignerKeyId())
                            .build();

                    idToken = new SignedJWT(header, idClaims.build());

                    // sign it with the server's key
                    jwtService.signJwt((SignedJWT) idToken);
                }
            }

        }

        return idToken;
    }

    @Override
    public AccessTokenEntity createRegistrationAccessToken(ClientEntity client) {
        return createAssociatedToken(client, Sets.newHashSet(SystemScopeType.REGISTRATION_TOKEN_SCOPE.getValue()));
    }

    @Override
    public AccessTokenEntity createResourceAccessToken(ClientEntity client) {
        return createAssociatedToken(client, Sets.newHashSet(SystemScopeType.RESOURCE_TOKEN_SCOPE.getValue()));
    }

    @Override
    public AccessTokenEntity rotateRegistrationAccessTokenForClient(ClientEntity client) {
        return null;
    }

    private AccessTokenEntity createAssociatedToken(ClientEntity client, Set<String> scope) {

        // revoke any previous tokens that might exist, just to be sure
        AccessTokenEntity oldToken = tokenService.getRegistrationAccessTokenForClient(client);
        if (oldToken != null) {
            tokenService.revokeAccessToken(oldToken);
        }

        // create a new token

        Map<String, String> authorizationParameters = Maps.newHashMap();
        OAuth2Request clientAuth = new OAuth2Request(authorizationParameters, client.getClientId(),
                Sets.newHashSet(new SimpleGrantedAuthority("ROLE_CLIENT")), true,
                scope, null, null, null, null);
        OAuth2Authentication authentication = new OAuth2Authentication(clientAuth, null);


        AccessTokenEntity token = new AccessTokenEntity();
        Set<AccessTokenScope> accessTokenScopes = scope.stream().map(s -> new AccessTokenScope(token, s)).collect(Collectors.toSet());
        token.setClient(client);
        token.setScopes(accessTokenScopes);

        AuthenticationHolderEntity authHolder = new AuthenticationHolderEntity();
        authHolder.setAuthentication(authentication);
        authHolder = authenticationHolderRepository.save(authHolder);
        token.setAuthenticationHolder(authHolder);

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .audience(Lists.newArrayList(client.getClientId()))
                .issuer(configurationProperty.getIssuer())
                .issueTime(new Date())
                .expirationTime(token.getExpiration())
                .jwtID(UUID.randomUUID().toString()) // set a random NONCE in the middle of it
                .build();

        JWSAlgorithm signingAlg = jwtService.getDefaultSigningAlgorithm();
        JWSHeader header = new JWSHeader.Builder(signingAlg)
                .keyID(jwtService.getDefaultSignerKeyId())
                .build();
        SignedJWT signed = new SignedJWT(header, claims);
        jwtService.signJwt(signed);
        token.setJwtValue(signed);
        return token;
    }
}
