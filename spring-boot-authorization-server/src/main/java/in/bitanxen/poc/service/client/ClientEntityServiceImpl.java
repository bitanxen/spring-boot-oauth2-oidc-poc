package in.bitanxen.poc.service.client;

import com.google.common.base.Strings;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.LoadingCache;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import in.bitanxen.poc.config.bean.ConfigurationProperty;
import in.bitanxen.poc.config.jose.PKCEAlgorithm;
import in.bitanxen.poc.dto.client.*;
import in.bitanxen.poc.exception.ClientNotFoundException;
import in.bitanxen.poc.exception.ClientRegistrationException;
import in.bitanxen.poc.model.client.*;
import in.bitanxen.poc.model.scope.SystemScope;
import in.bitanxen.poc.model.statics.*;
import in.bitanxen.poc.model.token.AccessTokenEntity;
import in.bitanxen.poc.repository.ClientEntityRepository;
import in.bitanxen.poc.service.assertion.AssertionValidatorService;
import in.bitanxen.poc.service.oidc.OIDCTokenService;
import in.bitanxen.poc.service.scope.SystemScopeService;
import in.bitanxen.poc.service.token.TokenEntityService;
import in.bitanxen.poc.service.watchlist.BlackListService;
import in.bitanxen.poc.util.CommonUtil;
import in.bitanxen.poc.util.SectorIdentifierLoaderUtil;
import lombok.extern.log4j.Log4j2;
import org.apache.http.impl.client.HttpClientBuilder;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriUtils;

import javax.transaction.Transactional;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.text.ParseException;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static in.bitanxen.poc.dto.client.RegisteredClientFields.*;

@Service
@Log4j2
@Transactional
public class ClientEntityServiceImpl implements ClientEntityService {

    private final ConfigurationProperty configurationProperty;
    private final ClientEntityRepository clientEntityRepository;
    private final TokenEntityService tokenEntityService;
    private final AssertionValidatorService assertionValidatorService;
    private final SystemScopeService systemScopeService;
    private final BlackListService blackListService;
    private final OIDCTokenService oidcTokenService;

    private final LoadingCache<String, List<String>> sectorRedirects;

    public ClientEntityServiceImpl(ConfigurationProperty configurationProperty, ClientEntityRepository clientEntityRepository, TokenEntityService tokenEntityService,
                                   AssertionValidatorService assertionValidatorService, SystemScopeService systemScopeService, BlackListService blackListService,
                                   OIDCTokenService oidcTokenService) {
        this.configurationProperty = configurationProperty;
        this.clientEntityRepository = clientEntityRepository;
        this.tokenEntityService = tokenEntityService;
        this.assertionValidatorService = assertionValidatorService;

        sectorRedirects = CacheBuilder.newBuilder()
                .expireAfterAccess(1, TimeUnit.HOURS)
                .maximumSize(100)
                .build(new SectorIdentifierLoaderUtil(HttpClientBuilder.create().useSystemProperties().build(), configurationProperty.isForceHttps()));
        this.systemScopeService = systemScopeService;
        this.blackListService = blackListService;
        this.oidcTokenService = oidcTokenService;
    }

    @Override
    public ClientEntity getClientEntityById(String id) {
        Optional<ClientEntity> clientEntityOptional = clientEntityRepository.findById(id);
        if(!clientEntityOptional.isPresent()) {
            throw new ClientNotFoundException("Client doesn't exists");
        }
        return clientEntityOptional.get();
    }

    @Override
    public ClientEntity getClientEntityByClientId(String clientId) {
        Optional<ClientEntity> clientEntityOptional = clientEntityRepository.findByClientId(clientId);
        if(!clientEntityOptional.isPresent()) {
            throw new ClientNotFoundException("Client doesn't exists");
        }
        return clientEntityOptional.get();
    }

    @Override
    public Collection<ClientEntity> getAllClients() {
        return clientEntityRepository.findAll();
    }


    @Override
    public ClientEntityDTO loadClientByClientId(String clientId) throws OAuth2Exception {
        try {
            return convertClientEntityIntoDTO(getClientEntityByClientId(clientId));
        } catch (Exception e) {
            throw new OAuth2Exception(e.getLocalizedMessage());
        }
    }

    @Override
    public ClientEntityDTO createClient(CreateUpdateClientEntityDTO createClientEntity) {
        String clientId = generateClientId();
        String clientSecret = generateClientSecret();
        ClientEntity clientEntity = new ClientEntity();

        if(createClientEntity.getSoftwareStatement() != null) {
            validateSoftwareStatement(clientEntity, createClientEntity);
        } else {
            retrofitClient(clientEntity, createClientEntity);
        }

        validateScopes(clientEntity, createClientEntity);
        validateGrantTypes(clientEntity, createClientEntity);
        validateRedirectUris(clientEntity, createClientEntity);
        validateAuth(clientEntity, clientSecret);

        clientEntity.setClientId(clientId);

        if (clientEntity.getTokenEndpointAuthMethod() == null) {
            clientEntity.setTokenEndpointAuthMethod(AuthMethod.SECRET_BASIC);
        }

        if (clientEntity.getTokenEndpointAuthMethod() == AuthMethod.SECRET_BASIC || clientEntity.getTokenEndpointAuthMethod() == AuthMethod.SECRET_JWT || clientEntity.getTokenEndpointAuthMethod() == AuthMethod.SECRET_POST) {
            clientEntity.setClientSecret(clientSecret);
        }

        validateTokenLifespan(clientEntity);

        clientEntity.setDynamicallyRegistered(true);
        clientEntity.setAllowIntrospection(false);
        clientEntity.setCreatedAt(LocalDateTime.now());
        clientEntity = clientEntityRepository.save(clientEntity);

        AccessTokenEntity registrationAccessToken = oidcTokenService.createRegistrationAccessToken(clientEntity);
        registrationAccessToken = tokenEntityService.saveAccessToken(registrationAccessToken);

        return convertClientEntityIntoDTO(clientEntity);
    }

    @Override
    public void deleteClient(String id) {
        ClientEntity clientById = getClientEntityById(id);
        clientEntityRepository.delete(clientById);
    }

    @Override
    public ClientEntityDTO updateClient(String id, CreateUpdateClientEntityDTO updateClientEntity, OAuth2Authentication auth) {
        ClientEntity clientEntity = getClientEntityById(id);

        if(!clientEntity.getClientId().equals(auth.getOAuth2Request().getClientId())) {
            throw new ClientRegistrationException("Not allowed to update the client. Client ID mismatch");
        }

        if(updateClientEntity.getSoftwareStatement() != null) {
            validateSoftwareStatement(clientEntity, updateClientEntity);
        } else {
            retrofitClient(clientEntity, updateClientEntity);
        }

        validateScopes(clientEntity, updateClientEntity);
        validateGrantTypes(clientEntity, updateClientEntity);
        validateRedirectUris(clientEntity, updateClientEntity);
        validateAuth(clientEntity, clientEntity.getClientSecret());

        auth.getUserAuthentication().getPrincipal();

        return null;
    }

    @Override
    public String generateClientId() {
        return CommonUtil.generateAlphaNumeric(10);
    }

    @Override
    public String generateClientSecret() {
        return CommonUtil.generateAlphaNumeric(20);
    }

    @Override
    public UserDetails convertClientIntoUser(String clientId, boolean isUriEncoded, boolean isHeartMode, GrantedAuthority grantedAuthority) {
        if(isUriEncoded) {
            clientId = UriUtils.decode(clientId, "UTF-8");
        }

        ClientEntityDTO client = loadClientByClientId(clientId);
        String clientSecret = client.getClientSecret();

        if(isUriEncoded) {
            clientSecret = UriUtils.encodePathSegment(Strings.nullToEmpty(clientSecret), "UTF-8");
        }

        if(isHeartMode ||
                (client.getTokenEndpointAuthMethod() != null &&
                        (client.getTokenEndpointAuthMethod().equals(AuthMethod.PRIVATE_KEY) || client.getTokenEndpointAuthMethod().equals(AuthMethod.SECRET_JWT)))) {
            clientSecret = new BigInteger(512, new SecureRandom()).toString(16);
        }

        boolean enabled = true;
        boolean accountNonExpired = true;
        boolean credentialsNonExpired = true;
        boolean accountNonLocked = true;
        Set<GrantedAuthority> authorities = new HashSet<>(client.getAuthorities());
        authorities.add(grantedAuthority);

        return new User(clientId, clientSecret, enabled, accountNonExpired, credentialsNonExpired, accountNonLocked, authorities);
    }

    private void retrofitClient(ClientEntity clientEntity, CreateUpdateClientEntityDTO createClientEntity) {
        clientEntity.setClientName(createClientEntity.getClientName());
        clientEntity.setRedirectUris(createClientEntity.getRedirectUris().stream().map(r -> new ClientRedirect(clientEntity, r)).collect(Collectors.toSet()));
        clientEntity.setClientUri(createClientEntity.getClientUri());
        clientEntity.setContacts(createClientEntity.getContacts().stream().map(c -> new ClientContact(clientEntity, c)).collect(Collectors.toSet()));
        clientEntity.setLogoUri(createClientEntity.getLogoUri());
        clientEntity.setTosUri(createClientEntity.getTosUri());
        clientEntity.setTokenEndpointAuthMethod(createClientEntity.getTokenEndpointAuthMethod());
        clientEntity.setClientScopes(createClientEntity.getScopes().stream().map(g -> new ClientScope(clientEntity, g, null, null, false)).collect(Collectors.toSet()));
        clientEntity.setGrantTypes(createClientEntity.getGrantTypes().stream().map(g -> new ClientGrantType(clientEntity, GrantType.getGrantType(g))).collect(Collectors.toSet()));
        clientEntity.setResponseTypes(createClientEntity.getResponseTypes().stream().map(g -> new ClientResponseType(clientEntity, ResponseType.getResponseType(g))).collect(Collectors.toSet()));
        clientEntity.setPolicyUri(createClientEntity.getPolicyUri());
        clientEntity.setJwksUri(createClientEntity.getJwksUri());
        try {
            clientEntity.setJwks(createClientEntity.getJwks() != null ? JWKSet.parse(createClientEntity.getJwks()) : null);
            clientEntity.setSoftwareStatement(SignedJWT.parse(createClientEntity.getSoftwareStatement()));
        } catch (ParseException e) {
            e.printStackTrace();
        }
        clientEntity.setSoftwareId(createClientEntity.getSoftwareId());
        clientEntity.setSoftwareVersion(createClientEntity.getSoftwareVersion());
        clientEntity.setApplicationType(createClientEntity.getApplicationType());
        clientEntity.setSectorIdentifierUri(createClientEntity.getSectorIdentifierUri());
        clientEntity.setSubjectType(createClientEntity.getSubjectType());
        clientEntity.setRequestObjectSigningAlg(createClientEntity.getRequestObjectSigningAlg() != null ? JWSAlgorithm.parse(createClientEntity.getRequestObjectSigningAlg()) : null);
        clientEntity.setUserInfoSignedResponseAlg(createClientEntity.getUserInfoSignedResponseAlg() != null ? JWSAlgorithm.parse(createClientEntity.getUserInfoSignedResponseAlg()) : null);
        clientEntity.setUserInfoEncryptedResponseAlg(createClientEntity.getUserInfoEncryptedResponseAlg() != null ? JWEAlgorithm.parse(createClientEntity.getUserInfoEncryptedResponseAlg()) : null);
        clientEntity.setUserInfoEncryptedResponseEnc(createClientEntity.getUserInfoEncryptedResponseEnc() != null ? EncryptionMethod.parse(createClientEntity.getUserInfoEncryptedResponseEnc()) : null);
        clientEntity.setIdTokenSignedResponseAlg(createClientEntity.getIdTokenSignedResponseAlg() != null ? JWSAlgorithm.parse(createClientEntity.getIdTokenSignedResponseAlg()) : null);
        clientEntity.setIdTokenEncryptedResponseAlg(createClientEntity.getIdTokenEncryptedResponseAlg() != null ? JWEAlgorithm.parse(createClientEntity.getIdTokenEncryptedResponseAlg()) : null);
        clientEntity.setIdTokenEncryptedResponseEnc(createClientEntity.getIdTokenEncryptedResponseEnc() != null ? EncryptionMethod.parse(createClientEntity.getIdTokenEncryptedResponseEnc()) : null);
        clientEntity.setTokenEndpointAuthSigningAlg(createClientEntity.getTokenEndpointAuthSigningAlg() != null ? JWSAlgorithm.parse(createClientEntity.getTokenEndpointAuthSigningAlg()) : null);
        clientEntity.setDefaultMaxAge(createClientEntity.getDefaultMaxAge());
        clientEntity.setRequireAuthTime(createClientEntity.isRequireAuthTime());
        clientEntity.setDefaultACRvalues(createClientEntity.getDefaultACRvalues().stream().map(a -> new ClientACRValue(clientEntity, a)).collect(Collectors.toSet()));
        clientEntity.setInitiateLoginUri(createClientEntity.getInitiateLoginUri());
        clientEntity.setPostLogoutRedirectUris(createClientEntity.getPostLogoutRedirectUris().stream().map(l -> new ClientLogoutRedirect(clientEntity, l)).collect(Collectors.toSet()));
        clientEntity.setRequestUris(createClientEntity.getRequestUris().stream().map(r -> new ClientRequest(clientEntity, r)).collect(Collectors.toSet()));
        clientEntity.setAuthorities(createClientEntity.getAuthorities().stream().map(a -> new ClientGrantedAuthority(clientEntity, a)).collect(Collectors.toSet()));
        clientEntity.setResourceIds(createClientEntity.getResourceIds().stream().map(r -> new ClientResource(clientEntity, r)).collect(Collectors.toSet()));
        clientEntity.setClientDescription(createClientEntity.getClientDescription());
        clientEntity.setClaimsRedirectUris(createClientEntity.getClaimsRedirectUris().stream().map(r -> new ClientClaimRedirect(clientEntity, r)).collect(Collectors.toSet()));
        clientEntity.setCodeChallengeMethod(createClientEntity.getCodeChallengeMethod() != null ? PKCEAlgorithm.parse(createClientEntity.getCodeChallengeMethod()) : null);
    }

    private void validateSoftwareStatement(ClientEntity clientEntity, CreateUpdateClientEntityDTO createClientEntity) {
        if(createClientEntity.getSoftwareStatement() == null){
            throw new ClientRegistrationException("Software statement is null");
        }

        try {
            SignedJWT signedJWT = SignedJWT.parse(createClientEntity.getSoftwareStatement());

            if(!assertionValidatorService.isValid(signedJWT)) {
                throw new ClientRegistrationException("Software statement is invalid");
            }

            JWTClaimsSet claimSet = signedJWT.getJWTClaimsSet();
            for (String claim : claimSet.getClaims().keySet()) {
                switch (claim) {
                    case SOFTWARE_STATEMENT:
                        throw new ClientRegistrationException("Software statement can't include another software statement");
                    case CLAIMS_REDIRECT_URIS:
                        clientEntity.setClaimsRedirectUris(claimSet.getStringListClaim(claim).stream().map(c -> new ClientClaimRedirect(clientEntity, c)).collect(Collectors.toSet()));
                        break;
                    case CLIENT_SECRET_EXPIRES_AT:
                        throw new ClientRegistrationException("Software statement can't include a client secret expiration time");
                    case CLIENT_ID_ISSUED_AT:
                        throw new ClientRegistrationException("Software statement can't include a client ID issuance time");
                    case REGISTRATION_CLIENT_URI:
                        throw new ClientRegistrationException("Software statement can't include a client configuration endpoint");
                    case REGISTRATION_ACCESS_TOKEN:
                        throw new ClientRegistrationException("Software statement can't include a client registration access token");
                    case REQUEST_URIS:
                        clientEntity.setRequestUris(claimSet.getStringListClaim(claim).stream().map(c -> new ClientRequest(clientEntity, c)).collect(Collectors.toSet()));
                        break;
                    case POST_LOGOUT_REDIRECT_URIS:
                        clientEntity.setPostLogoutRedirectUris(claimSet.getStringListClaim(claim).stream().map(c -> new ClientLogoutRedirect(clientEntity, c)).collect(Collectors.toSet()));
                        break;
                    case INITIATE_LOGIN_URI:
                        clientEntity.setInitiateLoginUri(claimSet.getStringClaim(claim));
                        break;
                    case DEFAULT_ACR_VALUES:
                        clientEntity.setDefaultACRvalues(claimSet.getStringListClaim(claim).stream().map(c -> new ClientACRValue(clientEntity, c)).collect(Collectors.toSet()));
                        break;
                    case REQUIRE_AUTH_TIME:
                        clientEntity.setRequireAuthTime(claimSet.getBooleanClaim(claim));
                        break;
                    case DEFAULT_MAX_AGE:
                        clientEntity.setDefaultMaxAge(claimSet.getIntegerClaim(claim));
                        break;
                    case TOKEN_ENDPOINT_AUTH_SIGNING_ALG:
                        clientEntity.setTokenEndpointAuthSigningAlg(JWSAlgorithm.parse(claimSet.getStringClaim(claim)));
                        break;
                    case ID_TOKEN_ENCRYPTED_RESPONSE_ENC:
                        clientEntity.setIdTokenEncryptedResponseEnc(EncryptionMethod.parse(claimSet.getStringClaim(claim)));
                        break;
                    case ID_TOKEN_ENCRYPTED_RESPONSE_ALG:
                        clientEntity.setIdTokenEncryptedResponseAlg(JWEAlgorithm.parse(claimSet.getStringClaim(claim)));
                        break;
                    case ID_TOKEN_SIGNED_RESPONSE_ALG:
                        clientEntity.setIdTokenSignedResponseAlg(JWSAlgorithm.parse(claimSet.getStringClaim(claim)));
                        break;
                    case USERINFO_ENCRYPTED_RESPONSE_ENC:
                        clientEntity.setUserInfoEncryptedResponseEnc(EncryptionMethod.parse(claimSet.getStringClaim(claim)));
                        break;
                    case USERINFO_ENCRYPTED_RESPONSE_ALG:
                        clientEntity.setUserInfoEncryptedResponseAlg(JWEAlgorithm.parse(claimSet.getStringClaim(claim)));
                        break;
                    case USERINFO_SIGNED_RESPONSE_ALG:
                        clientEntity.setUserInfoSignedResponseAlg(JWSAlgorithm.parse(claimSet.getStringClaim(claim)));
                        break;
                    case REQUEST_OBJECT_SIGNING_ALG:
                        clientEntity.setRequestObjectSigningAlg(JWSAlgorithm.parse(claimSet.getStringClaim(claim)));
                        break;
                    case SUBJECT_TYPE:
                        clientEntity.setSubjectType(SubjectType.getByValue(claimSet.getStringClaim(claim)));
                        break;
                    case SECTOR_IDENTIFIER_URI:
                        clientEntity.setSectorIdentifierUri(claimSet.getStringClaim(claim));
                        break;
                    case APPLICATION_TYPE:
                        clientEntity.setApplicationType(AppType.getByValue(claimSet.getStringClaim(claim)));
                        break;
                    case JWKS_URI:
                        clientEntity.setJwksUri(claimSet.getStringClaim(claim));
                        break;
                    case JWKS:
                        clientEntity.setJwks(JWKSet.parse(claimSet.getJSONObjectClaim(claim)));
                        break;
                    case POLICY_URI:
                        clientEntity.setPolicyUri(claimSet.getStringClaim(claim));
                        break;
                    case RESPONSE_TYPES:
                        clientEntity.setResponseTypes(claimSet.getStringListClaim(claim).stream().map(c -> new ClientResponseType(clientEntity, ResponseType.getResponseType(c))).collect(Collectors.toSet()));
                        break;
                    case GRANT_TYPES:
                        clientEntity.setGrantTypes(claimSet.getStringListClaim(claim).stream().map(c -> new ClientGrantType(clientEntity, GrantType.getGrantType(c))).collect(Collectors.toSet()));
                        break;
                    case SCOPE:
                        OAuth2Utils.parseParameterList(claimSet.getStringClaim(claim)).forEach(clientEntity::setScope);
                        break;
                    case TOKEN_ENDPOINT_AUTH_METHOD:
                        clientEntity.setTokenEndpointAuthMethod(AuthMethod.getByValue(claimSet.getStringClaim(claim)));
                        break;
                    case TOS_URI:
                        clientEntity.setTosUri(claimSet.getStringClaim(claim));
                        break;
                    case CONTACTS:
                        clientEntity.setContacts(claimSet.getStringListClaim(claim).stream().map(c -> new ClientContact(clientEntity, c)).collect(Collectors.toSet()));
                        break;
                    case LOGO_URI:
                        clientEntity.setLogoUri(claimSet.getStringClaim(claim));
                        break;
                    case CLIENT_URI:
                        clientEntity.setClientUri(claimSet.getStringClaim(claim));
                        break;
                    case CLIENT_NAME:
                        clientEntity.setClientName(claimSet.getStringClaim(claim));
                        break;
                    case REDIRECT_URIS:
                        clientEntity.setRedirectUris(claimSet.getStringListClaim(claim).stream().map(c -> new ClientRedirect(clientEntity, c)).collect(Collectors.toSet()));
                        break;
                    case CLIENT_SECRET:
                        throw new ClientRegistrationException("Software statement can't contain client secret");
                    case CLIENT_ID:
                        throw new ClientRegistrationException("Software statement can't contain client ID");

                    default:
                        log.warn("Software statement contained unknown field: " + claim + " with value " + claimSet.getClaim(claim));
                        break;
                }
            }
        } catch (ParseException e) {
            throw new ClientRegistrationException("Unable to parse software statement "+e.getLocalizedMessage());
        }
    }

    private void validateTokenLifespan(ClientEntity clientEntity) {
        if (configurationProperty.isHeartMode()) {
            // heart mode has different defaults depending on primary grant type
            if (clientEntity.hasGrantType(GrantType.AUTHORIZATION_CODE)) {
                clientEntity.setAccessTokenValiditySeconds((int)TimeUnit.HOURS.toSeconds(1)); // access tokens good for 1hr
                clientEntity.setIdTokenValiditySeconds((int)TimeUnit.MINUTES.toSeconds(5)); // id tokens good for 5min
                clientEntity.setRefreshTokenValiditySeconds((int)TimeUnit.HOURS.toSeconds(24)); // refresh tokens good for 24hr
            } else if (clientEntity.hasGrantType(GrantType.IMPLICIT)) {
                clientEntity.setAccessTokenValiditySeconds((int)TimeUnit.MINUTES.toSeconds(15)); // access tokens good for 15min
                clientEntity.setIdTokenValiditySeconds((int)TimeUnit.MINUTES.toSeconds(5)); // id tokens good for 5min
                clientEntity.setRefreshTokenValiditySeconds(0); // no refresh tokens
            } else if (clientEntity.hasGrantType(GrantType.CLIENT_CREDENTIALS)) {
                clientEntity.setAccessTokenValiditySeconds((int)TimeUnit.HOURS.toSeconds(6)); // access tokens good for 6hr
                clientEntity.setIdTokenValiditySeconds(0); // no id tokens
                clientEntity.setRefreshTokenValiditySeconds(0); // no refresh tokens
            }
        } else {
            clientEntity.setAccessTokenValiditySeconds((int)TimeUnit.HOURS.toSeconds(1)); // access tokens good for 1hr
            clientEntity.setIdTokenValiditySeconds((int)TimeUnit.MINUTES.toSeconds(10)); // id tokens good for 10min
            clientEntity.setRefreshTokenValiditySeconds(-1); // refresh tokens good until revoked
        }
    }

    private void validateAuth(ClientEntity clientEntity, String clientSecret) {
        if (clientEntity.getTokenEndpointAuthMethod() == null) {
            clientEntity.setTokenEndpointAuthMethod(AuthMethod.SECRET_BASIC);
        }

        if (clientEntity.getTokenEndpointAuthMethod() == AuthMethod.SECRET_BASIC ||
                clientEntity.getTokenEndpointAuthMethod() == AuthMethod.SECRET_JWT ||
                clientEntity.getTokenEndpointAuthMethod() == AuthMethod.SECRET_POST) {

            if (Strings.isNullOrEmpty(clientEntity.getClientSecret())) {
                clientEntity.setClientSecret(clientSecret);
            }
        } else if (clientEntity.getTokenEndpointAuthMethod() == AuthMethod.PRIVATE_KEY) {
            if (Strings.isNullOrEmpty(clientEntity.getJwksUri()) && clientEntity.getJwks() == null) {
                throw new ClientRegistrationException("JWK Set URI required when using private key authentication");
            }

            clientEntity.setClientSecret(null);
        } else if (clientEntity.getTokenEndpointAuthMethod() == AuthMethod.NONE) {
            clientEntity.setClientSecret(null);
        } else {
            throw new ClientRegistrationException("Unknown authentication method");
        }
    }

    private void validateRedirectUris(ClientEntity clientEntity, CreateUpdateClientEntityDTO createClientEntity) {
        Set<String> grantTypes = clientEntity.getGrantTypes().stream().map(clientGrantType -> clientGrantType.getGrantType().getType()).collect(Collectors.toSet());

        if (grantTypes.contains("authorization_code") || grantTypes.contains("implicit")) {
            if (createClientEntity.getRedirectUris() == null || createClientEntity.getRedirectUris().isEmpty()) {
                throw new ClientRegistrationException("Clients using a redirect-based grant type must register at least one redirect URI.");
            }

            for (String uri : createClientEntity.getRedirectUris()) {
                if (blackListService.isSiteBlacklisted(uri)) {
                    throw new ClientRegistrationException("Redirect URI is not allowed: " + uri);
                }

                if (uri.contains("#")) {
                    throw new ClientRegistrationException("Redirect URI can not have a fragment");
                }
            }
        }
    }

    private void validateGrantTypes(ClientEntity clientEntity, CreateUpdateClientEntityDTO createClientEntity) {
        Set<GrantType> finalGrantTypes = new HashSet<>();

        if(createClientEntity.getGrantTypes() == null || createClientEntity.getGrantTypes().isEmpty()) {
            if(clientEntity.hasScope(SystemScopeType.OFFLINE_ACCESS.getValue())) {
                finalGrantTypes.add(GrantType.AUTHORIZATION_CODE);
                finalGrantTypes.add(GrantType.REFRESH_TOKEN);
            } else {
                finalGrantTypes.add(GrantType.AUTHORIZATION_CODE);
            }

            if(configurationProperty.isDualClient()) {
                finalGrantTypes.add(GrantType.CLIENT_CREDENTIALS);
            }
        }

        finalGrantTypes.retainAll(Arrays.asList(GrantType.values()));

        if (finalGrantTypes.contains(GrantType.PASSWORD)) {
            throw new ClientRegistrationException("The password grant type is not allowed in dynamic registration on this server.");
        }

        if (finalGrantTypes.contains(GrantType.AUTHORIZATION_CODE)) {
            if (finalGrantTypes.contains(GrantType.IMPLICIT) ||
                    (!configurationProperty.isDualClient() && finalGrantTypes.contains(GrantType.CLIENT_CREDENTIALS))) {
                throw new ClientRegistrationException("Incompatible grant types requested : "+finalGrantTypes);
            }

            if(createClientEntity.getResponseTypes().contains("token")) {
                throw new ClientRegistrationException("Token response type is not allowed with authorization_code grant type");
            }

            clientEntity.setResponseType(ResponseType.CODE);
        }

        if (finalGrantTypes.contains(GrantType.IMPLICIT)) {
            if (finalGrantTypes.contains(GrantType.AUTHORIZATION_CODE) ||
                    (!configurationProperty.isDualClient() && finalGrantTypes.contains(GrantType.CLIENT_CREDENTIALS))) {
                throw new ClientRegistrationException("Incompatible grant types requested : "+finalGrantTypes);
            }

            if(createClientEntity.getResponseTypes().contains("code")) {
                throw new ClientRegistrationException("Code response type is not allowed with implicit grant type");
            }

            clientEntity.setResponseType(ResponseType.TOKEN);
            clientEntity.removeGrantType(GrantType.REFRESH_TOKEN);
            clientEntity.removeScope(SystemScopeType.OFFLINE_ACCESS.getValue());
        }

        if (finalGrantTypes.contains(GrantType.CLIENT_CREDENTIALS)) {
            if (!configurationProperty.isDualClient() &&
                    (finalGrantTypes.contains(GrantType.AUTHORIZATION_CODE) || finalGrantTypes.contains(GrantType.IMPLICIT))) {
                // return an error, you can't have these grant types together
                throw new ClientRegistrationException("Incompatible grant types requested : "+finalGrantTypes);
            }

            if (!clientEntity.getResponseTypes().isEmpty()) {
                // return an error, you can't have this grant type and response type together
                throw new ClientRegistrationException("Incompatible response types requested");
            }

            // don't allow refresh tokens or id tokens in client_credentials clients
            clientEntity.removeGrantType(GrantType.REFRESH_TOKEN);
            clientEntity.removeScope(SystemScopeType.OFFLINE_ACCESS.getValue());
            clientEntity.removeScope(SystemScopeType.OPENID_SCOPE.getValue());
        }

        if (finalGrantTypes.isEmpty()) {
            throw new ClientRegistrationException("Clients must register at least one grant type.");
        }

        finalGrantTypes.forEach(clientEntity::setGrantType);
    }

    private void validateScopes(ClientEntity clientEntity, CreateUpdateClientEntityDTO createClientEntity) {
        Set<SystemScope> requestedScopes = new HashSet<>(systemScopeService.fromStrings(createClientEntity.getScopes()));
        Set<SystemScope> allowedScopes = new HashSet<>(systemScopeService.removeRestrictedAndReservedScopes(requestedScopes));

        if (allowedScopes.isEmpty()) {
            allowedScopes = new HashSet<>(systemScopeService.getDefaults());
        }
        allowedScopes.stream().map(SystemScope::getValue).collect(Collectors.toSet()).forEach(clientEntity::setScope);
    }

    private ClientEntityDTO convertClientEntityIntoDTO(ClientEntity clientEntity) {
        if(clientEntity == null) {
            return null;
        }
        return ClientEntityDTO.builder()
                .id(clientEntity.getId())
                .clientId(clientEntity.getClientId())
                .clientSecret(clientEntity.getClientSecret())
                .clientName(clientEntity.getClientName())
                .redirectUris(clientEntity.getRedirectUris().stream().map(this::convertIntoClientRedirectDTO).collect(Collectors.toSet()))
                .clientUri(clientEntity.getClientUri())
                .contacts(clientEntity.getContacts().stream().map(this::convertIntoClientRedirectDTO).collect(Collectors.toSet()))
                .logoUri(clientEntity.getLogoUri())
                .tosUri(clientEntity.getTosUri())
                .tokenEndpointAuthMethod(clientEntity.getTokenEndpointAuthMethod())
                .clientScopes(clientEntity.getClientScopes().stream().map(this::convertIntoClientScopeDTO).collect(Collectors.toSet()))
                .grantTypes(clientEntity.getGrantTypes().stream().map(this::convertIntoClientGrantTypeDTO).collect(Collectors.toSet()))
                .responseTypes(clientEntity.getResponseTypes().stream().map(this::convertIntoClientResponseTypeDTO).collect(Collectors.toSet()))
                .policyUri(clientEntity.getPolicyUri())
                .jwksUri(clientEntity.getJwksUri())
                .jwks(clientEntity.getJwks() != null ? clientEntity.getJwks() : null)
                .softwareId(clientEntity.getSoftwareId())
                .softwareVersion(clientEntity.getSoftwareVersion())
                .applicationType(clientEntity.getApplicationType())
                .sectorIdentifierUri(clientEntity.getSectorIdentifierUri())
                .subjectType(clientEntity.getSubjectType())
                .requestObjectSigningAlg(clientEntity.getRequestObjectSigningAlg() != null ? clientEntity.getRequestObjectSigningAlg() : null)
                .userInfoSignedResponseAlg(clientEntity.getUserInfoSignedResponseAlg() != null ? clientEntity.getUserInfoSignedResponseAlg() : null)
                .userInfoEncryptedResponseAlg(clientEntity.getUserInfoEncryptedResponseAlg() != null ? clientEntity.getUserInfoEncryptedResponseAlg() : null)
                .userInfoEncryptedResponseEnc(clientEntity.getUserInfoEncryptedResponseEnc() != null ? clientEntity.getUserInfoEncryptedResponseEnc() : null)
                .idTokenSignedResponseAlg(clientEntity.getIdTokenSignedResponseAlg() != null ? clientEntity.getIdTokenSignedResponseAlg() : null)
                .idTokenEncryptedResponseAlg(clientEntity.getIdTokenEncryptedResponseAlg() != null ? clientEntity.getIdTokenEncryptedResponseAlg() : null)
                .idTokenEncryptedResponseEnc(clientEntity.getIdTokenEncryptedResponseEnc() != null ? clientEntity.getIdTokenEncryptedResponseEnc() : null)
                .tokenEndpointAuthSigningAlg(clientEntity.getTokenEndpointAuthSigningAlg() != null ? clientEntity.getTokenEndpointAuthSigningAlg() : null)
                .defaultMaxAge(clientEntity.getDefaultMaxAge())
                .requireAuthTime(clientEntity.isRequireAuthTime())
                .defaultACRvalues(clientEntity.getDefaultACRvalues().stream().map(this::convertIntoClientACRvalueDTO).collect(Collectors.toSet()))
                .initiateLoginUri(clientEntity.getInitiateLoginUri())
                .postLogoutRedirectUris(clientEntity.getPostLogoutRedirectUris().stream().map(this::convertIntoClientLogoutRedirectDTO).collect(Collectors.toSet()))
                .requestUris(clientEntity.getRequestUris().stream().map(this::convertIntoClientRequestURI).collect(Collectors.toSet()))
                .authorities(clientEntity.getAuthorities().stream().map(this::convertIntoClientAuthorityDTO).collect(Collectors.toSet()))
                .accessTokenValiditySeconds(clientEntity.getAccessTokenValiditySeconds())
                .refreshTokenValiditySeconds(clientEntity.getRefreshTokenValiditySeconds())
                .resourceIds(clientEntity.getResourceIds().stream().map(this::convertIntoClientResourceIdDTO).collect(Collectors.toSet()))
                .clientDescription(clientEntity.getClientDescription())
                .reuseRefreshToken(clientEntity.isReuseRefreshToken())
                .dynamicallyRegistered(clientEntity.isDynamicallyRegistered())
                .allowIntrospection(clientEntity.isAllowIntrospection())
                .idTokenValiditySeconds(clientEntity.getIdTokenValiditySeconds())
                .createdAt(clientEntity.getCreatedAt())
                .clearAccessTokensOnRefresh(clientEntity.isClearAccessTokensOnRefresh())
                .deviceCodeValiditySeconds(clientEntity.getDeviceCodeValiditySeconds())
                .claimsRedirectUris(clientEntity.getClaimsRedirectUris().stream().map(this::convertIntoClientClaimRedirectDTO).collect(Collectors.toSet()))
                .softwareStatement(clientEntity.getSoftwareStatement() != null ? clientEntity.getSoftwareStatement().getParsedString() : null)
                .codeChallengeMethod(clientEntity.getCodeChallengeMethod() != null ? clientEntity.getCodeChallengeMethod().toJSONString() : null)
                .build();
    }

    private ClientRedirectDTO convertIntoClientRedirectDTO(ClientRedirect clientRedirect) {
        if(clientRedirect == null) {
            return null;
        }
        return ClientRedirectDTO.builder()
                .clientRedirectId(clientRedirect.getId())
                .entityId(clientRedirect.getClientEntity().getId())
                .clientId(clientRedirect.getClientEntity().getClientId())
                .redirectUri(clientRedirect.getRedirectUri())
                .build();
    }

    private ClientContactDTO convertIntoClientRedirectDTO(ClientContact clientContact) {
        if(clientContact == null) {
            return null;
        }
        return ClientContactDTO.builder()
                .clientContactId(clientContact.getId())
                .entityId(clientContact.getClientEntity().getId())
                .clientId(clientContact.getClientEntity().getClientId())
                .contact(clientContact.getContact())
                .build();
    }

    private ClientScopeDTO convertIntoClientScopeDTO(ClientScope clientScope) {
        if(clientScope == null) {
            return null;
        }

        return ClientScopeDTO.builder()
                .clientScopeId(clientScope.getId())
                .entityId(clientScope.getClientEntity().getId())
                .clientId(clientScope.getClientEntity().getClientId())
                .scope(clientScope.getValue())
                .description(clientScope.getDescription())
                .icon(clientScope.getIcon())
                .defaultScope(clientScope.isDefaultScope())
                .build();
    }

    private ClientGrantTypeDTO convertIntoClientGrantTypeDTO(ClientGrantType clientGrantType) {
        if(clientGrantType == null) {
            return null;
        }

        return ClientGrantTypeDTO.builder()
                .clientGrantTypeId(clientGrantType.getId())
                .entityId(clientGrantType.getClientEntity().getId())
                .clientId(clientGrantType.getClientEntity().getClientId())
                .grantType(clientGrantType.getGrantType())
                .build();
    }

    private ClientResponseTypeDTO convertIntoClientResponseTypeDTO(ClientResponseType clientResponseType) {
        if(clientResponseType == null) {
            return null;
        }

        return ClientResponseTypeDTO.builder()
                .clientResponseTypeId(clientResponseType.getId())
                .entityId(clientResponseType.getClientEntity().getId())
                .clientId(clientResponseType.getClientEntity().getClientId())
                .responseType(clientResponseType.getResponseType())
                .build();
    }

    private ClientACRValueDTO convertIntoClientACRvalueDTO(ClientACRValue clientACRValue) {
        if(clientACRValue == null) {
            return null;
        }

        return ClientACRValueDTO.builder()
                .clientACRValueId(clientACRValue.getId())
                .entityId(clientACRValue.getClientEntity().getId())
                .clientId(clientACRValue.getClientEntity().getClientId())
                .acrValue(clientACRValue.getDefaultACRValue())
                .build();
    }

    private ClientLogoutRedirectDTO convertIntoClientLogoutRedirectDTO(ClientLogoutRedirect clientLogoutRedirect) {
        if(clientLogoutRedirect == null) {
            return null;
        }

        return ClientLogoutRedirectDTO.builder()
                .clientPostLogoutRedirectId(clientLogoutRedirect.getId())
                .entityId(clientLogoutRedirect.getClientEntity().getId())
                .clientId(clientLogoutRedirect.getClientEntity().getClientId())
                .logoutRedirectUri(clientLogoutRedirect.getLogoutRedirectUri())
                .build();
    }

    private ClientRequestURIDTO convertIntoClientRequestURI(ClientRequest clientRequest) {
        if(clientRequest == null) {
            return null;
        }

        return ClientRequestURIDTO.builder()
                .clientRequestUriId(clientRequest.getId())
                .entityId(clientRequest.getClientEntity().getId())
                .clientId(clientRequest.getClientEntity().getClientId())
                .requestUri(clientRequest.getRequestUri())
                .build();
    }

    private ClientAuthorityDTO convertIntoClientAuthorityDTO(ClientGrantedAuthority clientGrantedAuthority) {
        if(clientGrantedAuthority == null) {
            return null;
        }

        return ClientAuthorityDTO.builder()
                .clientAuthorityId(clientGrantedAuthority.getId())
                .entityId(clientGrantedAuthority.getClientEntity().getId())
                .clientId(clientGrantedAuthority.getClientEntity().getClientId())
                .authority(clientGrantedAuthority.getAuthority())
                .build();
    }

    private ClientResourceIDDTO convertIntoClientResourceIdDTO(ClientResource clientResource) {
        if (clientResource == null) {
            return null;
        }

        return ClientResourceIDDTO.builder()
                .clientResourceId(clientResource.getId())
                .entityId(clientResource.getClientEntity().getId())
                .clientId(clientResource.getClientEntity().getClientId())
                .resourceId(clientResource.getResourceId())
                .build();
    }

    private ClientClaimsRedirectURIDTO convertIntoClientClaimRedirectDTO(ClientClaimRedirect clientClaimRedirect) {
        if(clientClaimRedirect == null) {
            return null;
        }

        return ClientClaimsRedirectURIDTO.builder()
                .clientClaimRedirectId(clientClaimRedirect.getId())
                .entityId(clientClaimRedirect.getClientEntity().getId())
                .clientId(clientClaimRedirect.getClientEntity().getClientId())
                .claimsRedirectUri(clientClaimRedirect.getClaimsRedirectUri())
                .build();
    }
}
