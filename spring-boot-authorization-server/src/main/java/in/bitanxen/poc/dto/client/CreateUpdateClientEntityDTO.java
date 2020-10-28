package in.bitanxen.poc.dto.client;

import in.bitanxen.poc.model.statics.AppType;
import in.bitanxen.poc.model.statics.AuthMethod;
import in.bitanxen.poc.model.statics.SubjectType;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
public class CreateUpdateClientEntityDTO {
    private String clientName;
    private List<String> redirectUris;
    private String clientUri;
    private List<String> contacts;
    private String logoUri;
    private String tosUri;
    private AuthMethod tokenEndpointAuthMethod;
    private List<String> scopes;
    private List<String> grantTypes;
    private List<String> responseTypes;
    private String policyUri;
    private String jwksUri;
    private String jwks;
    private String softwareId;
    private String softwareVersion;
    private AppType applicationType;
    private String sectorIdentifierUri;
    private SubjectType subjectType;
    private String requestObjectSigningAlg;
    private String userInfoSignedResponseAlg;
    private String userInfoEncryptedResponseAlg;
    private String userInfoEncryptedResponseEnc;
    private String idTokenSignedResponseAlg;
    private String idTokenEncryptedResponseAlg;
    private String idTokenEncryptedResponseEnc;
    private String tokenEndpointAuthSigningAlg;
    private int defaultMaxAge;
    private boolean requireAuthTime;
    private List<String> defaultACRvalues;
    private String initiateLoginUri;
    private List<String> postLogoutRedirectUris;
    private List<String> requestUris;
    private List<String> authorities;
    private List<String> resourceIds;
    private String clientDescription;
    private List<String> claimsRedirectUris;
    private String softwareStatement;
    private String codeChallengeMethod;
}
