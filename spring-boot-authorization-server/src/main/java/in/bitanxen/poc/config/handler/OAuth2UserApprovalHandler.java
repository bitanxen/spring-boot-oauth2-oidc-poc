package in.bitanxen.poc.config.handler;

import com.google.common.base.Splitter;
import com.google.common.base.Strings;
import com.google.common.collect.Sets;
import in.bitanxen.poc.dto.watchlist.ApprovedSiteDTO;
import in.bitanxen.poc.dto.watchlist.ApprovedSiteScopeDTO;
import in.bitanxen.poc.dto.watchlist.CreateUpdateApprovedSiteDTO;
import in.bitanxen.poc.model.watchlist.WhiteListSite;
import in.bitanxen.poc.model.watchlist.WhiteListSiteScope;
import in.bitanxen.poc.service.client.ClientEntityService;
import in.bitanxen.poc.service.scope.SystemScopeService;
import in.bitanxen.poc.service.watchlist.ApprovedSiteService;
import in.bitanxen.poc.service.watchlist.WhiteListService;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.approval.UserApprovalHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpSession;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

import static in.bitanxen.poc.config.openid.ConnectRequestParameters.*;

@Component
public class OAuth2UserApprovalHandler implements UserApprovalHandler {

    private final ApprovedSiteService approvedSiteService;
    private final WhiteListService whiteListService;
    private final ClientEntityService clientEntityService;
    private final SystemScopeService systemScopeService;

    public OAuth2UserApprovalHandler(ApprovedSiteService approvedSiteService, WhiteListService whiteListService,
                                     ClientEntityService clientEntityService, SystemScopeService systemScopeService) {
        this.approvedSiteService = approvedSiteService;
        this.whiteListService = whiteListService;
        this.clientEntityService = clientEntityService;
        this.systemScopeService = systemScopeService;
    }

    @Override
    public boolean isApproved(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {
        if (authorizationRequest.isApproved()) {
            return true;
        } else {
            // if not, check to see if the user has approved it
            // TODO: make parameter name configurable?
            return Boolean.parseBoolean(authorizationRequest.getApprovalParameters().get("user_oauth_approval"));
        }
    }

    @Override
    public AuthorizationRequest checkForPreApproval(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {
        String userId = userAuthentication.getName();
        String clientId = authorizationRequest.getClientId();
        LocalDateTime now = LocalDateTime.now();
        boolean alreadyApproved = false;

        String prompt = (String) authorizationRequest.getExtensions().get(PROMPT);
        List<String> prompts = Splitter.on(PROMPT_SEPARATOR).splitToList(Strings.nullToEmpty(prompt));
        if (!prompts.contains(PROMPT_CONSENT)) {
            Collection<ApprovedSiteDTO> approvedSites = approvedSiteService.getByClientIdAndUserId(clientId, userId);

            for (ApprovedSiteDTO approvedSite : approvedSites) {
                if (!approvedSite.getTimeoutDate().isAfter(now)) {
                    List<String> approvedScopes = approvedSite.getApprovedSiteScopes().stream().map(ApprovedSiteScopeDTO::getScope).collect(Collectors.toList());
                    if (systemScopeService.scopesMatch(approvedScopes, authorizationRequest.getScope())) {

                        CreateUpdateApprovedSiteDTO approvedSiteDTO = CreateUpdateApprovedSiteDTO.builder()
                                .timeoutDate(LocalDateTime.now().plusHours(1))
                                .scopes(approvedScopes)
                                .build();

                        //We have a match; update the access date on the AP entry and return true.
                        approvedSite.setAccessDate(LocalDateTime.now());
                        approvedSiteService.updateApprovedSite(approvedSite.getId(), approvedSiteDTO);
                        authorizationRequest.getExtensions().put(APPROVED_SITE, approvedSite.getId());
                        authorizationRequest.setApproved(true);
                        alreadyApproved = true;

                        setAuthTime(authorizationRequest);
                    }
                }
            }

            if (!alreadyApproved) {
                WhiteListSite whiteListSite = whiteListService.getByClientId(clientId);

                if(whiteListSite != null) {
                    List<String> whileListSiteScopes = whiteListSite.getAllowedScopes().stream().map(WhiteListSiteScope::getScope).collect(Collectors.toList());
                    if (systemScopeService.scopesMatch(whileListSiteScopes, authorizationRequest.getScope())) {
                        authorizationRequest.setApproved(true);
                        setAuthTime(authorizationRequest);
                    }
                }
            }
        }
        return authorizationRequest;
    }

    @Override
    public AuthorizationRequest updateAfterApproval(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {
        String userId = userAuthentication.getName();
        String clientId = authorizationRequest.getClientId();
        ClientDetails client = clientEntityService.loadClientByClientId(clientId);

        if (Boolean.parseBoolean(authorizationRequest.getApprovalParameters().get("user_oauth_approval"))) {
            authorizationRequest.setApproved(true);

            Set<String> allowedScopes = Sets.newHashSet();
            Map<String,String> approvalParams = authorizationRequest.getApprovalParameters();

            Set<String> keys = approvalParams.keySet();
            Set<String> clientScope = client.getScope();

            for (String key : keys) {
                if (key.startsWith("scope_")) {
                    String scope = approvalParams.get(key);
                    Set<String> approveSet = Sets.newHashSet(scope);

                    if(clientScope.contains(scope)) {
                        allowedScopes.add(scope);
                    }
                    /*
                    if (systemScopeService.scopesMatch(client.getScope(), approveSet)) {

                    }
                     */

                }
            }
            authorizationRequest.setScope(allowedScopes);

            String remember = authorizationRequest.getApprovalParameters().get("remember");
            if (!Strings.isNullOrEmpty(remember) && !remember.equals("none")) {

                CreateUpdateApprovedSiteDTO.CreateUpdateApprovedSiteDTOBuilder approvedSiteDTOBuilder = CreateUpdateApprovedSiteDTO.builder()
                        .clientId(clientId)
                        .userId(userId)
                        .scopes(new ArrayList<>(allowedScopes));

                Date timeout = null;
                if (remember.equals("one-hour")) {
                    approvedSiteDTOBuilder.timeoutDate(LocalDateTime.now().plusHours(1));
                } else {
                    approvedSiteDTOBuilder.timeoutDate(LocalDateTime.now().plusMinutes(15));
                }

                CreateUpdateApprovedSiteDTO approvedSiteDTO = approvedSiteDTOBuilder.build();

                ApprovedSiteDTO approvedSite = approvedSiteService.createApprovedSite(approvedSiteDTO);
                authorizationRequest.getExtensions().put(APPROVED_SITE, approvedSite.getId());
            }

            setAuthTime(authorizationRequest);
        }
        return authorizationRequest;
    }

    @Override
    public Map<String, Object> getUserApprovalRequest(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {
        return new HashMap<>(authorizationRequest.getRequestParameters());
    }

    private void setAuthTime(AuthorizationRequest authorizationRequest) {
        // Get the session auth time, if we have it, and store it in the request
        ServletRequestAttributes attr = (ServletRequestAttributes) RequestContextHolder.currentRequestAttributes();
        HttpSession session = attr.getRequest().getSession();
        if (session != null) {
            Date authTime = (Date) session.getAttribute(AUTH_TIMESTAMP);
            if (authTime != null) {
                String authTimeString = Long.toString(authTime.getTime());
                authorizationRequest.getExtensions().put(AUTH_TIMESTAMP, authTimeString);
            }
        }
    }
}
