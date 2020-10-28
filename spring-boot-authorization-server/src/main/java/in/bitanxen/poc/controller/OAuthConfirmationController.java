package in.bitanxen.poc.controller;

import com.google.common.base.Joiner;
import com.google.common.base.Splitter;
import com.google.common.base.Strings;
import in.bitanxen.poc.dto.client.ClientEntityDTO;
import in.bitanxen.poc.dto.scope.ScopeDTO;
import in.bitanxen.poc.service.client.ClientEntityService;
import in.bitanxen.poc.service.scope.SystemScopeService;
import lombok.extern.log4j.Log4j2;
import org.apache.http.client.utils.URIBuilder;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.endpoint.RedirectResolver;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.SessionAttributes;

import java.net.URISyntaxException;
import java.security.Principal;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static in.bitanxen.poc.config.openid.ConnectRequestParameters.*;

@Log4j2
@Controller
@SessionAttributes("authorizationRequest")
public class OAuthConfirmationController {

    private final ClientEntityService clientEntityService;
    private final RedirectResolver redirectResolver;
    private final SystemScopeService systemScopeService;

    public OAuthConfirmationController(ClientEntityService clientEntityService, RedirectResolver redirectResolver, SystemScopeService systemScopeService) {
        this.clientEntityService = clientEntityService;
        this.redirectResolver = redirectResolver;
        this.systemScopeService = systemScopeService;
    }

    @PreAuthorize("hasRole('ROLE_USER')")
    @RequestMapping("/confirm_access")
    public String confimAccess(Model model, @ModelAttribute("authorizationRequest") AuthorizationRequest authRequest, Principal p) {
        String prompt = (String)authRequest.getExtensions().get(PROMPT);
        List<String> prompts = Splitter.on(PROMPT_SEPARATOR).splitToList(Strings.nullToEmpty(prompt));
        ClientEntityDTO client = null;

        try {
            client = clientEntityService.loadClientByClientId(authRequest.getClientId());
        } catch (OAuth2Exception e) {
            log.error("confirmAccess: OAuth2Exception was thrown when attempting to load client", e);
            model.addAttribute("error_code", HttpStatus.BAD_REQUEST);
            model.addAttribute("error_message", "Client Not Found");
        } catch (IllegalArgumentException e) {
            log.error("confirmAccess: IllegalArgumentException was thrown when attempting to load client", e);
            model.addAttribute("error_code", HttpStatus.BAD_REQUEST);
            model.addAttribute("error_message", "Unable to parse OAuth Request");
        }

        if (prompts.contains(PROMPT_NONE)) {
            // if we've got a redirect URI then we'll send it
            String url = redirectResolver.resolveRedirect(authRequest.getRedirectUri(), client);
            try {
                URIBuilder uriBuilder = new URIBuilder(url);
                uriBuilder.addParameter("error", "interaction_required");
                if (!Strings.isNullOrEmpty(authRequest.getState())) {
                    uriBuilder.addParameter("state", authRequest.getState()); // copy the state parameter if one was given
                }
                return "redirect:" + uriBuilder.toString();
            } catch (URISyntaxException e) {
                log.error("Can't build redirect URI for prompt=none, sending error instead", e);
                model.addAttribute("error_code", HttpStatus.FORBIDDEN);
                model.addAttribute("error_message", "Cannot Send you back to origin");
            }
        }
        String redirect_uri = authRequest.getRedirectUri();

        model.addAttribute("auth_request", authRequest);
        model.addAttribute("client", client);
        model.addAttribute("redirect_uri", redirect_uri);

        Set<String> scope = authRequest.getScope();
        Collection<ScopeDTO> requestedScopes = systemScopeService.getScopeFromString(scope);
        Set<ScopeDTO> allowedScopes = requestedScopes.stream().filter(scopeDTO -> !scopeDTO.isRestricted()).collect(Collectors.toSet());

        model.addAttribute("scopes", allowedScopes);

        if (client.getContacts() != null) {
            String contacts = Joiner.on(", ").join(client.getContacts());
            model.addAttribute("contacts", contacts);
        }

        return "approve";
    }
}
