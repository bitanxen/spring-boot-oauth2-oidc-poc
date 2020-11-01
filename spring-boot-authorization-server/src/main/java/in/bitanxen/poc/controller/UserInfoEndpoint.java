package in.bitanxen.poc.controller;

import com.nimbusds.jwt.SignedJWT;
import in.bitanxen.poc.model.user.SystemUserInfo;
import in.bitanxen.poc.service.jwt.signer.JWTSignerVerifierService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.text.ParseException;

@RestController
public class UserInfoEndpoint {

    public static final String URL = "userinfo";

    private final JWTSignerVerifierService jwtSignerVerifierService;

    public UserInfoEndpoint(JWTSignerVerifierService jwtSignerVerifierService) {
        this.jwtSignerVerifierService = jwtSignerVerifierService;
    }

    @GetMapping(value = URL)
    public ResponseEntity<Object> getUserInfo(HttpServletRequest request, Authentication authentication) {
        System.out.println("User Info Endpoint");
        System.out.println(authentication);

        OAuth2Authentication oAuth2Authentication = (OAuth2Authentication) authentication;
        OAuth2Request clientAuthentication = oAuth2Authentication.getOAuth2Request();
        String clientId = clientAuthentication.getClientId();

        System.out.println(oAuth2Authentication.getPrincipal());
        System.out.println(clientAuthentication.getScope());

        OAuth2AuthenticationDetails details = (OAuth2AuthenticationDetails) oAuth2Authentication.getDetails();

        return ResponseEntity.ok("UserInfo");
    }
}
