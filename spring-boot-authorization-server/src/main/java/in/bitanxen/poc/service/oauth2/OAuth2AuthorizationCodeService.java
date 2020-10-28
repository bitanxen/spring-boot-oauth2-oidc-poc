package in.bitanxen.poc.service.oauth2;

import in.bitanxen.poc.dto.authcode.AuthorizationCodeDTO;
import in.bitanxen.poc.model.authcode.AuthorizationCodeEntity;
import in.bitanxen.poc.model.authholder.AuthenticationHolderEntity;
import in.bitanxen.poc.repository.AuthorizationCodeEntityRepository;
import in.bitanxen.poc.service.auth.AuthenticationHolderService;
import in.bitanxen.poc.util.CommonUtil;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.time.LocalDateTime;

@Service
@Log4j2
@Transactional
public class OAuth2AuthorizationCodeService implements AuthorizationCodeServices {

    private final AuthenticationHolderService authenticationHolderService;
    private final AuthorizationCodeEntityRepository codeRepository;

    @Value("${sysbean.oauth2.server.config.auth-code.validity-min}")
    private int authCodeExpiryMin;

    public OAuth2AuthorizationCodeService(AuthenticationHolderService authenticationHolderService, AuthorizationCodeEntityRepository codeRepository) {
        this.authenticationHolderService = authenticationHolderService;
        this.codeRepository = codeRepository;
    }

    @Override
    public String createAuthorizationCode(OAuth2Authentication authentication) {
        String code = CommonUtil.generateAlphaNumeric(10);
        AuthenticationHolderEntity authHolder = new AuthenticationHolderEntity();
        authHolder.setAuthentication(authentication);
        authHolder = authenticationHolderService.save(authHolder);
        LocalDateTime expiration = LocalDateTime.now().plusMinutes(authCodeExpiryMin);
        AuthorizationCodeEntity authorizationCodeEntity = codeRepository.save(new AuthorizationCodeEntity(code, authHolder, expiration));
        return authorizationCodeEntity.getCode();
    }

    @Override
    public OAuth2Authentication consumeAuthorizationCode(String code) throws InvalidGrantException {
        AuthorizationCodeEntity authorizationCodeEntity = codeRepository.findByCode(code);

        if(authorizationCodeEntity == null) {
            throw new InvalidGrantException("Authorization Code not found.");
        }

        if(authorizationCodeEntity.isExpired()) {
            throw new InvalidGrantException("Authorization Code expired.");
        }

        if(LocalDateTime.now().isAfter(authorizationCodeEntity.getExpiration())) {
            throw new InvalidGrantException("Authorization Code expired.");
        }

        authorizationCodeEntity.setExpiration(LocalDateTime.now());
        authorizationCodeEntity.setExpired(true);

        return authorizationCodeEntity.getAuthenticationHolder().getAuthentication();
    }

    private AuthorizationCodeDTO convertIntoDTO(AuthorizationCodeEntity authorizationCodeEntity) {
        if(authorizationCodeEntity == null) {
            return null;
        }

        return AuthorizationCodeDTO.builder()
                .id(authorizationCodeEntity.getId())
                .code(authorizationCodeEntity.getCode())
                .authHolderId(authorizationCodeEntity.getAuthenticationHolder().getId())
                .expiration(authorizationCodeEntity.getExpiration())
                .build();
    }
}
