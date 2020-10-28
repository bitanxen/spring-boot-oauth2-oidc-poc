package in.bitanxen.poc.config.oauth2;

import com.google.common.base.Strings;
import in.bitanxen.poc.exception.AuthorizationPendingException;
import in.bitanxen.poc.exception.DeviceCodeException;
import in.bitanxen.poc.model.device.DeviceCode;
import in.bitanxen.poc.model.device.DeviceCodeScope;
import in.bitanxen.poc.service.client.ClientEntityService;
import in.bitanxen.poc.service.device.DeviceServiceImpl;
import in.bitanxen.poc.service.oauth2.OAuth2TokenEntityService;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.token.AbstractTokenGranter;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.Set;
import java.util.stream.Collectors;

@Component
public class DeviceTokenGranter extends AbstractTokenGranter {

    public static final String GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code";

    private final DeviceServiceImpl deviceService;

    protected DeviceTokenGranter(OAuth2TokenEntityService tokenServices, ClientEntityService clientService, OAuth2RequestFactory requestFactory, DeviceServiceImpl deviceService) {
        super(tokenServices, clientService, requestFactory, GRANT_TYPE);
        this.deviceService = deviceService;
    }

    @Override
    protected OAuth2Authentication getOAuth2Authentication(ClientDetails client, TokenRequest tokenRequest) {
        String deviceCode = tokenRequest.getRequestParameters().get("device_code");

        if(Strings.isNullOrEmpty(deviceCode)) {
            throw new InvalidGrantException("Invalid device code : Null");
        }

        DeviceCode savedDeviceCode = deviceService.findDeviceCode(deviceCode, client.getClientId());

        if(savedDeviceCode == null) {
            throw new InvalidGrantException("Invalid device code : Device Code not found");
        }

        if(savedDeviceCode.getExpiration().isAfter(LocalDateTime.now())) {
            deviceService.clearDeviceCode(deviceCode, client.getClientId());
            throw new DeviceCodeException("Device code has expired " + deviceCode);
        } else if (!savedDeviceCode.isApproved()) {
            throw new AuthorizationPendingException("Authorization pending for code " + deviceCode);
        } else {
            deviceService.clearDeviceCode(deviceCode, client.getClientId());
            Set<String> deviceScope = savedDeviceCode.getScopes().stream().map(DeviceCodeScope::getScope).collect(Collectors.toSet());
            tokenRequest.setScope(deviceScope);
            return new OAuth2Authentication(getRequestFactory().createOAuth2Request(client, tokenRequest), savedDeviceCode.getAuthenticationHolder().getUserAuth());
        }
    }
}
