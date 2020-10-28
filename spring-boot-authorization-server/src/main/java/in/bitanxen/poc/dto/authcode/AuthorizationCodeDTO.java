package in.bitanxen.poc.dto.authcode;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter
@Setter
@Builder
public class AuthorizationCodeDTO {
    private String id;
    private String code;
    private String authHolderId;
    private LocalDateTime expiration;
}
