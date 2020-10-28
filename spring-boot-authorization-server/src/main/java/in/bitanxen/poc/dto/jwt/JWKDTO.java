package in.bitanxen.poc.dto.jwt;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class JWKDTO {
    private String kid;
    private String e;
    private String alg;
    private String kty;
    private String use;
    private String n;
}
