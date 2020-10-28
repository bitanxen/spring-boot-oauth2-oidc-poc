package in.bitanxen.poc.model.statics;

public enum GrantType {
    AUTHORIZATION_CODE("authorization_code"),
    IMPLICIT("implicit"),
    REDELEGATE("urn:ietf:params:oauth:grant_type:redelegate"),
    REFRESH_TOKEN("refresh_token"),
    CLIENT_CREDENTIALS("client_credentials"),
    PASSWORD("password");

    private final String type;

    GrantType(String type) {
        this.type = type;
    }

    public String getType() {
        return this.type;
    }

    public static GrantType getGrantType(String type) {
        for(GrantType grantType : values()) {
            if(grantType.getType().equals(type)) {
                return grantType;
            }
        }
        return null;
    }
}
