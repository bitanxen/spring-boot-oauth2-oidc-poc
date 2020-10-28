package in.bitanxen.poc.model.statics;

public enum ResponseType {
    CODE("code"),
    TOKEN("token");

    private final String type;

    ResponseType(String type) {
        this.type = type;
    }

    public String getType() {
        return this.type;
    }

    public static ResponseType getResponseType(String type) {
        for(ResponseType responseType : values()) {
            if(responseType.getType().equals(type)) {
                return responseType;
            }
        }
        return null;
    }
}
