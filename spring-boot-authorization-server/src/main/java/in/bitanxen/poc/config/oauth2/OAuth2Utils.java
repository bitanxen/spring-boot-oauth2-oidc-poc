package in.bitanxen.poc.config.oauth2;

import org.springframework.util.StringUtils;

import java.util.*;

public interface OAuth2Utils {
    String CLIENT_ID = "client_id";
    String STATE = "state";
    String SCOPE = "scope";
    String REDIRECT_URI = "redirect_uri";
    String RESPONSE_TYPE = "response_type";
    String USER_OAUTH_APPROVAL = "user_oauth_approval";
    String SCOPE_PREFIX = "scope.";
    String GRANT_TYPE = "grant_type";

    static Set<String> parseParameterList(String values) {
        Set<String> result = new TreeSet<String>();
        if (values != null && values.trim().length() > 0) {
            // the spec says the scope is separated by spaces
            String[] tokens = values.split("[\\s+]");
            result.addAll(Arrays.asList(tokens));
        }
        return result;
    }

    static String formatParameterList(Collection<String> value) {
        return value == null ? null : StringUtils.collectionToDelimitedString(value, " ");
    }

    static Map<String, String> extractMap(String query) {
        Map<String, String> map = new HashMap<String, String>();
        Properties properties = StringUtils.splitArrayElementsIntoProperties(
                StringUtils.delimitedListToStringArray(query, "&"), "=");
        if (properties != null) {
            for (Object key : properties.keySet()) {
                map.put(key.toString(), properties.get(key).toString());
            }
        }
        return map;
    }

    static boolean containsAll(Set<String> target, Set<String> members) {
        target = new HashSet<String>(target);
        target.retainAll(members);
        return target.size() == members.size();
    }
}
