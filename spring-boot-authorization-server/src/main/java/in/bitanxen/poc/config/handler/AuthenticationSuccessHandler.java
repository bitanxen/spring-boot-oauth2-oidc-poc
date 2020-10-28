package in.bitanxen.poc.config.handler;

import in.bitanxen.poc.config.filter.AuthorizationRequestFilter;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.Date;

import static in.bitanxen.poc.config.openid.ConnectRequestParameters.AUTH_TIMESTAMP;

@Component
public class AuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        Date authTimestamp = new Date();

        HttpSession session = request.getSession();

        session.setAttribute(AUTH_TIMESTAMP, authTimestamp);

        if (session.getAttribute(AuthorizationRequestFilter.PROMPT_REQUESTED) != null) {
            session.setAttribute(AuthorizationRequestFilter.PROMPTED, Boolean.TRUE);
            session.removeAttribute(AuthorizationRequestFilter.PROMPT_REQUESTED);
        }

        logger.info("Successful Authentication of " + authentication.getName() + " at " + authTimestamp.toString());

        super.onAuthenticationSuccess(request, response, authentication);
    }
}
