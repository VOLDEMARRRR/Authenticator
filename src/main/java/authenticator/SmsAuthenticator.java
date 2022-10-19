package authenticator;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.models.*;
import org.keycloak.sessions.AuthenticationSessionModel;
import sms.SmsServiceFactory;

import javax.ws.rs.core.Response;
import java.io.IOException;


public class SmsAuthenticator implements Authenticator {

    private static final String TPL_CODE = "login-sms.ftl";

    @Override
    public void authenticate(AuthenticationFlowContext context) {

        KeycloakSession session = context.getSession();
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        UserModel user = context.getUser();

        int length = Integer.parseInt(config.getConfig().get("length"));
        int ttl = Integer.parseInt(config.getConfig().get("ttl"));
        String code = SecretGenerator.getInstance().randomString(length, SecretGenerator.DIGITS);
        String smsText = String.format("Your SMS code is %s and is valid for %s minutes.", code, Math.floorDiv(ttl, 60));
        String mobileNumber = user.getFirstAttribute("mobile_number");

        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        try {
            SmsServiceFactory.get(config.getConfig()).send(mobileNumber, smsText);
        } catch (IOException e) {
            e.printStackTrace();
        }
        context.challenge(context.form().setAttribute("realm", context.getRealm()).createForm(TPL_CODE));//???

        authSession.setAuthNote("code", code);
        authSession.setAuthNote("ttl", Long.toString(System.currentTimeMillis() + (ttl * 1000L)));
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        String enteredCode = context.getHttpRequest().getDecodedFormParameters().getFirst("code");

        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        String code = authSession.getAuthNote("code");
        String ttl = authSession.getAuthNote("ttl");

        boolean isValid = enteredCode.equals(code);

        if (isValid) {
            if (Long.parseLong(ttl) < System.currentTimeMillis()) {
                // expired
                context.failureChallenge(AuthenticationFlowError.EXPIRED_CODE,
                        context.form().setError("smsAuthCodeExpired").createErrorPage(Response.Status.BAD_REQUEST));
            } else {
                // valid
                context.success();
            }
        } else {
            // invalid
            AuthenticationExecutionModel execution = context.getExecution();
            if (execution.isRequired()) {
                context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
                        context.form().setAttribute("realm", context.getRealm())
                                .setError("smsAuthCodeInvalid").createForm(TPL_CODE));
            } else if (execution.isConditional() || execution.isAlternative()) {
                context.attempted();
            }
        }
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {
        return false;
    }

    @Override
    public void setRequiredActions(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {

    }

    @Override
    public void close() {

    }

}
