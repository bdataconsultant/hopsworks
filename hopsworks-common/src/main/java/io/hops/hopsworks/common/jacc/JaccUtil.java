package io.hops.hopsworks.common.jacc;


import javax.security.auth.Subject;
import javax.security.jacc.PolicyContext;
import javax.security.jacc.PolicyContextException;
import java.security.Principal;
import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;

public final class JaccUtil {

    private static final String GLASSFISH_GROUP_CLASS_NAME = "org.glassfish.security.common.Group";

    private static final Set<String> NO_ROLES = Collections.emptySet();

    /**
     * Retrieves the declared Servlet security role that have been mapped to the {@code Principal}s of
     * the currently authenticated {@code Subject}, optionally limited to the scope of the Servlet
     * referenced by {@code servletName}.
     *
     *
     * @return the role
     */
    public static String getAuthenticatedUserRole() {
        // get current subject
        Subject subject = getSubject();
        if (subject == null) {
            return null;
        }
        Set<Principal> principals = subject.getPrincipals();
        if (principals.isEmpty()) {
            return null;
        }
        return principals.stream()
                .filter(p -> p.getClass().getName().equals(GLASSFISH_GROUP_CLASS_NAME))
                .map(Principal::getName)
                .collect(Collectors.toList()).get(0);
    }

    private static Subject getSubject() {
        return getFromJaccPolicyContext("javax.security.auth.Subject.container");
    }

    @SuppressWarnings("unchecked")
    private static <T> T getFromJaccPolicyContext(String key) {
        try {
            return (T) PolicyContext.getContext(key);
        }
        catch (PolicyContextException | IllegalArgumentException e) {
            return null;
        }
    }

    private JaccUtil() {
    }
}
