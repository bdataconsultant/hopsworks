package io.hops.hopsworks.common.jacc;

import io.hops.hopsworks.common.user.UsersController;

import javax.security.auth.Subject;
import javax.security.jacc.PolicyContext;
import javax.security.jacc.PolicyContextException;
import javax.security.jacc.WebRoleRefPermission;
import java.security.*;
import java.security.cert.Certificate;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

public final class JaccUtil {

    private static final Logger LOGGER = Logger.getLogger(JaccUtil.class.getName());

    private static final Set<String> NO_ROLES =
            Collections.emptySet();
    private static final Permission DUMMY_WEB_ROLE_REF_PERM = new WebRoleRefPermission("", "dummy");

    /**
     * Retrieves the declared Servlet security roles that have been mapped to the {@code Principal}s of
     * the currently authenticated {@code Subject}, optionally limited to the scope of the Servlet
     * referenced by {@code servletName}.
     *
     * @param servletName
     *            The scope; {@code null} indicates Servlet-context-wide matching.
     * @return the roles; empty {@code Set} iff:
     *         <ul>
     *         <li>the remote user is unauthenticated</li>
     *         <li>the remote user has not been associated with any roles declared within the search
     *         scope</li>
     *         <li>the method has not been called within a Servlet invocation context</li>
     *         </ul>
     */
    public static Set<String> getCallerWebRoles(String servletName) {
        // get current subject
        Subject subject = getSubject();
        if (subject == null) {
            // unauthenticated
            LOGGER.log(Level.INFO, "No subject!");
            return NO_ROLES;
        }
        Set<Principal> principals = subject.getPrincipals();
        principals.forEach(p -> LOGGER.log(Level.INFO, "LOGGED_PRINCIPAL: " + p + ", class: " + p.getClass()));
        if (principals.isEmpty()) {
            // unauthenticated?
            LOGGER.log(Level.INFO, "No roles!");
            return NO_ROLES;
        }
        // construct a domain for querying the policy; the code source shouldn't matter, as far as
        // JACC permissions are concerned
        ProtectionDomain domain = new ProtectionDomain(new CodeSource(null, (Certificate[]) null), null, null,
                principals.toArray(new Principal[principals.size()]));
        // get all permissions accorded to those principals
        PermissionCollection pc = Policy.getPolicy().getPermissions(domain);
        // cause resolution of WebRoleRefPermissions, if any, in the collection, if still unresolved
        pc.implies(DUMMY_WEB_ROLE_REF_PERM);
        Enumeration<Permission> e = pc.elements();
        if (!e.hasMoreElements()) {
            // nothing granted, hence no roles
            LOGGER.log(Level.INFO, "No permissions!");
            return NO_ROLES;
        }
        Set<String> roleNames = NO_ROLES;
        // iterate over the collection and eliminate duplicates
        while (e.hasMoreElements()) {
            Permission p = e.nextElement();
            LOGGER.log(Level.INFO, "permission: " + p);
            // only interested in Servlet container security-role(-ref) permissions
            if (p instanceof WebRoleRefPermission) {
                String candidateRoleName = p.getActions();
                LOGGER.log(Level.INFO, "candidateRoleName: " + candidateRoleName);
                // - ignore the "any-authenticated-user" role (only collect it if your
                // application has actually declared a role named "**")
                // - also restrict to the scope of the Servlet identified by the servletName
                // argument, unless null
                if (!"**".equals(candidateRoleName) && ((servletName == null) || servletName.equals(p.getName()))
                        && ((roleNames == NO_ROLES) || !roleNames.contains(candidateRoleName))) {
                    if (roleNames == NO_ROLES) {
                        roleNames = new HashSet<>();
                    }
                    roleNames.add(candidateRoleName);
                }
            }
        }
        return roleNames;
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
