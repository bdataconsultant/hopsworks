package io.hops.hopsworks.common.glassfish;

import com.sun.enterprise.security.PrincipalGroupFactory;
import com.sun.enterprise.security.SecurityContext;
import org.glassfish.security.common.Group;

import javax.security.auth.Subject;
import java.security.Principal;
import java.util.Set;

public class GlassfishUtils {
    public static void addGroupToCurrentUser(String groupName) {
        Subject subject = SecurityContext.getCurrent().getSubject();
        Set<Principal> principals = subject.getPrincipals();
        Group group = new Group(groupName);
        principals.add(group);
    }
}
